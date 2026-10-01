"""Server creation: Quick Start, advanced creator, JSON create/auto-create API."""
import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError as PydanticValidationError

from .. import queries as sql
from .. import store
from ..auth import current_user
from ..models import RuntimeCreate
from ..services import (
    _is_safe_fetch_url,
    adapter_contract,
    create_runtime_adapter_binding,
    create_runtime_from_package,
    enqueue_runtime_action,
    extract_schema_values,
    install_tool_package,
    validate_runtime_class_adapter,
    write_runtime_config,
)
from ..strings import slug
from ..web import render_page


router = APIRouter()


@router.get("/quick-start", response_class=HTMLResponse)
def quick_start_page(error: str = "") -> str:
    _cu = current_user.get()
    _role = (_cu or {}).get("role", "admin")
    _is_admin = _role in ("admin", "read_write")
    _can_shell = _role == "admin"
    _all_pkgs = store.rows("SELECT id, name, description, category, risk_level, package_json FROM tool_packages WHERE enabled=1 ORDER BY source='builtin' DESC, created_at ASC")
    _seen_names: set[str] = set()
    packages = []
    for _p in _all_pkgs:
        if _p["name"] not in _seen_names:
            _seen_names.add(_p["name"])
            packages.append(_p)
    # Available base images: built-in + previously built
    _builtin_images = [
        ("mcp-runtime-shell:latest", "mcp-runtime-shell:latest — standardowy UBI9 (oc, kubectl, curl, jq) [zalecane]"),
        ("mcp-runtime-http-gateway:latest", "mcp-runtime-http-gateway:latest — HTTP gateway"),
        ("mcp-runtime-openapi:latest", "mcp-runtime-openapi:latest — auto-MCP z OpenAPI spec (FastMCP)"),
        ("registry.access.redhat.com/ubi9/python-312-minimal", "ubi9/python-312-minimal — czysty Python 3.12 / RHEL 9"),
        ("python:3.12-slim", "python:3.12-slim — czysty Python/Debian"),
        ("python:3.11-slim", "python:3.11-slim — Python 3.11 Debian"),
        ("debian:bookworm-slim", "debian:bookworm-slim — czysty Debian"),
    ]
    _built_images = store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' AND runtime_image NOT LIKE 'mcp-runtime-http-gateway%' AND runtime_image NOT LIKE 'mcp-runtime-shell:latest' ORDER BY runtime_image"
    )
    def _tool_cmd(t: dict) -> str:
        # package_json uses 'config', deployed tools use 'execution'
        ex = t.get('config') or t.get('execution') or {}
        cmd = ex.get('command') or []
        url = ex.get('url') or ''
        method = ex.get('method') or 'POST'
        if cmd:
            return ' '.join(str(c) for c in cmd)
        if url:
            return f'{method} {url}'
        return ''

    def _pkg_card(p: dict) -> dict[str, Any]:
        try:
            pj = json.loads(p['package_json'] or '{}')
        except Exception:
            pj = {}
        rc = pj.get('runtime_class') or {}
        risk = p.get('risk_level') or 'low'
        return {
            "pkg": p,
            "image": rc.get('runtime_image') or '—',
            "tools": [(t, _tool_cmd(t)) for t in pj.get('tools') or []],
            "risk": risk,
            "risk_color": {'low': 'var(--success)', 'medium': 'var(--warning)', 'high': 'var(--danger)'}.get(risk, 'var(--muted)'),
            "category_icon": {'rag': '🧠', 'http': '🌐', 'shell': '🐚', 'openshift': '🔴', 'kubernetes': '☸️', 'database': '🗄️'}.get(p.get('category', ''), '📦'),
        }

    pkg_cards = [_pkg_card(p) for p in packages]

    return render_page('quickstart', "pages/quick_start.html", _built_images=_built_images, _builtin_images=_builtin_images, _can_shell=_can_shell, _is_admin=_is_admin, error=error, pkg_cards=pkg_cards)


@router.post("/api/quick-start")
async def quick_start_create(request: Request):
    form = await request.form()
    type_ = str(form.get("type") or "")
    name = str(form.get("name") or "Mój serwer MCP").strip() or "Mój serwer MCP"

    _cu = current_user.get()
    _role = (_cu or {}).get("role", "admin")
    if type_ == "shell" and _role != "admin":
        from urllib.parse import quote
        return RedirectResponse(f"/quick-start?error={quote('Brak uprawnień: definiowanie własnych poleceń shell wymaga roli admin.')}", status_code=303)

    # Read ENV vars from form (env_key_N / env_val_N)
    _qs_env: dict[str, str] = {}
    _i = 0
    while True:
        _k = str(form.get(f"env_key_{_i}") or "").strip()
        _v = str(form.get(f"env_val_{_i}") or "")
        if _k:
            _qs_env[_k] = _v
        elif f"env_key_{_i}" not in form:
            break
        _i += 1

    def _save_env(runtime_id: str) -> None:
        if not _qs_env:
            return
        _ep = store.CONFIG_ROOT / runtime_id / "runtime-env.json"
        _ep.parent.mkdir(parents=True, exist_ok=True)
        _existing: dict[str, str] = {}
        if _ep.exists():
            try:
                _existing = json.loads(_ep.read_text(encoding="utf-8")).get("env") or {}
            except Exception:
                pass
        _existing.update(_qs_env)
        _ep.write_text(json.dumps({"env": _existing}, indent=2), encoding="utf-8")

    # Read policy fields from form
    def _qs_policy(form: Any, timeout_default: int = 30, response_kb_default: int = 5120) -> dict[str, Any]:
        try:
            timeout = max(5, min(300, int(form.get("policy_timeout") or timeout_default)))
        except (ValueError, TypeError):
            timeout = timeout_default
        try:
            max_response_kb = max(64, min(51200, int(form.get("policy_max_response_kb") or response_kb_default)))
        except (ValueError, TypeError):
            max_response_kb = response_kb_default
        return {
            "require_read_only": bool(form.get("policy_read_only")),
            "block_write_tools": bool(form.get("policy_block_write")),
            "block_destructive_tools": bool(form.get("policy_block_destructive")),
            "timeout_seconds": timeout,
            "max_payload_bytes": 262144,
            "max_response_bytes": max_response_kb * 1024,
        }

    try:
        if type_ == "api":
            url = str(form.get("url") or "").strip()
            method = str(form.get("method") or "POST").upper()
            param = re.sub(r"[^a-zA-Z0-9_]", "_", str(form.get("param") or "query").strip()) or "query"
            if not url:
                return RedirectResponse(f"/quick-start?error={quote('Wpisz URL API')}", status_code=303)
            pol = _qs_policy(form)
            tool_config: dict[str, Any] = {"method": method, "url": url, "timeout_seconds": pol["timeout_seconds"], "max_response_bytes": pol["max_response_bytes"]}
            if method in {"POST", "PUT", "PATCH"}:
                tool_config["body"] = {param: f"${{{param}}}"}
            tool_mode = "read-only" if pol["require_read_only"] else "read-write"
            package: dict[str, Any] = {
                "id": slug(name) + "-" + uuid.uuid4().hex[:4],
                "name": name,
                "description": f"REST API tool — {url}",
                "category": "http",
                "risk_level": "low",
                "runtime_class": {"name": "http-gateway", "runtime_image": "mcp-runtime-http-gateway:latest",
                                  "allowed_execution_types": ["http_request"], "risk_level": "low", "security_profile": "restricted"},
                "adapters": [{"name": "http_request", "adapter_type": "http", "implemented": True, "enabled": True, "risk_level": "low", "mode": tool_mode}],
                "policy": pol,
                "tools": [{"name": "call_api", "description": f"Wywołaj {url}", "execution_type": "http_request", "enabled": True,
                           "risk_level": "low", "mode": tool_mode, "category": "http", "config": tool_config,
                           "input_schema": {"type": "object", "properties": {param: {"type": "string", "description": "Zapytanie do API"}}, "required": [param]}}],
            }
            pkg_id = install_tool_package(package, source="quick-start")
            runtime_id = create_runtime_from_package(pkg_id, name, deploy=True)
            _save_env(runtime_id)

        elif type_ == "shell":
            cmd_raw = str(form.get("cmd") or "").strip()
            desc = str(form.get("desc") or "Wykonaj komendę").strip()
            if not cmd_raw:
                return RedirectResponse(f"/quick-start?error={quote('Wpisz komendę')}", status_code=303)
            cmd_parts = cmd_raw.split()
            binary = Path(cmd_parts[0]).name if cmd_parts else "curl"

            # Detect ${*varname} multi-arg params separately from regular ${var}
            splat_vars = re.findall(r"\$\{\*(\w+)\}", cmd_raw)
            regular_vars = re.findall(r"\$\{(\w+)\}", cmd_raw)  # includes splat names too
            all_vars = splat_vars + [v for v in regular_vars if v not in splat_vars]
            schema_props = {}
            for v in all_vars:
                if v in splat_vars:
                    schema_props[v] = {"type": "string", "description": f"Argumenty dla {cmd_parts[0] if cmd_parts else 'komendy'} (np. 'pods -n production -o json')"}
                else:
                    schema_props[v] = {"type": "string", "description": f"Wartość dla {v}"}

            pol = _qs_policy(form, timeout_default=30, response_kb_default=1024)
            pol["allowed_binaries"] = [binary]

            # Read shell-specific access controls from step 2
            allowed_prefix = str(form.get("allowed_prefix") or "").strip()
            blocked_raw = str(form.get("blocked_prefixes") or "").strip()
            blocked_prefixes = [l.strip() for l in blocked_raw.splitlines() if l.strip()]
            if allowed_prefix:
                pol["allowed_command_prefixes"] = [allowed_prefix]
            if blocked_prefixes:
                pol["blocked_command_prefixes"] = blocked_prefixes

            tool_mode = "read-only" if pol["require_read_only"] else "read-write"
            package = {
                "id": slug(name) + "-" + uuid.uuid4().hex[:4],
                "name": name,
                "description": desc,
                "category": "other",
                "risk_level": "low",
                "runtime_class": {"name": str(form.get("shell_runtime_class") or "shell-readonly"),
                                  "runtime_image": "mcp-runtime-shell:latest",
                                  "allowed_execution_types": ["shell"], "risk_level": "low", "security_profile": "restricted"},
                "adapters": [{"name": "shell", "adapter_type": "shell", "implemented": True, "enabled": True, "risk_level": "low", "mode": tool_mode}],
                "policy": pol,
                "tools": [{"name": "run_command", "description": desc, "execution_type": "shell", "enabled": True,
                           "risk_level": "low", "mode": tool_mode, "category": "other",
                           "config": {"command": cmd_parts, "timeout_seconds": pol["timeout_seconds"]},
                           "input_schema": {"type": "object", "properties": schema_props, "required": list(schema_props.keys())}}],
            }
            pkg_id = install_tool_package(package, source="quick-start")
            runtime_id = create_runtime_from_package(pkg_id, name, deploy=True)
            _save_env(runtime_id)

        elif type_ == "package":
            pkg_id = str(form.get("package_id") or "").strip()
            if not pkg_id:
                return RedirectResponse(f"/quick-start?error={quote('Wybierz zestaw z listy')}", status_code=303)
            runtime_id = create_runtime_from_package(pkg_id, name, deploy=True)
            _save_env(runtime_id)

        elif type_ == "import":
            import_source = str(form.get("import_source") or "paste")
            raw_json: str | None = None

            if import_source == "url":
                import_url = str(form.get("import_url") or "").strip()
                if not import_url:
                    return RedirectResponse(f"/quick-start?error={quote('Wpisz URL do pliku JSON')}", status_code=303)
                if not _is_safe_fetch_url(import_url):
                    return RedirectResponse(f"/quick-start?error={quote('Niedozwolony URL (prywatne IP lub zablokowana domena)')}", status_code=303)
                try:
                    async with httpx.AsyncClient(follow_redirects=False, timeout=15) as client:
                        resp = await client.get(import_url)
                    if resp.status_code != 200:
                        return RedirectResponse(f"/quick-start?error={quote(f'Błąd pobierania URL: HTTP {resp.status_code}')}", status_code=303)
                    raw_json = resp.text
                except Exception as exc:
                    return RedirectResponse(f"/quick-start?error={quote(f'Nie można pobrać URL: {exc}')}", status_code=303)

            elif import_source == "file":
                upload = form.get("import_file")
                if not upload or not getattr(upload, "filename", None):
                    return RedirectResponse(f"/quick-start?error={quote('Wybierz plik JSON')}", status_code=303)
                raw_json = (await upload.read()).decode("utf-8", errors="replace")

            else:  # paste
                raw_json = str(form.get("import_json") or "").strip()
                if not raw_json:
                    return RedirectResponse(f"/quick-start?error={quote('Wklej JSON konfiguracji')}", status_code=303)

            try:
                package = json.loads(raw_json)
            except json.JSONDecodeError as exc:
                return RedirectResponse(f"/quick-start?error={quote(f'Nieprawidłowy JSON: {exc}')}", status_code=303)

            if not isinstance(package, dict) or not package.get("tools"):
                return RedirectResponse(f"/quick-start?error={quote('Plik nie wygląda jak Package JSON — brakuje pola \"tools\"')}", status_code=303)

            # Use provided name as override if different from package name
            if name and name != "Mój serwer MCP":
                package["name"] = name
            elif not package.get("name"):
                package["name"] = name

            # Ensure unique ID to avoid conflicts
            package["id"] = slug(package["name"]) + "-" + uuid.uuid4().hex[:6]

            pkg_id = install_tool_package(package, source="import")
            runtime_id = create_runtime_from_package(pkg_id, package["name"], deploy=True)
            _save_env(runtime_id)

        else:
            return RedirectResponse(f"/quick-start?error={quote('Wybierz typ serwera')}", status_code=303)

    except HTTPException as exc:
        return RedirectResponse(f"/quick-start?error={quote(str(exc.detail))}", status_code=303)

    return RedirectResponse(f"/runtimes/{runtime_id}?welcome=1", status_code=303)


@router.get("/create", response_class=HTMLResponse)
def create_page(error: str = "") -> str:
    _cu = current_user.get()
    _can_shell = (_cu or {}).get("role") == "admin"
    packages = store.rows("SELECT id, name, description FROM tool_packages WHERE enabled=1 ORDER BY category, name")
    runtime_classes = store.rows("SELECT name, runtime_image FROM runtime_classes WHERE enabled=1 ORDER BY name")
    # Available images for env picker
    _adv_builtin = [
        ("mcp-runtime-shell:latest", "🐚 Standardowe — oc, kubectl, curl, jq (Python 3.12 UBI9) [zalecane]"),
        ("mcp-runtime-http-gateway:latest", "🌐 HTTP Gateway — REST API calls"),
        ("python:3.12-slim", "🐍 Python 3.12 czysty Debian"),
        ("debian:bookworm-slim", "📦 Debian czysty"),
    ]
    _adv_custom_images = store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' AND runtime_image NOT IN ('mcp-runtime-shell:latest','mcp-runtime-http-gateway:latest') ORDER BY runtime_image"
    )

    return render_page('create', "pages/create.html", _adv_builtin=_adv_builtin, _adv_custom_images=_adv_custom_images, _can_shell=_can_shell, error=error, packages=packages, runtime_classes=runtime_classes)


@router.post("/api/runtimes")
async def create_runtime(request: Request):
    form = await request.form()
    selected_adapters = list(form.getlist("adapter_names")) if hasattr(form, "getlist") else []
    try:
        data = RuntimeCreate(
            name=str(form.get("name") or ""),
            package_id=str(form.get("package_id") or ""),
            runtime_class=str(form.get("runtime_class") or "http-gateway"),
            risk_level=str(form.get("risk_level") or "low"),
            first_tool_name=str(form.get("first_tool_name") or ""),
            first_tool_url=str(form.get("first_tool_url") or ""),
            first_tool_method=str(form.get("first_tool_method") or "POST"),
            first_tool_enabled=str(form.get("first_tool_enabled") or "true") == "true",
        )
    except PydanticValidationError as exc:
        detail = "; ".join(
            f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors()[:3]
        )
        return RedirectResponse(f"/create?error={quote(detail)}", status_code=303)
    # Read policy from new advanced form fields
    deploy_after = str(form.get("deploy_after_create") or "false") == "true"
    try:
        timeout_sec = max(5, min(300, int(form.get("timeout_seconds") or 30)))
    except (ValueError, TypeError):
        timeout_sec = 30
    try:
        max_resp_bytes = max(65536, min(52428800, int(form.get("max_response_kb") or 5120) * 1024))
    except (ValueError, TypeError):
        max_resp_bytes = 5242880
    try:
        max_payload_bytes = max(16384, min(10485760, int(form.get("max_payload_kb") or 256) * 1024))
    except (ValueError, TypeError):
        max_payload_bytes = 262144
    bins_raw = str(form.get("allowed_binaries") or "").strip()
    allowed_bins = [b.strip() for b in re.split(r"[\s,]+", bins_raw) if b.strip()]
    allowed_prefix = str(form.get("allowed_prefix") or "").strip()
    blocked_raw = str(form.get("blocked_prefixes") or "").strip()
    blocked_prefixes = [l.strip() for l in blocked_raw.splitlines() if l.strip()]
    adv_policy: dict[str, Any] = {
        "require_read_only": form.get("policy_read_only") == "1",
        "block_write_tools": form.get("policy_block_write") == "1",
        "block_destructive_tools": form.get("policy_block_destructive") == "1",
        "timeout_seconds": timeout_sec,
        "max_payload_bytes": max_payload_bytes,
        "max_response_bytes": max_resp_bytes,
    }
    if allowed_bins:
        adv_policy["allowed_binaries"] = allowed_bins
    if allowed_prefix:
        adv_policy["allowed_command_prefixes"] = [allowed_prefix]
    if blocked_prefixes:
        adv_policy["blocked_command_prefixes"] = blocked_prefixes

    _cu = current_user.get()
    _role = (_cu or {}).get("role", "admin")
    if not data.package_id and _role != "admin":
        return RedirectResponse(f"/create?error={quote('Brak uprawnień: tworzenie serwera od zera wymaga roli admin. Wybierz gotową paczkę.')}", status_code=303)

    if data.package_id:
        try:
            runtime_id = create_runtime_from_package(data.package_id, data.name, deploy=deploy_after)
        except HTTPException as exc:
            return RedirectResponse(f"/create?error={quote(str(exc.detail))}", status_code=303)
        # Override policy with advanced form values
        store.execute(
            sql.UPSERT_POLICY_COMPACT,
            (runtime_id, json.dumps(adv_policy), store.now_iso()),
        )
        return RedirectResponse(f"/runtimes/{runtime_id}?welcome=1", status_code=303)
    runtime_class = store.one(sql.SELECT_RUNTIME_CLASS_ENABLED_BY_NAME, (data.runtime_class,))
    if not runtime_class:
        raise HTTPException(status_code=400, detail=f"Runtime class is not enabled: {data.runtime_class}")
    runtime_id = slug(data.name) + "-" + uuid.uuid4().hex[:6]
    now = store.now_iso()
    store.execute(
        sql.INSERT_RUNTIME,
        (runtime_id, data.name, data.description, data.runtime_class, data.template, "draft", data.risk_level, runtime_class["runtime_image"], now, now),
    )
    store.execute(
        sql.INSERT_POLICY,
        (runtime_id, json.dumps(adv_policy), now),
    )
    # Read ENV vars from dynamic form fields env_key_N / env_val_N
    env_vars: dict[str, str] = {}
    i = 0
    while True:
        k = str(form.get(f"env_key_{i}") or "").strip()
        v = str(form.get(f"env_val_{i}") or "")
        if k:
            env_vars[k] = v
        elif f"env_key_{i}" not in form:
            break
        i += 1
    # OpenAPI runtime: inject connection config from dedicated form fields as env vars
    if data.runtime_class == "openapi":
        _oa_backend = str(form.get("openapi_backend_url") or "").strip()
        _oa_spec    = str(form.get("openapi_spec_url")    or "").strip()
        _oa_token   = str(form.get("openapi_auth_token")  or "").strip()
        _oa_header  = str(form.get("openapi_auth_header") or "").strip()
        if _oa_backend:
            env_vars["BACKEND_BASE_URL"] = _oa_backend
        if _oa_spec:
            env_vars["OPENAPI_SPEC_URL"] = _oa_spec
        if _oa_token:
            env_vars["BACKEND_AUTH_TOKEN"] = _oa_token
        if _oa_header:
            env_vars["BACKEND_AUTH_HEADER"] = _oa_header
        env_vars.setdefault("SERVER_NAME", data.name)
    # Create config directory and files so operator can deploy
    config_dir = store.CONFIG_ROOT / runtime_id
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "runtime-config.json").write_text(
        json.dumps({"server_id": runtime_id, "name": data.name, "runtime_class": data.runtime_class}, indent=2),
        encoding="utf-8",
    )
    (config_dir / "policy.json").write_text(json.dumps(adv_policy, indent=2), encoding="utf-8")
    (config_dir / "tools.json").write_text(json.dumps({"tools": []}, indent=2), encoding="utf-8")
    (config_dir / "runtime-env.json").write_text(json.dumps({"env": env_vars}, indent=2), encoding="utf-8")
    store.execute(
        "UPDATE runtimes SET config_path = ? WHERE id = ?",
        (str(config_dir), runtime_id),
    )
    for adapter_name in selected_adapters:
        adapter = store.one(sql.SELECT_ADAPTER_ENABLED_IMPLEMENTED, (adapter_name,))
        if not adapter:
            continue
        contract = adapter_contract(adapter_name)
        config = extract_schema_values(form, f"adapter.{adapter_name}.config", contract.get("config_schema") or {})
        adapter_policy = extract_schema_values(form, f"adapter.{adapter_name}.policy", contract.get("policy_schema") or {})
        create_runtime_adapter_binding(runtime_id, adapter_name, config, adapter_policy)
    if data.first_tool_name and data.first_tool_url:
        try:
            body = json.loads(str(form.get("first_tool_body_json") or "{}"))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid first tool body JSON: {exc}") from exc
        validate_runtime_class_adapter(data.runtime_class, "http_request")
        config = {
            "method": data.first_tool_method.upper(),
            "url": data.first_tool_url,
            "body": body,
            "timeout_seconds": 30,
            "max_response_bytes": 5242880,
        }
        store.execute(
            sql.INSERT_TOOL,
            (
                runtime_id,
                data.first_tool_name,
                f"{data.first_tool_name} HTTP tool",
                "http_request",
                json.dumps(config),
                json.dumps({"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
                "{}",
                1 if data.first_tool_enabled else 0,
                data.risk_level,
                "read-only",
                "other",
                now,
                now,
            ),
        )
        store.audit("admin", "add_initial_tool", "runtime", runtime_id, {"tool": data.first_tool_name})
    # Shell tool from advanced creator step 3
    shell_cmd_raw = str(form.get("shell_cmd_adv") or "").strip()
    if shell_cmd_raw:
        shell_tool_name = re.sub(r"[^a-z0-9_]", "_", str(form.get("shell_tool_name_adv") or "run_command").strip().lower()) or "run_command"
        shell_desc = str(form.get("first_tool_desc_adv") or f"Wykonaj komendę: {shell_cmd_raw[:60]}").strip()
        cmd_parts = shell_cmd_raw.split()
        splat_vars = re.findall(r"\$\{\*(\w+)\}", shell_cmd_raw)
        regular_vars = [v for v in re.findall(r"\$\{(\w+)\}", shell_cmd_raw) if v not in splat_vars]
        _env_names = {c["name"] for c in store.rows("SELECT name FROM runtime_credentials WHERE runtime_id = ?", (runtime_id,))}
        _env_like = {v for v in regular_vars if v.isupper() and (v in _env_names or any(v.startswith(p) for p in ("AWX_", "API_", "DB_", "PG", "MIKROTIK_", "TOKEN", "SECRET", "PASS", "AUTH")))}
        regular_vars = [v for v in regular_vars if v not in _env_like]
        schema_props: dict[str, Any] = {}
        for v in splat_vars:
            schema_props[v] = {"type": "string", "description": f"Argumenty dla {cmd_parts[0] if cmd_parts else 'komendy'}"}
        for v in regular_vars:
            schema_props[v] = {"type": "string", "description": f"Wartość parametru {v}"}
        shell_schema = {"type": "object", "properties": schema_props, "required": list(schema_props.keys())} if schema_props else {"type": "object"}
        store.execute(
            sql.INSERT_TOOL,
            (runtime_id, shell_tool_name, shell_desc, "shell",
             json.dumps({"command": cmd_parts, "timeout_seconds": adv_policy.get("timeout_seconds", 30)}),
             json.dumps(shell_schema), "{}", 1, data.risk_level, "read-only", "other", now, now),
        )
        store.audit("admin", "add_initial_tool", "runtime", runtime_id, {"tool": shell_tool_name})

    # Extra tools from multi-tool step 3
    try:
        extra_tools = json.loads(str(form.get("extra_tools_json") or "[]"))
    except Exception:
        extra_tools = []
    for et in extra_tools:
        if not isinstance(et, dict):
            continue
        et_name = re.sub(r"[^a-z0-9_]", "_", str(et.get("name") or "tool").strip().lower()) or "tool"
        et_desc = str(et.get("desc") or et_name)
        if et.get("isShell") or et.get("cmd"):
            et_cmd_raw = str(et.get("cmd") or "").strip()
            if not et_cmd_raw:
                continue
            et_parts = et_cmd_raw.split()
            et_splat = re.findall(r"\$\{\*(\w+)\}", et_cmd_raw)
            et_regular = [v for v in re.findall(r"\$\{(\w+)\}", et_cmd_raw) if v not in et_splat]
            _env_names = {c["name"] for c in store.rows("SELECT name FROM runtime_credentials WHERE runtime_id = ?", (runtime_id,))}
            _env_like = {v for v in et_regular if v.isupper() and (v in _env_names or any(v.startswith(p) for p in ("AWX_", "API_", "DB_", "PG", "MIKROTIK_", "TOKEN", "SECRET", "PASS", "AUTH")))}
            et_regular = [v for v in et_regular if v not in _env_like]
            et_props: dict[str, Any] = {}
            for v in et_splat:
                et_props[v] = {"type": "string", "description": f"Argumenty dla {et_parts[0] if et_parts else 'komendy'}"}
            for v in et_regular:
                et_props[v] = {"type": "string", "description": f"Wartość parametru {v}"}
            et_schema = {"type": "object", "properties": et_props, "required": list(et_props.keys())} if et_props else {"type": "object"}
            store.execute(
                sql.INSERT_TOOL,
                (runtime_id, et_name, et_desc, "shell",
                 json.dumps({"command": et_parts, "timeout_seconds": adv_policy.get("timeout_seconds", 30)}),
                 json.dumps(et_schema), "{}", 1, data.risk_level, "read-only", "other", now, now),
            )
        else:
            et_url = str(et.get("url") or "")
            et_method = str(et.get("method") or "POST").upper()
            if not et_url:
                continue
            store.execute(
                sql.INSERT_TOOL,
                (runtime_id, et_name, et_desc, "http_request",
                 json.dumps({"method": et_method, "url": et_url, "body": {}, "timeout_seconds": 30}),
                 json.dumps({"type": "object"}), "{}", 1, data.risk_level, "read-only", "other", now, now),
            )
        store.audit("admin", "add_initial_tool", "runtime", runtime_id, {"tool": et_name})

    # Auto-create tool package in catalog so it's reusable
    _tools_in_db = store.rows("SELECT * FROM tools WHERE runtime_id = ?", (runtime_id,))
    if _tools_in_db:
        _pkg_tools = []
        for _t in _tools_in_db:
            _tc = json.loads(_t["config_json"] or "{}")
            _pkg_tools.append({
                "name": _t["name"],
                "description": _t["description"],
                "execution_type": _t["execution_type"],
                "enabled": bool(_t["enabled"]),
                "risk_level": _t["risk_level"],
                "mode": _t["mode"],
                "category": _t["category"],
                "config": _tc,
                "input_schema": json.loads(_t["input_schema_json"] or "{}"),
            })
        _rc = store.one(sql.SELECT_RUNTIME_CLASS_BY_NAME, (data.runtime_class,))
        _pkg: dict[str, Any] = {
            "id": runtime_id,
            "name": data.name,
            "description": data.description or f"Serwer MCP — {data.name}",
            "category": "other",
            "risk_level": data.risk_level,
            "runtime_class": {
                "name": data.runtime_class,
                "runtime_image": (_rc or {}).get("runtime_image", runtime_class["runtime_image"]),
                "allowed_execution_types": ["shell"] if shell_cmd_raw else ["http_request"],
                "risk_level": data.risk_level,
                "security_profile": "restricted",
            },
            "adapters": [{"name": "shell" if shell_cmd_raw else "http_request",
                          "adapter_type": "shell" if shell_cmd_raw else "http",
                          "implemented": True, "enabled": True,
                          "risk_level": data.risk_level, "mode": "read-only"}],
            "policy": adv_policy,
            "tools": _pkg_tools,
        }
        if not store.one(sql.SELECT_TOOL_PACKAGE_ID_BY_ID, (runtime_id,)):
            store.execute(
                "INSERT INTO tool_packages(id, name, description, category, risk_level, source, enabled, package_json, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (runtime_id, data.name, _pkg["description"], "other", data.risk_level, "advanced-creator", 1,
                 json.dumps(_pkg, ensure_ascii=False), now, now),
            )
            store.audit("admin", "create_tool_package", "tool_package", runtime_id, {"name": data.name})

    store.audit("admin", "create_runtime", "runtime", runtime_id, data.model_dump())
    if deploy_after:
        store.execute(
            "INSERT INTO deployment_requests(runtime_id, action, status, created_at, updated_at) VALUES(?,?,?,?,?)",
            (runtime_id, "deploy", "pending", store.now_iso(), store.now_iso()),
        )
    return RedirectResponse(f"/runtimes/{runtime_id}?welcome=1", status_code=303)


@router.post("/api/auto-create")
async def auto_create_mcp(request: Request):
    """One-shot: accepts package JSON + optional credentials, creates runtime, deploys."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    package = data.get("package")
    if not package or not isinstance(package, dict):
        raise HTTPException(status_code=400, detail="Missing 'package' object")
    server_name = str(data.get("name") or package.get("name") or "mcp-server")
    credentials = data.get("credentials") or {}
    auto_deploy = data.get("deploy", True)
    try:
        package_id = install_tool_package(package, source="auto-api")
        runtime_id = create_runtime_from_package(package_id, server_name, deploy=False)
    except HTTPException as exc:
        return JSONResponse({"ok": False, "error": str(exc.detail)}, status_code=exc.status_code)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    now = store.now_iso()
    for key, value in credentials.items():
        existing = store.one("SELECT id FROM runtime_credentials WHERE runtime_id = ? AND name = ? AND kind = 'env'", (runtime_id, key))
        if existing:
            store.execute("UPDATE runtime_credentials SET value = ?, updated_at = ? WHERE id = ?", (str(value), now, existing["id"]))
        else:
            store.execute(
                "INSERT INTO runtime_credentials(runtime_id, kind, name, value, env_name, mount_path, enabled, created_at, updated_at) VALUES (?, 'env', ?, ?, '', '', 1, ?, ?)",
                (runtime_id, str(key), str(value), now, now),
            )
    write_runtime_config(runtime_id)
    if auto_deploy:
        enqueue_runtime_action(runtime_id, "deploy")
    store.audit("admin", "auto_create", "runtime", runtime_id, {"package_id": package.get("id", ""), "tools": len(package.get("tools", []))})
    return JSONResponse({
        "ok": True,
        "runtime_id": runtime_id,
        "name": server_name,
        "tools": len(package.get("tools", [])),
        "credentials": len(credentials),
        "deploy": auto_deploy,
        "message": f"MCP server '{server_name}' created with {len(package.get('tools', []))} tools. {'Deployment started.' if auto_deploy else 'Not deployed yet — call deploy manually.'}",
    })

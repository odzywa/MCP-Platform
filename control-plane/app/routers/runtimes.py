"""Runtimes (MCP servers): list/detail pages, tools, adapters, secrets, policy, lifecycle actions, runtime API."""
import json
import re
import secrets as _secrets_mod
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..auth import current_user
from ..services import (
    _dispatch_webhooks,
    _runtime_internal_base,
    adapter_contract,
    create_runtime_adapter_binding,
    enqueue_runtime_action,
    extract_schema_values,
    runtime_payload,
    safe_return_to,
    validate_runtime_class_adapter,
    write_runtime_config,
)
from ..strings import clean_words, slug
from ..web import render_page


router = APIRouter()


@router.get("/runtimes", response_class=HTMLResponse)
def runtimes_page(status: str = "all") -> str:
    all_runtimes = store.rows(sql.SELECT_RUNTIMES_ACTIVE)
    running_count = len([r for r in all_runtimes if r["status"] == "running"])
    problem_count = len([r for r in all_runtimes if r["status"] in {"failed", "unhealthy", "missing", "exited"} or (r.get("last_error") and r["status"] not in {"running", "deleted"})])
    if status == "running":
        runtimes = [r for r in all_runtimes if r["status"] == "running"]
    elif status == "problem":
        runtimes = [r for r in all_runtimes if r["status"] in {"failed", "unhealthy", "missing", "exited"} or (r.get("last_error") and r["status"] not in {"running", "deleted"})]
    else:
        runtimes = all_runtimes

    if not runtimes and not all_runtimes:
        return render_page("runtimes", "pages/runtimes_empty.html")

    # Pobierz ostatnią aktywność audit dla każdego runtime
    audit_by_rid: dict[str, dict] = {}
    if runtimes:
        rids_in = ",".join("?" for _ in runtimes)
        recent_audit = store.rows(
            f"SELECT target_id, actor, action, created_at FROM audit_log WHERE target_type='runtime' AND target_id IN ({rids_in}) GROUP BY target_id HAVING id=MAX(id)",
            tuple(r["id"] for r in runtimes),
        )
        audit_by_rid = {a["target_id"]: a for a in recent_audit}

    _action_icons_card = {
        "deploy_runtime": "🚀", "stop_runtime": "⏹️", "start_runtime": "▶️",
        "restart_runtime": "🔄", "delete_runtime": "🗑️", "reload_runtime": "♻️",
        "create_runtime": "➕", "health_refresh": "🩺", "update_policy": "🔒",
        "add_tool": "🔧", "delete_tool": "🗑️", "update_tool": "✏️",
        "view_runtime": "👁️", "action_failed": "❌", "clone_runtime": "🔁",
    }

    return render_page('runtimes', 'pages/runtimes.html', _action_icons_card=_action_icons_card, all_runtimes=all_runtimes, audit_by_rid=audit_by_rid, problem_count=problem_count, running_count=running_count, runtimes=runtimes, status=status)


@router.get("/runtimes/{runtime_id}", response_class=HTMLResponse)
def runtime_detail(runtime_id: str, request: Request, welcome: str = "", tool_added: str = "") -> str:
    payload = runtime_payload(runtime_id)
    # Base URL without /mcp suffix — used for /openwebui and other non-MCP paths
    _ep = (payload.get("endpoint_url") or "").rstrip("/")
    _base_url = _ep[:-4] if _ep.endswith("/mcp") else _ep
    _platform_base = f"{request.url.scheme}://{request.url.netloc}"
    runtime_adapters = store.rows("SELECT * FROM runtime_adapters WHERE runtime_id = ? ORDER BY adapter_name", (runtime_id,))
    targets = store.rows("SELECT * FROM targets WHERE runtime_id = ? ORDER BY adapter_name, name", (runtime_id,))
    credentials = store.rows("SELECT * FROM runtime_credentials WHERE runtime_id = ? ORDER BY id", (runtime_id,))
    runtime_logs = store.rows(
        "SELECT * FROM runtime_logs WHERE runtime_id = ? ORDER BY id DESC LIMIT 80",
        (runtime_id,),
    )
    runtime_tool_calls = store.rows(
        "SELECT * FROM tool_calls WHERE runtime_id = ? ORDER BY id DESC LIMIT 100",
        (runtime_id,),
    )
    runtime_audit = store.rows(
        "SELECT * FROM audit_log WHERE target_type = 'runtime' AND target_id = ? AND action != 'view_runtime' ORDER BY id DESC LIMIT 30",
        (runtime_id,),
    )
    # Load ENV vars from DB credentials
    _env_vars: dict[str, str] = {c["name"]: c["value"] for c in credentials if c["kind"] == "env"}
    # Tool config preview for dry-run mode
    _cu = current_user.get()
    _is_admin = (_cu or {}).get("role") == "admin"
    # Audit: kto otworzył stronę serwera
    _actor = (_cu or {}).get("username") or "anonymous"
    store.audit(_actor, "view_runtime", "runtime", runtime_id, {"name": payload.get("name", runtime_id)})
    policy_json = json.dumps(payload["policy"], indent=2, ensure_ascii=False)
    logs_text = "\n".join(
        f"{line['created_at']} [{line['level']}] {line['message']}" for line in runtime_logs
    )
    bound_adapter_names = {item['adapter_name'] for item in runtime_adapters}
    # Build dynamic adapter bind form — one hidden section per available adapter
    available_adapters = [a for a in store.rows("SELECT * FROM execution_adapters WHERE enabled=1 AND implemented=1 ORDER BY name")
                          if a['name'] not in bound_adapter_names]
    return render_page('runtimes', 'pages/runtime_detail.html', _base_url=_base_url, _env_vars=_env_vars, _is_admin=_is_admin, _platform_base=_platform_base, available_adapters=available_adapters, credentials=credentials, logs_text=logs_text, payload=payload, policy_json=policy_json, runtime_adapters=runtime_adapters, runtime_audit=runtime_audit, runtime_id=runtime_id, runtime_tool_calls=runtime_tool_calls, targets=targets, tool_added=tool_added, welcome=welcome)


@router.post("/api/runtimes/{runtime_id}/tools")
async def add_tool(runtime_id: str, request: Request):
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    execution_type = str(form.get("execution_type") or "http_request")
    validate_runtime_class_adapter(runtime["runtime_class"], execution_type)
    if execution_type in {"shell", "ssh"}:
        cmd_raw = str(form.get("cmd") or form.get("command_template") or "").strip()
        cmd_parts = cmd_raw.split() if cmd_raw else []
        try:
            timeout_sec = max(5, min(300, int(form.get("timeout_seconds") or 30)))
        except (ValueError, TypeError):
            timeout_sec = 30
        # Build input schema from ${var} and ${*var} placeholders
        splat_vars = re.findall(r"\$\{\*(\w+)\}", cmd_raw)
        regular_vars = [v for v in re.findall(r"\$\{(\w+)\}", cmd_raw) if v not in splat_vars]
        schema_props: dict[str, Any] = {}
        for v in splat_vars:
            schema_props[v] = {"type": "string", "description": f"Argumenty dla {cmd_parts[0] if cmd_parts else 'komendy'} (np. '-h host -U user -d db')"}
        for v in regular_vars:
            schema_props[v] = {"type": "string", "description": f"Wartość parametru {v}"}
        input_schema = {"type": "object", "properties": schema_props, "required": list(schema_props.keys())} if schema_props else {"type": "object"}
        config = {
            "command": cmd_parts,
            "timeout_seconds": timeout_sec,
        }
    else:
        try:
            body = json.loads(str(form.get("body_json") or "{}"))
            headers = json.loads(str(form.get("headers_json") or "{}"))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid body/headers JSON: {exc}") from exc
        url = str(form.get("url") or "")
        # Build input schema from ${var} in body values
        all_vars = re.findall(r"\$\{(\w+)\}", json.dumps(body))
        schema_props = {v: {"type": "string", "description": f"Parametr {v}"} for v in dict.fromkeys(all_vars)}
        input_schema = {"type": "object", "properties": schema_props, "required": list(schema_props.keys())} if schema_props else {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        config = {
            "method": str(form.get("method") or "POST").upper(),
            "url": url,
            "body": body,
            "timeout_seconds": 30,
            "max_response_bytes": 5242880,
        }
        if headers:
            config["headers"] = headers
    now = store.now_iso()
    store.execute(
        sql.INSERT_TOOL,
        (
            runtime_id,
            str(form.get("name") or ""),
            str(form.get("description") or ""),
            execution_type,
            json.dumps(config),
            json.dumps(input_schema),
            "{}",
            1 if str(form.get("enabled")) == "true" else 0,
            str(form.get("risk_level") or "low"),
            "read-only",
            str(form.get("category") or "other"),
            now,
            now,
        ),
    )
    store.audit("admin", "add_tool", "runtime", runtime_id, {"tool": str(form.get("name") or "")})
    # Auto-reload config so new tool is immediately active (no redeploy needed)
    try:
        base = _runtime_internal_base(runtime)
        if base:
            import httpx as _httpx
            _tok = runtime.get("mcp_auth_token") or ""
            _hdr = {"X-API-Key": _tok} if _tok else {}
            _httpx.post(f"{base}/reload", timeout=5, headers=_hdr)
    except Exception:
        pass
    return RedirectResponse(f"/runtimes/{runtime_id}?tool_added={execution_type}#pane-tools", status_code=303)


@router.post("/api/runtimes/{runtime_id}/adapters")
async def add_runtime_adapter(runtime_id: str, request: Request):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    adapter_name = str(form.get("adapter_name") or "").strip()
    if not adapter_name:
        raise HTTPException(status_code=400, detail="Adapter name required")
    adapter = store.one(sql.SELECT_ADAPTER_ENABLED_IMPLEMENTED, (adapter_name,))
    if not adapter:
        raise HTTPException(status_code=400, detail=f"Adapter not available: {adapter_name}")
    contract = adapter_contract(adapter_name)
    config = extract_schema_values(form, "adapter_config", contract.get("config_schema") or {})
    policy = extract_schema_values(form, "adapter_policy", contract.get("policy_schema") or {})
    create_runtime_adapter_binding(runtime_id, adapter_name, config, policy)
    store.audit("admin", "add_adapter_binding", "runtime", runtime_id, {"adapter": adapter_name})
    store.log(runtime_id, f"Adapter bound: {adapter_name}")
    return RedirectResponse(f"/runtimes/{runtime_id}#adapters", status_code=303)


@router.post("/api/runtimes/{runtime_id}/adapters/{adapter_name}/unbind")
def unbind_runtime_adapter(runtime_id: str, adapter_name: str):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    store.execute(
        "DELETE FROM runtime_adapters WHERE runtime_id = ? AND adapter_name = ?",
        (runtime_id, adapter_name),
    )
    store.audit("admin", "remove_adapter_binding", "runtime", runtime_id, {"adapter": adapter_name})
    store.log(runtime_id, f"Adapter unbound: {adapter_name}")
    return RedirectResponse(f"/runtimes/{runtime_id}#adapters", status_code=303)


@router.post("/api/runtimes/{runtime_id}/targets")
async def add_target(runtime_id: str, request: Request):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    adapter_name = str(form.get("adapter_name") or "")
    binding = store.one("SELECT * FROM runtime_adapters WHERE runtime_id = ? AND adapter_name = ?", (runtime_id, adapter_name))
    if not binding:
        raise HTTPException(status_code=400, detail=f"Adapter is not bound to runtime: {adapter_name}")
    contract = adapter_contract(adapter_name)
    target = extract_schema_values(form, "target", contract.get("target_schema") or {})
    secret_refs = extract_schema_values(form, "secret_refs", contract.get("secret_schema") or {})
    try:
        tags = json.loads(str(form.get("tags_json") or "[]"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid tags JSON: {exc}") from exc
    now = store.now_iso()
    name = str(target.get("name") or f"{adapter_name}-target")
    store.execute(
        sql.INSERT_TARGET,
        (runtime_id, adapter_name, name, json.dumps(target), json.dumps(secret_refs), json.dumps(tags), 1, now, now),
    )
    store.audit("admin", "add_target", "runtime", runtime_id, {"adapter": adapter_name, "target": name})
    store.log(runtime_id, f"Target added: {name}")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/env")
async def add_env_var(runtime_id: str, request: Request):
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404)
    data = await request.json()
    key = str(data.get("key") or "").strip()
    value = str(data.get("value") or "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,100}", key):
        raise HTTPException(status_code=400, detail="Nieprawidłowa nazwa zmiennej")
    now = store.now_iso()
    existing = store.one("SELECT id FROM runtime_credentials WHERE runtime_id = ? AND name = ? AND kind = 'env'", (runtime_id, key))
    if existing:
        store.execute("UPDATE runtime_credentials SET value = ?, updated_at = ? WHERE id = ?", (value, now, existing["id"]))
    else:
        store.execute(
            "INSERT INTO runtime_credentials(runtime_id, kind, name, value, env_name, mount_path, enabled, created_at, updated_at) VALUES (?, 'env', ?, ?, '', '', 1, ?, ?)",
            (runtime_id, key, value, now, now),
        )
    write_runtime_config(runtime_id)
    store.audit("admin", "set_env_var", "runtime", runtime_id, {"key": key})
    return {"ok": True}


@router.delete("/api/runtimes/{runtime_id}/env/{key}")
async def delete_env_var(runtime_id: str, key: str):
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404)
    store.execute("DELETE FROM runtime_credentials WHERE runtime_id = ? AND name = ? AND kind = 'env'", (runtime_id, key))
    write_runtime_config(runtime_id)
    store.audit("admin", "delete_env_var", "runtime", runtime_id, {"key": key})
    return {"ok": True}


@router.post("/api/runtimes/{runtime_id}/credentials")
async def add_credential(runtime_id: str, request: Request):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    kind = str(form.get("kind") or "env")
    if kind not in {"env", "file"}:
        raise HTTPException(status_code=400, detail="Invalid credential kind")
    name = str(form.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,80}", name):
        raise HTTPException(status_code=400, detail="Invalid credential name")
    env_name = str(form.get("env_name") or "").strip()
    if env_name and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", env_name):
        raise HTTPException(status_code=400, detail="Invalid env name")
    mount_path = str(form.get("mount_path") or "").strip()
    if mount_path and not mount_path.startswith("/config/secrets/"):
        raise HTTPException(status_code=400, detail="Mount path must start with /config/secrets/")
    value = str(form.get("value") or "")
    if not value:
        raise HTTPException(status_code=400, detail="Credential value is required")
    now = store.now_iso()
    store.execute(
        """
        INSERT INTO runtime_credentials(runtime_id, kind, name, value, env_name, mount_path, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (runtime_id, kind, name, value, env_name, mount_path, 1, now, now),
    )
    store.audit("admin", "add_runtime_credential", "runtime", runtime_id, {"kind": kind, "name": name, "env": env_name})
    store.log(runtime_id, f"Credential added: {kind}:{name}")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/credentials/{credential_id}/delete")
def delete_credential(runtime_id: str, credential_id: int):
    store.execute("DELETE FROM runtime_credentials WHERE id = ? AND runtime_id = ?", (credential_id, runtime_id))
    store.audit("admin", "delete_runtime_credential", "runtime", runtime_id, {"credential_id": credential_id})
    store.log(runtime_id, "Credential deleted")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/tools/{tool_id}/update")
async def update_tool(runtime_id: str, tool_id: int, request: Request):
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    tool = store.one(sql.SELECT_TOOL_BY_ID_AND_RUNTIME, (tool_id, runtime_id))
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    form = await request.form()
    execution_type = str(form.get("execution_type") or "http_request")
    validate_runtime_class_adapter(runtime["runtime_class"], execution_type)
    try:
        body = json.loads(str(form.get("body_json") or "{}"))
        headers = json.loads(str(form.get("headers_json") or "{}"))
        input_schema = json.loads(str(form.get("input_schema_json") or "{}"))
        output_schema = json.loads(str(form.get("output_schema_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc
    if execution_type in {"shell", "ssh"}:
        existing_config = json.loads(tool["config_json"] or "{}")
        cmd_raw = str(form.get("cmd") or "").strip()
        cmd_parts = cmd_raw.split() if cmd_raw else existing_config.get("command") or []
        try:
            timeout_sec = max(1, min(300, int(form.get("timeout_seconds") or existing_config.get("timeout_seconds") or 30)))
        except (ValueError, TypeError):
            timeout_sec = 30
        config = {
            "command": cmd_parts,
            "timeout_seconds": timeout_sec,
        }
    else:
        config = {
            "method": str(form.get("method") or "POST").upper(),
            "url": str(form.get("url") or ""),
            "body": body,
            "timeout_seconds": 30,
            "max_response_bytes": 5242880,
        }
        if headers:
            config["headers"] = headers
    for pname in list((input_schema.get("properties") or {}).keys()):
        val_rules: dict[str, Any] = {}
        allowed_raw = str(form.get(f"val_allowed_{pname}") or "").strip()
        blocked_raw = str(form.get(f"val_blocked_{pname}") or "").strip()
        pattern_raw = str(form.get(f"val_pattern_{pname}") or "").strip()
        maxlen_raw = str(form.get(f"val_maxlen_{pname}") or "").strip()
        if allowed_raw:
            val_rules["allowed_values"] = [v.strip() for v in allowed_raw.split(",") if v.strip()]
        if blocked_raw:
            val_rules["blocked_words"] = [v.strip() for v in blocked_raw.split(",") if v.strip()]
        if pattern_raw:
            val_rules["pattern"] = pattern_raw
        if maxlen_raw and maxlen_raw != "0":
            try:
                val_rules["max_length"] = int(maxlen_raw)
            except ValueError:
                pass
        if val_rules:
            input_schema["properties"][pname]["validation"] = val_rules
        else:
            input_schema["properties"][pname].pop("validation", None)
    store.execute(
        """
        UPDATE tools
        SET name = ?, description = ?, execution_type = ?, config_json = ?, input_schema_json = ?, output_schema_json = ?,
            enabled = ?, risk_level = ?, mode = ?, category = ?, updated_at = ?
        WHERE id = ? AND runtime_id = ?
        """,
        (
            str(form.get("name") or ""),
            str(form.get("description") or ""),
            execution_type,
            json.dumps(config),
            json.dumps(input_schema),
            json.dumps(output_schema),
            1 if str(form.get("enabled")) == "true" else 0,
            str(form.get("risk_level") or "low"),
            str(form.get("mode") or "read-only"),
            str(form.get("category") or "other"),
            store.now_iso(),
            tool_id,
            runtime_id,
        ),
    )
    store.audit("admin", "update_tool", "runtime", runtime_id, {"tool_id": tool_id, "tool": str(form.get("name") or "")})
    store.log(runtime_id, f"Tool updated: {form.get('name') or tool['name']}")
    return RedirectResponse(f"/runtimes/{runtime_id}#tool-{tool_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/tools/{tool_id}/delete")
def delete_tool(runtime_id: str, tool_id: int):
    tool = store.one(sql.SELECT_TOOL_BY_ID_AND_RUNTIME, (tool_id, runtime_id))
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    store.execute("DELETE FROM tools WHERE id = ? AND runtime_id = ?", (tool_id, runtime_id))
    store.audit("admin", "delete_tool", "runtime", runtime_id, {"tool_id": tool_id, "tool": tool["name"]})
    store.log(runtime_id, f"Tool deleted: {tool['name']}")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/policy/update")
async def update_policy(runtime_id: str, request: Request):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    try:
        policy = json.loads(str(form.get("policy_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid policy JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise HTTPException(status_code=400, detail="Policy JSON must be an object")
    store.execute(
        sql.UPSERT_POLICY,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "update_policy", "runtime", runtime_id, {"keys": sorted(policy.keys())})
    store.log(runtime_id, "Policy updated")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/policy/shell-preset")
async def update_shell_policy(runtime_id: str, request: Request):
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    current = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    try:
        policy = json.loads(current["policy_json"] if current else "{}")
    except json.JSONDecodeError:
        policy = {}
    policy["allowed_binaries"] = clean_words(str(form.get("allowed_binaries") or ""), r"[A-Za-z0-9_.-]+", "binary")
    policy["blocked_commands"] = clean_words(str(form.get("blocked_commands") or ""), r"[A-Za-z0-9_.:/-]+", "blocked token")
    policy["allowed_command_prefixes"] = [line.strip() for line in str(form.get("allowed_command_prefixes") or "").splitlines() if line.strip()]
    policy["blocked_command_prefixes"] = [line.strip() for line in str(form.get("blocked_command_prefixes") or "").splitlines() if line.strip()]
    _approval_val = str(form.get("require_approval_for") or "").strip()
    if _approval_val == "":
        policy.pop("require_approval_for", None)
    elif _approval_val == "auto":
        policy["require_approval_for"] = "auto"
    elif _approval_val == "destructive":
        policy["require_approval_for"] = ["destructive"]
    elif _approval_val == "write_destructive":
        policy["require_approval_for"] = ["write", "destructive"]
    policy["require_approval_for_prefixes"] = [
        line.strip() for line in str(form.get("require_approval_for_prefixes") or "").splitlines()
        if line.strip()
    ]
    try:
        policy["approval_timeout_seconds"] = max(30, int(form.get("approval_timeout_seconds") or 300))
    except (ValueError, TypeError):
        policy["approval_timeout_seconds"] = 300
    policy.pop("approval_mode", None)  # removed setting: approval is always decided by a human
    # One-time codes typed in the chat (authenticator app) may approve operations of this runtime.
    policy["approval_allow_code"] = form.get("approval_allow_code") == "1"
    store.execute(
        sql.UPSERT_POLICY,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "update_shell_policy", "runtime", runtime_id, {"allowed": policy["allowed_command_prefixes"], "blocked": policy["blocked_command_prefixes"]})
    store.log(runtime_id, "Shell policy updated")
    # Regenerate policy.json on disk and trigger reload so changes take effect without manual "Reload Config".
    try:
        write_runtime_config(runtime_id)
        enqueue_runtime_action(runtime_id, "reload")
    except Exception:
        pass
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@router.post("/api/runtimes/{runtime_id}/generate-mcp-token")
async def generate_mcp_token(runtime_id: str, request: Request):
    """Generate (or rotate) the Bearer token that MCP clients must present."""
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}#pane-auth")
    runtime = store.one("SELECT id FROM runtimes WHERE id = ?", (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    token = _secrets_mod.token_urlsafe(32)
    store.execute(
        "UPDATE runtimes SET mcp_auth_token = ?, updated_at = ? WHERE id = ?",
        (token, store.now_iso(), runtime_id),
    )
    # Restart, nie reload: /reload wymaga tokenu, a kontener wciąż wymusza stary —
    # żądanie z nowym tokenem dostałoby 401 i zmiana nigdy by nie weszła.
    try:
        write_runtime_config(runtime_id)
        enqueue_runtime_action(runtime_id, "restart")
    except Exception:
        pass
    user = current_user.get() or {}
    store.audit(user.get("username", "admin"), "generate_mcp_token", "runtime", runtime_id, {})
    return RedirectResponse(return_to, status_code=303)


@router.post("/api/runtimes/{runtime_id}/revoke-mcp-token")
async def revoke_mcp_token(runtime_id: str, request: Request):
    """Remove the MCP auth token — runtime becomes accessible without authentication."""
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}#pane-auth")
    runtime = store.one("SELECT id FROM runtimes WHERE id = ?", (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    store.execute(
        "UPDATE runtimes SET mcp_auth_token = '', updated_at = ? WHERE id = ?",
        (store.now_iso(), runtime_id),
    )
    # Jak wyżej — po odwołaniu tokenu reload nie miałby czym się uwierzytelnić.
    try:
        write_runtime_config(runtime_id)
        enqueue_runtime_action(runtime_id, "restart")
    except Exception:
        pass
    user = current_user.get() or {}
    store.audit(user.get("username", "admin"), "revoke_mcp_token", "runtime", runtime_id, {})
    return RedirectResponse(return_to, status_code=303)


@router.post("/api/runtimes/{runtime_id}/deploy")
async def deploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), "/runtimes")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "deploy")
    return RedirectResponse(return_to, status_code=303)


@router.post("/api/runtimes/{runtime_id}/redeploy")
async def redeploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "redeploy")
    return RedirectResponse(return_to, status_code=303)


@router.post("/api/runtimes/{runtime_id}/rebuild-redeploy")
async def rebuild_redeploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "rebuild_redeploy")
    return RedirectResponse(return_to, status_code=303)


@router.post("/api/runtimes/{runtime_id}/{action}")
async def runtime_action(runtime_id: str, action: str, request: Request):
    # Delegate to specific handlers that FastAPI can't resolve before this generic route
    if action == "clone":
        return await clone_runtime(runtime_id, request)
    if action == "test-tool":
        return await test_tool(runtime_id, request)
    allowed = {"start", "stop", "restart", "delete", "health", "logs", "reload"}
    if action not in allowed:
        raise HTTPException(status_code=404, detail="Unknown lifecycle action")
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}")
    if action == "reload":
        write_runtime_config(runtime_id)
    enqueue_runtime_action(runtime_id, action)
    if action == "delete":
        return RedirectResponse("/runtimes", status_code=303)
    if action == "logs":
        return RedirectResponse(f"/runtimes/{runtime_id}#runtime-logs", status_code=303)
    return RedirectResponse(return_to, status_code=303)


@router.get("/api/runtimes/{runtime_id}/status")
def runtime_status(runtime_id: str):
    row = store.one(
        "SELECT id, status, endpoint_url, container_name, last_error FROM runtimes WHERE id = ?",
        (runtime_id,),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Runtime not found")
    return dict(row)


@router.post("/api/runtimes/{runtime_id}/clone")
async def clone_runtime(runtime_id: str, request: Request):
    form = await request.form()
    new_name = str(form.get("name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Name required")
    payload = runtime_payload(runtime_id)
    runtime_adapters = store.rows("SELECT * FROM runtime_adapters WHERE runtime_id = ?", (runtime_id,))
    targets = store.rows("SELECT * FROM targets WHERE runtime_id = ?", (runtime_id,))
    new_id = slug(new_name) + "-" + uuid.uuid4().hex[:6]
    now = store.now_iso()
    store.execute(
        """INSERT INTO runtimes(id, name, description, runtime_class, template, status, risk_level, image, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)""",
        (new_id, new_name, payload["description"], payload["runtime_class"],
         payload["template"], payload["risk_level"], payload["image"], now, now),
    )
    store.execute(
        sql.INSERT_POLICY,
        (new_id, json.dumps(payload["policy"]), now),
    )
    for tool in payload["tools"]:
        store.execute(
            sql.INSERT_TOOL,
            (new_id, tool["name"], tool["description"], tool["execution_type"],
             tool["config_json"], tool["input_schema_json"], tool["output_schema_json"],
             tool["enabled"], tool["risk_level"], tool["mode"], tool["category"], now, now),
        )
    for ra in runtime_adapters:
        store.execute(
            """INSERT INTO runtime_adapters(runtime_id, adapter_name, config_json, policy_json, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (new_id, ra["adapter_name"], ra["config_json"], ra["policy_json"], ra["enabled"], now, now),
        )
    for tgt in targets:
        store.execute(
            sql.INSERT_TARGET,
            (new_id, tgt["adapter_name"], tgt["name"], tgt["target_json"],
             tgt["secret_refs_json"], tgt["tags_json"], tgt["enabled"], now, now),
        )
    store.audit("admin", "clone_runtime", "runtime", new_id, {"source": runtime_id})
    return RedirectResponse(f"/runtimes/{new_id}", status_code=303)


@router.get("/api/runtimes/{runtime_id}/export-package")
def export_runtime_as_package(runtime_id: str):
    from fastapi.responses import JSONResponse as _JSONResponse
    payload = runtime_payload(runtime_id)
    rc_row = store.one(sql.SELECT_RUNTIME_CLASS_BY_NAME, (payload["runtime_class"],))
    runtime_adapters = store.rows(
        "SELECT * FROM runtime_adapters WHERE runtime_id = ? AND enabled = 1", (runtime_id,)
    )
    adapters = []
    for ra in runtime_adapters:
        contract = adapter_contract(ra["adapter_name"])
        adapters.append({
            "name": ra["adapter_name"],
            "adapter_type": contract.get("category", ra["adapter_name"]),
            "implemented": True,
            "enabled": True,
            "risk_level": payload["risk_level"],
            "mode": "read-only",
        })
    tools_out = []
    for tool in payload["tools"]:
        if not tool["enabled"]:
            continue
        tools_out.append({
            "name": tool["name"],
            "description": tool["description"],
            "execution_type": tool["execution_type"],
            "enabled": True,
            "risk_level": tool["risk_level"],
            "mode": tool["mode"],
            "category": tool["category"],
            "config": json.loads(tool["config_json"] or "{}"),
            "input_schema": json.loads(tool["input_schema_json"] or "{}"),
        })
    package = {
        "id": payload["id"],
        "name": payload["name"],
        "description": payload["description"],
        "category": "custom",
        "risk_level": payload["risk_level"],
        "runtime_class": {
            "name": payload["runtime_class"],
            "runtime_image": payload["image"],
            "allowed_execution_types": (
                json.loads(rc_row["allowed_execution_types_json"])
                if rc_row else ["http_request"]
            ),
            "risk_level": payload["risk_level"],
            "security_profile": rc_row["security_profile"] if rc_row else "restricted",
        },
        "adapters": adapters,
        "policy": payload["policy"],
        "tools": tools_out,
    }
    resp = _JSONResponse(package)
    resp.headers["Content-Disposition"] = f'attachment; filename="{payload["id"]}-package.json"'
    return resp


@router.post("/api/runtimes/{runtime_id}/test-tool")
async def test_tool(runtime_id: str, request: Request):
    body = await request.json()
    tool_name = str(body.get("tool_name") or "")
    args_raw = str(body.get("args_json") or "{}")
    runtime = store.one("SELECT endpoint_url, container_name, status FROM runtimes WHERE id = ?", (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    if runtime["status"] != "running":
        return {"ok": False, "error": f"Runtime nie jest running (status: {runtime['status']})"}
    try:
        args = json.loads(args_raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Nieprawidłowy JSON argumentów: {exc}"}
    base_url = _runtime_internal_base(runtime)
    if not base_url:
        return {"ok": False, "error": "Brak endpointu — najpierw zdeployuj runtime"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{base_url}/tools/{tool_name}", json=args)
        try:
            result = resp.json()
        except Exception:
            result = {"text": resp.text[:4000]}
        return {"ok": 200 <= resp.status_code < 300, "status_code": resp.status_code, "result": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.get("/api/runtimes/{runtime_id}/openwebui-tool.py")
def export_openwebui_tool(runtime_id: str):
    """Generate a ready-to-import OpenWebUI Python tool file for this runtime."""
    from fastapi.responses import PlainTextResponse
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    tools = store.rows(
        "SELECT name, description, input_schema_json, config_json, execution_type FROM tools WHERE runtime_id = ? AND enabled = 1",
        (runtime_id,),
    )
    _ep = (runtime["endpoint_url"] or "").rstrip("/")
    # endpoint_url ends with /mcp — strip it to get the gateway base URL
    endpoint = _ep[:-4] if _ep.endswith("/mcp") else _ep
    rname = runtime["name"] or runtime_id
    slug_name = re.sub(r"[^a-z0-9]", "_", rname.lower()).strip("_") or "mcp_tool"

    def _py_type(schema_type: str) -> str:
        return {"integer": "int", "number": "float", "boolean": "bool"}.get(schema_type, "str")

    def _build_method(t: dict) -> str:
        schema = json.loads(t["input_schema_json"] or "{}")
        props = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        cfg = json.loads(t["config_json"] or "{}")
        tool_url = cfg.get("url") or f"{endpoint}/tools/{t['name']}"
        exec_type = t.get("execution_type", "http_request")

        params = []
        for pname, pdef in props.items():
            ptype = _py_type(pdef.get("type", "string"))
            default = pdef.get("default")
            if pname in required:
                params.append(f"{pname}: {ptype}")
            else:
                dval = repr(default) if default is not None else ("0" if ptype in ("int", "float") else '""')
                params.append(f"{pname}: {ptype} = {dval}")

        param_sig = ", ".join(params)
        if param_sig:
            param_sig = ", " + param_sig

        # Build docstring from description
        desc = (t["description"] or t["name"]).replace('"""', "'''")
        param_docs = "\n".join(
            f"        :param {pname}: {(pdef.get('description') or pdef.get('type','string'))}"
            for pname, pdef in props.items()
        )
        docstring = f'        """\n        {desc}\n{param_docs}\n        """' if param_docs else f'        """{desc}"""'

        # Build payload
        payload_items = ", ".join(f'"{p}": {p}' for p in props)
        payload_str = "{" + payload_items + "}" if payload_items else "{}"

        method_name = re.sub(r"[^a-z0-9]", "_", t["name"].lower()).strip("_")

        _headers_code = '        _client_ip = ""\n        try:\n            if __request__ and hasattr(__request__, "client") and __request__.client:\n                _client_ip = __request__.client.host or ""\n        except Exception:\n            pass\n        _model_str = __model__.get("id", str(__model__)) if isinstance(__model__, dict) else str(__model__ or "")\n        _hdrs = {"X-Model": _model_str, "X-AI-Model": _model_str, "X-Real-IP": _client_ip, "X-Forwarded-For": _client_ip}\n'
        if exec_type == "http_request":
            http_method = (cfg.get("method") or "POST").upper()
            if http_method == "GET":
                body_code = _headers_code
                request_code = f'r = requests.get("{tool_url}", headers=_hdrs, timeout=self.valves.timeout)'
            else:
                body_code = _headers_code + f"        payload = {payload_str}\n"
                request_code = f'r = requests.post("{tool_url}", json=payload, headers=_hdrs, timeout=self.valves.timeout)'
        else:
            body_code = _headers_code + f"        payload = {payload_str}\n"
            request_code = f'r = requests.post("{endpoint}/tools/{t["name"]}", json=payload, headers=_hdrs, timeout=self.valves.timeout)'

        return f'''
    def {method_name}(self{param_sig}, __model__: str = "", __user__: dict = {{}}, __request__: object = None) -> str:
{docstring}
{body_code}        try:
            {request_code}
            r.raise_for_status()
            data = r.json()
            if isinstance(data, dict) and "output" in data:
                data = data["output"]
            if isinstance(data, (dict, list)):
                return json.dumps(data, ensure_ascii=False, indent=2)
            return str(data)
        except Exception as exc:
            return f"Błąd: {{exc}}"
'''

    methods = "".join(_build_method(t) for t in tools)
    if not methods:
        methods = '\n    def ping(self) -> str:\n        """Sprawdź połączenie z serwerem MCP."""\n        try:\n            r = requests.get(f"{endpoint}/health", timeout=self.valves.timeout)\n            return r.text\n        except Exception as exc:\n            return f"Błąd: {exc}"\n'

    tool_ids_comment = ", ".join(t["name"] for t in tools)
    py = f'''"""
title: {rname}
author: mcp-platform
version: 1.0.0
description: {rname} — wygenerowany przez MCP Platform. Narzędzia: {tool_ids_comment}
"""
import json
import requests
from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        endpoint: str = Field(default="{endpoint}")
        timeout: int = Field(default=30, ge=5, le=120)

    def __init__(self):
        self.valves = self.Valves()
{methods}'''

    filename = f"{slug_name}.py"
    return PlainTextResponse(
        py,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        media_type="text/x-python",
    )


_RUNTIME_API_HIDDEN_FIELDS = ("mcp_auth_token",)


@router.get("/api/runtimes")
def list_runtimes():
    # SELECT * zawiera mcp_auth_token — platform-manager podaje tę listę wprost modelowi.
    return [
        {k: v for k, v in row.items() if k not in _RUNTIME_API_HIDDEN_FIELDS}
        for row in store.rows(sql.SELECT_RUNTIMES_ACTIVE)
    ]


@router.get("/api/runtimes/{runtime_id}")
def get_runtime(runtime_id: str):
    # Token MCP jest poświadczeniem do wywoływania serwera — nie wychodzi przez
    # JSON API. W UI pokazuje go dedykowana sekcja na stronie runtime'u.
    payload = runtime_payload(runtime_id)
    return {k: v for k, v in payload.items() if k not in _RUNTIME_API_HIDDEN_FIELDS}


@router.post("/api/runtimes/{runtime_id}/action")
async def runtime_action_json(runtime_id: str, request: Request):
    """JSON API for lifecycle actions — used by platform-manager LLM tools."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    action = str(data.get("action") or "").strip()
    allowed = {"start", "stop", "restart", "delete", "reload", "deploy", "redeploy"}
    if action not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown action. Allowed: {sorted(allowed)}")
    if action in {"deploy", "redeploy"}:
        write_runtime_config(runtime_id)
    enqueue_runtime_action(runtime_id, action)
    store.audit("admin", f"{action}_runtime", "runtime", runtime_id, {"via": "json-api"})
    messages = {
        "deploy": "Deployment started — runtime will be running in ~30s.",
        "redeploy": "Redeploy started — container will restart.",
        "stop": "Stop enqueued — runtime will shut down shortly.",
        "start": "Start enqueued.",
        "restart": "Restart enqueued.",
        "reload": "Config reload triggered.",
        "delete": "Delete enqueued — runtime and container will be removed.",
    }
    return {"ok": True, "action": action, "runtime_id": runtime_id, "message": messages[action]}


@router.get("/api/runtimes/{runtime_id}/logs")
def get_runtime_logs(runtime_id: str, limit: int = 50):
    """Return recent runtime log lines as JSON — used by platform-manager LLM tools."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    rows = store.rows(
        "SELECT created_at, level, message FROM runtime_logs WHERE runtime_id = ? ORDER BY id DESC LIMIT ?",
        (runtime_id, min(limit, 200)),
    )
    return {"runtime_id": runtime_id, "logs": [dict(r) for r in reversed(rows)]}


@router.get("/api/runtimes/{runtime_id}/tool-calls")
def get_tool_calls(runtime_id: str, since_id: int = 0):
    calls = store.rows(
        "SELECT * FROM tool_calls WHERE runtime_id = ? AND id > ? ORDER BY id DESC LIMIT 50",
        (runtime_id, since_id),
    )
    return {"calls": calls, "max_id": calls[0]["id"] if calls else since_id}


@router.post("/api/tool-call")
async def record_tool_call(request: Request):
    """Internal endpoint — called by runtime containers to log tool invocations."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid json"}, status_code=400)
    runtime_id = str(data.get("runtime_id") or "")
    tool_name = str(data.get("tool_name") or "")
    if not runtime_id or not tool_name:
        return JSONResponse({"ok": False, "error": "runtime_id and tool_name required"}, status_code=400)
    result_ok = 1 if data.get("ok") else 0
    store.execute(
        "INSERT INTO tool_calls(runtime_id, tool_name, arguments_json, result_ok, result_json, duration_ms, caller, caller_ip, model, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            runtime_id,
            tool_name,
            json.dumps(data.get("arguments") or {}),
            result_ok,
            json.dumps(data.get("result") or {}),
            int(data.get("duration_ms") or 0),
            str(data.get("caller") or ""),
            str(data.get("caller_ip") or ""),
            str(data.get("model") or ""),
            store.now_iso(),
        ),
    )
    if not result_ok:
        _dispatch_webhooks("tool_error", runtime_id, {"tool": tool_name, "result": data.get("result")})
    return {"ok": True}

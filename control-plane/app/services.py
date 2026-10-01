"""Domain logic shared by the routers: runtime artifacts, deployment queue, packages, validation."""
import ipaddress
import json
import socket
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException

from . import queries as sql
from . import store
from .build_images import build_runtime_dockerfile
from .catalog.seed import upsert_package_dependencies
from .strings import slug


def enqueue_runtime_image_build(
    image: str,
    base_image: str,
    apt_packages: list[str],
    pip_packages: list[str],
    extra_dockerfile: str,
    runtime_class: str,
) -> str:
    build_id = slug(image.rsplit("/", 1)[-1].replace(":", "-")) + "-" + uuid.uuid4().hex[:6]
    context_dir = store.CONFIG_ROOT / "image-builds" / build_id
    context_dir.mkdir(parents=True, exist_ok=True)
    dockerfile = build_runtime_dockerfile(base_image, apt_packages, pip_packages, extra_dockerfile)
    (context_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    (context_dir / "README.md").write_text(
        f"# Runtime image build\n\nImage: `{image}`\n\nBase image: `{base_image}`\n",
        encoding="utf-8",
    )
    now = store.now_iso()
    store.execute(
        """
        INSERT INTO runtime_image_builds(id, image, base_image, runtime_class, context_path, dockerfile, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (build_id, image, base_image, runtime_class, str(context_dir), dockerfile, "pending", now, now),
    )
    store.audit("admin", "runtime_image_build_requested", "runtime_image", build_id, {"image": image, "runtime_class": runtime_class})
    store.log(build_id, f"Runtime image build requested: {image}")
    return build_id


def runtime_payload(runtime_id: str) -> dict[str, Any]:
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404, detail="Runtime not found")
    tools = store.rows("SELECT * FROM tools WHERE runtime_id = ? ORDER BY name", (runtime_id,))
    policy = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    return {
        **runtime,
        "tools": tools,
        "policy": json.loads(policy["policy_json"]) if policy else {},
    }


def enabled_runtime_classes() -> list[dict[str, Any]]:
    return store.rows("SELECT * FROM runtime_classes WHERE enabled = 1 ORDER BY name")


def enabled_adapters() -> list[dict[str, Any]]:
    return store.rows("SELECT * FROM execution_adapters WHERE enabled = 1 ORDER BY name")


def schema_defaults(schema: dict[str, Any]) -> dict[str, Any]:
    defaults = {}
    for name, spec in (schema.get("properties") or {}).items():
        if isinstance(spec, dict) and "default" in spec:
            defaults[name] = spec["default"]
    return defaults


def extract_schema_values(form: Any, prefix: str, schema: dict[str, Any]) -> dict[str, Any]:
    values = {}
    for name, spec in (schema.get("properties") or {}).items():
        key = f"{prefix}.{name}"
        if key not in form:
            continue
        raw = str(form.get(key) or "")
        field_type = spec.get("type", "string") if isinstance(spec, dict) else "string"
        if field_type == "integer":
            values[name] = int(raw) if raw else None
        elif field_type == "boolean":
            values[name] = raw == "true"
        elif field_type in {"array", "object"}:
            values[name] = json.loads(raw or ("[]" if field_type == "array" else "{}"))
        else:
            values[name] = raw
    return {key: value for key, value in values.items() if value is not None}


def validate_runtime_class_adapter(runtime_class: str, execution_type: str) -> None:
    runtime = store.one(sql.SELECT_RUNTIME_CLASS_ENABLED_BY_NAME, (runtime_class,))
    if not runtime:
        raise HTTPException(status_code=400, detail=f"Runtime class is not enabled: {runtime_class}")
    allowed = json.loads(runtime["allowed_execution_types_json"] or "[]")
    if execution_type not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Execution adapter {execution_type} is not allowed by runtime class {runtime_class}",
        )
    adapter = store.one("SELECT * FROM execution_adapters WHERE name = ? AND enabled = 1", (execution_type,))
    if not adapter:
        raise HTTPException(status_code=400, detail=f"Execution adapter is not enabled: {execution_type}")
    if not adapter["implemented"]:
        raise HTTPException(status_code=400, detail=f"Execution adapter is registered but not implemented: {execution_type}")


def package_spec(package_id: str) -> dict[str, Any]:
    row = store.one(sql.SELECT_TOOL_PACKAGE_BY_ID, (package_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Tool package not found")
    if not row.get("enabled", 1):
        raise HTTPException(status_code=400, detail="Tool package is disabled by admin")
    return json.loads(row["package_json"])


def adapter_contract(adapter_name: str) -> dict[str, Any]:
    adapter = store.one(sql.SELECT_ADAPTER_BY_NAME, (adapter_name,))
    if not adapter:
        return {}
    try:
        return json.loads(adapter.get("adapter_contract_json") or "{}")
    except json.JSONDecodeError:
        return {}


def create_runtime_adapter_binding(runtime_id: str, adapter_name: str, config: dict[str, Any] | None = None, policy: dict[str, Any] | None = None) -> None:
    now = store.now_iso()
    store.execute(
        """
        INSERT INTO runtime_adapters(runtime_id, adapter_name, config_json, policy_json, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(runtime_id, adapter_name) DO UPDATE SET
          config_json = excluded.config_json,
          policy_json = excluded.policy_json,
          enabled = excluded.enabled,
          updated_at = excluded.updated_at
        """,
        (runtime_id, adapter_name, json.dumps(config or {}), json.dumps(policy or {}), 1, now, now),
    )


def install_tool_package(package: dict[str, Any], source: str = "custom") -> str:
    if not isinstance(package, dict):
        raise HTTPException(status_code=400, detail="Package must be a JSON object")
    package_id = slug(str(package.get("id") or package.get("name") or "tool-package"))
    if not package.get("name"):
        raise HTTPException(status_code=400, detail="Package requires name")
    if not package.get("runtime_class"):
        raise HTTPException(status_code=400, detail="Package requires runtime_class")
    now = store.now_iso()
    package["id"] = package_id
    store.execute(
        """
        INSERT INTO tool_packages(id, name, description, category, risk_level, source, enabled, package_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          description = excluded.description,
          category = excluded.category,
          risk_level = excluded.risk_level,
          source = excluded.source,
          enabled = excluded.enabled,
          package_json = excluded.package_json,
          updated_at = excluded.updated_at
        """,
        (
            package_id,
            str(package["name"]),
            str(package.get("description", "")),
            str(package.get("category", "other")),
            str(package.get("risk_level", "low")),
            source,
            1,
            json.dumps(package),
            now,
            now,
        ),
    )
    upsert_package_dependencies(package)
    store.audit("admin", "install_tool_package", "tool_package", package_id, {"source": source, "tools": len(package.get("tools") or [])})
    return package_id


def create_runtime_from_package(package_id: str, name: str, deploy: bool) -> str:
    package = package_spec(package_id)
    upsert_package_dependencies(package)
    runtime_class = package["runtime_class"]
    runtime_class_name = runtime_class["name"]
    class_row = store.one(sql.SELECT_RUNTIME_CLASS_ENABLED_BY_NAME, (runtime_class_name,))
    if not class_row:
        raise HTTPException(status_code=400, detail=f"Runtime class is not enabled: {runtime_class_name}")
    runtime_id = slug(name or package["name"]) + "-" + uuid.uuid4().hex[:6]
    now = store.now_iso()
    store.execute(
        sql.INSERT_RUNTIME,
        (
            runtime_id,
            name or package["name"],
            package.get("description", ""),
            runtime_class_name,
            package_id,
            "draft",
            package.get("risk_level", class_row["risk_level"]),
            runtime_class.get("runtime_image") or class_row["runtime_image"],
            now,
            now,
        ),
    )
    store.execute(
        sql.INSERT_POLICY,
        (runtime_id, json.dumps(package.get("policy") or {}), now),
    )
    for adapter in package.get("adapters") or []:
        create_runtime_adapter_binding(
            runtime_id,
            adapter["name"],
            adapter.get("config") or {},
            adapter.get("policy") or {},
        )
    for tool in package.get("tools") or []:
        store.execute(
            sql.INSERT_TOOL,
            (
                runtime_id,
                tool["name"],
                tool.get("description", ""),
                tool.get("execution_type", "http_request"),
                json.dumps(tool.get("config") or tool.get("execution") or {}),
                json.dumps(tool.get("input_schema") or {"type": "object"}),
                json.dumps(tool.get("output_schema") or {"type": "object"}),
                1 if tool.get("enabled", True) else 0,
                tool.get("risk_level", package.get("risk_level", "low")),
                tool.get("mode", "read-only"),
                tool.get("category", package.get("category", "other")),
                now,
                now,
            ),
        )
    store.audit("admin", "create_runtime_from_package", "runtime", runtime_id, {"package": package_id, "tools": len(package.get("tools") or [])})
    if deploy:
        config_path = write_runtime_config(runtime_id)
        store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
        enqueue_runtime_action(runtime_id, "deploy")
    return runtime_id


def write_runtime_config(runtime_id: str) -> str:
    payload = runtime_payload(runtime_id)
    runtime_adapters = store.rows("SELECT * FROM runtime_adapters WHERE runtime_id = ? AND enabled = 1 ORDER BY adapter_name", (runtime_id,))
    targets = store.rows("SELECT * FROM targets WHERE runtime_id = ? AND enabled = 1 ORDER BY adapter_name, name", (runtime_id,))
    credentials = store.rows("SELECT * FROM runtime_credentials WHERE runtime_id = ? AND enabled = 1 ORDER BY id", (runtime_id,))
    config_dir = store.CONFIG_ROOT / runtime_id
    config_dir.mkdir(parents=True, exist_ok=True)
    secrets_dir = config_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    enabled_tools = []
    for tool in payload["tools"]:
        if not tool["enabled"]:
            continue
        validate_runtime_class_adapter(payload["runtime_class"], tool["execution_type"])
        enabled_tools.append(
            {
                "name": tool["name"],
                "description": tool["description"],
                "execution_type": tool["execution_type"],
                "input_schema": json.loads(tool["input_schema_json"] or "{}"),
                "output_schema": json.loads(tool["output_schema_json"] or "{}"),
                "execution": json.loads(tool["config_json"] or "{}"),
                "openwebui_enabled": True,
                "security": {"risk_level": tool["risk_level"], "mode": tool["mode"], "category": tool["category"]},
            }
        )
    runtime_row = store.one("SELECT mcp_auth_token FROM runtimes WHERE id = ?", (runtime_id,)) or {}
    runtime_config = {
        "server_id": runtime_id,
        "name": payload["name"],
        "runtime_class": payload["runtime_class"],
        "transport": {"type": "streamable_http", "mcp_endpoint": "/mcp"},
        "auth_token": runtime_row.get("mcp_auth_token") or "",
    }
    adapter_config = {
        "adapters": [
            {
                "name": item["adapter_name"],
                "config": json.loads(item["config_json"] or "{}"),
                "policy": json.loads(item["policy_json"] or "{}"),
                "contract": adapter_contract(item["adapter_name"]),
            }
            for item in runtime_adapters
        ]
    }
    target_config = {
        "targets": [
            {
                "id": item["id"],
                "adapter": item["adapter_name"],
                "name": item["name"],
                "target": json.loads(item["target_json"] or "{}"),
                "secret_refs": json.loads(item["secret_refs_json"] or "{}"),
                "tags": json.loads(item["tags_json"] or "[]"),
            }
            for item in targets
        ]
    }
    runtime_env: dict[str, str] = {}
    secret_manifest = []
    for credential in credentials:
        if credential["kind"] == "env":
            runtime_env[credential["name"]] = credential["value"]
            secret_manifest.append({"kind": "env", "name": credential["name"], "masked": True})
        elif credential["kind"] == "file":
            filename = Path(credential["mount_path"]).name if credential["mount_path"] else slug(credential["name"])
            mount_path = credential["mount_path"] or f"/config/secrets/{filename}"
            secret_path = secrets_dir / filename
            secret_path.write_text(credential["value"], encoding="utf-8")
            env_name = credential["env_name"]
            if env_name:
                runtime_env[env_name] = mount_path
            secret_manifest.append({"kind": "file", "name": credential["name"], "path": mount_path, "env": env_name, "masked": True})
    (config_dir / "runtime-config.json").write_text(json.dumps(runtime_config, indent=2), encoding="utf-8")
    (config_dir / "tools.json").write_text(json.dumps({"tools": enabled_tools}, indent=2), encoding="utf-8")
    (config_dir / "policy.json").write_text(json.dumps(payload["policy"], indent=2), encoding="utf-8")
    (config_dir / "adapter-config.json").write_text(json.dumps(adapter_config, indent=2), encoding="utf-8")
    (config_dir / "targets.json").write_text(json.dumps(target_config, indent=2), encoding="utf-8")
    (config_dir / "secrets.json").write_text(json.dumps({"secrets": secret_manifest}, indent=2), encoding="utf-8")
    (config_dir / "runtime-env.json").write_text(json.dumps({"env": runtime_env}, indent=2), encoding="utf-8")
    store.execute("UPDATE runtimes SET config_path = ?, updated_at = ? WHERE id = ?", (str(config_dir), store.now_iso(), runtime_id))
    return str(config_dir)


def enqueue_runtime_action(runtime_id: str, action: str) -> None:
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    now = store.now_iso()
    status = {
        "deploy": "deploying",
        "redeploy": "deploying",
        "rebuild_redeploy": "building",
        "reload": "running",
        "start": "starting",
        "stop": "stopping",
        "restart": "restarting",
        "delete": "deleting",
        "health": "checking",
        "logs": "syncing_logs",
    }.get(action, "pending")
    store.execute("UPDATE runtimes SET status = ?, updated_at = ? WHERE id = ?", (status, now, runtime_id))
    store.execute(
        "INSERT INTO deployment_requests(runtime_id, action, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (runtime_id, action, "pending", now, now),
    )
    store.audit("admin", f"{action}_requested", "runtime", runtime_id, {})
    store.log(runtime_id, f"{action.title()} requested")


def _is_safe_fetch_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname or ""
        if not hostname:
            return False
        blocked_names = {"localhost", "metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in blocked_names:
            return False
        try:
            addr = ipaddress.ip_address(hostname)
            return not (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
            )
        except ValueError:
            # hostname is not a numeric IP literal — resolve it and check every
            # returned address to block DNS rebinding to private/loopback ranges.
            try:
                infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                return False
            if not infos:
                return False
            for info in infos:
                try:
                    addr = ipaddress.ip_address(info[4][0])
                except ValueError:
                    return False
                if (addr.is_private or addr.is_loopback or addr.is_link_local
                        or addr.is_reserved or addr.is_multicast):
                    return False
            return True
    except Exception:
        return False


def safe_return_to(value: str | None, default: str) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return default


def _dispatch_webhooks(event: str, runtime_id: str, details: dict[str, Any]) -> None:
    webhooks = store.rows(
        "SELECT * FROM webhooks WHERE enabled = 1 AND (runtime_id = '' OR runtime_id = ?)",
        (runtime_id,),
    )
    for wh in webhooks:
        events = json.loads(wh["events_json"] or "[]")
        if event not in events:
            continue
        payload = json.dumps({
            "event": event, "runtime_id": runtime_id,
            "timestamp": store.now_iso(), "details": details,
        }).encode()
        def _fire(url: str, data: bytes, wh_id: int) -> None:
            import urllib.request as _ur
            try:
                req = _ur.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
                resp = _ur.urlopen(req, timeout=5)
                store.execute(sql.UPDATE_WEBHOOK_FIRED,
                              (store.now_iso(), resp.status, store.now_iso(), wh_id))
            except Exception:
                store.execute(sql.UPDATE_WEBHOOK_FIRED,
                              (store.now_iso(), 0, store.now_iso(), wh_id))
        import threading as _th
        _th.Thread(target=_fire, args=(wh["url"], payload, wh["id"]), daemon=True).start()


def _runtime_internal_base(runtime: dict) -> str:
    """
    Bazowy URL do wywołań runtime'u z wnętrza platformy.

    container_name jest nazwą kontenera (Docker) lub Deploymentu == Service (K8s),
    więc rozwiązuje się w obu środowiskach. endpoint_url to na K8s zewnętrzny
    Route — z wnętrza klastra wymagałby zaufania certyfikatowi routera, więc
    używamy go tylko jako fallbacku.
    """
    container = runtime.get("container_name")
    if container:
        return f"http://{container}:8080"
    endpoint = (runtime.get("endpoint_url") or "").rstrip("/")
    return endpoint[:-4] if endpoint.endswith("/mcp") else endpoint

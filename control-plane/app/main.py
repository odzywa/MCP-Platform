import hashlib
import ipaddress
import json
import os
import re
import secrets as _secrets_mod
import shlex
import socket
import uuid
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

from . import queries as sql
from . import store
from .adapters_config import adapter_contracts
from .config import (
    _ADMIN_ONLY,
    _FAVICON_TAG,
    _PUBLIC,
    _READONLY_GET,
    AUTH_COOKIE,
    CUSTOM_TEMPLATES_FILE,
    SESSION_TTL_H,
)
from .models import AdapterCreate, RuntimeCreate, ToolCreate
from .templates import render_template
from .tools.docker import build_runtime_dockerfile
from .tools.strings import clean_words, slug, validate_image_ref


app = FastAPI(title="MCP Platform", version="0.1.0", docs_url="/api-swagger", redoc_url=None)

# ── Auth / RBAC ────────────────────────────────────────────────────────────────
_current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)


def _hash_pw(pw: str) -> str:
    salt = _secrets_mod.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000)
    return f"{salt}:{dk.hex()}"


def _verify_pw(pw: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split(":", 1)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000)
        return _secrets_mod.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _create_session(user_id: int, username: str, role: str) -> str:
    token = _secrets_mod.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_H)).isoformat()
    store.execute(
        "INSERT INTO sessions(token,user_id,username,role,expires_at,created_at) VALUES(?,?,?,?,?,?)",
        (token, user_id, username, role, expires, store.now_iso()),
    )
    return token


def _get_session(token: str) -> dict | None:
    if not token:
        return None
    row = store.one("SELECT user_id,username,role,expires_at FROM sessions WHERE token=?", (token,))
    if not row:
        return None
    try:
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            store.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
    except Exception:
        pass
    return dict(row)


def _ensure_admin() -> None:
    """Create default admin:admin if no users exist."""
    if not store.one("SELECT id FROM users LIMIT 1"):
        store.execute(
            "INSERT INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("admin", _hash_pw("admin"), "admin", 1, store.now_iso(), store.now_iso()),
        )


def _access_denied_html(user: dict, msg: str) -> str:
    return render_template(
        "access_denied",
        msg=escape(msg),
        username=escape(user.get("username", "?")),
        role=escape(user.get("role", "?")),
    )


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        path = request.url.path

        # Always allow public paths and static assets
        if _PUBLIC.match(path) or path.startswith("/static/"):
            user = _get_session(request.cookies.get(AUTH_COOKIE, ""))
            _current_user.set(user)
            return await call_next(request)

        token = request.cookies.get(AUTH_COOKIE, "")
        user = _get_session(token)

        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not authenticated"}, status_code=401)
            return RedirectResponse("/login", status_code=303)

        _current_user.set(user)
        role = user["role"]
        method = request.method

        # read_only: block all POST/PUT/DELETE except change-password and logout
        if role == "read_only" and method not in ("GET", "HEAD"):
            if not re.match(r"^/api/user/|^/logout", path):
                return HTMLResponse(_access_denied_html(user, "Twoja rola (tylko odczyt) nie pozwala na modyfikacje."), status_code=403)

        # read_write and read_only: block admin-only paths
        if role != "admin" and _ADMIN_ONLY.match(path):
            return HTMLResponse(_access_denied_html(user, "Ta funkcja jest dostępna tylko dla administratorów."), status_code=403)

        # /admin panel — admin only
        if path.startswith("/admin") and role != "admin":
            return HTMLResponse(_access_denied_html(user, "Panel administratora jest dostępny tylko dla adminów."), status_code=403)

        return await call_next(request)


app.add_middleware(AuthMiddleware)


@app.on_event("startup")
def startup() -> None:
    store.init_db()
    _ensure_admin()
    seed_platform_catalog()
    seed_raghybrid_template()
    seed_openshift_monitor()


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


def seed_platform_catalog() -> None:
    now = store.now_iso()
    changed = False
    adapters = [
        {
            "name": "http_request",
            "description": "Execute schema-validated HTTP requests from the generic HTTP gateway runtime.",
            "adapter_type": "http",
            "runtime_image": "mcp-runtime-http-gateway:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "low",
            "mode": "read-only",
            "schema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                    "body": {"type": "object"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
                },
            },
        },
        {
            "name": "shell",
            "description": "Adapter shell — wykonuje dozwolone komendy w izolowanych kontenerach runtime.",
            "adapter_type": "shell",
            "runtime_image": "mcp-runtime-shell:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "high",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "ssh",
            "description": "Adapter SSH — wykonuje komendy na zdalnych serwerach infrastruktury.",
            "adapter_type": "ssh",
            "runtime_image": "mcp-generic-runtime:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "high",
            "mode": "read-only",
            "schema": adapter_contracts()["ssh"]["config_schema"],
        },
        {
            "name": "python",
            "description": "Planowany adapter Python — izolowany sandbox do skryptów Python.",
            "adapter_type": "python",
            "runtime_image": "mcp-runtime-python:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "openshift",
            "description": "Planowany adapter OpenShift/Kubernetes — tylko odczyt zasobów klastra.",
            "adapter_type": "openshift",
            "runtime_image": "mcp-runtime-openshift:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "workflow",
            "description": "Planowany adapter workflow — łączenie wielu toolów w sekwencje.",
            "adapter_type": "workflow",
            "runtime_image": "mcp-runtime-workflow:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
    ]
    for adapter in adapters:
        contract_json = json.dumps(adapter_contracts().get(adapter["name"], {"name": adapter["name"], "config_schema": adapter["schema"]}))
        if not store.one(sql.SELECT_ADAPTER_NAME_BY_NAME, (adapter["name"],)):
            changed = True
            store.execute(
                sql.INSERT_EXECUTION_ADAPTER,
                (
                    adapter["name"],
                    adapter["description"],
                    adapter["adapter_type"],
                    adapter["runtime_image"],
                    json.dumps(adapter["schema"]),
                    contract_json,
                    adapter["enabled"],
                    adapter["implemented"],
                    adapter["risk_level"],
                    adapter["mode"],
                    now,
                    now,
                ),
            )
        else:
            store.execute(
                """
                UPDATE execution_adapters
                SET description = ?, adapter_type = ?, adapter_contract_json = ?, config_schema_json = ?, runtime_image = ?,
                    enabled = ?, implemented = ?, risk_level = ?, mode = ?, updated_at = ?
                WHERE name = ?
                """,
                (
                    adapter["description"],
                    adapter["adapter_type"],
                    contract_json,
                    json.dumps(adapter["schema"]),
                    adapter["runtime_image"],
                    adapter["enabled"],
                    adapter["implemented"],
                    adapter["risk_level"],
                    adapter["mode"],
                    now,
                    adapter["name"],
                ),
            )
    for _rc_name, _rc_desc, _rc_image, _rc_types in [
        ("shell-readonly",  "Shell runtime for CLI tools (curl, psql, oc, ping...)",   "mcp-runtime-shell:latest",        ["shell"]),
        ("shell-readwrite", "Shell runtime — write mode allowed",                       "mcp-runtime-shell:latest",        ["shell"]),
        ("openapi",         "Auto-MCP from OpenAPI spec via FastMCP.from_openapi()",    "mcp-runtime-openapi:latest",      ["http_request"]),
    ]:
        if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, (_rc_name,)):
            changed = True
            store.execute(
                "INSERT INTO runtime_classes(name, description, runtime_image, allowed_execution_types_json, enabled, risk_level, security_profile, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (_rc_name, _rc_desc, _rc_image, json.dumps(_rc_types), 1, "low", "restricted", now, now),
            )
        else:
            store.execute(
                "UPDATE runtime_classes SET runtime_image=?, allowed_execution_types_json=?, enabled=1, updated_at=? WHERE name=?",
                (_rc_image, json.dumps(_rc_types), now, _rc_name),
            )
    if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, ("http-gateway",)):
        changed = True
        store.execute(
            sql.INSERT_RUNTIME_CLASS,
            (
                "http-gateway",
                "Generic HTTP MCP runtime. Supports config-driven HTTP tools.",
                "mcp-runtime-http-gateway:latest",
                json.dumps(["http_request"]),
                1,
                "low",
                "restricted",
                now,
                now,
            ),
        )
    if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, ("generic-runtime",)):
        changed = True
        store.execute(
            sql.INSERT_RUNTIME_CLASS,
            (
                "generic-runtime",
                "Generic adapter-driven MCP runtime. Loads adapter-config, targets, tools and policy.",
                "mcp-generic-runtime:latest",
                json.dumps(["http_request", "ssh"]),
                1,
                "medium",
                "restricted",
                now,
                now,
            ),
        )
    else:
        store.execute(
            """
            UPDATE runtime_classes
            SET runtime_image = ?, allowed_execution_types_json = ?, enabled = ?, risk_level = ?, security_profile = ?, updated_at = ?
            WHERE name = ?
            """,
            (
                "mcp-generic-runtime:latest",
                json.dumps(["http_request", "ssh"]),
                1,
                "medium",
                "restricted",
                now,
                "generic-runtime",
            ),
        )
    if changed:
        store.audit("system", "seed_catalog", "platform", "runtime-adapters", {})
    seed_builtin_tool_packages()


def raghybrid_tool_definitions(base_url: str = "http://raghybrid-app:8000") -> list[dict[str, Any]]:
    retrieval_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "query": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4000,
                "description": "Standalone search query or coding question.",
            },
            "top_k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 8},
            "max_vector": {"type": "integer", "minimum": 1, "maximum": 10, "default": 8},
            "max_graph": {"type": "integer", "minimum": 0, "maximum": 30, "default": 12},
            "max_evidence": {"type": "integer", "minimum": 0, "maximum": 12, "default": 8},
        },
        "required": ["query"],
    }
    retrieve_body = {
        "query": "${query}",
        "top_k": "${top_k}",
        "max_vector": "${max_vector}",
        "max_graph": "${max_graph}",
        "max_evidence": "${max_evidence}",
        "max_context_chars": 20000,
        "telemetry": True,
    }
    retrieve_execution = {
        "method": "POST",
        "url": f"{base_url}/retrieve_json",
        "body": retrieve_body,
        "timeout_seconds": 60,
        "max_response_bytes": 5242880,
    }
    return [
        {
            "name": "hybridrag_context",
            "description": (
                "Best default tool for Continue coding help. Retrieves concise source-grounded context "
                "from RAGHybrid and returns model-ready text with source markers."
            ),
            "execution_type": "http_request",
            "enabled": True,
            "risk_level": "low",
            "mode": "read-only",
            "category": "rag",
            "openwebui_enabled": False,
            "mcp_response_mode": "context_text",
            "response_formatter": {"max_items": 8, "content_chars": 1400, "include_debug": False},
            "config": {
                **retrieve_execution,
                "openwebui_enabled": False,
                "mcp_response_mode": "context_text",
                "response_formatter": {"max_items": 8, "content_chars": 1400, "include_debug": False},
            },
            "input_schema": retrieval_schema,
            "output_schema": {"type": "object"},
        },
        {
            "name": "hybridrag_search",
            "description": (
                "Raw RAGHybrid retrieval JSON for OpenWebUI and debugging. For Continue, prefer "
                "hybridrag_context unless raw metadata is needed."
            ),
            "execution_type": "http_request",
            "enabled": True,
            "risk_level": "low",
            "mode": "read-only",
            "category": "rag",
            "openwebui_enabled": True,
            "config": {**retrieve_execution, "openwebui_enabled": True},
            "input_schema": retrieval_schema,
            "output_schema": {"type": "object"},
        },
        {
            "name": "hybridrag_sources",
            "description": "List source documents and metadata related to a query without returning full chunks.",
            "execution_type": "http_request",
            "enabled": True,
            "risk_level": "low",
            "mode": "read-only",
            "category": "rag",
            "openwebui_enabled": False,
            "mcp_response_mode": "sources_text",
            "response_formatter": {"max_items": 16},
            "config": {
                **retrieve_execution,
                "openwebui_enabled": False,
                "mcp_response_mode": "sources_text",
                "response_formatter": {"max_items": 16},
            },
            "input_schema": retrieval_schema,
            "output_schema": {"type": "object"},
        },
        {
            "name": "hybridrag_health",
            "description": "Check RAGHybrid API health before relying on retrieval results.",
            "execution_type": "http_request",
            "enabled": True,
            "risk_level": "low",
            "mode": "read-only",
            "category": "rag",
            "openwebui_enabled": False,
            "mcp_response_mode": "health_text",
            "config": {
                "method": "GET",
                "url": f"{base_url}/health",
                "timeout_seconds": 10,
                "max_response_bytes": 262144,
                "openwebui_enabled": False,
                "mcp_response_mode": "health_text",
            },
            "input_schema": {"type": "object", "additionalProperties": False, "properties": {}},
            "output_schema": {"type": "object"},
        },
    ]


def builtin_tool_packages() -> list[dict[str, Any]]:
    raghybrid_package = {
        "id": "raghybrid-assistant",
        "name": "RAGHybrid Assistant",
        "description": "Gotowy MCP runtime z toolami do RAGHybrid API.",
        "category": "rag",
        "risk_level": "low",
        "runtime_class": {
            "name": "http-gateway",
            "runtime_image": "mcp-runtime-http-gateway:latest",
            "allowed_execution_types": ["http_request"],
            "risk_level": "low",
            "security_profile": "restricted",
        },
        "adapters": [
            {
                "name": "http_request",
                "description": "Adapter HTTP — wywołuje zewnętrzne REST API.",
                "adapter_type": "http",
                "runtime_image": "mcp-runtime-http-gateway:latest",
                "implemented": True,
                "enabled": True,
                "risk_level": "low",
                "mode": "read-only",
                "schema": {"type": "object"},
            }
        ],
        "policy": {
            "block_write_tools": True,
            "block_destructive_tools": True,
            "require_read_only": True,
            "timeout_seconds": 60,
            "max_payload_bytes": 1048576,
            "max_response_bytes": 5242880,
            "allowed_clients": ["OpenWebUI", "local"],
        },
        "tools": raghybrid_tool_definitions("http://raghybrid-app:8000"),
    }
    openshift_package = {
        "id": "openshift-readonly",
        "name": "OpenShift ReadOnly Assistant",
        "description": "Paczka gotowych read-only tooli OCP. Wymaga runtime image z binarką oc i kubeconfig/secret w runtime.",
        "category": "openshift",
        "risk_level": "medium",
        "runtime_class": {
            "name": "openshift-readonly",
            "runtime_image": "mcp-runtime-shell:latest",
            "allowed_execution_types": ["shell"],
            "risk_level": "medium",
            "security_profile": "read-only-cluster-access",
            "required_binaries": ["oc", "jq"],
            "binary_source_hint": "Use your own mcp-runtime-shell image with oc installed, or import a package that points to such image.",
        },
        "adapters": [
            {
                "name": "shell",
                "description": "Adapter shell — wykonuje dozwolone komendy tylko do odczytu w izolowanym kontenerze.",
                "adapter_type": "shell",
                "runtime_image": "mcp-runtime-shell:latest",
                "implemented": True,
                "enabled": True,
                "risk_level": "high",
                "mode": "read-only",
                "schema": {"type": "object"},
            }
        ],
        "policy": {
            "block_write_tools": True,
            "block_destructive_tools": True,
            "require_read_only": True,
            "timeout_seconds": 20,
            "max_payload_bytes": 262144,
            "max_response_bytes": 1048576,
            "allowed_binaries": ["oc", "jq"],
            "blocked_commands": ["delete", "apply", "patch", "replace", "exec", "rsh", "debug", "adm", "create", "scale"],
            "allowed_clients": ["OpenWebUI", "local"],
        },
        "tools": [
            {
                "name": "oc_get_pods",
                "description": "List pods in namespace.",
                "execution_type": "shell",
                "enabled": True,
                "risk_level": "medium",
                "mode": "read-only",
                "category": "openshift",
                "config": {"command": ["oc", "get", "pods", "-n", "${namespace}", "-o", "json"], "timeout_seconds": 20},
                "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]},
                "output_schema": {"type": "object"},
            },
            {
                "name": "oc_get_events",
                "description": "List events in namespace sorted by time.",
                "execution_type": "shell",
                "enabled": True,
                "risk_level": "medium",
                "mode": "read-only",
                "category": "openshift",
                "config": {"command": ["oc", "get", "events", "-n", "${namespace}", "--sort-by=.lastTimestamp", "-o", "json"], "timeout_seconds": 20},
                "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]},
                "output_schema": {"type": "object"},
            },
            {
                "name": "oc_logs",
                "description": "Read recent logs from a pod.",
                "execution_type": "shell",
                "enabled": True,
                "risk_level": "medium",
                "mode": "read-only",
                "category": "openshift",
                "config": {"command": ["oc", "logs", "-n", "${namespace}", "${pod}", "--tail=${tail}"], "timeout_seconds": 20},
                "input_schema": {
                    "type": "object",
                    "properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}, "tail": {"type": "integer", "default": 100}},
                    "required": ["namespace", "pod"],
                },
                "output_schema": {"type": "object"},
            },
            {
                "name": "oc_describe_pod",
                "description": "Describe a pod.",
                "execution_type": "shell",
                "enabled": True,
                "risk_level": "medium",
                "mode": "read-only",
                "category": "openshift",
                "config": {"command": ["oc", "describe", "pod", "-n", "${namespace}", "${pod}"], "timeout_seconds": 20},
                "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}, "pod": {"type": "string"}}, "required": ["namespace", "pod"]},
                "output_schema": {"type": "object"},
            },
        ],
    }
    platform_manager_package = {
        "id": "platform-manager",
        "name": "MCP Platform Manager",
        "description": "Meta-MCP: AI tworzy i zarządza serwerami MCP na platformie. Czyta instrukcje, generuje paczki, deployuje — wszystko automatycznie.",
        "category": "other",
        "risk_level": "high",
        "runtime_class": {
            "name": "shell-readwrite",
            "runtime_image": "mcp-runtime-shell:latest",
            "allowed_execution_types": ["shell"],
            "security_profile": "restricted",
        },
        "policy": {"allowed_binaries": ["curl", "jq"], "require_read_only": False, "timeout_seconds": 30},
        "tools": [
            {"name": "get_instructions", "description": "Pobiera instrukcję jak tworzyć serwery MCP. ZAWSZE wywołaj PRZED tworzeniem serwera.", "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "other",
             "config": {"command": ["curl", "-s", "${PLATFORM_URL}/api/platform-docs"], "timeout_seconds": 10},
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "create_mcp_server", "description": "Tworzy nowy serwer MCP. Przyjmuje JSON z package, name, credentials. NAJPIERW wywołaj get_instructions.", "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "other",
             "config": {"command": ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json", "${PLATFORM_URL}/api/auto-create", "-d", "${payload}"], "timeout_seconds": 30},
             "input_schema": {"type": "object", "properties": {"payload": {"type": "string", "description": "JSON: {package: {...}, name: '...', credentials: {KEY: 'val'}, deploy: true}"}}, "required": ["payload"]}},
            {"name": "list_servers", "description": "Lista serwerów MCP — nazwy, statusy, endpointy.", "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "other",
             "config": {"command": ["curl", "-s", "${PLATFORM_URL}/api/runtimes"], "timeout_seconds": 10},
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "list_packages", "description": "Lista gotowych paczek narzędzi.", "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "other",
             "config": {"command": ["curl", "-s", "${PLATFORM_URL}/api/tool-packages"], "timeout_seconds": 10},
             "input_schema": {"type": "object", "properties": {}}},
            {"name": "server_details", "description": "Szczegóły serwera MCP.", "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "other",
             "config": {"command": ["curl", "-s", "${PLATFORM_URL}/api/runtimes/${runtime_id}"], "timeout_seconds": 10},
             "input_schema": {"type": "object", "properties": {"runtime_id": {"type": "string", "description": "ID serwera"}}, "required": ["runtime_id"]}},
            {"name": "deploy_server", "description": "Deployuje serwer MCP.", "execution_type": "shell", "enabled": True, "risk_level": "medium", "mode": "write", "category": "other",
             "config": {"command": ["curl", "-s", "-X", "POST", "${PLATFORM_URL}/api/runtimes/${runtime_id}/deploy"], "timeout_seconds": 15},
             "input_schema": {"type": "object", "properties": {"runtime_id": {"type": "string", "description": "ID serwera"}}, "required": ["runtime_id"]}},
            {"name": "stop_server", "description": "Zatrzymuje serwer MCP.", "execution_type": "shell", "enabled": True, "risk_level": "medium", "mode": "write", "category": "other",
             "config": {"command": ["curl", "-s", "-X", "POST", "${PLATFORM_URL}/api/runtimes/${runtime_id}/stop"], "timeout_seconds": 15},
             "input_schema": {"type": "object", "properties": {"runtime_id": {"type": "string", "description": "ID serwera"}}, "required": ["runtime_id"]}},
        ],
    }
    # Load extra templates from templates/ directory
    _extra_packages = []
    _templates_dir = Path(__file__).resolve().parent.parent.parent / "templates"
    if _templates_dir.exists():
        for _tf in _templates_dir.rglob("*.json"):
            try:
                _tp = json.loads(_tf.read_text(encoding="utf-8"))
                if _tp.get("id") and _tp.get("tools") and _tp["id"] not in {"raghybrid-assistant", "openshift-readonly", "platform-manager"}:
                    _extra_packages.append(_tp)
            except Exception:
                pass
    openshift_monitor_package = {
        "id": "openshift-monitor",
        "name": "OpenShift Monitor (Full Deploy)",
        "description": "Pełne zarządzanie klastrem OCP — wdrażanie, skalowanie, monitorowanie, zarządzanie aplikacjami. Wymaga SA z rolą admin.",
        "category": "openshift",
        "risk_level": "high",
        "runtime_class": {
            "name": "shell-readwrite",
            "runtime_image": "mcp-runtime-shell:latest",
            "allowed_execution_types": ["shell"],
            "risk_level": "high",
            "security_profile": "cluster-admin",
            "required_binaries": ["oc", "jq"],
        },
        "adapters": [
            {
                "name": "shell",
                "description": "Adapter shell — wykonuje komendy oc w izolowanym kontenerze.",
                "adapter_type": "shell",
                "runtime_image": "mcp-runtime-shell:latest",
                "implemented": True,
                "enabled": True,
                "risk_level": "high",
                "mode": "read-only",
                "schema": {"type": "object"},
            }
        ],
        "policy": {
            "allowed_binaries": ["oc", "kubectl", "jq", "printf", "rm", "cat", "bash", "sh"],
            "blocked_commands": [],
            "require_read_only": False,
            "block_write_tools": False,
            "block_destructive_tools": False,
            "timeout_seconds": 60,
        },
        "credentials_hint": {"OC_TOKEN": "Service account token (oc create token <sa>)", "OC_SERVER": "API server URL (https://api.cluster.dom:6443)"},
        "tools": _openshift_monitor_tools(),
    }
    return [raghybrid_package, openshift_package, openshift_monitor_package, platform_manager_package] + _extra_packages


def seed_builtin_tool_packages() -> None:
    now = store.now_iso()
    for package in builtin_tool_packages():
        store.execute(
            """
            INSERT INTO tool_packages(id, name, description, category, risk_level, source, enabled, package_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              category = excluded.category,
              risk_level = excluded.risk_level,
              package_json = excluded.package_json,
              updated_at = excluded.updated_at
            """,
            (
                package["id"],
                package["name"],
                package["description"],
                package["category"],
                package["risk_level"],
                "builtin",
                1,
                json.dumps(package),
                now,
                now,
            ),
        )
        upsert_package_dependencies(package)


def seed_raghybrid_template() -> None:
    if store.one(sql.SELECT_RUNTIME_ID_EXISTS, ("raghybrid-assistant",)):
        return
    now = store.now_iso()
    store.execute(
        sql.INSERT_RUNTIME,
        (
            "raghybrid-assistant",
            "RAGHybrid Assistant",
            "HTTP gateway runtime calling RAGHybrid /retrieve_json.",
            "http-gateway",
            "raghybrid-assistant",
            "draft",
            "low",
            "mcp-runtime-http-gateway:latest",
            now,
            now,
        ),
    )
    tool_config = {
        "method": "POST",
        "url": "http://raghybrid-app:8000/retrieve_json",
        "body": {
            "query": "${query}",
            "top_k": "${top_k}",
            "max_vector": "${max_vector}",
            "max_graph": "${max_graph}",
            "max_evidence": "${max_evidence}",
            "max_context_chars": 20000,
            "telemetry": True,
        },
        "timeout_seconds": 60,
        "max_response_bytes": 5242880,
    }
    input_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 4000},
            "top_k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 8},
            "max_vector": {"type": "integer", "minimum": 1, "maximum": 10, "default": 8},
            "max_graph": {"type": "integer", "minimum": 0, "maximum": 30, "default": 12},
            "max_evidence": {"type": "integer", "minimum": 0, "maximum": 12, "default": 8},
        },
        "required": ["query"],
    }
    store.execute(
        sql.INSERT_TOOL,
        (
            "raghybrid-assistant",
            "hybridrag_search",
            "Retrieve source-grounded context from RAGHybrid. Send a standalone query with the concrete topic.",
            "http_request",
            json.dumps(tool_config),
            json.dumps(input_schema),
            "{}",
            1,
            "low",
            "read-only",
            "rag",
            now,
            now,
        ),
    )
    store.execute(
        sql.INSERT_POLICY,
        (
            "raghybrid-assistant",
            json.dumps(
                {
                    "block_write_tools": True,
                    "block_destructive_tools": True,
                    "require_read_only": True,
                    "timeout_seconds": 60,
                    "max_payload_bytes": 1048576,
                    "max_response_bytes": 5242880,
                    "allowed_clients": ["OpenWebUI", "local"],
                }
            ),
            now,
        ),
    )
    store.audit("system", "seed_runtime", "runtime", "raghybrid-assistant", {"template": "raghybrid-assistant"})


def _openshift_monitor_tools() -> list[dict[str, Any]]:
    """Tool definitions for the openshift-monitor runtime."""
    _auth = ["oc", "--token=${OC_TOKEN}", "--server=${OC_SERVER}", "--insecure-skip-tls-verify"]
    _confirm_prop = {"__confirm": {"type": "string", "description": "Wpisz 'yes' aby potwierdzić wykonanie po zatwierdzeniu przez użytkownika (wymagane gdy narzędzie zgłosi approval_required)"}}
    _args_schema = {"type": "object", "properties": {"args": {"type": "string", "description": "Argumenty komendy oc"}, **_confirm_prop}, "required": ["args"]}
    _yaml_schema = {
        "type": "object",
        "properties": {
            "yaml_content": {"type": "string", "description": "Pełna treść YAML zasobu Kubernetes/OpenShift"},
            "extra_args": {"type": "string", "description": "Dodatkowe argumenty, np. -n mynamespace"},
            **_confirm_prop,
        },
        "required": ["yaml_content"],
    }
    return [
        {"name": "oc_get", "description": "Execute oc get command with arguments",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["get", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_describe", "description": "Describe a resource using oc describe command",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["describe", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_logs", "description": "Get logs from a pod using oc logs command",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["logs", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_events", "description": "Get events for a namespace",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["get", "events", "-n", "${namespace}", "--sort-by=.lastTimestamp"], "timeout_seconds": 30},
         "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]}},
        {"name": "oc_status", "description": "Get cluster status for a namespace",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["status", "-n", "${namespace}"], "timeout_seconds": 30},
         "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]}},
        {"name": "oc_top", "description": "Get pod resource usage for a namespace",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["adm", "top", "pods", "-n", "${namespace}"], "timeout_seconds": 30},
         "input_schema": {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]}},
        {"name": "oc_projects", "description": "Wyświetla dostępne projekty/namespace'y na klastrze.",
         "execution_type": "shell", "enabled": True, "risk_level": "low", "mode": "read-only", "category": "openshift",
         "config": {"command": _auth + ["get", "projects"], "timeout_seconds": 15},
         "input_schema": {"type": "object"}},
        {"name": "oc_apply", "description": "Aplikuje zasoby na klaster (flagi CLI, NIE pliki). Dla YAML użyj oc_apply_yaml.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["apply", "${*args}"], "timeout_seconds": 60},
         "input_schema": _args_schema},
        {"name": "oc_apply_yaml",
         "description": "GŁÓWNE NARZĘDZIE do wdrażania zasobów. Przyjmuje treść YAML inline w yaml_content i aplikuje na klaster (Deployment, Service, Route, ConfigMap itp.).",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": ["printf", "%s", "${yaml_content}", "|"] + _auth + ["apply", "-f", "-", "${*extra_args}"], "timeout_seconds": 60},
         "input_schema": _yaml_schema},
        {"name": "oc_create", "description": "Tworzy zasób przez CLI (NIE pliki). Dla YAML użyj oc_create_yaml.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["create", "${*args}"], "timeout_seconds": 60},
         "input_schema": _args_schema},
        {"name": "oc_create_yaml",
         "description": "Tworzy zasoby z inline YAML na klastrze OpenShift. Podaj treść YAML w yaml_content.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": ["printf", "%s", "${yaml_content}", "|"] + _auth + ["create", "-f", "-", "${*extra_args}"], "timeout_seconds": 60},
         "input_schema": _yaml_schema},
        {"name": "oc_delete", "description": "Usuwa zasób z klastra OpenShift. UWAGA: operacja nieodwracalna!",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "destructive", "category": "openshift",
         "config": {"command": _auth + ["delete", "${*args}"], "timeout_seconds": 60},
         "input_schema": _args_schema},
        {"name": "oc_exec", "description": "Wykonuje komendę wewnątrz poda OpenShift.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["exec", "${*args}"], "timeout_seconds": 60},
         "input_schema": _args_schema},
        {"name": "oc_patch", "description": "Patchuje zasób — zmienia pojedyncze pola bez zastępowania całego obiektu.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["patch", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_rollout", "description": "Zarządza rolloutami — restart, status, history, undo.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["rollout", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_scale", "description": "Skaluje deployment/statefulset — zmienia liczbę replik.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["scale", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_new_app", "description": "Tworzy nową aplikację na klastrze — deployment, service i inne zasoby z jednej komendy.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["new-app", "${*args}"], "timeout_seconds": 120},
         "input_schema": _args_schema},
        {"name": "oc_expose", "description": "Tworzy route/expose dla serwisu — udostępnia aplikację na zewnątrz.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["expose", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_set", "description": "Ustawia właściwości zasobów — env vars, image, resources, volumes.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["set", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
        {"name": "oc_adm", "description": "Operacje administracyjne — oc adm policy, oc adm top, oc adm prune. Np. policy add-scc-to-user anyuid -z mysa -n ns.",
         "execution_type": "shell", "enabled": True, "risk_level": "high", "mode": "write", "category": "openshift",
         "config": {"command": _auth + ["adm", "${*args}"], "timeout_seconds": 30},
         "input_schema": _args_schema},
    ]


def seed_openshift_monitor() -> None:
    runtime_id = "openshift-monitor"
    now = store.now_iso()
    if store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        # Runtime exists — patch tool schemas and configs to match current code
        for tool in _openshift_monitor_tools():
            store.execute(
                """UPDATE tools SET config_json=?, input_schema_json=?, updated_at=?
                   WHERE runtime_id=? AND name=?""",
                (
                    json.dumps(tool.get("config") or {}),
                    json.dumps(tool.get("input_schema") or {"type": "object"}),
                    now,
                    runtime_id,
                    tool["name"],
                ),
            )
        return
    now = store.now_iso()
    store.execute(
        sql.INSERT_RUNTIME,
        (
            runtime_id,
            "openshift-monitor",
            "Full OpenShift cluster management — deploy, scale, monitor, manage applications.",
            "shell-readwrite",
            "openshift-monitor",
            "draft",
            "high",
            "mcp-runtime-shell:latest",
            now,
            now,
        ),
    )
    for tool in _openshift_monitor_tools():
        store.execute(
            sql.INSERT_TOOL,
            (
                runtime_id,
                tool["name"],
                tool.get("description", ""),
                tool.get("execution_type", "shell"),
                json.dumps(tool.get("config") or {}),
                json.dumps(tool.get("input_schema") or {"type": "object"}),
                json.dumps(tool.get("output_schema") or {"type": "object"}),
                1 if tool.get("enabled", True) else 0,
                tool.get("risk_level", "low"),
                tool.get("mode", "read-only"),
                tool.get("category", "openshift"),
                now,
                now,
            ),
        )
    store.execute(
        sql.INSERT_POLICY,
        (
            runtime_id,
            json.dumps({
                "allowed_binaries": ["oc", "kubectl", "jq", "printf", "rm", "cat", "bash", "sh"],
                "blocked_commands": [],
                "require_read_only": False,
                "block_write_tools": False,
                "block_destructive_tools": False,
                "timeout_seconds": 60,
                "require_approval_for": "auto",
                "require_approval_for_prefixes": ["oc delete", "oc apply", "oc patch", "kubectl delete"],
                "approval_timeout_seconds": 120,
                "allowed_command_prefixes": [],
                "blocked_command_prefixes": [],
            }),
            now,
        ),
    )
    store.audit("system", "seed_runtime", "runtime", runtime_id, {"template": "openshift-monitor"})


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


def runtime_class_options(selected: str = "") -> str:
    classes = enabled_runtime_classes()
    return "".join(
        f'<option value="{item["name"]}" {"selected" if item["name"] == selected else ""}>{item["name"]}</option>'
        for item in classes
    )


def package_options(selected: str = "") -> str:
    packages = store.rows("SELECT id, name, category FROM tool_packages WHERE enabled = 1 ORDER BY category, name")
    options = ['<option value="">Blank / custom tools</option>']
    options.extend(
        f'<option value="{escape(item["id"])}" {"selected" if item["id"] == selected else ""}>{escape(item["name"])} ({escape(item["category"])})</option>'
        for item in packages
    )
    return "".join(options)


def adapter_options(selected: str = "") -> str:
    adapters = enabled_adapters()
    return "".join(
        f'<option value="{item["name"]}" {"selected" if item["name"] == selected else ""}>{item["name"]}</option>'
        for item in adapters
    )


def select_options(values: list[str], selected: str) -> str:
    return "".join(
        f'<option value="{escape(value)}" {"selected" if value == selected else ""}>{escape(value)}</option>'
        for value in values
    )


def schema_defaults(schema: dict[str, Any]) -> dict[str, Any]:
    defaults = {}
    for name, spec in (schema.get("properties") or {}).items():
        if isinstance(spec, dict) and "default" in spec:
            defaults[name] = spec["default"]
    return defaults


def schema_form(schema: dict[str, Any], prefix: str, values: dict[str, Any] | None = None) -> str:
    values = {**schema_defaults(schema), **(values or {})}
    fields = []
    required = set(schema.get("required") or [])
    for name, spec in (schema.get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        field_name = f"{prefix}.{name}"
        label = escape(str(spec.get("title") or name.replace("_", " ").title()))
        required_mark = " *" if name in required else ""
        value = values.get(name, "")
        enum = spec.get("enum")
        field_type = spec.get("type", "string")
        if enum:
            options = "".join(
                f'<option value="{escape(str(item))}" {"selected" if str(item) == str(value) else ""}>{escape(str(item))}</option>'
                for item in enum
            )
            control = f'<select name="{escape(field_name)}">{options}</select>'
        elif field_type == "boolean":
            control = f'<select name="{escape(field_name)}">{select_options(["true", "false"], "true" if bool(value) else "false")}</select>'
        elif field_type == "integer":
            control = f'<input type="number" name="{escape(field_name)}" value="{escape(str(value))}">'
        elif field_type in {"array", "object"}:
            encoded_value = value
            if encoded_value == "" or encoded_value is None:
                encoded_value = [] if field_type == "array" else {}
            encoded = json.dumps(encoded_value, ensure_ascii=False)
            control = f'<textarea name="{escape(field_name)}">{escape(encoded)}</textarea>'
        else:
            control = f'<input name="{escape(field_name)}" value="{escape(str(value))}">'
        fields.append(f"<label>{label}{required_mark}{control}</label>")
    if not fields:
        return '<p class="muted">This schema does not declare configurable fields.</p>'
    return '<div class="grid">' + "".join(fields) + "</div>"


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


def upsert_package_dependencies(package: dict[str, Any]) -> None:
    now = store.now_iso()
    runtime_class = package.get("runtime_class") or {}
    if runtime_class.get("name"):
        store.execute(
            sql.UPSERT_RUNTIME_CLASS,
            (
                runtime_class["name"],
                runtime_class.get("description") or package.get("description", ""),
                runtime_class.get("runtime_image") or "mcp-runtime-http-gateway:latest",
                json.dumps(runtime_class.get("allowed_execution_types") or ["http_request"]),
                1,
                runtime_class.get("risk_level") or package.get("risk_level", "low"),
                runtime_class.get("security_profile") or "restricted",
                now,
                now,
            ),
        )
    for adapter in package.get("adapters") or []:
        store.execute(
            """
            INSERT INTO execution_adapters(name, description, adapter_type, runtime_image, config_schema_json,
                                           adapter_contract_json, enabled, implemented, risk_level, mode, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              description = excluded.description,
              adapter_type = excluded.adapter_type,
              runtime_image = excluded.runtime_image,
              config_schema_json = excluded.config_schema_json,
              adapter_contract_json = excluded.adapter_contract_json,
              enabled = excluded.enabled,
              implemented = excluded.implemented,
              risk_level = excluded.risk_level,
              mode = excluded.mode,
              updated_at = excluded.updated_at
            """,
            (
                adapter["name"],
                adapter.get("description", ""),
                adapter.get("adapter_type", adapter["name"]),
                adapter.get("runtime_image", runtime_class.get("runtime_image", "")),
                json.dumps(adapter.get("schema") or {}),
                json.dumps(adapter.get("contract") or adapter_contracts().get(adapter["name"], {"name": adapter["name"], "config_schema": adapter.get("schema") or {}})),
                1 if adapter.get("enabled") else 0,
                1 if adapter.get("implemented") else 0,
                adapter.get("risk_level", package.get("risk_level", "low")),
                adapter.get("mode", "read-only"),
                now,
                now,
            ),
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


def action_forms(runtime_id: str, compact: bool = False, return_to: str | None = None) -> str:
    rid = escape(runtime_id)
    if compact:
        # compact = simple forms for lists
        _actions = [("deploy","Deploy",None),("stop","Zatrzymaj",None),("start","Uruchom",None),
                    ("delete","Usuń","Trwale usunąć ten serwer MCP?")]
        target = escape(return_to or "/runtimes")
        parts = []
        for action, label, confirm_msg in _actions:
            ca = f' onclick="return confirm(\'{confirm_msg}\')"' if confirm_msg else ""
            cls = "delete" if action == "delete" else ("stop" if action == "stop" else "")
            parts.append(f'<form method="post" action="/api/runtimes/{rid}/{action}"><input type="hidden" name="return_to" value="{target}"><button class="{cls}"{ca}>{label}</button></form>')
        return '<div class="actions compact">' + "".join(parts) + "</div>"

    # Full detail page — JS-powered with inline feedback
    msg_id = f"act-msg-{rid}"
    return f"""
<style>
.act-btn {{ padding:8px 14px; border:0; border-radius:6px; font-weight:700; cursor:pointer; font-size:13px; transition:.12s; color:white; }}
.act-btn:hover {{ filter:brightness(1.15); transform:translateY(-1px); }}
.act-btn.primary {{ background:var(--blue); }}
.act-btn.secondary {{ background:#3d5268; }}
.act-btn.warn {{ background:#d9822b; }}
.act-btn.danger {{ background:#c43b3b; }}
.act-btn.dark {{ background:#263548; }}
#{msg_id} {{ padding:10px 14px; border-radius:8px; font-size:13px; font-weight:600; margin-top:10px; display:none; }}
#{msg_id}.ok {{ background:#0e2e1e; border:1px solid #1a5a38; color:#5ce89a; }}
#{msg_id}.err {{ background:#2c0e10; border:1px solid #5a2025; color:#f47a80; }}
#{msg_id}.info {{ background:#0d1e2e; border:1px solid #1a3a50; color:#7dd3fc; }}
</style>
<div class="actions" style="flex-wrap:wrap;gap:8px" id="act-btns-{rid}">
  <button class="act-btn primary"   onclick="doAct('{rid}','deploy')">🚀 Deploy</button>
  <button class="act-btn dark"      onclick="doAct('{rid}','reload')">♻️ Reload Config</button>
  <button class="act-btn warn"      onclick="doAct('{rid}','stop')">⏹ Zatrzymaj</button>
  <button class="act-btn secondary" onclick="doAct('{rid}','start')">▶️ Uruchom</button>
  <button class="act-btn secondary" onclick="doAct('{rid}','restart')">🔄 Restart</button>
  <button class="act-btn dark"      onclick="doAct('{rid}','health')">🩺 Sprawdź status</button>
  <button class="act-btn dark"      onclick="doAct('{rid}','logs')">📋 Pobierz logi</button>
  <button class="act-btn dark"      onclick="doAct('{rid}','rebuild-redeploy')" style="background:#6b3a0a">🔨 Przebuduj obraz + Deploy</button>
  <button class="act-btn danger"    onclick="doAct('{rid}','delete')">🗑️ Usuń</button>
</div>
<div id="{msg_id}"></div>
<script>
(function() {{
  var rid = '{rid}';
  var msgs = {{
    'deploy':           ['info', '🚀 Deployment zlecony — kontener uruchomi się za kilka sekund. Status zmieni się automatycznie.'],
    'reload':           ['info', '♻️ Przeładowuję konfigurację...'],
    'stop':             ['info', '⏹ Zatrzymywanie kontenera...'],
    'start':            ['info', '▶️ Uruchamianie kontenera...'],
    'restart':          ['info', '🔄 Restartowanie kontenera...'],
    'health':           ['info', '🩺 Sprawdzam status...'],
    'logs':             ['info', '📋 Pobieranie logów z kontenera...'],
    'rebuild-redeploy': ['info', '🔨 Przebudowywanie obrazu Docker — może potrwać kilka minut. Status zaktualizuje się automatycznie.'],
    'delete':           ['info', '🗑️ Usuwanie serwera...']
  }};
  var confirms = {{
    'rebuild-redeploy': 'Przebuduje obraz Docker i zrestartuje serwer. Może potrwać kilka minut. Kontynuować?',
    'delete':           'Trwale usunąć ten serwer MCP i jego kontener?'
  }};
  var successMsgs = {{
    'deploy':    '🚀 Deployment zlecony! Kontener uruchomi się za chwilę.',
    'stop':      '⏹️ Serwer zatrzymany.',
    'start':     '▶️ Serwer uruchomiony.',
    'restart':   '🔄 Serwer zrestartowany.',
    'delete':    '🗑️ Serwer usunięty. Przekierowuję...',
    'rebuild-redeploy': '🔨 Przebudowanie obrazu zlecone. Może potrwać kilka minut.'
  }};

  window.doAct = function(r, action) {{
    if (confirms[action] && !confirm(confirms[action])) return;
    var box = document.getElementById('act-msg-' + r);
    var pair = msgs[action] || ['info', 'Wykonuję operację...'];
    box.className = pair[0]; box.textContent = pair[1]; box.style.display = 'block';

    fetch('/api/runtimes/' + r + '/' + action, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
      body: 'return_to=' + encodeURIComponent('/runtimes/' + r),
      redirect: 'manual'
    }}).then(function(resp) {{
      if (action === 'delete') {{
        box.className = 'ok'; box.textContent = successMsgs['delete'] || '✅ Gotowe.';
        setTimeout(function() {{ window.location = '/runtimes'; }}, 1200);
        return;
      }}
      if (action === 'logs') {{
        box.className = 'ok'; box.textContent = '📋 Pobieranie logów zlecone — odśwież za chwilę.';
        setTimeout(function() {{
          var el = document.getElementById('sec-logs');
          if (el) {{ el.open = true; el.scrollIntoView({{behavior:'smooth'}}); }}
        }}, 800);
        return;
      }}
      if (action === 'reload') {{
        fetch('/api/runtimes/' + r + '/status').then(function(r2){{return r2.json();}}).then(function(d) {{
          box.className = 'ok';
          box.textContent = '✅ Konfiguracja przeładowana. Status: ' + (d.status || '?');
        }});
        return;
      }}
      if (action === 'health') {{
        setTimeout(function() {{
          fetch('/api/runtimes/' + r + '/status').then(function(r2){{return r2.json();}}).then(function(d) {{
            var ok = d.status === 'running';
            box.className = ok ? 'ok' : 'err';
            box.textContent = ok
              ? '✅ Kontener żyje i odpowiada! Status: running · Endpoint: ' + (d.endpoint_url || '?')
              : '❌ Problem z kontenerem. Status: ' + (d.status || '?') + (d.last_error ? ' · Błąd: ' + d.last_error : '');
          }});
        }}, 1200);
        return;
      }}
      // deploy, stop, start, restart, rebuild
      var msg = successMsgs[action];
      if (msg) {{
        box.className = 'ok'; box.textContent = msg;
        // after deploy/restart/start, poll for running
        if (['deploy','start','restart','rebuild-redeploy'].includes(action)) {{
          var polls = 0;
          var t = setInterval(function() {{
            polls++;
            fetch('/api/runtimes/' + r + '/status').then(function(r2){{return r2.json();}}).then(function(d) {{
              if (d.status === 'running') {{
                clearInterval(t);
                box.textContent = '✅ Serwer działa! · ' + (d.endpoint_url || '');
                setTimeout(function() {{ location.reload(); }}, 1500);
              }} else if (d.status === 'failed' || d.status === 'missing') {{
                clearInterval(t);
                box.className = 'err';
                box.textContent = '❌ Błąd: ' + (d.last_error || d.status);
              }} else if (polls > 30) {{ clearInterval(t); }}
            }});
          }}, 2000);
        }} else if (action === 'stop') {{
          setTimeout(function() {{ location.reload(); }}, 1500);
        }}
      }}
    }}).catch(function(e) {{
      box.className = 'err'; box.textContent = '❌ Błąd połączenia: ' + e;
    }});
  }};
}})();
</script>"""


def _validation_ui(tool: dict[str, Any]) -> str:
    schema = json.loads(tool["input_schema_json"] or "{}")
    props = schema.get("properties") or {}
    if not props:
        return '<p class="muted" style="font-size:11px">Brak parametrów — dodaj w Input Schema JSON wyżej.</p>'
    rows = []
    for pname, pdef in props.items():
        val = pdef.get("validation") or {}
        allowed = ", ".join(val.get("allowed_values") or [])
        blocked = ", ".join(val.get("blocked_words") or [])
        pattern = val.get("pattern") or ""
        max_len = val.get("max_length") or ""
        rows.append(f"""<tr>
          <td style="font-weight:700;color:#7dd3fc;font-size:12px">{escape(pname)}</td>
          <td><input name="val_allowed_{escape(pname)}" value="{escape(allowed)}" placeholder="wartość1, wartość2" style="font-size:11px;padding:4px 8px;width:100%;box-sizing:border-box"></td>
          <td><input name="val_blocked_{escape(pname)}" value="{escape(blocked)}" placeholder="DROP, DELETE, rm" style="font-size:11px;padding:4px 8px;width:100%;box-sizing:border-box"></td>
          <td><input name="val_pattern_{escape(pname)}" value="{escape(pattern)}" placeholder="^[0-9]+$" style="font-size:11px;padding:4px 8px;width:100%;box-sizing:border-box;font-family:monospace"></td>
          <td><input name="val_maxlen_{escape(pname)}" value="{escape(str(max_len))}" type="number" min="0" placeholder="0" style="font-size:11px;padding:4px 8px;width:80px"></td>
        </tr>""")
    return f"""
    <div style="background:#0d1822;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px">
      <div style="font-weight:700;font-size:12px;color:#7dd3fc;margin-bottom:6px">🛡️ Walidacja wartości parametrów (Pydantic)</div>
      <div class="muted" style="font-size:11px;margin-bottom:8px">Allow list = tylko te wartości przejdą | Block list = zabronione słowa | Pattern = regex | + blocked_commands z polityki</div>
      <table style="width:100%;font-size:12px">
        <thead><tr>
          <th style="text-align:left;padding:4px;width:120px">Parametr</th>
          <th style="text-align:left;padding:4px">Allow list</th>
          <th style="text-align:left;padding:4px">Block list</th>
          <th style="text-align:left;padding:4px;width:140px">Pattern (regex)</th>
          <th style="text-align:left;padding:4px;width:90px">Max length</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>"""


def tool_edit_form(runtime_id: str, tool: dict[str, Any]) -> str:
    config = json.loads(tool["config_json"] or "{}")
    is_shell = tool["execution_type"] in ("shell", "ssh")
    input_schema_json = json.dumps(json.loads(tool["input_schema_json"] or "{}"), indent=2, ensure_ascii=False)
    output_schema_json = json.dumps(json.loads(tool["output_schema_json"] or "{}"), indent=2, ensure_ascii=False)
    if is_shell:
        cmd_parts = config.get("command") or []
        cmd_str = " ".join(shlex.quote(p) if " " in str(p) else str(p) for p in cmd_parts)
        timeout_val = config.get("timeout_seconds", 30)
        exec_fields = f"""
        <label>Komenda<input name="cmd" value="{escape(cmd_str)}" placeholder="ping -c 4 ${{*args}}"></label>
        <label>Timeout (s)<input name="timeout_seconds" type="number" value="{timeout_val}" min="1" max="300" style="width:120px"></label>"""
    else:
        body_json = json.dumps(config.get("body", {}), indent=2, ensure_ascii=False)
        headers_json = json.dumps(config.get("headers", {}), indent=2, ensure_ascii=False)
        exec_fields = f"""
        <label>Method<select name="method">{select_options(["GET", "POST", "PUT", "PATCH", "DELETE"], str(config.get("method", "POST")).upper())}</select></label>
        <label>URL<input name="url" value="{escape(str(config.get("url", "")))}"></label>
        <label>Body JSON<textarea name="body_json">{escape(body_json)}</textarea></label>
        <label>Headers JSON<textarea name="headers_json" placeholder='{{"Authorization": "Bearer ${{API_TOKEN}}"}}'>{escape(headers_json)}</textarea></label>
        <div class="muted" style="font-size:11px;margin-top:-4px">Wartości <code>${{ZMIENNA}}</code> są podstawiane z ENV kontenera (zakładka 🔑 Sekrety) — np. tokeny API, klucze.</div>"""
    return f"""
    <details id="tool-{tool['id']}">
      <summary>{escape(tool['name'])} <span class="muted">{escape(tool['execution_type'])} / {'enabled' if tool['enabled'] else 'disabled'}</span></summary>
      <form method="post" action="/api/runtimes/{runtime_id}/tools/{tool['id']}/update">
        <div class="grid">
          <label>Name<input name="name" value="{escape(tool['name'])}"></label>
          <label>Execution Adapter<select name="execution_type">{adapter_options(tool['execution_type'])}</select></label>
          <label>Enabled<select name="enabled">{select_options(["true", "false"], "true" if tool["enabled"] else "false")}</select></label>
          <label>Risk<select name="risk_level">{select_options(["low", "medium", "high"], tool["risk_level"])}</select></label>
          <label>Mode<select name="mode">{select_options(["read-only", "write", "destructive"], tool["mode"])}</select></label>
          <label>Category<input name="category" value="{escape(tool['category'])}"></label>
        </div>
        <label>Description<textarea name="description" style="min-height:52px">{escape(tool['description'])}</textarea></label>
        {exec_fields}
        <label style="margin-top:8px">Input Schema JSON<textarea name="input_schema_json" id="sch-{tool['id']}" oninput="renderValidationUI('{tool['id']}')">{escape(input_schema_json)}</textarea></label>
        <div id="val-ui-{tool['id']}" style="margin-top:8px">{_validation_ui(tool)}</div>
        <label>Output Schema JSON<textarea name="output_schema_json">{escape(output_schema_json)}</textarea></label>
        <div class="actions" style="margin-top:10px">
          <button>💾 Zapisz tool</button>
        </div>
      </form>
      <form method="post" action="/api/runtimes/{runtime_id}/tools/{tool['id']}/delete" style="margin-top:6px">
        <button class="delete">🗑️ Usuń tool</button>
      </form>
    </details>
    """


def masked_secret(value: str) -> str:
    if not value:
        return ""
    return "***" + value[-4:] if len(value) > 4 else "***"


def base_styles() -> str:
    return """
    :root { --blue:#1f9bd1; --blue-dark:#157aa8; --sidebar:#0f1722; --sidebar-2:#172231; --line:#2b394a; --text:#dce7f3; --muted:#8ea2b8; --bg:#111820; --panel:#182230; --panel-2:#1d2a3a; --field:#101722; }
    * { box-sizing:border-box; }
    body { font-family: Arial, system-ui, sans-serif; margin:0; background:var(--bg); color:var(--text); font-size:14px; }
    .layout { min-height:100vh; display:grid; grid-template-columns:250px minmax(0, 1fr); }
    aside.sidebar { background:var(--sidebar); color:#d9e4ef; display:flex; flex-direction:column; border-right:1px solid #0b1220; }
    .brand { padding:18px 18px 16px; border-bottom:1px solid rgba(255,255,255,.08); }
    .brand-title { font-size:20px; font-weight:800; color:white; letter-spacing:.2px; }
    .brand-subtitle { color:#91a4bb; font-size:12px; margin-top:4px; }
    nav.tabs { display:flex; flex-direction:column; gap:2px; padding:12px 10px; }
    nav.tabs a { color:#b8cad9; border-radius:7px; padding:9px 12px; font-size:13px; font-weight:600; border-left:3px solid transparent; display:flex; align-items:center; gap:6px; transition:.12s; }
    nav.tabs a:hover { background:var(--sidebar-2); color:white; }
    nav.tabs a.active { background:#0d3a55; color:white; border-left-color:var(--blue); }
    .content { min-width:0; display:flex; flex-direction:column; }
    header.topbar { background:var(--panel); border-bottom:1px solid var(--line); padding:16px 26px; display:flex; justify-content:space-between; align-items:center; }
    header.topbar h1 { margin:0; font-size:22px; font-weight:800; }
    header.topbar .sub { color:var(--muted); margin-top:3px; font-size:13px; }
    main { padding:24px 26px; display:grid; gap:18px; }
    section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:22px 24px; box-shadow:0 2px 4px rgba(0,0,0,.2); }
    section h2 { margin-top:0; font-size:17px; font-weight:800; color:white; margin-bottom:14px; }
    section h3 { margin-top:0; font-size:15px; font-weight:700; color:#c6d7e8; }
    table { width:100%; border-collapse:collapse; }
    th { color:#7fa8c4; font-size:11px; text-transform:uppercase; letter-spacing:.5px; background:#111d2a; font-weight:700; }
    th,td { text-align:left; border-bottom:1px solid var(--line); padding:11px 12px; vertical-align:middle; }
    tr:last-child td { border-bottom:none; }
    tr:hover td { background:rgba(31,155,209,.04); }
    input,select,textarea { width:100%; box-sizing:border-box; padding:10px 12px; border:1px solid #34465b; border-radius:6px; background:var(--field); color:var(--text); font-size:14px; transition:.12s; }
    input:focus,select:focus,textarea:focus { outline:none; border-color:var(--blue); box-shadow:0 0 0 2px rgba(31,155,209,.15); }
    input:disabled { color:#7f91a6; background:#182230; }
    textarea { min-height:74px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; }
    button { padding:9px 14px; border:0; border-radius:6px; background:var(--blue); color:white; font-weight:700; cursor:pointer; font-size:13px; transition:.12s; }
    button:hover { background:var(--blue-dark); transform:translateY(-1px); }
    button:active { transform:translateY(0); }
    button.delete { background:#c43b3b; }
    button.delete:hover { background:#a83030; }
    button.stop { background:#d9822b; }
    button.health, button.logs { background:#3d5268; }
    button.secondary { background:#263548; color:#c9d7e6; }
    button.secondary:hover { background:#34465b; }
    button.disabled, button:disabled { background:#222e3b; color:#576778; cursor:not-allowed; transform:none; }
    .actions { display:flex; flex-wrap:wrap; gap:7px; align-items:center; }
    .actions form { display:inline; }
    .actions.compact button { padding:6px 9px; font-size:12px; }
    form.inline { display:grid; grid-template-columns: 1fr 1fr 1fr auto; gap:10px; align-items:end; }
    label { font-weight:600; font-size:13px; color:#a8c0d6; display:block; margin-bottom:4px; }
    label input, label select, label textarea { margin-top:5px; }
    .badge,.risk { border-radius:999px; padding:3px 9px; font-size:12px; font-weight:700; background:#263548; display:inline-block; }
    .running,.healthy { background:#0e2e1e; color:#5ce89a; border:1px solid #1a5a38; }
    .deploying,.pending { background:#2c2008; color:#f4c163; border:1px solid #5a420f; }
    .failed,.unhealthy,.missing { background:#2c0e10; color:#f47a80; border:1px solid #5a2025; }
    .stopped,.draft { background:#1e252e; color:#7a92a8; border:1px solid #2b394a; }
    .high { background:#2c0e10; color:#f47a80; border:1px solid #5a2025; }
    .medium { background:#2c2008; color:#f4c163; border:1px solid #5a420f; }
    .low { background:#0e2e1e; color:#5ce89a; border:1px solid #1a5a38; }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
    .grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
    .wizard { display:grid; grid-template-columns: repeat(5, 1fr); gap:12px; }
    .step { border:1px solid var(--line); border-radius:8px; padding:12px; background:var(--panel-2); }
    .step.active { border-color:var(--blue); background:#0d2f45; }
    .wizard-page { display:none; margin-top:16px; }
    .wizard-page.active { display:block; }
    .wizard-nav { display:flex; justify-content:space-between; gap:10px; margin-top:16px; }
    .wizard-nav .secondary { background:#607083; }
    .admin-panel { display:none; }
    .admin-panel:target { display:block; }
    .cards { display:grid; grid-template-columns: repeat(4, 1fr); gap:14px; }
    .card { border:1px solid var(--line); border-radius:12px; padding:18px; background:var(--panel); box-shadow:0 2px 4px rgba(0,0,0,.2); display:block; color:var(--text); transition:.15s; }
    a.card:hover { border-color:var(--blue); box-shadow:0 3px 10px rgba(31,155,209,.12); transform:translateY(-2px); }
    .metric { font-size:32px; font-weight:800; color:#3ab8f5; line-height:1; margin-bottom:4px; }
    .muted { color:var(--muted); font-size:13px; }
    .hint { color:var(--muted); font-size:12px; margin-top:4px; }
    .alert { border:1px solid #7a4b16; background:#1e1508; color:#ffd08a; padding:12px 16px; border-radius:8px; margin-bottom:14px; }
    .success { border:1px solid #1a7a3f; background:#0a2018; color:#8ee7b3; padding:12px 16px; border-radius:8px; margin-bottom:14px; }
    details { border:1px solid var(--line); border-radius:8px; padding:14px; background:var(--panel-2); }
    summary { cursor:pointer; font-weight:700; margin-bottom:8px; }
    details[open] summary { margin-bottom:12px; }
    pre { background:#0b1520; color:#d6e8f8; padding:14px; border-radius:8px; overflow:auto; font-size:13px; border:1px solid var(--line); }
    code { background:#0b1520; color:#7dd3fc; padding:2px 6px; border-radius:4px; font-size:12px; }
    a { color:var(--blue); text-decoration:none; }
    a:hover { text-decoration:underline; }
    .filter-bar { display:flex; gap:6px; margin-bottom:16px; flex-wrap:wrap; }
    .filter-pill { padding:6px 14px; border-radius:999px; font-size:13px; font-weight:600; border:1px solid var(--line); color:var(--muted); background:var(--panel-2); cursor:pointer; transition:.12s; }
    .filter-pill:hover { border-color:var(--blue); color:white; }
    .filter-pill.active { background:#0d3a55; color:white; border-color:var(--blue); }
    .page-inner { max-width:800px; }
    .srv-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(360px,1fr)); gap:14px; }
    .srv-card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px 22px; transition:.15s; position:relative; }
    .srv-card:hover { border-color:#3a7fa8; box-shadow:0 3px 12px rgba(31,155,209,.1); }
    .srv-card-top { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px; }
    .srv-card-name { font-size:16px; font-weight:800; color:white; }
    .srv-card-meta { color:var(--muted); font-size:12px; margin-top:2px; }
    .srv-card-endpoint { font-size:12px; color:#5db7ee; margin:8px 0 14px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .pkg-grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(340px,1fr)); gap:14px; }
    .pkg-card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px 22px; display:flex; flex-direction:column; gap:10px; transition:.15s; }
    .pkg-card:hover { border-color:#3a7fa8; }
    .pkg-card-name { font-size:15px; font-weight:800; color:white; }
    .pkg-card-desc { color:var(--muted); font-size:13px; flex:1; }
    .pkg-card-meta { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
    .pkg-card-actions { margin-top:4px; display:flex; gap:8px; align-items:center; }
    .log-info td:last-child { color:#b0c8e0; }
    .log-error td:last-child { color:#f47a80; }
    .log-warn td:last-child { color:#f4c163; }
    @media (max-width: 900px) {
      .layout { grid-template-columns:1fr; }
      aside.sidebar { position:relative; }
      nav.tabs { flex-direction:row; flex-wrap:wrap; }
      .cards,.wizard,.grid,.grid3,form.inline { grid-template-columns:1fr; }
      .srv-grid,.pkg-grid { grid-template-columns:1fr; }
    }
    .preset-btn { background:#0d1822; border:1px solid #2a3a4a; border-radius:6px; padding:5px 10px; font-size:12px; font-weight:600; color:#b0c8e0; cursor:pointer; transition:.12s; white-space:nowrap; }
    .preset-btn:hover { border-color:var(--blue); color:white; }
    """


_PAGE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "dashboard":  ("🏠 Dashboard", "Przegląd całej platformy — działające serwery, ostatnie operacje i logi błędów. Tu widzisz od razu co wymaga uwagi."),
    "quickstart": ("⚡ Szybki start", "Utwórz gotowy serwer MCP w kilku krokach bez pisania kodu. Wybierz gotowy zestaw z katalogu lub zaimportuj konfigurację."),
    "create":     ("🛠️ Kreator zaawansowany", "5-krokowy kreator z pełną kontrolą — wybierz źródło tools, środowisko Docker, zdefiniuj narzędzie, ustaw politykę bezpieczeństwa i uruchom serwer."),
    "runtimes":   ("🖥️ Moje serwery MCP", "Lista wszystkich serwerów MCP na platformie — statusy, endpointy do podłączenia w AI oraz zarządzanie (deploy, stop, restart, logi)."),
    "external":   ("🔗 Zewnętrzne MCP", "Rejestruj i monitoruj serwery MCP działające poza platformą — np. pobrane z GitHuba lub uruchomione ręcznie. Platforma sprawdza ich dostępność i wylistowuje tools."),
    "webhooks":   ("🔔 Webhooki", "Powiadomienia HTTP gdy serwer MCP padnie, health check się nie powiedzie lub tool zwróci błąd. Integracja ze Slackiem, Teams, Discordem lub własnym systemem."),
    "packages":   ("🏗️ Build", "Wbudowane szablony + serwery z Kreatora zaawansowanego. Wdróż jednym kliknięciem lub zbuduj własny obraz Docker z dowolnymi narzędziami."),
    "adapters":   ("⚙️ Silniki wykonania", "Globalne typy egzekucji dostępne na platformie (http_request, shell, ssh…). Określają jak runtime wywołuje narzędzia. Możesz dodawać własne silniki z własnym obrazem Docker."),
    "classes":    ("🏗️ Typy środowisk", "Typy środowisk określają jaki obraz Docker jest uruchamiany dla danego serwera i jakie silniki są dozwolone. Nowe typy tworzy Runtime Image Builder automatycznie."),
    "images":     ("🐳 Obrazy Docker", "Historia wszystkich zbudowanych obrazów kontenerów — status budowania, base image, data. Stąd możesz usuwać nieużywane lub nieudane buildy."),
    "security":   ("🔒 Bezpieczeństwo", "Przegląd polityk bezpieczeństwa wszystkich serwerów i globalny hardening kontenerów. Każdy kontener działa jako user 1000, bez uprawnień root, z read-only filesystem."),
    "audit":      ("🔍 Audit log", "Historia wszystkich operacji na platformie — kto i kiedy uruchomił deploy, zmienił konfigurację, otworzył stronę serwera lub wywołał akcję. Przydatne do audytu dostępu."),
    "logs":       ("📋 Logi", "Logi diagnostyczne kontenerów runtime — błędy startowania, komunikaty aplikacji, wyniki health checków. Pomocne przy debugowaniu problemów z serwerem."),
    "admin":      ("👥 Użytkownicy", "Zarządzanie kontami — zatwierdzanie rejestracji, zmiana ról (read_only / read_write / admin), włączanie i wyłączanie kont."),
    "docs":       ("📖 Jak to działa?", "Przewodnik po platformie — architektura, przepływ danych, różnice między kreatorami, bezpieczeństwo kontenerów i FAQ dla użytkowników technicznych i nietech."),
}


_lang_js_cache: str = ""

def _cached_lang_js() -> str:
    global _lang_js_cache
    if _lang_js_cache:
        return _lang_js_cache
    import inspect
    src = inspect.getsource(page_shell)
    start = src.find("var TRANS_RAW = [")
    end = src.find("];", start) + 2
    raw_block = src[start:end].replace("{{", "{").replace("}}", "}")
    _lang_js_cache = f"""(function(){{
if(typeof window.applyLang==='function'){{var s=localStorage.getItem('mcp_lang');if(s==='en')applyLang('en');return;}}
{raw_block}
TRANS_RAW.sort(function(a,b){{return b[0].length-a[0].length;}});
var TRANS_KEYS=TRANS_RAW.map(function(p){{return p[0];}});
var TRANS_VALS=TRANS_RAW.map(function(p){{return p[1];}});
function translateText(text){{
for(var i=0;i<TRANS_KEYS.length;i++){{
var k=TRANS_KEYS[i];if(text.indexOf(k)===-1)continue;
if(k.length<=6){{var ek=k.replace(/[.*+?^${{}}()|[\\]\\\\]/g,'\\\\$&');
var re=new RegExp('(?<![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])'+ek+'(?![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])','g');
text=text.replace(re,TRANS_VALS[i]);}}else{{text=text.split(k).join(TRANS_VALS[i]);}}}}return text;}}
function collectNodes(){{var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null,false);var n,r=[];while((n=w.nextNode())){{if(n.textContent.trim())r.push(n);}}return r;}}
window.applyLang=function(lang){{
var toEN=lang==='en';
if(toEN){{collectNodes().forEach(function(node){{if(node._orig===undefined)node._orig=node.textContent;node.textContent=translateText(node._orig);}});
document.querySelectorAll('[placeholder]').forEach(function(el){{if(el._origPh===undefined)el._origPh=el.placeholder;el.placeholder=translateText(el._origPh);}});
document.querySelectorAll('[title]').forEach(function(el){{if(el._origTitle===undefined)el._origTitle=el.title;el.title=translateText(el._origTitle);}});
}}else{{var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null,false);var n;while((n=w.nextNode())){{if(n._orig!==undefined){{n.textContent=n._orig;delete n._orig;}}}}
document.querySelectorAll('[placeholder]').forEach(function(el){{if(el._origPh!==undefined){{el.placeholder=el._origPh;delete el._origPh;}}}});
document.querySelectorAll('[title]').forEach(function(el){{if(el._origTitle!==undefined){{el.title=el._origTitle;delete el._origTitle;}}}});}}
var p=document.getElementById('btn-pl'),e=document.getElementById('btn-en');
if(p)p.className=!toEN?'lang-active':'';if(e)e.className=toEN?'lang-active':'';
document.documentElement.lang=lang;}};
window.setLang=function(lang){{localStorage.setItem('mcp_lang',lang);applyLang(lang);}};
var saved=localStorage.getItem('mcp_lang')||'pl';
if(saved==='en')applyLang('en');
}})();"""
    return _lang_js_cache


def _lang_bridge() -> str:
    """Auto-apply EN translation if saved in localStorage. For pages outside page_shell."""
    return """<script>
(function(){
  var saved = localStorage.getItem('mcp_lang');
  if(saved === 'en' && typeof window.applyLang === 'function') {
    applyLang('en');
  }
})();
</script>"""


def page_shell(active: str, body: str) -> str:
    user = _current_user.get()
    role = (user or {}).get("role", "admin")
    username = (user or {}).get("username", "")

    # Role-based tab visibility
    tabs_all = [
        ("dashboard",  "🏠  Dashboard",          "/",                "Przegląd stanu platformy — działające serwery, ostatnie operacje i logi", "read_only"),
        ("quickstart", "⚡  Szybki start",         "/quick-start",     "Utwórz gotowy serwer MCP w 2 krokach — bez pisania kodu",                "read_write"),
        ("create",     "🛠️  Kreator zaawansowany", "/create",          "Kreator krok po kroku z pełną kontrolą — wybór paczki, silnika, polityki","read_write"),
        ("runtimes",   "🖥️  Moje serwery",         "/runtimes",        "Lista wszystkich serwerów MCP — status, endpointy, zarządzanie",          "read_only"),
        ("external",   "🔗  Zewnętrzne MCP",       "/external-mcp",    "Rejestruj i monitoruj serwery MCP uruchomione poza platformą",            "read_only"),
        ("approvals",  "✅  Zatwierdzenia",          "/approvals",       "Oczekujące zatwierdzenia wywołań narzędzi write/destructive",              "read_write"),
        ("webhooks",   "🔔  Webhooki",              "/webhooks",        "Powiadomienia gdy serwer padnie lub tool zwróci błąd",                     "admin"),
        ("packages",   "🏗️  Build",                "/tool-packages",   "Buduj i wdrażaj serwery MCP — gotowe paczki + własne obrazy Docker",       "read_only"),
        ("adapters",   "⚙️  Silniki wykonania",    "/tool-types",      "Globalne typy egzekucji (http_request, shell…)",                          "admin"),
        ("classes",    "🏗️  Typy środowisk",       "/runtime-classes", "Docker images i klasy runtime — definiują jakie binarki są dostępne",     "admin"),
        ("images",     "🐳  Obrazy Docker",         "/runtime-images",  "Zbudowane obrazy kontenerów — historia buildów i zarządzanie",             "admin"),
        ("security",   "🔒  Bezpieczeństwo",       "/security",        "Przegląd polityk i hardening kontenerów",                                 "read_only"),
        ("audit",      "🔍  Audit",                "/audit",           "Historia wszystkich operacji — deploy, stop, reload, błędy",               "read_only"),
        ("logs",       "📋  Logi",                 "/logs",            "Logi runtimeów — informacje diagnostyczne i błędy kontenerów",            "read_only"),
        ("admin",      "👥  Użytkownicy",           "/admin/users",     "Zarządzanie użytkownikami — role, rejestracje, hasła",                    "admin"),
        ("docs",       "📖  Jak to działa?",       "/docs",            "Przewodnik po platformie dla użytkowników technicznych i nietech",         "read_only"),
    ]
    _role_order = {"read_only": 0, "read_write": 1, "admin": 2}
    user_level = _role_order.get(role, 2)
    tabs = [(k, l, h, d) for k, l, h, d, min_role in tabs_all if _role_order.get(min_role, 0) <= user_level]

    nav = "".join(
        f'<a class="{"active" if key == active else ""}" href="{href}" title="{desc}">{label}</a>'
        for key, label, href, desc in tabs
    )
    page_title, page_sub = next(((label.split("  ", 1)[-1].strip(), desc) for key, label, _, desc in tabs if key == active), ("MCP Platform", ""))

    role_badge_color = {"admin": "#c084fc", "read_write": "#5ce89a", "read_only": "#7a92a8"}
    role_bg = {"admin": "#2a1040", "read_write": "#0e2e1e", "read_only": "#1e252e"}
    user_bar = f"""
      <div style="display:flex;align-items:center;gap:10px">
        <span style="background:{role_bg.get(role,'#1e252e')};color:{role_badge_color.get(role,'#7a92a8')};
                     padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">
          {escape(role)}
        </span>
        <span style="color:#a0b8d0;font-size:13px">👤 {escape(username)}</span>
        <a href="/user/settings" style="color:var(--muted);font-size:12px" title="Zmień hasło">⚙️</a>
        <form method="post" action="/logout" style="display:inline">
          <button style="background:none;border:1px solid #34465b;color:#8ea2b8;padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer">Wyloguj</button>
        </form>
      </div>""" if username else ""

    return f"""
    <!doctype html>
    <html lang="pl"><head><title>{page_title} — MCP Platform</title>{_FAVICON_TAG}<style>{base_styles()}
.lang-btn{{display:flex;align-items:center;gap:2px;background:#0d1822;border:1px solid #1a3a50;border-radius:6px;overflow:hidden;flex-shrink:0}}
.lang-btn button{{border:none;padding:4px 9px;font-size:12px;font-weight:700;cursor:pointer;background:none;color:var(--muted);transition:.15s}}
.lang-btn button.lang-active{{background:#1a3a5a;color:white}}
</style></head><body>
    <div class="layout">
      <aside class="sidebar">
        <div class="brand">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px">
            <div class="brand-title">MCP Platform</div>
            <div class="lang-btn" title="Wybierz język / Select language">
              <button id="btn-pl" class="lang-active" onclick="setLang('pl')">PL</button>
              <button id="btn-en" onclick="setLang('en')">EN</button>
            </div>
          </div>
          <div class="brand-subtitle" data-i18n="brand_sub">Platforma MCP serverów</div>
        </div>
        <nav class="tabs">{nav}</nav>
      </aside>
      <div class="content">
        <header class="topbar">
          <div><h1>{page_title}</h1><div class="sub">{page_sub}</div></div>
          {user_bar}
        </header>
        <main>{"" if active not in _PAGE_DESCRIPTIONS else f'<div style="background:linear-gradient(90deg,#0d1a2a,#0a1520);border-left:3px solid var(--blue);border-radius:0 8px 8px 0;padding:10px 16px;margin-bottom:16px;display:flex;gap:12px;align-items:center"><div><div style="font-weight:700;color:white;font-size:13px">{_PAGE_DESCRIPTIONS[active][0]}</div><div style="color:var(--muted);font-size:12px;margin-top:2px;line-height:1.5">{_PAGE_DESCRIPTIONS[active][1]}</div></div></div>'}{body}</main>
      </div>
    </div>
<script>
(function(){{
  var PL = {{
    'aktywny':'aktywny','wyłączony':'wyłączony','działa':'działa','błąd':'błąd',
    'szkic':'szkic','deployowanie':'deployowanie','oczekuje':'oczekuje',
    'niski':'niski','średni':'średni','wysoki':'wysoki',
    'tylko odczyt':'tylko odczyt','odczyt-zapis':'odczyt-zapis',
    'brand_sub':'Platforma MCP serverów'
  }};
  var EN = {{
    'aktywny':'enabled','wyłączony':'disabled','działa':'running','błąd':'failed',
    'szkic':'draft','deployowanie':'deploying','oczekuje':'pending',
    'niski':'low','średni':'medium','wysoki':'high',
    'tylko odczyt':'read-only','odczyt-zapis':'read-write',
    'brand_sub':'MCP Server Platform'
  }};

  // Full PL→EN dictionary — sorted longest-first so longer phrases match before substrings
  var TRANS_RAW = [
    // ---- Page descriptions (long first) ----
    ['Historia wszystkich operacji na platformie — kto i kiedy uruchomił deploy, zmienił konfigurację, otworzył stronę serwera lub wywołał akcję. Przydatne do audytu dostępu.',
     'Full history of platform operations — who deployed, changed config, opened a server page or triggered an action. Useful for access auditing.'],
    ['Logi diagnostyczne kontenerów runtime — błędy startowania, komunikaty aplikacji, wyniki health checków. Pomocne przy debugowaniu problemów z serwerem.',
     'Runtime container diagnostic logs — startup errors, app messages, health check results. Helpful for debugging server issues.'],
    ['Przewodnik po platformie — architektura, przepływ danych, różnice między kreatorami, bezpieczeństwo kontenerów i FAQ dla użytkowników technicznych i nietech.',
     'Platform guide — architecture, data flow, creator differences, container security and FAQ for technical and non-technical users.'],
    ['Przegląd polityk bezpieczeństwa wszystkich serwerów i globalny hardening kontenerów. Każdy kontener działa jako user 1000, bez uprawnień root, z read-only filesystem.',
     'Security policy overview for all servers and global container hardening. Every container runs as user 1000, without root, with a read-only filesystem.'],
    ['Przegląd całej platformy — działające serwery, ostatnie operacje i logi błędów. Tu widzisz od razu co wymaga uwagi.',
     'Full platform overview — running servers, recent operations and error logs. See at a glance what needs attention.'],
    ['Rejestruj i monitoruj serwery MCP działające poza platformą — np. pobrane z GitHuba lub uruchomione ręcznie. Platforma sprawdza ich dostępność i wylistowuje tools.',
     'Register and monitor MCP servers running outside the platform — e.g. from GitHub or started manually. The platform checks availability and lists tools.'],
    ['Historia wszystkich zbudowanych obrazów kontenerów — status budowania, base image, data. Stąd możesz usuwać nieużywane lub nieudane buildy.',
     'History of all built container images — build status, base image, date. Delete unused or failed builds from here.'],
    ['Globalne typy egzekucji dostępne na platformie (http_request, shell, ssh…). Określają jak runtime wywołuje narzędzia. Możesz dodawać własne silniki z własnym obrazem Docker.',
     'Global execution types available on the platform (http_request, shell, ssh…). Define how the runtime calls tools. Add custom engines with your own Docker image.'],
    ['Katalog gotowych zestawów narzędzi. Każda paczka zawiera definicję tools, silnik wykonania i politykę — kliknij Stwórz MCP żeby uruchomić serwer jednym kliknięciem.',
     'Ready-made tool set catalog. Each package contains tool definitions, an execution engine and a policy — click Create MCP to launch a server in one click.'],
    ['5-krokowy kreator z pełną kontrolą — wybierz źródło tools, środowisko Docker, zdefiniuj narzędzie, ustaw politykę bezpieczeństwa i uruchom serwer.',
     '5-step creator with full control — choose tool source, Docker environment, define a tool, set security policy and launch the server.'],
    ['Lista wszystkich serwerów MCP na platformie — statusy, endpointy do podłączenia w AI oraz zarządzanie (deploy, stop, restart, logi).',
     'All MCP servers on the platform — statuses, endpoints for AI connection and management (deploy, stop, restart, logs).'],
    ['Zarządzanie kontami użytkowników — role, prośby o rejestrację, zmiana haseł.',
     'User account management — roles, registration requests, password changes.'],
    ['Typy środowisk określają bazowy obraz Docker i dostępne silniki egzekucji dla serwerów MCP.',
     'Environment types define the base Docker image and available execution engines for MCP servers.'],
    // ---- Medium phrases ----
    ['Jak podłączyć do klienta AI?','How to connect to an AI client?'],
    ['Serwer musi być w statusie','Server must have status'],
    ['Wywołaj tool bezpośrednio z przeglądarki.','Call a tool directly from the browser.'],
    ['Tworzy kopię z tymi samymi toolami, polityką i silnikami. Sekrety trzeba dodać osobno.',
     'Creates a copy with the same tools, policy and engines. Secrets must be added separately.'],
    ['Brak serwerów w tym filtrze.','No servers match this filter.'],
    ['Brak oczekujących próśb.','No pending requests.'],
    ['Brak logów — uruchom serwer i odśwież.','No logs — start the server and refresh.'],
    ['Brak wywołań — AI jeszcze nie używał tego serwera.','No calls — AI has not used this server yet.'],
    ['Brak historii.','No history.'],
    ['Brak zdefiniowanych narzędzi.','No tools defined.'],
    ['Hardening kontenerów (zawsze aktywne)','Container Hardening (always active)'],
    ['Sekrety i zmienne środowiskowe','Secrets & Environment Variables'],
    ['Historia wszystkich operacji — deploy, stop, reload, błędy','Full operation history — deploy, stop, reload, errors'],
    ['Historia operacji adminów','Admin operations history'],
    ['Wywołania narzędzi przez AI','AI tool invocations'],
    ['Wywołania AI','AI Calls'],
    ['ostatnich wywołań','recent calls'],
    ['Polityka bezpieczeństwa','Security Policy'],
    ['Logi kontenera','Container Logs'],
    ['Klonuj serwer','Clone server'],
    ['Testuj tool','Test tool'],
    ['Historia operacji','Operations History'],
    ['Narzędzia (Tools)','Tools'],
    ['Zarządzanie serwerem','Server Management'],
    ['Moje serwery MCP','My MCP Servers'],
    ['Katalog paczek tools','Tool Packages Catalog'],
    ['Silniki wykonania','Execution Engines'],
    ['Typy środowisk','Environment Types'],
    ['Szablony polityk','Policy Templates'],
    ['Działające silniki','Active engines'],
    ['Planowane silniki','Planned engines'],
    ['Przebuduj obraz + Deploy','Rebuild image + Deploy'],
    ['Sprawdź status','Check status'],
    ['Pobierz logi','Get logs'],
    ['Usuń serwer','Delete server'],
    ['Stwórz MCP','Create MCP'],
    ['Obrazy Docker','Docker Images'],
    ['Zbudowane obrazy','Built images'],
    ['Dodaj nowy silnik','Add new engine'],
    ['Wszystkie buildy','All builds'],
    ['Operacje adminów','Admin operations'],
    ['Nowa nazwa','New name'],
    ['Nowy serwer','New server'],
    ['Klonuj','Clone'],
    // ---- Single words / short ----
    ['Platforma MCP serverów','MCP Server Platform'],
    ['Szybki start','Quick Start'],
    ['Kreator zaawansowany','Advanced Creator'],
    ['Moje serwery','My Servers'],
    ['Zewnętrzne MCP','External MCP'],
    ['Paczki tools','Tool Packages'],
    ['Bezpieczeństwo','Security'],
    ['Jak to działa?','How it works?'],
    ['Użytkownicy','Users'],
    ['Działające','Running'],
    ['Z problemami','With issues'],
    ['Wyloguj','Logout'],
    ['Zapisz','Save'],
    ['Anuluj','Cancel'],
    ['Edytuj','Edit'],
    ['Włącz','Enable'],
    ['Wyłącz','Disable'],
    ['Generuj','Generate'],
    ['Zatrzymaj','Stop'],
    ['Uruchom','Start'],
    ['Utwórz','Create'],
    ['Dalej','Next'],
    ['Zbudowane','Built'],
    ['Nieudane','Failed'],
    ['Nazwa','Name'],
    ['Opis','Description'],
    ['Ryzyko','Risk'],
    ['Tryb','Mode'],
    ['Silnik','Engine'],
    ['Obraz','Image'],
    ['Kontener','Container'],
    ['Kategoria','Category'],
    ['Wersja','Version'],
    ['Czas','Time'],
    ['Aktor','Actor'],
    ['Akcja','Action'],
    ['Szczegóły','Details'],
    ['argumenty','arguments'],
    ['Serwer','Server'],
    ['Cel','Target'],
    ['Skopiowano','Copied'],
    ['aktywny','enabled'],['aktywna','enabled'],
    ['wyłączony','disabled'],['wyłączona','disabled'],
    ['działa','running'],['szkic','draft'],
    ['deployowanie','deploying'],['oczekuje','pending'],
    ['nieznany','unknown'],['brakujący','missing'],
    ['niski','low'],['średni','medium'],['wysoki','high'],
    ['tylko odczyt','read-only'],['odczyt-zapis','read-write'],
    ['enabled','enabled'],['disabled','disabled'],
    ['running','running'],['failed','failed'],
    // ---- Table / form labels ----
    ['wpisz fragment ID...','search by ID...'],
    ['wszystkie akcje','all actions'],
    ['wszyscy','all'],
    ['wszystkie','all'],
    ['Wyczyść filtry','Clear filters'],
    ['Wyczyść','Clear'],
    ['wpisów','entries'],
    ['wywołań','calls'],
    ['Pobierz logi','Fetch logs'],
    ['Odśwież logi','Refresh logs'],
    ['Run Tool','Run Tool'],
    ['Kliknij żeby skopiować','Click to copy'],
    // ---- Tabs (runtime detail) ----
    ['Podłącz','Connect'],
    ['Narzędzia','Tools'],
    ['Polityka','Policy'],
    ['Sekrety','Secrets'],
    ['Silniki','Engines'],
    ['Audit','Audit'],
    ['Test','Test'],
    // ---- Sidebar/page descriptions ----
    ['Przegląd stanu platformy — działające serwery, ostatnie operacje i logi',
     'Platform overview — running servers, recent operations and logs'],
    ['Utwórz gotowy serwer MCP w 2 krokach — bez pisania kodu',
     'Create a ready MCP server in 2 steps — no coding'],
    ['Kreator krok po kroku z pełną kontrolą — wybór paczki, silnika, polityki',
     'Step-by-step creator with full control — choose package, engine, policy'],
    ['Lista wszystkich serwerów MCP — status, endpointy, zarządzanie',
     'All MCP servers — status, endpoints, management'],
    ['Rejestruj i monitoruj serwery MCP uruchomione poza platformą',
     'Register and monitor MCP servers running outside the platform'],
    ['Powiadomienia gdy serwer padnie lub tool zwróci błąd',
     'Notifications when a server fails or a tool returns an error'],
    ['Buduj i wdrażaj serwery MCP — gotowe paczki + własne obrazy Docker',
     'Build and deploy MCP servers — ready packages + custom Docker images'],
    ['Globalne typy egzekucji (http_request, shell…)',
     'Global execution types (http_request, shell…)'],
    ['Docker images i klasy runtime — definiują jakie binarki są dostępne',
     'Docker images and runtime classes — define available binaries'],
    ['Zbudowane obrazy kontenerów — historia buildów i zarządzanie',
     'Built container images — build history and management'],
    ['Przegląd polityk i hardening kontenerów',
     'Policy overview and container hardening'],
    ['Historia wszystkich operacji — deploy, stop, reload, błędy',
     'Full operation history — deploy, stop, reload, errors'],
    ['Logi runtimeów — informacje diagnostyczne i błędy kontenerów',
     'Runtime logs — diagnostics and container errors'],
    ['Zarządzanie użytkownikami — role, rejestracje, hasła',
     'User management — roles, registrations, passwords'],
    ['Przewodnik po platformie dla użytkowników technicznych i nietech',
     'Platform guide for technical and non-technical users'],
    ['Szybki start','Quick Start'],
    ['Kreator zaawansowany','Advanced Creator'],
    ['Webhooki','Webhooks'],
    // ---- Quick Start page ----
    ['Co chcesz podłączyć do AI?','What do you want to connect to AI?'],
    ['Wybierz typ i wypełnij 2-3 pola — serwer uruchomi się automatycznie.','Choose a type and fill 2-3 fields — the server starts automatically.'],
    ['Chcesz uruchomić komendę shell (psql, oc, curl)? Skorzystaj z','Want to run a shell command (psql, oc, curl)? Use the'],
    ['Kreatora zaawansowanego','Advanced Creator'],
    ['tam możesz wybrać środowisko i zdefiniować narzędzia.','where you can choose an environment and define tools.'],
    ['Masz już działający serwer MCP? Podaj jego URL — platforma go zarejestruje i będzie monitorować','Already have a running MCP server? Enter its URL — the platform will register and monitor it'],
    ['Zewnętrzny MCP','External MCP'],
    ['Gotowy zestaw','Ready-made set'],
    ['Wybierz gotowy zestaw narzędzi z katalogu — tools, silnik i polityka konfigurują się automatycznie','Choose a ready-made tool set from the catalog — tools, engine and policy are configured automatically'],
    ['Importuj z pliku / Git / URL','Import from file / Git / URL'],
    ['Masz gotowy plik JSON konfiguracji MCP? Wklej go, podaj URL albo wgraj plik — serwer uruchomi się automatycznie','Have a ready MCP config JSON? Paste it, enter a URL or upload a file — the server starts automatically'],
    ['Utwórz gotowy serwer MCP w kilku krokach bez pisania kodu. Wybierz gotowy zestaw z katalogu lub zaimportuj konfigurację.',
     'Create a ready MCP server in a few steps without coding. Choose a ready-made set from the catalog or import a config.'],
    // ---- Advanced Creator ----
    ['Wybierz źródło tools','Choose tool source'],
    ['Zdefiniuj narzędzia','Define tools'],
    ['Zdefiniuj komendy które AI będzie wykonywać w kontenerze.','Define commands that AI will execute in the container.'],
    ['Ustawienia bezpieczeństwa','Security settings'],
    ['Podsumowanie i utwórz','Summary and create'],
    ['Źródło tools','Tool source'],
    ['Dalej →','Next →'],
    ['← Wróć','← Back'],
    ['Dalej → Bezpieczeństwo','Next → Security'],
    ['Dalej → Utwórz','Next → Create'],
    // ---- Runtime types ----
    ['REST API','REST API'],
    ['Wywołania HTTP do zewnętrznych API: GitLab, Jira, własny serwis','HTTP calls to external APIs: GitLab, Jira, custom services'],
    ['Shell / CLI','Shell / CLI'],
    ['Komendy: curl, oc, kubectl, dowolne CLI dostępne w kontenerze','Commands: curl, oc, kubectl, any CLI available in the container'],
    ['Shell + HTTP','Shell + HTTP'],
    ['Mieszane narzędzia — część shell, część REST API','Mixed tools — some shell, some REST API'],
    ['Od zera','From scratch'],
    ['Niedostępne dla roli read_write','Not available for read_write role'],
    // ---- Common UI elements ----
    ['Nazwa serwera','Server name'],
    ['Serwer MCP gotowy!','MCP Server ready!'],
    ['Za chwilę uruchomi się automatycznie. Gdy status zmieni się na','It will start automatically. When the status changes to'],
    ['skopiuj adres endpointu i wklej do Continue lub OpenWebUI.','copy the endpoint address and paste into Continue or OpenWebUI.'],
    ['Następny krok:','Next step:'],
    ['Znajdź pole','Find the field'],
    ['poniżej → skopiuj URL → wklej do konfiguracji AI jako','below → copy URL → paste into AI config as'],
    ['Powrót do dashboardu','Back to dashboard'],
    ['Kontener:','Container:'],
    ['Endpoint:','Endpoint:'],
    // ---- Policy ----
    ['Zapisz politykę shell','Save shell policy'],
    ['Dozwolone binarki','Allowed binaries'],
    ['Zablokowane tokeny','Blocked tokens'],
    ['Dozwolone prefixy (jeden/linię)','Allowed prefixes (one per line)'],
    ['Zablokowane prefixy (jeden/linię)','Blocked prefixes (one per line)'],
    ['Komendy zaczynające się od tych prefiksów będą zablokowane.','Commands starting with these prefixes will be blocked.'],
    ['Zostaw puste = brak ograniczeń na prefix.','Leave empty = no prefix restrictions.'],
    ['Wymusza żeby każdy tool miał mode: read-only.','Enforces that every tool has mode: read-only.'],
    // ---- Secrets/ENV ----
    ['Zmienne środowiskowe (ENV)','Environment Variables (ENV)'],
    ['Zmienne są wstrzykiwane do kontenera przy następnym deploy. Po zmianie kliknij','Variables are injected into the container on next deploy. After changes click'],
    ['Brak zmiennych ENV — dodaj poniżej.','No ENV variables — add below.'],
    ['Sekrety zaawansowane (pliki, mounty)','Advanced secrets (files, mounts)'],
    ['wpisów','entries'],
    ['Dodaj sekret','Add secret'],
    // ---- Tools ----
    ['Lista tools','Tool list'],
    ['Edytuj tool','Edit tool'],
    ['Usuń tool','Delete tool'],
    ['Zapisz tool','Save tool'],
    ['Dodaj tool','Add tool'],
    ['Dodaj narzędzie','Add tool'],
    // ---- Dashboard ----
    ['Serwery MCP','MCP Servers'],
    ['wszystkie środowiska','all environments'],
    ['Działające','Running'],
    ['Z problemami','With issues'],
    ['Historia operacji','Operations History'],
    ['Ostatnie logi','Recent Logs'],
    ['brak endpointu','no endpoint'],
    // ---- Docker Images ----
    ['Wszystkie obrazy','All images'],
    ['Zbudowane','Built'],
    ['Nieudane','Failed'],
    ['Obrazy Docker','Docker Images'],
    ['bazowy obraz platformy','platform base image'],
    ['wbudowany','built-in'],
    ['Data buildu','Build date'],
    ['Brak zbudowanych obrazów.','No built images.'],
    ['Zbuduj obraz','Build image'],
    ['Zbuduj własne środowisko','Build custom environment'],
    // ---- Validation ----
    ['Walidacja wartości parametrów (Pydantic)','Parameter Value Validation (Pydantic)'],
    ['Allow list = tylko te wartości przejdą','Allow list = only these values pass'],
    ['Block list = zabronione słowa','Block list = blocked words'],
    ['Pattern = regex','Pattern = regex'],
    ['blocked_commands z polityki','blocked_commands from policy'],
    // ---- Users ----
    ['Wszyscy użytkownicy','All users'],
    ['Brak uprawnień','No permissions'],
    ['Twoja rola','Your role'],
    ['nie pozwala na modyfikacje.','does not allow modifications.'],
    ['Zmień hasło','Change password'],
    ['Oczekujące prośby o rejestrację','Pending registration requests'],
    ['Zaakceptuj','Accept'],
    ['Odrzuć','Reject'],
    // ---- Misc ----
    ['Kliknij żeby skopiować','Click to copy'],
    ['Skopiowano','Copied'],
    ['Pobierz logi','Fetch logs'],
    ['Odśwież logi','Refresh logs'],
    ['Pełna historia','Full history'],
    ['Wszystkie logi','All logs'],
    ['Klasa runtime','Runtime class'],
    ['Błąd','Error'],
    ['Typ','Type'],
    ['Wartość','Value'],
    ['Akcja','Action'],
    ['Status','Status'],
    ['Czas','Time'],
    ['Wywołania narzędzi przez AI','AI tool invocations'],
    ['ostatnich wywołań','recent invocations'],
    ['Wywołaj tool przez platformę — serwer odpowie bezpośrednio.','Call a tool via the platform — the server responds directly.'],
    ['Wdróż serwer żeby móc testować narzędzia.','Deploy the server to test tools.'],
    ['Powiadomienia HTTP gdy serwer MCP padnie, health check się nie powiedzie lub tool zwróci błąd.','HTTP notifications when an MCP server fails, health check fails or a tool returns an error.'],
    ['Serwer już gdzieś działa? Zarejestruj jego endpoint — platforma odkryje tools i będzie go monitorować.','Server already running? Register its endpoint — the platform will discover tools and monitor it.'],
    ['Masz już działający serwer MCP?','Already have a running MCP server?'],
    ['Podaj jego URL — platforma go zarejestruje i będzie monitorować','Enter its URL — the platform will register and monitor it'],
    // ---- Alerts & confirmations ----
    ['Usunąć?','Delete?'],
    ['Usunąć tool','Delete tool'],
    ['Usunąć obraz','Delete image'],
    ['Usunąć zmienną','Delete variable'],
    ['Usunąć adapter?','Delete adapter?'],
    ['Usunąć serwer','Delete server'],
    ['Usunięto.','Deleted.'],
    ['Błąd:','Error:'],
    ['Błąd serwera:','Server error:'],
    ['Błąd połączenia:','Connection error:'],
    ['Błąd połączenia','Connection error'],
    ['Wykonuję operację...','Processing...'],
    ['Prośba odrzucona.','Request rejected.'],
    ['Hasła nie są zgodne','Passwords do not match'],
    ['Hasło zostało zmienione!','Password changed!'],
    ['Nazwa i URL są wymagane','Name and URL are required'],
    ['Masz już konto?','Already have an account?'],
    ['Brak toolów.','No tools.'],
    ['Wpisz komendę','Enter command'],
    ['wartość','value'],
    ['wartość / token / klucz','value / token / key'],
    // ---- Runtime detail extras ----
    ['Serwer działa!','Server is running!'],
    ['Pobierz zasób K8s','Get K8s resource'],
    ['Otwórz Politykę','Open Policy'],
    ['Wdrażanie:','Deploying:'],
    ['Idź na','Go to'],
    ['Masz już konto? Zaloguj się','Already have an account? Log in'],
    ['Brak uprawnień','No permissions'],
    ['nie pozwala na modyfikacje','does not allow modifications'],
    ['nie pozwala na definiowanie własnych poleceń shell','does not allow defining custom shell commands'],
    ['Skorzystaj z gotowego zestawu narzędzi','Use a ready-made tool set'],
    // ---- Security page ----
    ['ścisła','strict'],
    ['luźna','relaxed'],
    ['częściowa','partial'],
    ['Ścisła (produkcja)','Strict (production)'],
    // ---- Form labels ----
    ['Wartość parametru','Parameter value'],
    ['Wartość dla','Value for'],
    ['Szczegóły serwera MCP.','MCP server details.'],
    // ---- Quick start extras ----
    ['Masz gotowy serwer MCP? Zarejestruj endpoint i monitoruj','Have a running MCP server? Register its endpoint and monitor'],
    ['Standardowe','Standard'],
    ['Gotowe do użycia','Ready to use'],
    ['Własne środowisko','Custom environment'],
    ['Dodatkowe pakiety APT','Additional APT packages'],
    ['Dodatkowe pakiety pip','Additional pip packages'],
    ['Zbuduj własne środowisko','Build custom environment'],
    ['lub pomiń i użyj standardowego','or skip and use the standard one'],
    ['Budowanie obrazu Docker na bazie','Building Docker image from base'],
    ['może potrwać 2-5 minut','may take 2-5 minutes'],
    ['Środowisko zbudowane! Możesz teraz wpisać komendę.','Environment built! You can now enter a command.'],
    // ---- Webhooks ----
    ['Dodaj webhook','Add webhook'],
    ['Deploy gotowy','Deploy done'],
    // ---- Docs page ----
    ['Jak to działa?','How it works?'],
    ['Każdy kontener działa jako user 1000','Every container runs as user 1000'],
    ['Kontener jest rootless','Container is rootless'],
    // ---- External MCP ----
    ['Po zarejestrowaniu serwer pojawi się w zakładce','After registration the server will appear in'],
    ['platforma będzie sprawdzać jego dostępność i wylistuje dostępne tools','the platform will check availability and list available tools'],
    // ---- Image Builder ----
    ['Platforma buduje Docker image z Twoimi narzędziami','The platform builds a Docker image with your tools'],
    ['Możesz czekać lub wrócić później','You can wait or come back later'],
    ['Sprawdź nazwy paczek na','Check package names at'],
    // ---- Quick Start forms ----
    ['Zewnętrzny serwer MCP','External MCP Server'],
    ['Zewnętrzny MCP','External MCP'],
    ['Podaj adres istniejącego serwera MCP — platforma go zarejestruje, sprawdzi dostępność i zacznie monitorować.','Enter the address of an existing MCP server — the platform will register, check availability and start monitoring.'],
    ['Adres endpointu MCP','MCP endpoint address'],
    ['Pełny URL endpointu MCP','Full MCP endpoint URL'],
    ['Opis (opcjonalny)','Description (optional)'],
    ['Serwer MCP dla GitLab, pobrany z GitHub','MCP server for GitLab, downloaded from GitHub'],
    ['Wybierz gotowy zestaw narzędzi z katalogu — tools, silnik i polityka konfigurują się automatycznie',
     'Choose a ready-made tool set from the catalog — tools, engine and policy are configured automatically'],
    ['Masz gotowy plik JSON konfiguracji MCP? Wklej go, podaj URL albo wgraj plik — serwer uruchomi się automatycznie',
     'Have a ready MCP config JSON file? Paste it, provide a URL or upload a file — the server starts automatically'],
    ['Masz już działający serwer MCP? Podaj jego URL — platforma go zarejestruje i będzie monitorować',
     'Already have a running MCP server? Enter its URL — the platform will register and monitor it'],
    ['Chcesz uruchomić komendę shell (psql, oc, curl)? Skorzystaj z',
     'Want to run a shell command (psql, oc, curl)? Use the'],
    ['tam możesz wybrać środowisko i zdefiniować narzędzia.',
     'where you can choose an environment and define tools.'],
    ['Gotowy zestaw narzędzi','Ready-made tool set'],
    ['Masz gotowy serwer MCP? Zarejestruj endpoint i monitoruj',
     'Have a running MCP server? Register its endpoint and monitor'],
    ['Nazwa serwera','Server name'],
    ['Wklej JSON paczki','Paste package JSON'],
    ['URL do pliku JSON','URL to JSON file'],
    ['Wgraj plik JSON','Upload JSON file'],
    ['lub wklej JSON bezpośrednio','or paste JSON directly'],
    ['Zarejestruj i monitoruj','Register and monitor'],
    ['Utwórz serwer','Create server'],
    ['Zainstaluj i utwórz','Install and create'],
    ['Importuj i utwórz','Import and create'],
    // ---- Package descriptions ----
    ['Wybierz zestaw narzędzi — wszystko skonfiguruje się automatycznie.','Choose a tool set — everything configures automatically.'],
    ['Gotowy MCP runtime z toolami do RAGHybrid API.','Ready MCP runtime with tools for RAGHybrid API.'],
    ['Paczka gotowych read-only tooli OCP. Wymaga runtime image z binarką oc i kubeconfig/secret w runtime.','Ready-made read-only OCP tools. Requires runtime image with oc binary and kubeconfig/secret.'],
    ['Zarządzanie obiektami MinIO/S3 — listowanie bucketów, obiektów, statystyki, pobieranie plików. Wymaga mc (MinIO Client).','MinIO/S3 object management — listing buckets, objects, stats, downloading files. Requires mc (MinIO Client).'],
    ['Monitoring routera MikroTik przez REST API — interfejsy, DHCP, routing, firewall, logi, zasoby systemowe. RouterOS 7.1+.','MikroTik router monitoring via REST API — interfaces, DHCP, routing, firewall, logs, system resources. RouterOS 7.1+.'],
    ['Zapytania SELECT do Microsoft SQL Server przez sqlcmd. Read only — blokuje INSERT/UPDATE/DELETE/DROP.','SELECT queries to Microsoft SQL Server via sqlcmd. Read only — blocks INSERT/UPDATE/DELETE/DROP.'],
    ['Zapytania SQL do Trino (Presto) — catalogi, schematy, tabele, zapytania SELECT. Read only.','SQL queries to Trino (Presto) — catalogs, schemas, tables, SELECT queries. Read only.'],
    ['Zapytania SQL do Trino (Presto) — catalogi, schematy, tabele, zapytania SELECT. Tylko odczyt.','SQL queries to Trino (Presto) — catalogs, schemas, tables, SELECT queries. Read only.'],
    ['Przeglądanie repozytoriów Git — log, diff, status, branches, blame, show. Read only.','Git repository browsing — log, diff, status, branches, blame, show. Read only.'],
    ['Przeglądanie repozytoriów Git — log, diff, status, branches, blame, show. Tylko odczyt.','Git repository browsing — log, diff, status, branches, blame, show. Read only.'],
    ['Narzędzia do monitorowania klastra OpenShift — oc get, describe, logs, events, status, top. Tylko odczyt.','OpenShift cluster monitoring tools — oc get, describe, logs, events, status, top. Read only.'],
    ['Meta-MCP: AI tworzy i zarządza serwerami MCP na platformie. Czyta instrukcje, generuje paczki, deployuje — wszystko automatycznie.','Meta-MCP: AI creates and manages MCP servers on the platform. Reads instructions, generates packages, deploys — all automatically.'],
    // ---- User-created package descriptions ----
    ['Wykonaj dowolne oc get — AI podaje zasoby i flagi','Run any oc get — AI provides resources and flags'],
    ['Wykonaj dowolna komende curl','Run any curl command'],
    ['Wykonaj dowolną komendę curl','Run any curl command'],
    ['Server MCP psql — dostęp do bazy PostgreSQL przez psql','MCP server psql — PostgreSQL database access via psql'],
    ['Serwer MCP psql — dostęp do bazy PostgreSQL przez psql','MCP server psql — PostgreSQL database access via psql'],
    ['Server MCP —','MCP Server —'],
    ['Serwer MCP —','MCP Server —'],
    ['Meta-MCP: AI tworzy i zarządza serwerami MCP na platformie. Czyta instrukcje, generuje paczki, deployuje — wszystko auto','Meta-MCP: AI creates and manages MCP servers. Reads instructions, generates packages, deploys — all auto'],
    ['Monitorowanie routera MikroTik na adresie','MikroTik router monitoring at address'],
    ['z loginem','with login'],
    ['i hasłem','and password'],
    ['Pełne zarządzanie klastrem OCP — wdrażanie, skalowanie, monitorowanie, zarządzanie aplikacjami. Wymaga SA z rolą admin.','Full OCP cluster management — deploy, scale, monitor, manage apps. Requires SA with admin role.'],
    ['Name Twojego serwera MCP','Your MCP server name'],
    ['Nazwa Twojego serwera MCP','Your MCP server name'],
    // ---- Auth & permissions ----
    ['Ta funkcja jest dostępna tylko dla administratorów.','This feature is available to administrators only.'],
    ['Panel administratora jest dostępny tylko dla adminów.','Admin panel is available to admins only.'],
    ['Tylko admin może usuwać obrazy','Only admin can delete images'],
    ['Usuwanie obrazów dostępne tylko dla admina','Image deletion available to admin only'],
    ['Usuwanie dostępne tylko dla admina','Deletion available to admin only'],
    // ---- Confirmations & dialogs ----
    ['Trwale usunąć ten serwer MCP?','Permanently delete this MCP server?'],
    ['Trwale usunąć ten serwer MCP i jego kontener?','Permanently delete this MCP server and its container?'],
    ['Przebuduje obraz Docker i zrestartuje serwer. Może potrwać kilka minut. Kontynuować?','Rebuild Docker image and restart server. May take a few minutes. Continue?'],
    ['Przebudowanie obrazu zlecone. Może potrwać kilka minut.','Image rebuild queued. May take a few minutes.'],
    ['Przeładowuję konfigurację...','Reloading configuration...'],
    ['Pobieranie logów z kontenera...','Fetching container logs...'],
    ['Usunąć ten szablon?','Delete this template?'],
    // ---- Status messages ----
    ['Brak parametrów — dodaj w Input Schema JSON wyżej.','No parameters — add in Input Schema JSON above.'],
    ['Brak webhoków.','No webhooks.'],
    ['Brak ograniczeń','No restrictions'],
    ['brak ograniczeń','no restrictions'],
    ['własny (wcześniej zbudowany)','custom (previously built)'],
    ['własny zbudowany','custom built'],
    ['więcej...','more...'],
    ['Zapisano — odświeżam...','Saved — refreshing...'],
    ['Wykonuję...','Processing...'],
    ['Działa!','Works!'],
    // ---- Image Builder ----
    ['musi zawierać serwer MCP (zbudowany na bazie mcp-runtime-shell lub http-gateway)','must contain MCP server (built on mcp-runtime-shell or http-gateway base)'],
    ['Spróbuj ponownie','Try again'],
    ['Budowanie nie powiodło się','Build failed'],
    ['Popraw i spróbuj ponownie','Fix and try again'],
    ['Timeout — odśwież stronę i sprawdź Runtime Image Builds.','Timeout — refresh and check Runtime Image Builds.'],
    // ---- Creator hints & placeholders ----
    ['Pełny dostęp do kubectl — ustaw denylist w kroku bezpieczeństwa!','Full kubectl access — set denylist in the security step!'],
    ['Określ dokładnie co AI może robić.','Specify exactly what AI can do.'],
    ['Szczególnie ważne przy pełnym dostępie','Especially important with full access'],
    ['Mój asystent OC','My OC Assistant'],
    ['Mój asystent API','My API Assistant'],
    ['Mój serwer MCP','My MCP Server'],
    ['Podaj adresy API które AI ma wywoływać.','Enter API addresses that AI should call.'],
    ['Czysty Python — dodaj curl w APT jeśli potrzebny','Pure Python — add curl in APT if needed'],
    ['Narzędzie','Tool'],
    ['Dowolna nazwa — pojawi się w Continue i OpenWebUI','Any name — will appear in Continue and OpenWebUI'],
    ['domyślnie: maksymalne','default: maximum'],
    ['opcjonalne — tokeny, klucze API, hasła','optional — tokens, API keys, passwords'],
    ['Stwórz i uruchom serwer MCP','Create and launch MCP server'],
    ['Platforma automatycznie skonfiguruje i uruchomi serwer. Zajmie to kilka sekund.','The platform will configure and launch the server. Takes a few seconds.'],
    ['Zawiera: oc, kubectl, curl, jq','Contains: oc, kubectl, curl, jq'],
    // ---- Policy descriptions ----
    ['Blokuje operacje destruktywne, ale pozwala na zapis.','Blocks destructive operations but allows writes.'],
    ['Przydatna dla serwerów zarządzających danymi','Useful for data management servers'],
    ['Brak ograniczeń policy — tylko dla testów lokalnych. NIGDY nie używaj na produkcji.','No policy restrictions — for local testing only. NEVER use in production.'],
    // ---- Tool descriptions (OpenShift) ----
    ['Pełna treść YAML zasobu Kubernetes/OpenShift','Full YAML content of Kubernetes/OpenShift resource'],
    ['Wyświetla dostępne projekty/namespace','Lists available projects/namespaces'],
    ['Aplikuje zasoby na klaster','Applies resources to the cluster'],
    ['Tworzy zasób przez CLI','Creates resource via CLI'],
    ['Tworzy zasoby z inline YAML na klastrze OpenShift','Creates resources from inline YAML on OpenShift cluster'],
    ['Usuwa zasób z klastra OpenShift. UWAGA: operacja nieodwracalna!','Deletes from OpenShift. WARNING: irreversible!'],
    ['Wykonuje komendę wewnątrz poda OpenShift.','Executes command inside an OpenShift pod.'],
    ['Patchuje zasób — zmienia pojedyncze pola bez zastępowania całego obiektu.','Patches resource — changes fields without replacing the whole object.'],
    ['Zarządza rolloutami — restart, status, history, undo.','Manages rollouts — restart, status, history, undo.'],
    ['Skaluje deployment/statefulset — zmienia liczbę replik.','Scales deployment/statefulset — changes replica count.'],
    ['Tworzy nową aplikację na klastrze','Creates a new application on the cluster'],
    ['Tworzy route/expose dla serwisu','Creates route/expose for a service'],
    ['Ustawia właściwości zasobów — env vars, image, resources, volumes.','Sets resource properties — env vars, image, resources, volumes.'],
    ['Pobiera listę podów w podanym namespace','Lists pods in the given namespace'],
    ['GŁÓWNE NARZĘDZIE do wdrażania zasobów','MAIN TOOL for deploying resources'],
    // ---- Platform Manager tool descs ----
    ['Pobiera instrukcję jak tworzyć serwery MCP.','Retrieves instructions on how to create MCP servers.'],
    ['ZAWSZE wywołaj PRZED tworzeniem serwera.','ALWAYS call BEFORE creating a server.'],
    ['Tworzy nowy serwer MCP.','Creates a new MCP server.'],
    ['NAJPIERW wywołaj get_instructions.','FIRST call get_instructions.'],
    ['Lista serwerów MCP — nazwy, statusy, endpointy.','MCP servers — names, statuses, endpoints.'],
    ['Lista gotowych paczek narzędzi.','List of ready-made tool packages.'],
    ['Szczegóły konkretnego serwera MCP.','Details of a specific MCP server.'],
    ['Deployuje (uruchamia) serwer MCP.','Deploys (starts) an MCP server.'],
    ['Zatrzymuje serwer MCP.','Stops an MCP server.'],
    // ---- Form fields ----
    ['Litery, cyfry, kropki, myślniki','Letters, numbers, dots, dashes'],
    ['min. 6 znaków','min. 6 characters'],
    ['aktywowane z rolą','activated with role'],
    ['Krótki opis zastosowania','Short description of use'],
    ['Wpisz nazwę szablonu','Enter template name'],
    ['Nieprawidłowa nazwa zmiennej','Invalid variable name'],
    ['Nieprawidłowy JSON argumentów','Invalid arguments JSON'],
    ['Sprawdź połączenie z serwerem MCP.','Check connection to MCP server.'],
    // ---- Tool actions ----
    ['Wywołaj','Call'],
    ['Wykonaj komendę','Execute command'],
    ['Wykonaj komendę:','Execute command:'],
    ['wykonaj komendę oc get','run oc get command'],
    ['wywołaj to API','call this API'],
    ['znajdź umowy z 2024','find contracts from 2024'],
    ['Tool dodany — sprawdź politykę','Tool added — check policy'],
    ['Dodałeś','You added'],
    ['Upewnij się że binarka jest w','Make sure the binary is in'],
    ['inaczej tool będzie blokowany przez policy','otherwise tool will be blocked by policy'],
    ['Sprawdź URL i metodę w konfiguracji.','Check URL and method in config.'],
    ['uruchom serwer żeby zobaczyć endpoint','start the server to see the endpoint'],
    // ---- Runtime classes / adapters ----
    ['Zaktualizowano typ środowiska','Environment type updated'],
    ['już istnieje','already exists'],
    ['Ten typ toola jest tylko zaplanowany.','This tool type is only planned.'],
    ['Nie ma jeszcze zaimplementowanego pluginu runtime','No runtime plugin implemented yet'],
    ['Planowany adapter Python — izolowany sandbox do skryptów Python.','Planned Python adapter — isolated sandbox for Python scripts.'],
    ['Planowany adapter workflow — łączenie wielu toolów w sekwencje.','Planned workflow adapter — chaining multiple tools in sequences.'],
    ['Twój kreator','Your creator'],
    ['Inny — wpisz ręcznie (zaawansowane)','Other — enter manually (advanced)'],
    ['Zarządzanie kontami — zatwierdzanie rejestracji, zmiana ról','Account management — approving registrations, changing roles'],
    ['włączanie i wyłączanie kont','enabling and disabling accounts'],
    ['Wybierz język / Select language','Select language'],
    // ---- Advanced Creator step 3 (Tool) ----
    ['Zdefiniuj komendy które AI będzie wykonywać w kontenerze.','Define commands that AI will execute in the container.'],
    ['Narzędzie 1','Tool 1'],['Narzędzie 2','Tool 2'],['Narzędzie 3','Tool 3'],['Narzędzie 4','Tool 4'],['Narzędzie 5','Tool 5'],
    ['Komenda','Command'],
    ['Wzorce:','Patterns:'],
    ['= jeden parametr','= single parameter'],
    ['= AI podaje wszystkie argumenty naraz','= AI provides all arguments at once'],
    ['Nazwa','Name'],
    ['Opis (dla AI)','Description (for AI)'],
    ['Pobiera dane / wykonuje komendę','Fetches data / executes command'],
    ['zmienna','variable'],
    ['jeden parametr','single parameter'],
    ['wiele argumentów (pełny dostęp)','multiple arguments (full access)'],
    ['Presety:','Presets:'],
    ['Dodaj kolejne narzędzie','Add another tool'],
    ['+ Dodaj kolejne narzędzie','+ Add another tool'],
    ['Dalej → Bezpieczeństwo','Next → Security'],
    ['Nazwa narzędzia','Tool name'],
    ['Typ','Type'],
    ['shell — komenda CLI','shell — CLI command'],
    ['http_request — REST API','http_request — REST API'],
    ['Opis (wyświetlany AI)','Description (shown to AI)'],
    ['Pobiera listę podów w podanym namespace','Lists pods in the given namespace'],
    ['Metoda','Method'],
    ['Body template JSON','Body template JSON'],
    ['Parametry (input schema):','Parameters (input schema):'],
    ['+ Dodaj parametr','+ Add parameter'],
    // ---- Advanced Creator step 4 (Security) ----
    ['Pełna kontrola nad tym co serwer może robić. Domyślnie — maksymalna ochrona.','Full control over what the server can do. Default — maximum protection.'],
    ['Tryb dostępu','Access mode'],
    ['Tylko odczyt','Read only'],
    ['Serwer może tylko czytać dane — nie modyfikuje ani nie usuwa niczego','Server can only read data — does not modify or delete anything'],
    ['Blokuj zapis','Block writes'],
    ['Blokuje narzędzia w trybie','Blocks tools in mode'],
    ['zapis do baz, API PUT/POST/DELETE','database writes, API PUT/POST/DELETE'],
    ['Blokuj destruktywne','Block destructive'],
    ['Zapobiega usuwaniu danych i operacjom nieodwracalnym','Prevents data deletion and irreversible operations'],
    ['Limity','Limits'],
    ['Timeout (sekundy)','Timeout (seconds)'],
    ['Max payload (bajty)','Max payload (bytes)'],
    ['Max odpowiedź (bajty)','Max response (bytes)'],
    ['Dozwolone binarki (spacja)','Allowed binaries (space separated)'],
    ['np.','e.g.'],
    ['Zablokowane komendy (spacja)','Blocked commands (space separated)'],
    ['Dozwolone prefixy komend','Allowed command prefixes'],
    ['Zablokowane prefixy komend','Blocked command prefixes'],
    ['Dalej → Utwórz','Next → Create'],
    // ---- Advanced Creator step 5 (Create) ----
    ['Podsumowanie','Summary'],
    ['Sprawdź konfigurację i utwórz serwer.','Review configuration and create the server.'],
    ['Utwórz serwer MCP','Create MCP server'],
    ['Tworzenie...','Creating...'],
    // ---- Creator step 4 details ----
    ['Maks. odpowiedź (KB)','Max response (KB)'],
    ['Maks. payload (KB)','Max payload (KB)'],
    ['Max czas wykonania komendy','Max command execution time'],
    ['Max rozmiar danych zwracanych AI','Max data size returned to AI'],
    ['Max rozmiar danych od AI','Max data size from AI'],
    ['KONTROLA KOMEND','COMMAND CONTROL'],
    ['Kontrola komend','Command control'],
    ['dla shell tools','for shell tools'],
    // ---- Runtime detail page (Connect tab) ----
    ['wklej poniższy URL','paste the URL below'],
    ['OpenWebUI automatycznie doda','OpenWebUI will automatically add'],
    ['Albo importuj jako Python tool (Workspace → Narzędzia → Importuj z linku):','Or import as Python tool (Workspace → Tools → Import from link):'],
    ['Albo importuj jako Python tool','Or import as Python tool'],
    ['Importuj z linku','Import from link'],
    ['Pobierz .py','Download .py'],
    ['zalecane','recommended'],
    ['Continue, Cline, Claude Code, Claude Desktop, OpenChamber i inne klienty MCP','Continue, Cline, Claude Code, Claude Desktop, OpenChamber and other MCP clients'],
    ['Starsze klienty lub gdy streamable-http nie działa','Older clients or when streamable-http does not work'],
    ['Pełny przykład .continue/config.json','Full example .continue/config.json'],
    // ---- Runtime detail page ----
    ['Powrót do dashboardu','Back to dashboard'],
    ['Zarządzanie serwerem','Server management'],
    ['Kontener:','Container:'],
    ['Endpoint:','Endpoint:'],
    ['Jak podłączyć do klienta AI?','How to connect to an AI client?'],
    ['uruchom serwer żeby zobaczyć endpoint','start the server to see the endpoint'],
    ['Endpoint pojawi się po uruchomieniu','Endpoint will appear after starting'],
    ['Kliknij','Click'],
    ['status zmieni się na','status will change to'],
    ['tutaj pojawi się config dla Continue i OpenWebUI','config for Continue and OpenWebUI will appear here'],
    ['Podłącz','Connect'],
    ['Narzędzia','Tools'],
    ['Polityka','Policy'],
    ['Sekrety','Secrets'],
    ['Silniki','Engines'],
    ['Wywołania','Invocations'],
    ['Klonuj','Clone'],
    ['Sprawdź status','Check status'],
    ['Pobierz logi','Fetch logs'],
    ['Przebuduj obraz + Deploy','Rebuild image + Deploy'],
    ['Zatrzymaj','Stop'],
    ['Uruchom','Start'],
    ['Usuń','Delete'],
    ['dla shell tools','for shell tools'],
    ['Spacja — tylko te binarki mogą być uruchamiane. Puste = no restrictions.','Space separated — only these binaries can run. Empty = no restrictions.'],
    ['Spacja — tylko te binarki mogą być uruchamiane. Puste = brak ograniczeń.','Space separated — only these binaries can run. Empty = no restrictions.'],
    ['brak ograniczeń','no restrictions'],
    ['Dozwolony prefix komendy','Allowed command prefix'],
    ['AI może wywołać tylko komendy zaczynające się od tego prefiksu.','AI can only call commands starting with this prefix.'],
    ['nie może','cannot'],
    ['Zablokowane komendy (denylist)','Blocked commands (denylist)'],
    ['Jedna komenda na linię. Każda komenda','One command per line. Every command'],
    ['zaczynająca się','starting with'],
    ['od tego prefiksu zostanie zablokowana.','this prefix will be blocked.'],
    ['tokeny, klucze API, hasła','tokens, API keys, passwords'],
    ['Variables ENV są dostępne wewnątrz kontenera jako zmienne środowiskowe. Użyj ich dla tokenów API, kluczy SSH, URL baz danych — allgo co nie powinno być w kodzie.','ENV variables are available inside the container as environment variables. Use them for API tokens, SSH keys, database URLs — anything that should not be in code.'],
    ['Variables ENV są dostępne wewnątrz kontenera jako zmienne środowiskowe.','ENV variables are available inside the container as environment variables.'],
    ['Użyj ich dla tokenów API, kluczy SSH, URL baz danych','Use them for API tokens, SSH keys, database URLs'],
    ['allgo co nie powinno być w kodzie','anything that should not be in code'],
    ['wszystko co nie powinno być w kodzie','anything that should not be in code'],
    ['wszystkiego co nie powinno być w kodzie','anything that should not be in code'],
    ['Zmienne ENV są dostępne wewnątrz kontenera jako zmienne środowiskowe. Użyj ich dla tokenów API, kluczy SSH, URL baz danych — wszystkiego co nie powinno być w kodzie.','ENV variables are available inside the container as environment variables. Use them for API tokens, SSH keys, database URLs — anything that should not be in code.'],
    ['Add zmienną ENV','Add ENV variable'],
    ['+ Add zmienną ENV','+ Add ENV variable'],
    ['+ Dodaj zmienną ENV','+ Add ENV variable'],
    ['Dodaj zmienną ENV','Add ENV variable'],
    ['zmienną ENV','ENV variable'],
    ['Nazwa zmiennej','Variable name'],
    ['NAZWA_ZMIENNEJ','VARIABLE_NAME'],
    ['Np.','E.g.'],
    ['tylko te binarki mogą być uruchamiane','only these binaries can run'],
    ['Puste = no restrictions','Empty = no restrictions'],
    ['mogą być uruchamiane','can be run'],
    // ---- Container hardening ----
    ['Zawsze aktywne (nie można wyłączyć):','Always active (cannot be disabled):'],
    ['Zawsze aktywne','Always active'],
    ['nie można wyłączyć','cannot be disabled'],
    ['bez roota','no root'],
    // ---- Creator step 5 (Create/Summary) ----
    ['Done do utworzenia','Ready to create'],
    ['Gotowe do utworzenia','Ready to create'],
    ['Sprawdź podsumowanie i kliknij Create MCP server.','Review the summary and click Create MCP server.'],
    ['Sprawdź podsumowanie i kliknij','Review the summary and click'],
    ['Serwer:','Server:'],
    ['Silnik:','Engine:'],
    ['Środowisko:','Environment:'],
    ['Tylko odczyt:','Read only:'],
    ['Blokuj zapis:','Block writes:'],
    ['Blokuj destruktywne:','Block destructive:'],
    ['Start od razu po utworzeniu','Start immediately after creation'],
    ['Uruchom od razu po utworzeniu','Start immediately after creation'],
    ['od razu po utworzeniu','immediately after creation'],
    ['Server zostanie automatycznie zdeplojowany — będzie running za kilka sekund','Server will be automatically deployed — will be running in a few seconds'],
    ['Server zostanie automatycznie zdeplojowany — będzie działać za kilka sekund','Server will be automatically deployed — will be running in a few seconds'],
    ['Serwer zostanie automatycznie zdeplojowany — będzie działać za kilka sekund','Server will be automatically deployed — will be running in a few seconds'],
    ['zdeplojowany','deployed'],
    ['zostanie automatycznie','will be automatically'],
    ['za kilka sekund','in a few seconds'],
    ['będzie działać','will be running'],
    ['Możesz edytować tools i politykę po utworzeniu na stronie serwera.','You can edit tools and policy after creation on the server page.'],
    ['Możesz edytować tools i politykę po utworzeniu','You can edit tools and policy after creation'],
    ['na stronie serwera','on the server page'],
    ['po utworzeniu','after creation'],
    // ---- Dynamic JS content ----
    ['Narzędzia są już zdefiniowane w wybranej paczce — przejdź dalej.','Tools are already defined in the selected package — proceed.'],
    ['Dodaj jedno lub więcej narzędzi — AI użyje ich definicji do wywołań.','Add one or more tools — AI will use their definitions for calls.'],
    ['Pobiera dane / wykonuje komendę','Fetches data / executes command'],
    ['GET na URL','GET to URL'],
    ['Dowolna komenda curl','Any curl command'],
    ['Logi z poda OC','OC pod logs'],
    ['Wykonaj dowolne oc get','Run any oc get'],
    ['Wykonaj dowolne kubectl get','Run any kubectl get'],
    // ---- Audit: missing visible strings ----
    ['Typy środowisk określają jaki obraz Docker jest uruchamiany dla danego serwera i jakie silniki są dozwolone. Nowe typy tworzy Runtime Image Builder automatycznie.','Environment types define which Docker image is launched for a given server and which engines are allowed. New types are created automatically by Runtime Image Builder.'],
    ['Powiadomienia HTTP gdy serwer MCP padnie, health check się nie powiedzie lub tool zwróci błąd. Integracja ze Slackiem, Teams, Discordem lub własnym systemem.','HTTP notifications when an MCP server fails, a health check fails or a tool returns an error. Integration with Slack, Teams, Discord or your own system.'],
    ['Wbudowane szablony + serwery z Kreatora zaawansowanego. Wdróż jednym kliknięciem lub zbuduj własny obraz Docker z dowolnymi narzędziami.','Built-in templates + servers from the Advanced Creator. Deploy with one click or build a custom Docker image with any tools.'],
    ['Zarządzanie kontami — zatwierdzanie rejestracji, zmiana ról (read_only / read_write / admin), włączanie i wyłączanie kont.','Account management — approving registrations, changing roles (read_only / read_write / admin), enabling and disabling accounts.'],
    ['GŁÓWNE NARZĘDZIE do wdrażania zasobów. Przyjmuje treść YAML inline w yaml_content i aplikuje na klaster (Deployment, Service, Route, ConfigMap itp.).','MAIN TOOL for deploying resources. Takes inline YAML content in yaml_content and applies it to the cluster (Deployment, Service, Route, ConfigMap, etc.).'],
    ['Tworzy nowy serwer MCP. Przyjmuje JSON z package, name, credentials. NAJPIERW wywołaj get_instructions.','Creates a new MCP server. Takes JSON with package, name, credentials. FIRST call get_instructions.'],
    ['Pobiera instrukcję jak tworzyć serwery MCP. ZAWSZE wywołaj PRZED tworzeniem serwera.','Retrieves instructions on how to create MCP servers. ALWAYS call BEFORE creating a server.'],
    ['Tworzy nową aplikację na klastrze — deployment, service i inne zasoby z jednej komendy.','Creates a new application on the cluster — deployment, service and other resources from one command.'],
    ['Tworzy zasoby z inline YAML na klastrze OpenShift. Podaj treść YAML w yaml_content.','Creates resources from inline YAML on the OpenShift cluster. Provide YAML content in yaml_content.'],
    ['Aplikuje zasoby na klaster (flagi CLI, NIE pliki). Dla YAML użyj oc_apply_yaml.','Applies resources to the cluster (CLI flags, NOT files). For YAML use oc_apply_yaml.'],
    ['Tworzy zasób przez CLI (NIE pliki). Dla YAML użyj oc_create_yaml.','Creates a resource via CLI (NOT files). For YAML use oc_create_yaml.'],
    ['Tworzy route/expose dla serwisu — udostępnia aplikację na zewnątrz.','Creates a route/expose for a service — exposes the application externally.'],
    ['Planowany adapter OpenShift/Kubernetes — tylko odczyt zasobów klastra.','Planned OpenShift/Kubernetes adapter — read-only cluster resources.'],
    ['Adapter HTTP — wywołuje zewnętrzne REST API.','HTTP adapter — calls external REST APIs.'],
    ['Wyświetla dostępne projekty/namespacey na klastrze.','Lists available projects/namespaces on the cluster.'],
    ['Gdy AI chce np. pobrać dane z API, wysyła zapytanie do endpointu MCP. Kontener wykonuje operację i zwraca wynik. AI widzi tylko wynik — nic więcej.','When AI wants e.g. to fetch data from an API, it sends a request to the MCP endpoint. The container performs the operation and returns the result. AI sees only the result — nothing more.'],
    ['Dodatkowe flagi sprawdzane przez runtime przed wykonaniem narzędzia. Można blokować klasy operacji bez edytowania każdego toola osobno.','Extra flags checked by the runtime before executing a tool. You can block classes of operations without editing each tool separately.'],
    ['Maksymalna ochrona — tylko odczyt, blokada zapisu i destruktywnych operacji. Zalecana dla wszystkich serwerów produkcyjnych.','Maximum protection — read-only, write and destructive operations blocked. Recommended for all production servers.'],
    ['Blokuje operacje destruktywne, ale pozwala na zapis. Przydatna dla serwerów zarządzających danymi (np. tworzenie ticketów).','Blocks destructive operations but allows writes. Useful for data management servers (e.g. creating tickets).'],
    ['Allow list = tylko te wartości przejdą | Block list = zabronione słowa | Pattern = regex | + blocked_commands z polityki','Allow list = only these values pass | Block list = blocked words | Pattern = regex | + blocked_commands from policy'],
    ['z gotowymi snippetami dla Continue, OpenWebUI i innych klientów. Każdy snippet jest klikalny — kopiuje się do schowka.','with ready snippets for Continue, OpenWebUI and other clients. Each snippet is clickable — it copies to the clipboard.'],
    ['Ten typ toola jest tylko zaplanowany. Nie ma jeszcze zaimplementowanego pluginu runtime, więc nie można go włączyć.','This tool type is only planned. No runtime plugin is implemented yet, so it cannot be enabled.'],
    ['Wklej JSON, podaj URL (GitHub raw, własny serwer) lub wgraj plik — platforma zainstaluje paczkę i uruchomi serwer.','Paste JSON, provide a URL (GitHub raw, own server) or upload a file — the platform will install the package and start the server.'],
    ['Wklej JSON paczki albo podaj URL. Paczka może wskazać własny runtime image z zainstalowanymi narzędziami.','Paste the package JSON or provide a URL. A package can point to its own runtime image with installed tools.'],
    ['Zbuduj custom obraz z narzędziami których nie ma w bazowych obrazach (terraform, awscli, własne binarki).','Build a custom image with tools not in the base images (terraform, awscli, custom binaries).'],
    ['Wbudowane szablony + serwery z Kreatora. Wdróż jednym kliknięciem lub zbuduj własny obraz Docker.','Built-in templates + servers from the Creator. Deploy with one click or build a custom Docker image.'],
    ['Potrzebujesz psql, terraform, awscli lub innych? Platforma zbuduje obraz z tymi narzędziami.','Need psql, terraform, awscli or others? The platform will build an image with these tools.'],
    ['Gotowe konfiguracje — zastosuj do dowolnego serwera przyciskiem w tabeli polityk powyżej.','Ready configurations — apply to any server with the button in the policy table above.'],
    ['Zmienne są wstrzykiwane do kontenera. Użyj dla tokenów API, kluczy SSH, URL baz danych.','Variables are injected into the container. Use for API tokens, SSH keys, database URLs.'],
    ['Każdy tool to jedna komenda lub endpoint. AI może wywoływać każdy z nich niezależnie.','Each tool is one command or endpoint. AI can call each of them independently.'],
    ['Platforma buduje Docker image z Twoimi narzędziami. Możesz czekać lub wrócić później.','The platform builds a Docker image with your tools. You can wait or come back later.'],
    ['Brak uprawnień: tworzenie serwera od zera wymaga roli admin. Wybierz gotową paczkę.','No permissions: creating a server from scratch requires the admin role. Choose a ready package.'],
    ['Obraz musi być zbudowany przez Runtime Image Builder lub dostępny lokalnie w Docker','The image must be built by Runtime Image Builder or available locally in Docker'],
    ['Prośba wysłana! Administrator otrzyma powiadomienie i wkrótce aktywuje Twoje konto.','Request sent! The administrator will be notified and will activate your account soon.'],
    ['Wybierz środowisko — określa co jest dostępne w kontenerze gdy AI wywołuje komendę.','Choose an environment — it determines what is available in the container when AI runs a command.'],
    ['Mam repo GitHub z gotowym serwerem MCP w C# / Node.js — czy mogę go zaimportować?','I have a GitHub repo with a ready MCP server in C# / Node.js — can I import it?'],
    ['Określ co AI może, a czego nie może robić. Domyślnie maksymalna ochrona.','Specify what AI can and cannot do. Maximum protection by default.'],
    ['Serwer może tylko czytać dane — nie może niczego modyfikować ani usuwać','The server can only read data — it cannot modify or delete anything'],
    ['Tylko te obrazy mają wbudowany serwer MCP — inne bazy nie będą działać.','Only these images have a built-in MCP server — other bases will not work.'],
    ['Brak uprawnień: definiowanie własnych poleceń shell wymaga roli admin.','No permissions: defining custom shell commands requires the admin role.'],
    ['Komendy zaczynające się od tych prefiksów będą odrzucane przez runtime','Commands starting with these prefixes will be rejected by the runtime'],
    ['Wybór określa jakiego obrazu Docker użyjemy i jak tools będą działać.','The choice determines which Docker image is used and how tools will work.'],
    ['AI może wywołać tylko komendy zaczynające się od tego prefiksu. Np.','AI can only call commands starting with this prefix. E.g.'],
    ['Nadaj paczce nazwę i opis — pojawi się w katalogu Paczki tools.','Give the package a name and description — it will appear in the Tool Packages catalog.'],
    ['Dodatkowa warstwa blokująca operacje zapisu na poziomie policy','An extra layer blocking write operations at the policy level'],
    ['Wykonaj dowolną komendę curl — AI podaje wszystkie argumenty','Run any curl command — AI provides all arguments'],
    ['Brak zarejestrowanych external MCP servers. Dodaj poniżej.','No registered external MCP servers. Add below.'],
    ['Wpisz nazwę i opcjonalne zmienne ENV (tokeny, klucze API).','Enter a name and optional ENV variables (tokens, API keys).'],
    ['Wszystkie dostępne adaptery są już dodane do tego runtime.','All available adapters are already added to this runtime.'],
    ['CLI dla klastrów — oc, kubectl plus standardowe narzędzia','CLI for clusters — oc, kubectl plus standard tools'],
    ['AI będzie wykonywać tę komendę w izolowanym kontenerze.','AI will run this command in an isolated container.'],
    ['Wybierz plik z dysku — musi być w formacie Package JSON','Choose a file from disk — it must be in Package JSON format'],
    ['Masz własny Docker image z narzędziami — wpisz ręcznie','Have your own Docker image with tools — enter it manually'],
    ['Wykonuje komendy — psql, curl, oc, kubectl, własne CLI','Runs commands — psql, curl, oc, kubectl, custom CLI'],
    ['Niedostępne dla roli read_write — tylko gotowe paczki','Not available for the read_write role — ready packages only'],
    ['Wizard do tworzenia paczek tools wielokrotnego użytku','Wizard for creating reusable tool packages'],
    ['GitHub: otwórz plik JSON → kliknij Raw → skopiuj URL','GitHub: open the JSON file → click Raw → copy the URL'],
    ['Czy AI może zrobić cokolwiek chce na moim serwerze?','Can AI do anything it wants on my server?'],
    ['Jak podłączyć serwer MCP do Continue lub OpenWebUI?','How to connect an MCP server to Continue or OpenWebUI?'],
    ['Pobierz zasoby Kubernetes — AI podaje zasób i flagi','Get Kubernetes resources — AI provides the resource and flags'],
    ['Ostatnie 300 wpisów logów ze wszystkich runtimeów.','The last 300 log entries from all runtimes.'],
    ['Pobierz zasoby OpenShift — AI podaje zasób i flagi','Get OpenShift resources — AI provides the resource and flags'],
    ['Utwórz pierwszy serwer przez kreator Szybki start.','Create your first server with the Quick Start creator.'],
    ['Sprawdź podsumowanie i kliknij Utwórz serwer MCP.','Review the summary and click Create MCP server.'],
    ['Zablokowane komendy / prefixy (jedna na linię)','Blocked commands / prefixes (one per line)'],
    ['Prośba o ten login już oczekuje na akceptację','A request for this login is already pending approval'],
    ['Wypełnij 2-3 pola → serwer gotowy w 30 sekund','Fill in 2-3 fields → server ready in 30 seconds'],
    ['Zaawansowane: edytuj policy JSON bezpośrednio','Advanced: edit the policy JSON directly'],
    ['Zabronione komendy / prefixy (jedna na linię)','Blocked commands / prefixes (one per line)'],
    ['blokuje wszystkie narzędzia write/destructive','blocks all write/destructive tools'],
    ['Błąd 100 = paczka nie istnieje w Debian APT.','Error 100 = the package does not exist in Debian APT.'],
    ['Wdróż serwer żeby używać poniższego testera.','Deploy the server to use the tester below.'],
    ['Skopiuj zawartość pliku JSON i wklej tutaj','Copy the JSON file contents and paste here'],
    ['Usunąć ten external MCP server z rejestru?','Remove this external MCP server from the registry?'],
    ['Dozwolone prefixy komend (jedna na linię)','Allowed command prefixes (one per line)'],
    ['Szybki start → Komenda → Własne narzędzia','Quick Start → Command → Custom tools'],
    ['izolacja sieciowa, brak dostępu do hosta','network isolation, no host access'],
    ['tools do uruchomienia wewnątrz platformy','tools to run inside the platform'],
    ['Jak zmienić tools bez restartu serwera?','How to change tools without restarting the server?'],
    ['Jakiego typu narzędzia chcesz stworzyć?','What type of tools do you want to create?'],
    ['Brak — serwer jest dostępny bez tokena','None — the server is accessible without a token'],
    ['Maks. rozmiar danych które AI dostanie','Max size of data that AI receives'],
    ['Timeout — sprawdź logi w Paczki tools.','Timeout — check the logs in Tool Packages.'],
    ['dla parametrów które AI będzie podawać','for parameters that AI will provide'],
    ['brak wszystkich uprawnień systemowych','no system capabilities'],
    ['tylko ta binarka może być uruchamiana','only this binary can be run'],
    ['Brak uprawnień — wymagana rola admin','No permissions — admin role required'],
    ['kontener nie może zapisywać do dysku','the container cannot write to disk'],
    ['max rozmiar danych wejściowych od AI','max size of input data from AI'],
    ['Maks. czas oczekiwania na odpowiedź','Max wait time for a response'],
    ['max ile sekund może działać komenda','max seconds a command can run'],
    ['read_write — tworzenie serwerów MCP','read_write — creating MCP servers'],
    ['żaden kontener nie działa jako root','no container runs as root'],
    ['Dodaj co najmniej jedno narzędzie.','Add at least one tool.'],
    ['Jak używać z Continue / OpenWebUI?','How to use with Continue / OpenWebUI?'],
    ['Nowe hasło musi mieć min. 6 znaków','New password must be at least 6 characters'],
    ['Podgląd konfiguracji zabezpieczeń:','Security configuration preview:'],
    ['Jakie narzędzia ma mieć kontener?','What tools should the container have?'],
    ['blokuje narzędzia w trybie write','blocks tools in write mode'],
    ['Twórz i zarządzaj serwerami MCP','Create and manage MCP servers'],
    ['limit zasobów na każdy kontener','resource limit per container'],
    ['Tool zwrócił błąd (tool_error)','Tool returned an error (tool_error)'],
    ['unzip wget — pobieranie plików','unzip wget — file downloads'],
    ['Hasło musi mieć min. 6 znaków','Password must be at least 6 characters'],
    ['Jak zarejestrować nowe konto?','How to register a new account?'],
    ['Nieprawidłowy login lub hasło','Invalid login or password'],
    ['Sprawdź status i odkryj tools','Check status and discover tools'],
    ['Status użytkownika zmieniony.','User status changed.'],
    ['4 kroki z pełną konfiguracją','4 steps with full configuration'],
    ['Działające silniki wykonania','Active execution engines'],
    ['Eksport istniejącego serwera','Export an existing server'],
    ['Login musi mieć min. 2 znaki','Login must be at least 2 characters'],
    ['Nieprawidłowe aktualne hasło','Invalid current password'],
    ['Serwer padł (runtime_failed)','Server crashed (runtime_failed)'],
    ['Tools mogą tylko czytać dane','Tools can only read data'],
    ['Zarejestruj i sprawdź status','Register and check status'],
    ['Jedna odpowiedź na pytanie:','One answer per question:'],
    ['Lub wklej JSON bezpośrednio','Or paste JSON directly'],
    ['blokada eskalacji uprawnień','privilege escalation blocked'],
    ['jakie pody działają w prod?','which pods are running in prod?'],
    ['Definiuj narzędzia (tools)','Define tools'],
    ['Kiedy dodawać nowy silnik?','When to add a new engine?'],
    ['Nowe hasło (min. 6 znaków)','New password (min. 6 characters)'],
    ['Usunąć ten typ środowiska?','Delete this environment type?'],
    ['Ten login jest już zajęty','This login is already taken'],
    ['read_only — tylko podgląd','read_only — view only'],
    ['Bezpieczeństwo kontenera','Container security'],
    ['Brak aktywnych silników.','No active engines.'],
    ['ile KB/MB AI może dostać','how many KB/MB AI can receive'],
    ['ile możesz skonfigurować','how much you can configure'],
    ['Brak dostępnych paczek.','No packages available.'],
    ['Małe litery, bez spacji','Lowercase, no spaces'],
    ['Pełna kontrola, 4 kroki','Full control, 4 steps'],
    ['Opis działania silnika','Engine description'],
    ['brak ograniczeń policy','no policy restrictions'],
    ['tylko niektóre blokady','only some blocks'],
    ['Custom (własny obraz)','Custom (own image)'],
    ['Najczęstsze pytania','Frequently asked questions'],
    ['Dodaj typ środowiska','Add environment type'],
    ['Flagi bezpieczeństwa','Security flags'],
    ['Podgląd JSON paczki:','Package JSON preview:'],
    ['Potwierdź nowe hasło','Confirm new password'],
    ['Pełna konfiguracja','Full configuration'],
    ['Nowy własny szablon','New custom template'],
    ['Panelu użytkowników','the Users panel'],
    ['Własny obraz Docker','Custom Docker image'],
    ['Środowisko Docker','Docker environment'],
    ['Brak serwerów MCP','No MCP servers'],
    ['Nie bezpośrednio.','Not directly.'],
    ['Maks. odpowiedź','Max response'],
    ['Potwierdź hasło','Confirm password'],
    ['Usunąć webhook?','Delete webhook?'],
    ['Wybierz paczkę:','Choose a package:'],
    ['Zarejestruj się','Register'],
    ['Aktualne hasło','Current password'],
    ['Własny Runtime','Custom Runtime'],
    ['własny szablon','custom template'],
    ['Typy serwerów','Server types'],
    ['nieznany błąd','unknown error'],
    ['utwórz własny','create your own'],
    ['Ścieżka mount','Mount path'],
    ['Pełny wybór','Full choice'],
    ['pełna lista','full list'],
    ['Żądana rola','Requested role'],
    ['Zaloguj się','Log in'],
    ['Wiadomość','Message'],
    ['szczegóły','details'],
    ['ręczna lista','manual list'],
    ['Zmień','Change'],
    ['🔨 Przebudowywanie obrazu Docker — może potrwać kilka minut. Status zaktualizuje się automatycznie.','🔨 Rebuilding Docker image — may take a few minutes. Status will update automatically.'],
    ['🚀 Deployment zlecony — kontener uruchomi się za kilka sekund. Status zmieni się automatycznie.','🚀 Deployment queued — the container will start in a few seconds. Status will change automatically.'],
    ['✅ Zawiera:','✅ Contains:'],
    ['+ Python 3.12 (Debian) — dodaj tylko brakujące narzędzia','+ Python 3.12 (Debian) — add only the missing tools'],
    ['+ Python 3.12 (Debian Slim) — dodasz tylko brakujące narzędzia','+ Python 3.12 (Debian Slim) — you only add the missing tools'],
    ['🔨 Przebudowanie obrazu zlecone. Może potrwać kilka minut.','🔨 Image rebuild queued. May take a few minutes.'],
    ['🚀 Deployment zlecony! Kontener uruchomi się za chwilę.','🚀 Deployment queued! The container will start shortly.'],
    ['📋 Pobieranie logów zlecone — odśwież za chwilę.','📋 Log fetch queued — refresh shortly.'],
    ['⚡ vs 🛠️ Kiedy użyć Szybkiego startu, a kiedy Kreatora zaawansowanego?','⚡ vs 🛠️ When to use Quick Start and when the Advanced Creator?'],
    ['🏗️ Schemat — jak platforma działa pod spodem','🏗️ Diagram — how the platform works under the hood'],
    ['🔒 Usuwanie obrazów dostępne tylko dla admina','🔒 Image deletion available to admin only'],
    ['🔄 Jak to działa — cały przepływ w 5 krokach','🔄 How it works — the whole flow in 5 steps'],
    ['🛡️ Walidacja wartości parametrów (Pydantic)','🛡️ Parameter Value Validation (Pydantic)'],
    ['📖 Jak działa policy? Co blokuje, a co nie?','📖 How does policy work? What it blocks and what not?'],
    ['🔴 Operator — ręce platformy (Docker API)','🔴 Operator — the platforms hands (Docker API)'],
    ['🛡️ Hardening kontenerów (zawsze aktywne)','🛡️ Container hardening (always active)'],
    ['⚡ Gotowe wzorce — kliknij żeby wstawić:','⚡ Ready patterns — click to insert:'],
    ['🛠️ Własny obraz (Runtime Image Builder)','🛠️ Custom image (Runtime Image Builder)'],
    ['🛡️ Zawsze aktywne (nie można wyłączyć):','🛡️ Always active (cannot be disabled):'],
    ['⌨️ Inny — wpisz ręcznie (zaawansowane)','⌨️ Other — enter manually (advanced)'],
    ['🐳 Środowiska wykonania (obrazy Docker)','🐳 Execution environments (Docker images)'],
    ['🔧 Pełny przykład .continue/config.json','🔧 Full example .continue/config.json'],
    ['❌ Nie działa — repo z kodem aplikacji','❌ Does not work — a repo with app code'],
    ['⌨️ Jak pisać komendy shell — zmienne','⌨️ How to write shell commands — variables'],
    ['✅ Konfiguracja przeładowana. Status:','✅ Configuration reloaded. Status:'],
    ['🔒 Usuwanie dostępne tylko dla admina','🔒 Deletion available to admin only'],
    ['🗑️ Serwer usunięty. Przekierowuję...','🗑️ Server deleted. Redirecting...'],
    ['📄 Jak wygląda format Package JSON?','📄 What does the Package JSON format look like?'],
    ['🖥️ Platforma generuje konfigurację','🖥️ The platform generates the configuration'],
    ['🛠️ Dostępne narzędzia w kontenerze','🛠️ Available tools in the container'],
    ['📋 Pobieranie logów z kontenera...','📋 Fetching logs from the container...'],
    ['✅ Działa — Platform Package JSON','✅ Works — Platform Package JSON'],
    ['✅ Kontener żyje! Status: running','✅ Container is alive! Status: running'],
    ['📥 Importuj paczkę z JSON lub URL','📥 Import a package from JSON or URL'],
    ['🟢 Control Plane — mózg platformy','🟢 Control Plane — the platforms brain'],
    ['♻️ Przeładowuję konfigurację...','♻️ Reloading configuration...'],
    ['🔒 Bezpieczeństwo i ograniczenia','🔒 Security and restrictions'],
    ['🔗 Z URL (GitHub, własny serwer)','🔗 From URL (GitHub, own server)'],
    ['✅ Polityka zapisana pomyślnie.','✅ Policy saved successfully.'],
    ['🔌 Jak podłączyć do klienta AI?','🔌 How to connect to an AI client?'],
    ['📋 Zarządzaj paczkami (tabela)','📋 Manage packages (table)'],
    ['🔍 Podgląd konfiguracji toolów','🔍 Tool configuration preview'],
    ['🚀 Stwórz i uruchom serwer MCP','🚀 Create and launch the MCP server'],
    ['🤖 Wywołania narzędzi przez AI','🤖 AI tool invocations'],
    ['❌ Budowanie nie powiodło się','❌ Build failed'],
    ['🌐 Test przez własny endpoint','🌐 Test via custom endpoint'],
    ['💡 Jak działa Allowed Prefix?','💡 How does Allowed Prefix work?'],
    ['🔑 Zmienne środowiskowe (ENV)','🔑 Environment Variables (ENV)'],
    ['📥 Importuj konfigurację MCP','📥 Import MCP configuration'],
    ['🔒 Ustawienia bezpieczeństwa','🔒 Security settings'],
    ['🛠️ Zbuduj własne środowisko','🛠️ Build a custom environment'],
    ['👥 Role użytkowników (RBAC)','👥 User roles (RBAC)'],
    ['✅ Zapisano — odświeżam...','✅ Saved — refreshing...'],
    ['🔒 Polityka bezpieczeństwa','🔒 Security policy'],
    ['🤖 AI korzysta z narzędzi','🤖 AI uses the tools'],
    ['💡 Przykłady zastosowań','💡 Usage examples'],
    ['📏 Maks. odpowiedź (KB)','📏 Max response (KB)'],
    ['🔒 Ograniczenia dostępu','🔒 Access restrictions'],
    ['🔔 Webhooki powiadomień','🔔 Notification webhooks'],
    ['🔧 Zdefiniuj narzędzia','🔧 Define tools'],
    ['🏗️ Runtime Image Builder — zbuduj własny obraz Docker','🏗️ Runtime Image Builder — build a custom Docker image'],
    ['🔒 Ścisła (produkcja)','🔒 Strict (production)'],
    ['🔶 Częściowe polityki','🔶 Partial policies'],
    ['📥 Zainstaluj paczkę','📥 Install package'],
    ['🔧 Narzędzia (Tools)','🔧 Tools'],
    ['🚀 Utwórz serwer MCP','🚀 Create MCP server'],
    ['⌨️ Jak pisać komendy','⌨️ How to write commands'],
    ['← Popraw i spróbuj ponownie','← Fix and try again'],
    ['💡 Sprawdź nazwy pakietów na','💡 Check package names at'],
    ['← Powrót do dashboardu','← Back to dashboard'],
    ['➕ Dodaj nowe narzędzie','➕ Add a new tool'],
    ['🔶 częściowa','🔶 partial'],
    ['← Zmień środowisko','← Change environment'],
    ['🔨 Spróbuj ponownie','🔨 Try again'],
    ['🔒 Ścisłe polityki','🔒 Strict policies'],
    ['🔓 Luźne polityki','🔓 Relaxed policies'],
    ['🩺 Sprawdź status','🩺 Check status'],
    ['✨ Generuj paczkę','✨ Generate package'],
    ['🔒 Otwórz Politykę','🔒 Open Policy'],
    ['💾 Zapisz politykę','💾 Save policy'],
    ['➕ Dodaj narzędzie','➕ Add tool'],
    ['🔄 Odśwież logi','🔄 Refresh logs'],
    ['← Wróć do komendy','← Back to command'],
    ['🚀 Stwórz MCP','🚀 Create MCP'],
    ['🛠️ Twój kreator','🛠️ Your creator'],
    ['⏸ Wyłączony','⏸ Disabled'],
    ['⛔ wyłączona','⛔ disabled'],
    ['✅ Usunięto.','✅ Deleted.'],
    ['💡 Wskazówka','💡 Tip'],
    ['🚀 Wdrażanie:','🚀 Deploying:'],
    ['🔒 Ścisła','🔒 Strict'],
    ['🔒 ścisła','🔒 strict'],
    ['🔓 luźna','🔓 relaxed'],
    ['✅ Działa!','✅ Works!'],
    ['✕ Wyczyść','✕ Clear'],
    ['🔌 Podłącz','🔌 Connect'],
    ['❌ Odrzuć','❌ Reject'],
    ['🚀 Wdróż','🚀 Deploy'],
    ['❌ Błąd','❌ Error'],
    ['⚙️ Zarządzaj','⚙️ Manage'],
    ['🔧 Narzędzia','🔧 Tools'],
    ['🤖 Wywołania','🤖 Invocations'],
    ['🐘 psql (pełny)','🐘 psql (full)'],
    ['1. Typ narzędzi','1. Tool type'],
    ['2. Narzędzia (tools)','2. Tools'],
    ['3. Bezpieczeństwo','3. Security'],
    ['4. Bezpieczeństwo','4. Security'],
    ['5. Utwórz','5. Create'],
    ['3. Narzędzie','3. Tool'],
    ['Bezpieczeństwo:','Security:'],
    ['Typy środowisk (Runtime Classes)','Environment Types (Runtime Classes)'],
    ['Typ środowiska (Runtime Class)','Environment Type (Runtime Class)'],
    ['Pełny URL endpointu MCP — np.','Full MCP endpoint URL — e.g.'],
    ['przeglądaj gotowe zestawy','browse ready-made sets'],
    ['Wyślij prośbę o konto →','Send account request →'],
    ['Zaloguj się →','Log in →'],
    ['Dalej → Bezpieczeństwo 🔒','Next → Security 🔒'],
    ['(domyślnie: maksymalne)','(default: maximum)'],
    ['2-3 pola do wypełnienia','2-3 fields to fill in'],
    ['(opcjonalne — tokeny, klucze API, hasła)','(optional — tokens, API keys, passwords)'],
    ['Serwer MCP nasłuchuje','MCP server is listening'],
    ['Definiujesz narzędzia','You define the tools'],
    ['(brak ograniczeń)','(no restrictions)'],
    ['→ Pełna historia','→ Full history'],
    ['→ status zmieni się na','→ status will change to'],
    ['→ tutaj pojawi się config dla Continue i OpenWebUI','→ config for Continue and OpenWebUI will appear here'],
    ['Admin Panel → Settings → Tools → wklej poniższy URL','Admin Panel → Settings → Tools → paste the URL below'],
    ['Wykonuje komendy — psql','Runs commands — psql'],
    ['Komenda (użyj','Command (use'],
    ['Pełny dostęp:','Full access:'],
    ['Runtime używa','Runtime uses'],
    ['Przykład:','Example:'],
    ['Otwórz →','Open →'],
    ['Wartości','Values'],
    ['Środowisko','Environment'],
    // ---- Last remaining ----
    ['dodaj tylko brakujące narzędzia','add only the missing tools'],
    ['AI może zapytać','AI can ask'],
    ['błąd:','error:'],
    ['Zaktualizowano typ środowiska','Environment type updated'],
    ['Usunięto','Deleted'],
    ['już istnieje','already exists'],
    ['Usuń','Delete'],
    // ---- Advanced Creator step 2 (Basics) ----
    ['Podstawowe informacje','Basic information'],
    ['Nazwij serwer i opcjonalnie dostosuj typ środowiska.','Name the server and optionally adjust the environment type.'],
    ['Dowolna nazwa — pojawi się na liście serwerów i w Continue / OpenWebUI','Any name — will appear in server list and in Continue / OpenWebUI'],
    ['Asystent do przeszukiwania GitLab issues i MR','Assistant for searching GitLab issues and MRs'],
    ['Type środowiska (Runtime Class)','Environment Type (Runtime Class)'],
    ['Typ środowiska','Environment type'],
    ['Określa jaki obraz Docker zostanie uruchomiony','Determines which Docker image will be launched'],
    ['Dostępne narzędzia w kontenerze','Available tools in container'],
    ['Standardowy obraz ma już:','Standard image already has:'],
    ['Potrzebujesz innych? Zbuduj własny obraz poniżej.','Need others? Build a custom image below.'],
    ['Baza obrazu','Image base'],
    ['Baza obrazu (FROM)','Image base (FROM)'],
    ['Additional APT packages (spacja)','Additional APT packages (space separated)'],
    ['Pakiety pip (opcjonalne)','Pip packages (optional)'],
    ['Zawiera oc, kubectl, curl, jq + Python 3.12 Debian','Contains oc, kubectl, curl, jq + Python 3.12 Debian'],
    ['Zbuduj własne środowisko','Build custom environment'],
    ['lub pomiń i użyj standardowego','or skip and use the standard one'],
    ['Standardowe','Standard'],
    ['Standard — oc, kubectl, curl, jq','Standard — oc, kubectl, curl, jq'],
    // ---- Advanced Creator step 1 ----
    ['Skąd pochodzą tools?','Where do tools come from?'],
    ['Wybierz czy używasz gotowej paczki (najszybciej) czy budujesz serwer od zera.','Choose whether to use a ready package (fastest) or build a server from scratch.'],
    ['Gotowa paczka','Ready package'],
    ['Wybierz z katalogu — tools, silnik i polityka konfigurują się automatycznie','Choose from catalog — tools, engine and policy are configured automatically'],
    ['Od zera','From scratch'],
    ['Wybierz silnik wykonania i zdefiniuj tools ręcznie po utworzeniu','Choose execution engine and define tools manually after creation'],
    ['Wybierz silnik wykonania:','Choose execution engine:'],
    ['Wybierz silnik wykonania','Choose execution engine'],
    ['Wywołuje REST API — GitLab, Jira, własny serwis','Calls REST API — GitLab, Jira, custom service'],
    ['Wykonuje komendy — curl, oc, kubectl, dowolne CLI','Executes commands — curl, oc, kubectl, any CLI'],
    ['konfigurują się automatycznie','are configured automatically'],
    ['Gotowa paczka','Ready package'],
    ['ręcznie po utworzeniu','manually after creation'],
    ['własny serwis','custom service'],
    ['dowolne CLI','any CLI'],
    ['Zmienne środowiskowe (ENV)','Environment Variables (ENV)'],
    ['Zmienne są wstrzykiwane do kontenera przy następnym deploy. Po zmianie kliknij','Variables are injected into the container on next deploy. After changes click'],
    ['Walidacja wartości parametrów (Pydantic)','Parameter Value Validation (Pydantic)'],
    ['Dozwolone binarki','Allowed binaries'],
    ['Dozwolone prefixy (jeden/linię)','Allowed prefixes (one per line)'],
    ['Zablokowane tokeny','Blocked tokens'],
    ['Zablokowane prefixy (jeden/linię)','Blocked prefixes (one per line)'],
    ['Zapisz politykę shell','Save shell policy'],
    ['Zarządzanie serwerem','Server Management'],
    ['Zarządzaj','Manage'],
    ['Wywołania','Invocations'],
    ['Ostatnie logi','Recent Logs'],
    ['Pełna historia','Full history'],
    ['brak endpointu','no endpoint'],
    ['Brak zmiennych ENV','No ENV variables'],
    ['dodaj poniżej','add below'],
    ['Zmień hasło','Change password'],
    ['wszystkie środowiska','all environments'],
    ['zdefiniowanych','defined'],
    ['Serwery MCP','MCP Servers'],
    ['wszystkie środowiska','all environments'],
    ['Gotowy zestaw','Ready-made set'],
    ['Wybierz gotowy zestaw narzędzi','Choose a ready-made tool set'],
    ['Zdefiniuj narzędzia','Define tools'],
    ['Zdefiniuj komendy które AI będzie wykonywać w kontenerze','Define commands that AI will execute in the container'],
    ['Dodaj kolejne narzędzie','Add another tool'],
    ['Dodaj parametr','Add parameter'],
    ['Komenda','Command'],
    ['Wzorce','Patterns'],
    ['Parametr','Parameter'],
    ['Podstawy','Basics'],
    ['Źródło','Source'],
    ['Wdróż','Deploy'],
    ['Wróć','Back'],
    ['Logi','Logs'],
    ['Pobierz','Download'],
    ['Odśwież logi','Refresh logs'],
    ['Odśwież','Refresh'],
    ['Dodaj','Add'],
    ['Gotowe','Done'],
    ['Wszystkie','All'],
    ['Zmienne','Variables'],
    ['wartość / token','value / token'],
    ['Pokaż/ukryj','Show/hide'],
    ['Pobierz logi','Fetch logs'],
    ['Serwer MCP gotowy!','MCP Server ready!'],
    ['Za chwilę uruchomi się automatycznie','It will start automatically shortly'],
    ['Powrót do dashboardu','Back to dashboard'],
    ['Ustawienia bezpieczeństwa','Security Settings'],
    ['Tryb dostępu','Access mode'],
    ['Tylko odczyt','Read only'],
    ['Blokuj zapis','Block writes'],
    ['Blokuj destruktywne','Block destructive'],
    ['Limity','Limits'],
    ['Timeout (sekundy)','Timeout (seconds)'],
    ['Dozwolone komendy','Allowed commands'],
    ['Twoje serwery','Your servers'],
    ['status: running','status: running'],
    ['failed / unhealthy','failed / unhealthy'],
    ['zarejestrowane serwery','registered servers'],
    ['Zewnętrzne MCP','External MCP'],
    ['Webhooks','Webhooks'],
    ['Obrazy Docker','Docker Images'],
    ['Typy środowisk','Environment Types'],
    ['Silniki wykonania','Execution Engines'],
    ['Dashboard','Dashboard'],
    ['Brak zbudowanych obrazów','No built images'],
    ['bazowy obraz platformy','platform base image'],
    ['wbudowany','built-in'],
    ['Data buildu','Build date'],
    ['Błąd','Error'],
    ['Klasa runtime','Runtime class'],
  ];
  // Sort longest key first so longer phrases replace before their substrings
  TRANS_RAW.sort(function(a,b){{ return b[0].length - a[0].length; }});
  var TRANS_KEYS = TRANS_RAW.map(function(p){{ return p[0]; }});
  var TRANS_VALS = TRANS_RAW.map(function(p){{ return p[1]; }});

  function translateText(text) {{
    for(var i=0;i<TRANS_KEYS.length;i++) {{
      var k = TRANS_KEYS[i];
      if(text.indexOf(k) === -1) continue;
      // For short keys (<=8 chars), only match if surrounded by word boundaries or punctuation
      if(k.length <= 6) {{
        var ek = k.replace(/[.*+?^${{}}()|[\\]\\\\]/g, '\\\\$&');
        var re = new RegExp('(?<![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])' + ek + '(?![a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ])', 'g');
        text = text.replace(re, TRANS_VALS[i]);
      }} else {{
        text = text.split(k).join(TRANS_VALS[i]);
      }}
    }}
    return text;
  }}

  function collectNodes() {{
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    var nodes = [];
    var n;
    while((n = walker.nextNode())) {{ if(n.textContent.trim()) nodes.push(n); }}
    return nodes;
  }}

  window.applyLang = function(lang){{
    var toEN = lang === 'en';
    if(toEN) {{
      var nodes = collectNodes();
      nodes.forEach(function(node){{
        if(node._orig === undefined) node._orig = node.textContent;
        node.textContent = translateText(node._orig);
      }});
      document.querySelectorAll('[placeholder]').forEach(function(el){{
        if(el._origPh === undefined) el._origPh = el.placeholder;
        el.placeholder = translateText(el._origPh);
      }});
      document.querySelectorAll('[title]').forEach(function(el){{
        if(el._origTitle === undefined) el._origTitle = el.title;
        el.title = translateText(el._origTitle);
      }});
    }} else {{
      var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
      var n;
      while((n = walker.nextNode())) {{
        if(n._orig !== undefined) {{ n.textContent = n._orig; delete n._orig; }}
      }}
      document.querySelectorAll('[placeholder]').forEach(function(el){{
        if(el._origPh !== undefined) {{ el.placeholder = el._origPh; delete el._origPh; }}
      }});
      document.querySelectorAll('[title]').forEach(function(el){{
        if(el._origTitle !== undefined) {{ el.title = el._origTitle; delete el._origTitle; }}
      }});
    }}
    document.getElementById('btn-pl').className = !toEN ? 'lang-active' : '';
    document.getElementById('btn-en').className = toEN ? 'lang-active' : '';
    document.documentElement.lang = lang;
  }}

  window.setLang = function(lang){{
    localStorage.setItem('mcp_lang', lang);
    applyLang(lang);
  }};

  var saved = localStorage.getItem('mcp_lang') || 'pl';
  document.getElementById(saved==='en' ? 'btn-en' : 'btn-pl').className = 'lang-active';
  if(saved === 'en') {{
    if(document.readyState === 'loading') {{
      document.addEventListener('DOMContentLoaded', function(){{ applyLang('en'); }});
    }} else {{
      applyLang('en');
    }}
  }}
}})();
</script>
    </body></html>
    """


@app.get("/quick-start", response_class=HTMLResponse)
def quick_start_page(error: str = "") -> str:
    _cu = _current_user.get()
    _role = (_cu or {}).get("role", "admin")
    _is_admin = _role in ("admin", "read_write")
    _can_shell = _role == "admin"
    _shell_blocked_html = (
        '<div style="background:#2a1010;border:1px solid #6a2020;border-radius:10px;padding:24px;text-align:center">'
        '<div style="font-size:32px;margin-bottom:12px">🔒</div>'
        '<div style="font-weight:800;font-size:16px;color:#f47a80;margin-bottom:8px">Brak uprawnień</div>'
        '<div style="color:#a08080;font-size:14px;margin-bottom:16px">Twoja rola (<b>read_write</b>) nie pozwala'
        ' na definiowanie własnych poleceń shell.<br>Skorzystaj z gotowego zestawu narzędzi.</div>'
        '<button type="button" class="qs-big-btn" style="max-width:280px;margin:0 auto"'
        ' onclick="chooseType(\'package\')">📦 Wybierz gotowy zestaw</button></div>'
    ) if not _can_shell else ""
    _shell_s0_style = 'style="display:none"' if not _can_shell else ""
    _all_pkgs = store.rows("SELECT id, name, description, category, risk_level, package_json FROM tool_packages WHERE enabled=1 ORDER BY source='builtin' DESC, created_at ASC")
    _seen_names: set[str] = set()
    packages = []
    for _p in _all_pkgs:
        if _p["name"] not in _seen_names:
            _seen_names.add(_p["name"])
            packages.append(_p)
    # Available base images: built-in + previously built
    _builtin_images = [
        ("mcp-runtime-shell:latest", "mcp-runtime-shell:latest — standardowy (oc, kubectl, curl, jq) [zalecane]"),
        ("mcp-runtime-http-gateway:latest", "mcp-runtime-http-gateway:latest — HTTP gateway"),
        ("mcp-runtime-openapi:latest", "mcp-runtime-openapi:latest — auto-MCP z OpenAPI spec (FastMCP)"),
        ("python:3.12-slim", "python:3.12-slim — czysty Python/Debian"),
        ("python:3.11-slim", "python:3.11-slim — Python 3.11 Debian"),
        ("debian:bookworm-slim", "debian:bookworm-slim — czysty Debian"),
    ]
    _built_images = store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' AND runtime_image NOT LIKE 'mcp-runtime-http-gateway%' AND runtime_image NOT LIKE 'mcp-runtime-shell:latest' ORDER BY runtime_image"
    )
    _custom_options = "".join(
        f'<option value="{escape(r["runtime_image"])}">{escape(r["runtime_image"])} — własny (wcześniej zbudowany)</option>'
        for r in _built_images
    )
    _builtin_options = "".join(
        f'<option value="{escape(v)}"{"selected" if v=="mcp-runtime-shell:latest" else ""}>{escape(l)}</option>'
        for v, l in _builtin_images
    )
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    def _pkg_card(p: dict) -> str:
        import json as _json
        try:
            pj = _json.loads(p['package_json'] or '{}')
        except Exception:
            pj = {}
        rc = pj.get('runtime_class') or {}
        image = rc.get('runtime_image') or '—'
        tools = pj.get('tools') or []
        risk = p.get('risk_level') or 'low'
        risk_color = {'low': '#5ce89a', 'medium': '#f4c163', 'high': '#f47a80'}.get(risk, '#7a92a8')
        category_icon = {'rag': '🧠', 'http': '🌐', 'shell': '🐚', 'openshift': '🔴', 'kubernetes': '☸️', 'database': '🗄️'}.get(p.get('category',''), '📦')
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

        def _tool_row(t: dict) -> str:
            cmd = _tool_cmd(t)
            cmd_html = (
                f'<div style="margin-top:3px;font-family:monospace;font-size:11px;color:#f4c163;'
                f'background:#1a1000;border:1px solid #3a2800;border-radius:4px;padding:2px 6px;'
                f'word-break:break-all">{escape(cmd[:180])}</div>'
            ) if cmd else ''
            return (
                f'<div style="padding:7px 0;border-bottom:1px solid #1a2a3a">'
                f'<div style="display:flex;align-items:center;gap:6px">'
                f'<span style="color:#5ce89a;font-size:11px;flex-shrink:0">▸</span>'
                f'<div style="font-weight:700;font-size:12px;color:#d0e8ff">{escape(t.get("name","?"))}</div>'
                f'</div>'
                f'<div style="font-size:11px;color:var(--muted);line-height:1.4;margin-left:16px">{escape((t.get("description") or "")[:120])}</div>'
                f'{cmd_html}'
                f'</div>'
            )

        tools_html = "".join(_tool_row(t) for t in tools[:8]) or '<div style="color:var(--muted);font-size:12px">Brak zdefiniowanych tools</div>'
        more = f'<div style="font-size:11px;color:var(--muted);margin-top:4px">+ {len(tools)-8} więcej...</div>' if len(tools) > 8 else ''
        return f"""
        <div class="qs-pkg-card" onclick="qsPkgToggle(this)">
          <input type="radio" name="package_id" value="{escape(p['id'])}" style="display:none">
          <div class="qs-pkg-inner">
            <div style="display:flex;align-items:center;gap:8px;justify-content:space-between">
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:18px">{category_icon}</span>
                <div style="font-weight:800;font-size:14px;color:white">{escape(p['name'])}</div>
              </div>
              <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
                <span style="background:#0d1822;border:1px solid {risk_color};color:{risk_color};padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700">{risk}</span>
                <span class="qs-pkg-chevron" style="color:var(--muted);font-size:12px;transition:.2s">▼</span>
              </div>
            </div>
            <div style="color:var(--muted);font-size:12px;margin-top:4px;margin-left:26px">{escape(p['description'][:120])}</div>
            <div class="qs-pkg-details" style="display:none;margin-top:12px;border-top:1px solid var(--line);padding-top:12px">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
                <div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px">
                  <div style="font-size:10px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-bottom:4px">Obraz Docker</div>
                  <div style="font-size:12px;color:#7dd3fc;font-family:monospace;word-break:break-all">{escape(image)}</div>
                </div>
                <div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px">
                  <div style="font-size:10px;color:var(--muted);font-weight:700;text-transform:uppercase;margin-bottom:4px">Narzędzia</div>
                  <div style="font-size:13px;color:white;font-weight:700">{len(tools)} tool{'s' if len(tools) != 1 else ''}</div>
                </div>
              </div>
              <div style="font-size:11px;font-weight:700;color:#aac8e0;margin-bottom:6px;text-transform:uppercase">Tools w tej paczce:</div>
              <div style="max-height:200px;overflow-y:auto;border:1px solid #1a2a3a;border-radius:8px;padding:6px 10px">{tools_html}{more}</div>
            </div>
          </div>
        </div>"""
    pkg_cards = "".join(_pkg_card(p) for p in packages)

    qs_styles = """
<style>
.qs-wrap { max-width:720px; margin:0 auto; display:grid; gap:20px; }
.qs-step { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:28px; }
.qs-step h2 { margin:0 0 6px; font-size:22px; }
.qs-step .sub { color:var(--muted); font-size:14px; margin-bottom:22px; }
.qs-type-grid { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
.qs-type-btn { background:#0d1822; border:2px solid var(--line); border-radius:10px; padding:20px 16px; cursor:pointer;
               text-align:center; transition:.15s; color:var(--text); }
.qs-type-btn:hover { border-color:var(--blue); background:#0d2a40; }
.qs-type-btn .qs-icon { font-size:36px; margin-bottom:10px; }
.qs-type-btn .qs-name { font-weight:800; font-size:15px; margin-bottom:6px; }
.qs-type-btn .qs-desc { color:var(--muted); font-size:12px; line-height:1.5; }
.qs-form-section { display:none; margin-top:4px; }
.qs-form-section.active { display:block; }
.qs-field { margin-bottom:14px; }
.qs-field label { display:block; font-weight:700; font-size:13px; color:#aac8e0; margin-bottom:5px; }
.qs-field input, .qs-field select { width:100%; box-sizing:border-box; padding:10px 12px;
  border:1px solid #34465b; border-radius:6px; background:#0d1420; color:var(--text); font-size:14px; }
.qs-field .hint { color:var(--muted); font-size:12px; margin-top:4px; }
.qs-big-btn { width:100%; padding:14px; font-size:16px; font-weight:800; border:none; border-radius:8px;
              background:var(--blue); color:white; cursor:pointer; margin-top:8px; }
.qs-big-btn:hover { background:var(--blue-dark); }
.qs-pkg-card { display:block; cursor:pointer; margin-bottom:8px; }
.qs-pkg-inner { background:#0d1822; border:2px solid var(--line); border-radius:8px; padding:12px 16px;
                transition:.15s; }
.qs-pkg-card.selected .qs-pkg-inner { border-color:var(--blue); background:#0d2a40; }
.qs-pkg-card.selected .qs-pkg-chevron { transform:rotate(180deg); color:var(--blue); }
.qs-pkg-inner:hover { border-color:var(--blue); }
.qs-pkg-details { animation: fadeIn .15s ease; }
@keyframes fadeIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
.qs-back { background:#263548; color:#c9d7e6; border:none; padding:8px 14px; border-radius:6px;
           cursor:pointer; font-size:13px; margin-bottom:16px; }
</style>"""

    body = qs_styles + f"""
{alert}
<div class="qs-wrap">
  <div class="qs-step" id="step-choose">
    <h2>Co chcesz podłączyć do AI?</h2>
    <div class="sub">Wybierz typ i wypełnij 2-3 pola — serwer uruchomi się automatycznie.</div>
    {"" if not _is_admin else '<div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--muted)">💡 Chcesz uruchomić komendę shell (psql, oc, curl)? Skorzystaj z <a href="/create" style="color:var(--blue);font-weight:700">Kreatora zaawansowanego</a> — tam możesz wybrać środowisko i zdefiniować narzędzia.</div>'}
    <div class="qs-type-grid" style="grid-template-columns:1fr 1fr;grid-template-rows:auto auto">
      <button type="button" class="qs-type-btn" onclick="chooseType('external')">
        <div class="qs-icon">🔗</div>
        <div class="qs-name">Zewnętrzny MCP</div>
        <div class="qs-desc">Masz już działający serwer MCP? Podaj jego URL — platforma go zarejestruje i będzie monitorować</div>
      </button>
      <button type="button" class="qs-type-btn" onclick="chooseType('package')">
        <div class="qs-icon">📦</div>
        <div class="qs-name">Gotowy zestaw</div>
        <div class="qs-desc">Wybierz gotowy zestaw narzędzi z katalogu — tools, silnik i polityka konfigurują się automatycznie</div>
      </button>
      <button type="button" class="qs-type-btn" onclick="chooseType('import')" style="grid-column:1/-1;display:flex;align-items:center;gap:16px;text-align:left;padding:16px 20px">
        <div class="qs-icon" style="font-size:28px;flex-shrink:0">📥</div>
        <div>
          <div class="qs-name">Importuj z pliku / Git / URL</div>
          <div class="qs-desc">Masz gotowy plik JSON konfiguracji MCP? Wklej go, podaj URL albo wgraj plik — serwer uruchomi się automatycznie</div>
        </div>
      </button>
    </div>
  </div>

  <div class="qs-step" id="step-form" style="display:none">
    <button type="button" class="qs-back" onclick="goBack()">← Wróć</button>
    <form method="post" action="/api/quick-start" id="qs-form" enctype="multipart/form-data">
      <input type="hidden" name="type" id="qs-type">

      <!-- Zewnętrzny MCP -->
      <div class="qs-form-section" id="form-external">
        <h2>🔗 Zewnętrzny serwer MCP</h2>
        <div class="sub">Podaj adres istniejącego serwera MCP — platforma go zarejestruje, sprawdzi dostępność i zacznie monitorować.</div>
        <div class="qs-field">
          <label>Adres endpointu MCP</label>
          <input name="ext_endpoint_url" placeholder="http://moj-serwer.dom:8080/mcp" id="ext-url-input">
          <div class="hint">Pełny URL endpointu MCP — np. <code>http://192.168.1.10:8080/mcp</code> lub <code>https://mcp.firma.pl/mcp</code></div>
        </div>
        <div class="qs-field">
          <label>Opis (opcjonalny)</label>
          <input name="ext_description" placeholder="Serwer MCP dla GitLab, pobrany z GitHub">
        </div>
        <div class="qs-field">
          <label>Autoryzacja</label>
          <select name="ext_auth_type" id="ext-auth-select" onchange="document.getElementById('ext-token-field').style.display=this.value==='bearer'?'block':'none'">
            <option value="none">Brak — serwer jest dostępny bez tokena</option>
            <option value="bearer">Bearer token</option>
          </select>
        </div>
        <div class="qs-field" id="ext-token-field" style="display:none">
          <label>Token</label>
          <input name="ext_auth_token" type="password" placeholder="eyJhbGci...">
        </div>
        <div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:10px 14px;font-size:12px;color:var(--muted)">
          💡 Po zarejestrowaniu serwer pojawi się w zakładce <b>Zewnętrzne MCP</b> — platforma będzie sprawdzać jego dostępność i wylistuje dostępne tools.
        </div>
      </div>

      <!-- Shell command — step 0: choose environment -->
      <div class="qs-form-section" id="form-shell">
        {_shell_blocked_html}
        <div id="shell-s0" {_shell_s0_style}>
          <h2>Jakie narzędzia ma mieć kontener?</h2>
          <div class="sub">Wybierz środowisko — określa co jest dostępne w kontenerze gdy AI wywołuje komendę.</div>

          <div style="display:grid;gap:10px">

            <button type="button" class="qs-type-btn" style="text-align:left;padding:16px 18px;display:flex;gap:14px;align-items:flex-start"
                    onclick="pickEnv('standard')" id="env-btn-standard">
              <div style="font-size:28px;flex-shrink:0">🐚</div>
              <div>
                <div style="font-weight:800;font-size:14px;color:white;margin-bottom:4px">Standardowe</div>
                <div style="color:var(--muted);font-size:12px;margin-bottom:8px">Gotowe do użycia — bez konfiguracji</div>
                <div style="display:flex;flex-wrap:wrap;gap:5px">
                  {''.join(f'<code style="background:#0d1a2a;border:1px solid #1a3a50;padding:2px 7px;border-radius:4px;font-size:11px;color:#7dd3fc">{t}</code>' for t in ['curl','jq','bash','grep','sed','awk','cat','find','sort','uniq','head','tail','wc'])}
                </div>
              </div>
            </button>

            <button type="button" class="qs-type-btn" style="text-align:left;padding:16px 18px;display:flex;gap:14px;align-items:flex-start"
                    onclick="pickEnv('openshift')" id="env-btn-openshift">
              <div style="font-size:28px;flex-shrink:0">🔴</div>
              <div>
                <div style="font-weight:800;font-size:14px;color:white;margin-bottom:4px">OpenShift / Kubernetes</div>
                <div style="color:var(--muted);font-size:12px;margin-bottom:8px">CLI dla klastrów — oc, kubectl plus standardowe narzędzia</div>
                <div style="display:flex;flex-wrap:wrap;gap:5px">
                  {''.join(f'<code style="background:#0d1a2a;border:1px solid #1a3a50;padding:2px 7px;border-radius:4px;font-size:11px;color:#7dd3fc">{t}</code>' for t in ['oc','kubectl','curl','jq','bash','grep'])}
                </div>
              </div>
            </button>

            <button type="button" class="qs-type-btn" style="text-align:left;padding:16px 18px;display:flex;gap:14px;align-items:flex-start;border-color:#5a420f"
                    onclick="pickEnv('custom')" id="env-btn-custom">
              <div style="font-size:28px;flex-shrink:0">🛠️</div>
              <div style="flex:1">
                <div style="font-weight:800;font-size:14px;color:white;margin-bottom:4px">Własne narzędzia</div>
                <div style="color:var(--muted);font-size:12px;margin-bottom:8px">Potrzebujesz psql, terraform, awscli lub innych? Platforma zbuduje obraz z tymi narzędziami.</div>
                <div style="display:flex;flex-wrap:wrap;gap:5px">
                  {''.join(f'<code style="background:#1a1000;border:1px solid #3a2a00;padding:2px 7px;border-radius:4px;font-size:11px;color:#f4c163">{t}</code>' for t in ['psql','terraform','awscli','python3','node','git','...'])}
                </div>
              </div>
            </button>
          </div>

          <!-- Custom env builder (hidden until custom chosen) -->
          <div id="custom-build-box" style="display:none;margin-top:14px;background:#0d1a0a;border:1px solid #2a4a1a;border-radius:10px;padding:18px">
            <div style="font-weight:800;color:#5ce89a;margin-bottom:12px;font-size:14px">🛠️ Zbuduj własne środowisko</div>
            <div style="margin-bottom:12px">
              <div class="qs-field" style="margin:0 0 10px">
                <label>Baza obrazu (FROM)</label>
                <select id="build-base" style="font-size:13px" onchange="updateBaseHint()">
                  {_builtin_options}
                  {f'<optgroup label="── Wcześniej zbudowane ──">{_custom_options}</optgroup>' if _custom_options else ''}
                  <option value="__custom__">⌨️ Inny — wpisz ręcznie (zaawansowane)</option>
                </select>
                <input id="build-base-custom" placeholder="musi zawierać serwer MCP (zbudowany na bazie mcp-runtime-shell lub http-gateway)" style="display:none;font-size:13px;margin-top:6px">
                <div id="base-hint" class="hint" style="margin-top:4px;color:#7dd3fc">
                  ✅ Zawiera: <b>oc, kubectl, curl, jq</b> + Python 3.12 (Debian Slim) — dodasz tylko brakujące narzędzia
                </div>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
              <div class="qs-field" style="margin:0">
                <label>Pakiety APT (spacja)</label>
                <input id="build-apt" placeholder="postgresql-client python3-pip" style="font-size:13px" list="apt-suggestions">
                <datalist id="apt-suggestions">
                  <option value="postgresql-client">postgresql-client — psql CLI</option>
                  <option value="mysql-client">mysql-client — mysql CLI</option>
                  <option value="redis-tools">redis-tools — redis-cli</option>
                  <option value="mongodb-clients">mongodb-clients — mongo CLI</option>
                  <option value="git">git — version control</option>
                  <option value="python3-pip">python3-pip — pip</option>
                  <option value="python3-venv">python3-venv — virtualenv</option>
                  <option value="nodejs npm">nodejs npm — Node.js</option>
                  <option value="awscli">awscli — AWS CLI</option>
                  <option value="gnupg lsb-release">gnupg lsb-release — (do instalacji terraform)</option>
                  <option value="openssh-client">openssh-client — ssh CLI</option>
                  <option value="iputils-ping netcat-openbsd">iputils-ping netcat-openbsd — diagnostyka sieci</option>
                  <option value="unzip wget">unzip wget — pobieranie plików</option>
                </datalist>
                <div style="margin-top:6px;background:#0a1000;border:1px solid #2a3a0a;border-radius:6px;padding:8px 10px;font-size:11px">
                  ⚠️ <b style="color:#f4c163">Uwaga na nazwy!</b> Baza to <b>Debian</b> — używaj Debianowych nazw:<br>
                  <span style="color:#f47a80">❌ postgres-client</span> → <span style="color:#5ce89a">✅ postgresql-client</span><br>
                  <span style="color:#f47a80">❌ python3.12</span> → <span style="color:#5ce89a">✅ python3</span><br>
                  <span style="color:#f47a80">❌ terraform</span> → <span style="color:#5ce89a">✅ terraform (wymaga dodatkowego repo)</span>
                </div>
              </div>
              <div class="qs-field" style="margin:0">
                <label>Pakiety pip (opcjonalne)</label>
                <input id="build-pip" placeholder="boto3 kubernetes" style="font-size:13px">
              </div>
            </div>
            <button type="button" id="build-btn" onclick="startBuild()"
                    style="background:#1a7a3f;color:white;border:none;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">
              🔨 Zbuduj środowisko (2-5 min)
            </button>
            <div id="build-progress" style="display:none;margin-top:12px">
              <div style="display:flex;align-items:center;gap:10px">
                <div id="build-spinner" style="font-size:20px">⏳</div>
                <div>
                  <div style="font-weight:700;font-size:13px;color:white" id="build-status-text">Budowanie obrazu...</div>
                  <div style="color:var(--muted);font-size:12px">Platforma buduje Docker image z Twoimi narzędziami. Możesz czekać lub wrócić później.</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div id="shell-s1" style="display:none">
          <button type="button" class="qs-back" onclick="document.getElementById('shell-s0').style.display='';document.getElementById('shell-s1').style.display='none'">← Zmień środowisko</button>
          <div id="env-badge" style="margin-bottom:14px;padding:8px 12px;background:#0a1a0a;border:1px solid #1a4a1a;border-radius:8px;font-size:12px;color:#5ce89a">
            ✅ Środowisko wybrane — dostępne narzędzia pokazane powyżej
          </div>
          <h2>Komenda</h2>
          <div class="sub">AI będzie wykonywać tę komendę w izolowanym kontenerze.</div>

          <div style="margin-bottom:14px">
            <div style="font-size:12px;font-weight:700;color:#7ab8d8;margin-bottom:8px">⚡ Gotowe wzorce — kliknij żeby wstawić:</div>
            <div style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:10px">
              <span style="font-size:11px;color:var(--muted);align-self:center;margin-right:4px">Specyficzne:</span>
              <button type="button" class="preset-btn" onclick="setCmd('curl -s -L --max-time 30 ${{url}}','Wykonaj GET na podanym URL')">🌐 curl GET</button>
              <button type="button" class="preset-btn" onclick="setCmd('oc get ${{resource}} -n ${{namespace}} -o json','Pobierz zasób OC (pods, svc, deploy...)')">🔴 oc get resource</button>
              <button type="button" class="preset-btn" onclick="setCmd('kubectl get ${{resource}} -n ${{namespace}} -o json','Pobierz zasób K8s')">☸️ kubectl get resource</button>
              <button type="button" class="preset-btn" onclick="setCmd('oc logs ${{pod}} -n ${{namespace}} --tail ${{lines}}','Pobierz logi z poda OC')">🔴 oc logs</button>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:7px">
              <span style="font-size:11px;color:#f4c163;align-self:center;margin-right:4px">Pełny dostęp:</span>
              <button type="button" class="preset-btn" style="border-color:#5a420f;color:#f4c163"
                      onclick="setCmd('curl ${{*args}}','Wykonaj dowolną komendę curl — AI podaje wszystkie argumenty');setPrefix('curl')">
                🌐 curl (wszystko)
              </button>
              <button type="button" class="preset-btn" style="border-color:#5a2020;color:#f47a80"
                      onclick="setCmd('oc get ${{*args}}','Wykonaj dowolne oc get — AI podaje zasoby i flagi');setPrefix('oc get')">
                🔴 oc get (wszystko)
              </button>
              <button type="button" class="preset-btn" style="border-color:#5a2020;color:#f47a80"
                      onclick="setCmd('kubectl get ${{*args}}','Wykonaj dowolne kubectl get — AI podaje zasoby i flagi');setPrefix('kubectl get')">
                ☸️ kubectl get (wszystko)
              </button>
              <button type="button" class="preset-btn" style="border-color:#5a2020;color:#f47a80"
                      onclick="setCmd('kubectl ${{*args}}','Pełny dostęp do kubectl — ustaw denylist w kroku bezpieczeństwa!');setPrefix('')">
                ☸️ kubectl (pełny)
              </button>
            </div>
            <div style="margin-top:8px;font-size:11px;color:var(--muted)">
              💡 <b style="color:#f4c163">${'{'}*args{'}'}</b> = AI podaje <b>wszystkie argumenty naraz</b> (np. <code>pods -n production -o json</code>) — skonfiguruj denylist w następnym kroku
            </div>
          </div>

          <div class="qs-field">
            <label>Komenda do wykonania</label>
            <input name="cmd" id="shell-cmd-input" placeholder="oc get ${{*args}}">
            <div style="margin-top:6px;font-size:12px;color:var(--muted)">
              <code>${'{'}zmienna{'}'}</code> = jeden parametr &nbsp;|&nbsp;
              <code>${'{'}*args{'}'}</code> = wiele argumentów (pełny dostęp)
            </div>
          </div>
          <div class="qs-field">
            <label>Co robi ta komenda? (opis dla AI)</label>
            <input name="desc" id="shell-desc-input" placeholder="Pobiera zasoby OpenShift">
          </div>
          <button type="button" class="qs-big-btn" style="background:#263548;color:white;margin-top:4px"
                  onclick="goShellSec()">
            Dalej → Ustawienia dostępu 🔒
          </button>
        </div>

        <!-- Shell step 2: Security -->
        <div id="shell-s2" style="display:none">
          <button type="button" class="qs-back" onclick="backShellCmd()">← Wróć do komendy</button>
          <h2>🔒 Ograniczenia dostępu</h2>
          <div class="sub">Określ dokładnie co AI może robić. Szczególnie ważne przy pełnym dostępie <code>${'{'}*args{'}'}</code>.</div>

          <div class="qs-field">
            <label>Dozwolony prefix komendy</label>
            <input name="allowed_prefix" id="shell-prefix-input" placeholder="oc get">
            <div class="hint">
              Zostaw puste = brak ograniczeń na prefix.<br>
              Wpisz np. <code>oc get</code> → AI może TYLKO wywoływać <code>oc get ...</code> — nie może <code>oc delete</code>, <code>oc apply</code> itp.
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
              <button type="button" class="preset-btn" onclick="document.getElementById('shell-prefix-input').value='oc get'">oc get</button>
              <button type="button" class="preset-btn" onclick="document.getElementById('shell-prefix-input').value='kubectl get'">kubectl get</button>
              <button type="button" class="preset-btn" onclick="document.getElementById('shell-prefix-input').value='curl -s'">curl -s</button>
              <button type="button" class="preset-btn" onclick="document.getElementById('shell-prefix-input').value=''">brak ograniczeń</button>
            </div>
          </div>

          <div class="qs-field">
            <label>Zabronione komendy / prefixy (jedna na linię)</label>
            <textarea name="blocked_prefixes" id="shell-blocked-input"
                      placeholder="kubectl delete&#10;kubectl apply&#10;kubectl exec&#10;oc delete"
                      style="min-height:110px;font-family:monospace;font-size:13px"></textarea>
            <div class="hint">
              Komendy zaczynające się od tych prefiksów będą zablokowane.<br>
              Np. <code>kubectl delete</code> blokuje <code>kubectl delete pod xyz</code>, <code>kubectl delete -f ...</code> itp.
            </div>
          </div>

          <div style="background:#0d1822;border:1px solid #1a3a50;border-radius:8px;padding:12px 14px;margin-bottom:14px;font-size:12px">
            <b style="color:#7dd3fc">Podgląd konfiguracji zabezpieczeń:</b>
            <pre id="sec-preview" style="margin-top:6px;font-size:11px;max-height:80px;border:none;background:transparent;padding:0;color:#8ea2b8"></pre>
          </div>

          <div style="padding-top:18px;border-top:1px solid var(--line);margin-top:6px">
            <div class="qs-field">
              <label>Nazwa Twojego serwera MCP</label>
              <input id="shell-name-inline" placeholder="Mój asystent OC" style="font-size:15px;padding:12px 14px"
                     oninput="syncShellName(this.value)">
              <div class="hint">Dowolna nazwa — pojawi się w Continue i OpenWebUI</div>
            </div>
            <button type="button" class="qs-big-btn" style="background:#1a7a3f" onclick="launchShell()">
              🚀 Stwórz i uruchom serwer MCP
            </button>
          </div>
        </div>
      </div>

<style>
.preset-btn {{
  background:#0d1822; border:1px solid #2a3a4a; border-radius:6px;
  padding:5px 10px; font-size:12px; font-weight:600; color:#b0c8e0;
  cursor:pointer; transition:.12s; white-space:nowrap;
}}
.preset-btn:hover {{ background:#0d2a40; border-color:var(--blue); color:white; transform:none; }}
</style>
<script>
function setCmd(cmd, desc) {{
  var c = document.getElementById('shell-cmd-input');
  var d = document.getElementById('shell-desc-input');
  if (c) c.value = cmd;
  if (d && !d.value && desc) d.value = desc;
}}
function setPrefix(p) {{
  var el = document.getElementById('shell-prefix-input');
  if (el) el.value = p;
}}
function goShellSec() {{
  var cmd = document.getElementById('shell-cmd-input').value.trim();
  if (!cmd) {{ document.getElementById('shell-cmd-input').focus(); return; }}
  document.getElementById('shell-s1').style.display = 'none';
  document.getElementById('shell-s2').style.display = '';
  updateSecPreview();
}}
function backShellCmd() {{
  document.getElementById('shell-s2').style.display = 'none';
  document.getElementById('shell-s1').style.display = '';
}}
function syncShellName(v) {{
  var main = document.querySelector('input[name="name"]');
  if (main) main.value = v;
}}
function launchShell() {{
  var n = document.getElementById('shell-name-inline');
  if (n) {{ n = n.value.trim(); }} else {{ n = ''; }}
  if (!n) {{ document.getElementById('shell-name-inline').focus(); return; }}
  syncShellName(n);
  document.getElementById('qs-form').submit();
}}
function updateSecPreview() {{
  var prefix = (document.getElementById('shell-prefix-input')||{{}}).value || '';
  var blocked = (document.getElementById('shell-blocked-input')||{{}}).value || '';
  var lines = blocked.split('\\n').map(function(l){{return l.trim();}}).filter(Boolean);
  var obj = {{}};
  if (prefix) obj.allowed_command_prefixes = [prefix];
  if (lines.length) obj.blocked_command_prefixes = lines;
  document.getElementById('sec-preview').textContent = JSON.stringify(obj, null, 2) || '(brak ograniczeń)';
}}
document.addEventListener('input', function(e) {{
  if (e.target.id === 'shell-prefix-input' || e.target.id === 'shell-blocked-input') updateSecPreview();
}});
</script>

      <!-- Package -->
      <div class="qs-form-section" id="form-package">
        <h2>Gotowy zestaw</h2>
        <div class="sub">Wybierz zestaw narzędzi — wszystko skonfiguruje się automatycznie.</div>
        {pkg_cards}
      </div>

      <!-- Import -->
      <div class="qs-form-section" id="form-import">
        <h2>📥 Importuj konfigurację MCP</h2>
        <div class="sub">Wklej JSON, podaj URL (GitHub raw, własny serwer) lub wgraj plik — platforma zainstaluje paczkę i uruchomi serwer.</div>

        <!-- ⚠️ Ważna informacja: co można, a czego nie można importować -->
        <div style="border-radius:10px;overflow:hidden;margin-bottom:16px;border:1px solid #2a3a4a">

          <div style="background:#0d1e2e;padding:12px 16px;border-bottom:1px solid #1a3a50;font-weight:800;font-size:13px;color:#7dd3fc">
            ❓ Co mogę tutaj zaimportować?
          </div>

          <!-- ✅ Co działa -->
          <div style="background:#0a1e10;border-bottom:1px solid #1a3a20;padding:12px 16px">
            <div style="font-weight:700;color:#5ce89a;font-size:13px;margin-bottom:8px">✅ Działa — Platform Package JSON</div>
            <div style="color:#a0c8a8;font-size:12px;line-height:1.8">
              Plik JSON opisujący <b>tools do uruchomienia wewnątrz platformy</b> — stworzony przez Package Generator, wyeksportowany z innego serwera lub pobrany z repo który ma taki plik.
              <br>Poznasz go po polach: <code>"tools"</code>, <code>"runtime_class"</code>, <code>"policy"</code>
            </div>
          </div>

          <!-- ❌ Co nie działa — repo z kodem -->
          <div style="background:#1e0a0a;border-bottom:1px solid #3a1a1a;padding:12px 16px">
            <div style="font-weight:700;color:#f47a80;font-size:13px;margin-bottom:8px">❌ Nie działa — repo z kodem aplikacji</div>
            <div style="color:#c8a0a0;font-size:12px;line-height:1.8">
              Repo GitHub z kodem C#, Python, Node.js itp. (<b>np. ustabar/sql-mcp</b>) to gotowa aplikacja serwera MCP —
              nie plik konfiguracji. Platforma nie kompiluje ani nie uruchamia obcego kodu bezpośrednio.
            </div>
            <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:8px">
              <a href="/external-mcp" style="display:flex;align-items:flex-start;gap:8px;background:#0d1822;border:1px solid #2a3a4a;border-radius:8px;padding:10px 12px;text-decoration:none">
                <span style="font-size:18px;flex-shrink:0">🔗</span>
                <div>
                  <div style="font-weight:700;color:white;font-size:12px">Zewnętrzne MCP</div>
                  <div style="color:var(--muted);font-size:11px;margin-top:2px">Serwer już gdzieś działa? Zarejestruj jego endpoint — platforma odkryje tools i będzie go monitorować.</div>
                </div>
              </a>
              <a href="/tool-packages" style="display:flex;align-items:flex-start;gap:8px;background:#0d1822;border:1px solid #2a3a4a;border-radius:8px;padding:10px 12px;text-decoration:none">
                <span style="font-size:18px;flex-shrink:0">🏗️</span>
                <div>
                  <div style="font-weight:700;color:white;font-size:12px">Runtime Image Builder</div>
                  <div style="color:var(--muted);font-size:11px;margin-top:2px">Repo ma Dockerfile? Zbuduj custom obraz i uruchom go jako kontener w platformie.</div>
                </div>
              </a>
            </div>
          </div>

        </div>

        <div style="display:grid;gap:0;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:14px">

          <!-- Tab: URL -->
          <label style="display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);cursor:pointer;background:#0d1822"
                 onclick="switchImportTab('url')">
            <input type="radio" name="import_source" value="url" id="isrc-url" style="width:auto;flex-shrink:0" checked>
            <div>
              <div style="font-weight:700;font-size:13px;color:white">🔗 Z URL (GitHub, własny serwer)</div>
              <div class="hint" style="margin:0">np. <code>https://raw.githubusercontent.com/org/repo/main/mcp-package.json</code></div>
            </div>
          </label>
          <div id="itab-url" style="padding:14px 16px;border-bottom:1px solid var(--line);background:#0b1420">
            <input name="import_url" id="import-url-input" placeholder="https://raw.githubusercontent.com/.../.../mcp-package.json"
                   style="font-size:13px">
            <div class="hint">GitHub: otwórz plik JSON → kliknij Raw → skopiuj URL</div>
          </div>

          <!-- Tab: Paste -->
          <label style="display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);cursor:pointer;background:#0d1822"
                 onclick="switchImportTab('paste')">
            <input type="radio" name="import_source" value="paste" id="isrc-paste" style="width:auto;flex-shrink:0">
            <div>
              <div style="font-weight:700;font-size:13px;color:white">📋 Wklej JSON</div>
              <div class="hint" style="margin:0">Skopiuj zawartość pliku JSON i wklej tutaj</div>
            </div>
          </label>
          <div id="itab-paste" style="padding:14px 16px;border-bottom:1px solid var(--line);background:#0b1420;display:none">
            <textarea name="import_json" id="import-json-input" placeholder='{{&#10;  "id": "my-mcp-server",&#10;  "name": "My MCP Server",&#10;  "tools": [...]&#10;}}'
                      style="min-height:140px;font-family:monospace;font-size:12px"></textarea>
          </div>

          <!-- Tab: File -->
          <label style="display:flex;align-items:center;gap:10px;padding:14px 16px;cursor:pointer;background:#0d1822"
                 onclick="switchImportTab('file')">
            <input type="radio" name="import_source" value="file" id="isrc-file" style="width:auto;flex-shrink:0">
            <div>
              <div style="font-weight:700;font-size:13px;color:white">📂 Wgraj plik .json</div>
              <div class="hint" style="margin:0">Wybierz plik z dysku — musi być w formacie Package JSON</div>
            </div>
          </label>
          <div id="itab-file" style="padding:14px 16px;background:#0b1420;display:none">
            <input type="file" name="import_file" id="import-file-input" accept=".json,application/json" style="font-size:13px">
          </div>
        </div>

        <details style="background:#0b1a10;border:1px solid #1a3a20;border-radius:8px;padding:12px 14px">
          <summary style="font-size:12px;color:#5a9a6a;list-style:none;cursor:pointer;font-weight:700">📄 Jak wygląda format Package JSON?</summary>
          <div style="margin-top:10px;font-size:12px;color:var(--muted);line-height:1.7">
            Package JSON to plik definiujący kompletny serwer MCP. Możesz go dostać przez:<br>
            • <b>Eksport istniejącego serwera</b> → otwórz runtime → sekcja Lifecycle → "Eksportuj jako Package JSON"<br>
            • <b>GitHub</b> → szukaj plików <code>mcp-package.json</code> lub <code>*-package.json</code><br>
            • <b>Package Generator</b> → <a href="/tool-packages/generate">utwórz własny</a>
          </div>
        </details>
      </div>

      <!-- Common: server name + policy -->
      <div style="margin-top:22px;padding-top:18px;border-top:1px solid var(--line)">
        <div class="qs-field">
          <label>Nazwa Twojego serwera MCP</label>
          <input name="name" placeholder="Mój asystent API" required>
          <div class="hint">Dowolna nazwa — pojawi się w Continue i OpenWebUI</div>
        </div>

        <details style="background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-top:4px">
          <summary style="cursor:pointer;font-weight:700;font-size:13px;color:#7ab8d8;list-style:none">
            🔒 Ustawienia bezpieczeństwa <span style="color:var(--muted);font-weight:400">(domyślnie: maksymalne)</span>
          </summary>
          <div style="margin-top:14px;display:grid;gap:12px">
            <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer">
              <input type="checkbox" name="policy_read_only" value="1" checked style="width:auto;margin-top:2px;flex-shrink:0">
              <div>
                <div style="font-weight:700;font-size:13px;color:white">🔒 Tylko odczyt</div>
                <div style="color:var(--muted);font-size:12px;margin-top:2px">Serwer może tylko czytać dane — nie może niczego modyfikować ani usuwać</div>
              </div>
            </label>
            <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer">
              <input type="checkbox" name="policy_block_write" value="1" checked style="width:auto;margin-top:2px;flex-shrink:0">
              <div>
                <div style="font-weight:700;font-size:13px;color:white">🚫 Blokuj zapis</div>
                <div style="color:var(--muted);font-size:12px;margin-top:2px">Dodatkowa warstwa blokująca operacje zapisu na poziomie policy</div>
              </div>
            </label>
            <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer">
              <input type="checkbox" name="policy_block_destructive" value="1" checked style="width:auto;margin-top:2px;flex-shrink:0">
              <div>
                <div style="font-weight:700;font-size:13px;color:white">⛔ Blokuj operacje destruktywne</div>
                <div style="color:var(--muted);font-size:12px;margin-top:2px">Zapobiega usuwaniu danych, resetowaniu konfiguracji, drop/truncate</div>
              </div>
            </label>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:4px">
              <div class="qs-field" style="margin:0">
                <label>⏱️ Timeout (sekundy)</label>
                <input type="number" name="policy_timeout" value="30" min="5" max="300" style="width:100%">
                <div class="hint">Maks. czas oczekiwania na odpowiedź</div>
              </div>
              <div class="qs-field" style="margin:0">
                <label>📏 Maks. odpowiedź (KB)</label>
                <input type="number" name="policy_max_response_kb" value="5120" min="64" max="51200" style="width:100%">
                <div class="hint">Maks. rozmiar danych które AI dostanie</div>
              </div>
            </div>
            <div style="background:#0a1a0a;border:1px solid #1a3a1a;border-radius:6px;padding:10px 12px;margin-top:4px">
              <div style="color:#4ac86a;font-size:12px;font-weight:700;margin-bottom:4px">🛡️ Zawsze aktywne (nie można wyłączyć):</div>
              <div style="color:#7ab890;font-size:12px;line-height:1.7">
                ✅ Kontener bez roota (user 1000:1000)<br>
                ✅ Read-only filesystem<br>
                ✅ Brak uprawnień systemowych (cap_drop: ALL)<br>
                ✅ no-new-privileges<br>
                ✅ Limit pamięci 512 MB &amp; CPU 1 core<br>
                ✅ Izolacja sieciowa (tylko ai-net)
              </div>
            </div>
          </div>
        </details>

        <!-- ENV vars -->
        <details style="background:#1a1200;border:1px solid #3a2800;border-radius:8px;padding:14px 16px;margin-top:10px" id="qs-env-details">
          <summary style="cursor:pointer;font-weight:700;font-size:13px;color:#d4a820;list-style:none">
            🔑 Zmienne środowiskowe ENV <span style="color:var(--muted);font-weight:400">(opcjonalne — tokeny, klucze API, hasła)</span>
          </summary>
          <div style="margin-top:12px">
            <div style="font-size:12px;color:#a08020;margin-bottom:10px">Zmienne są wstrzykiwane do kontenera. Użyj dla tokenów API, kluczy SSH, URL baz danych.</div>
            <div id="qs-env-list" style="display:grid;gap:6px;margin-bottom:8px"></div>
            <button type="button" onclick="qsAddEnv()" style="background:#0d1000;border:1px solid #3a2800;color:#d4a820;padding:5px 12px;border-radius:6px;font-size:12px;cursor:pointer">+ Dodaj zmienną ENV</button>
          </div>
        </details>
      </div>

      <button type="submit" class="qs-big-btn">🚀 Stwórz i uruchom serwer MCP</button>
      <p style="text-align:center;color:var(--muted);font-size:12px;margin-top:8px">
        Platforma automatycznie skonfiguruje i uruchomi serwer. Zajmie to kilka sekund.
      </p>
    </form>
  </div>
</div>

<script>
function chooseType(t) {{
  document.getElementById('qs-type').value = t;
  document.getElementById('step-choose').style.display = 'none';
  document.getElementById('step-form').style.display = '';
  document.querySelectorAll('.qs-form-section').forEach(function(el) {{ el.classList.remove('active'); }});
  document.getElementById('form-' + t).classList.add('active');
  // For shell, show env picker first
  if (t === 'shell') {{
    document.getElementById('shell-s0').style.display = '';
    document.getElementById('shell-s1').style.display = 'none';
    document.getElementById('shell-s2').style.display = 'none';
    return;
  }}
  var first = document.getElementById('form-' + t).querySelector('input, select');
  if (first) first.focus();
}}

// Environment picker for shell
var _buildId = null;
var _buildRcName = null;

window.pickEnv = function(env) {{
  ['standard','openshift','custom'].forEach(function(e) {{
    var b = document.getElementById('env-btn-'+e);
    if (b) b.style.borderColor = e===env ? 'var(--blue)' : '';
  }});
  document.getElementById('custom-build-box').style.display = env==='custom' ? '' : 'none';
  if (env === 'standard' || env === 'openshift') {{
    // Update presets based on env
    document.getElementById('shell-s0').style.display = 'none';
    document.getElementById('shell-s1').style.display = '';
    // Focus command input
    setTimeout(function() {{
      var el = document.getElementById('shell-cmd-input');
      if (el) el.focus();
    }}, 100);
  }}
}};

// Base image hint updater
window.updateBaseHint = function() {{
  var sel = document.getElementById('build-base');
  var custom = document.getElementById('build-base-custom');
  var hint = document.getElementById('base-hint');
  var hints = {{
    'mcp-runtime-shell:latest': '✅ Zawiera: <b>oc, kubectl, curl, jq</b> + Python 3.12 (Debian) — dodaj tylko brakujące narzędzia',
    'mcp-runtime-http-gateway:latest': '✅ HTTP gateway — brak oc/kubectl, Python 3.12',
    'mcp-runtime-openapi:latest': '✅ <b>Auto-MCP z OpenAPI</b> — ustaw <code>BACKEND_BASE_URL</code> i <code>OPENAPI_SPEC_URL</code>; narzędzia generowane automatycznie z każdego endpointu',
    'python:3.12-slim': '⚠️ Czysty Python Debian — brak oc/kubectl/curl. Dodaj <b>curl ca-certificates</b> w APT',
    'python:3.11-slim': '⚠️ Python 3.11 Debian — brak oc/kubectl',
    'debian:bookworm-slim': '⚠️ Czysty Debian — brak wszystkiego, musisz dodać wszystkie potrzebne paczki APT',
    '__custom__': '⚠️ <b>UWAGA:</b> Czysty obraz OS (ubuntu, debian, alpine) nie zadziała! Obraz musi być zbudowany na bazie <b>mcp-runtime-shell:latest</b> lub <b>mcp-runtime-http-gateway:latest</b> — tylko te mają wbudowany serwer MCP (uvicorn). Przykład: <code>FROM mcp-runtime-shell:latest</code>'
  }};
  custom.style.display = sel.value === '__custom__' ? 'block' : 'none';
  if (hint) hint.innerHTML = hints[sel.value] || '';
}};

var _qsEnvCount = 0;
window.qsAddEnv = function() {{
  var i = _qsEnvCount++;
  var row = document.createElement('div');
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:center';
  row.innerHTML =
    '<input placeholder="NAZWA_ZMIENNEJ" name="env_key_' + i + '" style="padding:8px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px;font-family:monospace;width:100%;box-sizing:border-box">' +
    '<input type="password" placeholder="wartość / token" name="env_val_' + i + '" style="padding:8px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px;width:100%;box-sizing:border-box">' +
    '<button type="button" onclick="this.parentNode.remove()" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:6px 10px;border-radius:6px;font-size:12px;cursor:pointer;flex-shrink:0">✕</button>';
  document.getElementById('qs-env-list').appendChild(row);
  document.getElementById('qs-env-details').open = true;
}};

window.qsBuildReset = function() {{
  document.getElementById('build-progress').style.display = 'none';
  document.getElementById('build-btn').disabled = false;
  document.getElementById('build-btn').textContent = '🔨 Spróbuj ponownie';
}};

window.startBuild = function() {{
  var apt = (document.getElementById('build-apt').value || '').trim();
  var pip = (document.getElementById('build-pip').value || '').trim();
  if (!apt && !pip) {{ document.getElementById('build-apt').focus(); return; }}
  var selBase = document.getElementById('build-base');
  var baseVal = selBase && selBase.value !== '__custom__' ? selBase.value : (document.getElementById('build-base-custom').value.trim() || 'mcp-runtime-shell:latest');
  var basePart = baseVal.split('/').pop().replace(/[^a-z0-9]/gi,'-').replace(/-+/g,'-').replace(/^-|-$/g,'').toLowerCase().replace(/:[^:]*$/,'');
  var aptPart = apt.split(/\s+/).slice(0,3).map(function(p){{return p.replace(/[^a-z0-9]/g,'').substring(0,12);}}).filter(Boolean).join('-');
  var namePart = (aptPart || pip.split(/\s+/)[0].replace(/[^a-z0-9]/g,'').substring(0,12) || 'env');
  var rcName = basePart + '-' + namePart;
  _buildRcName = rcName;
  var imgTag = 'mcp-runtime-' + rcName + ':latest';
  var selBase = document.getElementById('build-base');
  var baseImage = selBase && selBase.value !== '__custom__' ? selBase.value : (document.getElementById('build-base-custom').value.trim() || 'mcp-runtime-shell:latest');
  document.getElementById('build-btn').disabled = true;
  document.getElementById('build-progress').style.display = 'block';
  document.getElementById('build-status-text').textContent = 'Budowanie obrazu Docker na bazie ' + baseImage + '... (może potrwać 2-5 minut)';

  var body = new URLSearchParams({{
    image: imgTag, base_image: baseImage,
    runtime_class: rcName, apt_packages: apt, pip_packages: pip,
    allowed_execution_types: 'shell', risk_level: 'low', security_profile: 'restricted'
  }});
  fetch('/api/runtime-images/build', {{ method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body: body.toString(), redirect:'manual' }})
  .then(function(r) {{
    // poll build status
    var polls = 0;
    var t = setInterval(function() {{
      polls++;
      fetch('/api/runtime-image-builds/latest?rc=' + encodeURIComponent(rcName))
      .then(function(r2) {{ return r2.json(); }})
      .then(function(d) {{
        if (d.status === 'done') {{
          clearInterval(t);
          document.getElementById('build-spinner').textContent = '✅';
          document.getElementById('build-status-text').textContent = 'Środowisko zbudowane! Możesz teraz wpisać komendę.';
          // set runtime class hidden input (for POST handler)
          var rcInput = document.getElementById('shell-rc-name');
          if (!rcInput) {{
            rcInput = document.createElement('input');
            rcInput.type = 'hidden'; rcInput.name = 'shell_runtime_class'; rcInput.id = 'shell-rc-name';
            document.getElementById('qs-form').appendChild(rcInput);
          }}
          rcInput.value = rcName;
          setTimeout(function() {{
            document.getElementById('shell-s0').style.display = 'none';
            document.getElementById('shell-s1').style.display = '';
          }}, 1000);
        }} else if (d.status === 'failed') {{
          clearInterval(t);
          document.getElementById('build-spinner').textContent = '❌';
          var errMsg = d.error || 'nieznany błąd';
          var hint = '';
          if (errMsg.indexOf('non-zero code: 100') !== -1 || errMsg.indexOf('Unable to locate package') !== -1) {{
            hint = '<br><br>💡 <b>Błąd 100 = paczka nie istnieje w Debian APT.</b><br>Sprawdź nazwę — np. <code>postgres-client</code> ❌ → <code>postgresql-client</code> ✅<br>Szukaj na <a href="https://packages.debian.org" target="_blank" style="color:#7dd3fc">packages.debian.org</a>';
          }} else if (errMsg.indexOf('non-zero code: 1') !== -1) {{
            hint = '<br><br>💡 Sprawdź nazwy pakietów na <a href="https://packages.debian.org" target="_blank" style="color:#7dd3fc">packages.debian.org</a>';
          }}
          document.getElementById('build-progress').innerHTML =
            '<div style="background:#2a0a0a;border:2px solid #8a2020;border-radius:8px;padding:14px 16px">' +
            '<div style="font-weight:800;color:#f47a80;font-size:14px;margin-bottom:8px">❌ Budowanie nie powiodło się</div>' +
            '<code style="font-size:11px;color:#f4c163;word-break:break-all;line-height:1.6">' + errMsg.slice(0, 300) + '</code>' +
            hint +
            '<br><br><button type="button" onclick="qsBuildReset()" ' +
            'style="background:#1a3a5a;border:none;color:white;padding:8px 14px;border-radius:6px;font-size:12px;cursor:pointer;margin-top:8px">← Popraw i spróbuj ponownie</button>' +
            '</div>';
          document.getElementById('build-btn').disabled = false;
        }} else if (polls > 90) {{ clearInterval(t); document.getElementById('build-status-text').textContent = 'Timeout — sprawdź logi w Paczki tools.'; }}
      }}).catch(function() {{ if (polls > 5) clearInterval(t); }});
    }}, 3000);
  }});
}};
function goBack() {{
  document.getElementById('step-choose').style.display = '';
  document.getElementById('step-form').style.display = 'none';
}}
// Package card toggle — select + expand details
window.qsPkgToggle = function(card) {{
  var radio = card.querySelector('input[type="radio"]');
  if (!radio) return;
  var isSelected = card.classList.contains('selected');
  // Collapse all
  document.querySelectorAll('.qs-pkg-card').forEach(function(c) {{
    c.classList.remove('selected');
    var d = c.querySelector('.qs-pkg-details');
    if (d) d.style.display = 'none';
  }});
  document.querySelectorAll('.qs-pkg-card input').forEach(function(r) {{ r.checked = false; }});
  if (!isSelected) {{
    card.classList.add('selected');
    radio.checked = true;
    var details = card.querySelector('.qs-pkg-details');
    if (details) details.style.display = '';
  }}
}};
// Import tab switcher
window.switchImportTab = function(tab) {{
  ['url','paste','file'].forEach(function(t) {{
    var el = document.getElementById('itab-' + t);
    if (el) el.style.display = (t === tab) ? '' : 'none';
  }});
  var radio = document.getElementById('isrc-' + tab);
  if (radio) radio.checked = true;
}};
// Sync import_source with visible tab on submit
document.getElementById('qs-form').addEventListener('submit', function() {{
  var src = document.querySelector('input[name="import_source"]:checked');
  if (src && src.value === 'url') {{
    var urlVal = document.getElementById('import-url-input');
    if (urlVal && !urlVal.value.trim()) {{ urlVal.focus(); return false; }}
  }}
}});
</script>
"""
    return page_shell("quickstart", body)


@app.post("/api/quick-start")
async def quick_start_create(request: Request):
    form = await request.form()
    type_ = str(form.get("type") or "")
    name = str(form.get("name") or "Mój serwer MCP").strip() or "Mój serwer MCP"

    _cu = _current_user.get()
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


@app.get("/docs", response_class=HTMLResponse)
def docs_page() -> str:
    body = """
<style>
.doc-flow { display:grid; gap:6px; max-width:700px; margin:0 auto; }
.doc-step { background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:16px 18px; }
.doc-arrow { text-align:center; font-size:18px; color:var(--blue); line-height:1; }
.doc-grid2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.doc-grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }
.doc-card { background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:16px 18px; }
.doc-card h3 { margin:0 0 8px; font-size:14px; font-weight:800; }
.doc-scenario { background:#0b1a10; border:1px solid #1a4a20; border-radius:10px; padding:16px 18px; }
.doc-scenario.shell { background:#0a1520; border-color:#1a3a50; }
.doc-scenario.ext { background:#1a1020; border-color:#3a2050; }
.qa-item { border-bottom:1px solid var(--line); padding:14px 0; }
.qa-item:last-child { border-bottom:none; }
.qa-q { font-weight:800; color:white; margin-bottom:6px; font-size:14px; }
.qa-a { color:var(--muted); font-size:13px; line-height:1.7; }
.role-card { border-radius:10px; padding:16px 18px; }
</style>

<!-- Hero -->
<div style="background:linear-gradient(135deg,#0d1e2e,#0a1a0a);border:1px solid #1a4a3a;border-radius:14px;padding:28px 32px;margin-bottom:4px">
  <div style="font-size:15px;color:#7dd3fc;font-weight:700;margin-bottom:6px">Jedna odpowiedź na pytanie:</div>
  <div style="font-size:24px;font-weight:800;color:white;line-height:1.3;margin-bottom:14px">
    Jak AI (Claude, ChatGPT, Copilot) może wywoływać Twoje narzędzia,<br>API i komendy — bez dostępu do całego systemu?
  </div>
  <div style="color:#a0c8b0;font-size:14px;line-height:1.7">
    MCP Platform tworzy <b>izolowane kontenery</b> z dokładnie tymi narzędziami które chcesz udostępnić.
    AI pyta kontener, kontener wykonuje operację, AI dostaje odpowiedź. Nic więcej nie jest dostępne.
  </div>
</div>

<!-- Section: Przepływ -->
<section>
  <h2>🔄 Jak to działa — cały przepływ w 5 krokach</h2>
  <div class="doc-flow">
    <div class="doc-step" style="border-color:#1a4a6a">
      <div style="font-size:11px;font-weight:800;color:#7dd3fc;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Krok 1</div>
      <div style="font-weight:700;color:white;margin-bottom:4px">📦 Definiujesz narzędzia</div>
      <div class="muted">Opisujesz CO AI ma robić — np. "wykonaj komendę oc get" albo "wywołaj to API". Robisz to w <b>Szybkim starcie</b>, <b>Kreatorze zaawansowanym</b> lub <b>Package Generator</b>.</div>
    </div>
    <div class="doc-arrow">↓</div>
    <div class="doc-step" style="border-color:#1a3a1a">
      <div style="font-size:11px;font-weight:800;color:#5ce89a;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Krok 2</div>
      <div style="font-weight:700;color:white;margin-bottom:4px">🖥️ Platforma generuje konfigurację</div>
      <div class="muted">Control plane tworzy pliki: <code>tools.json</code>, <code>policy.json</code>, <code>runtime-config.json</code>. Opisują co wolno uruchamiać i jak.</div>
    </div>
    <div class="doc-arrow">↓</div>
    <div class="doc-step" style="border-color:#2a2a0a">
      <div style="font-size:11px;font-weight:800;color:#f4c163;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Krok 3</div>
      <div style="font-weight:700;color:white;margin-bottom:4px">🐳 Operator uruchamia kontener Docker</div>
      <div class="muted">Kontener jest <b>rootless</b> (user 1000:1000), <b>read-only filesystem</b>, z limitem 512MB RAM i 1 CPU, odciętymi uprawnieniami (<code>cap_drop: ALL</code>) i izolacją sieciową.</div>
    </div>
    <div class="doc-arrow">↓</div>
    <div class="doc-step" style="border-color:#2a1a2a">
      <div style="font-size:11px;font-weight:800;color:#c084fc;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Krok 4</div>
      <div style="font-weight:700;color:white;margin-bottom:4px">🔌 Serwer MCP nasłuchuje</div>
      <div class="muted">Kontener wystawia endpoint np. <code>http://mcp.dom:19500/mcp</code> — wklejasz go do Continue, OpenWebUI lub innego klienta AI.</div>
    </div>
    <div class="doc-arrow">↓</div>
    <div class="doc-step" style="border-color:#1a3a4a">
      <div style="font-size:11px;font-weight:800;color:#7dd3fc;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Krok 5</div>
      <div style="font-weight:700;color:white;margin-bottom:4px">🤖 AI korzysta z narzędzi</div>
      <div class="muted">Gdy AI chce np. pobrać dane z API, wysyła zapytanie do endpointu MCP. Kontener wykonuje operację i zwraca wynik. AI widzi tylko wynik — nic więcej.</div>
    </div>
  </div>
</section>

<!-- Section: Sposoby tworzenia -->
<section>
  <h2>🛤️ Sposoby tworzenia serwera MCP</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">

    <div style="background:#0a1e10;border:2px solid #1a5a20;border-radius:12px;padding:18px">
      <div style="font-size:24px;margin-bottom:8px">⚡</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">Szybki start</div>
      <div class="muted" style="font-size:13px;line-height:1.7;margin-bottom:12px">
        Wypełnij 2-3 pola — serwer gotowy w 30 sekund. Dla osób które chcą szybko działającego serwera bez konfigurowania szczegółów.
      </div>
      <div style="font-size:12px;color:#5ce89a;line-height:1.8">
        ✅ REST API → wpisz URL<br>
        ✅ Komenda → wpisz np. <code>oc get ${'{'}*args{'}'}</code><br>
        ✅ Gotowy zestaw → wybierz z katalogu<br>
        ✅ Import z JSON/URL/Git
      </div>
      <a href="/quick-start" style="display:block;margin-top:14px;background:#1a7a3f;color:white;text-align:center;padding:8px;border-radius:6px;font-weight:700;font-size:13px;text-decoration:none">Otwórz →</a>
    </div>

    <div style="background:#0a1520;border:2px solid #1a3a50;border-radius:12px;padding:18px">
      <div style="font-size:24px;margin-bottom:8px">🛠️</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">Kreator zaawansowany</div>
      <div class="muted" style="font-size:13px;line-height:1.7;margin-bottom:12px">
        4-krokowy wizard z pełną kontrolą. Wybierz silnik (HTTP, Shell lub OpenAPI), paczkę lub zbuduj od zera — z własnym środowiskiem Docker i polityką.
      </div>
      <div style="font-size:12px;color:#7dd3fc;line-height:1.8">
        ✅ Wybór paczki tools<br>
        ✅ Własny obraz Docker (APT packages)<br>
        ✅ Silnik OpenAPI — auto-tools z dowolnego REST API<br>
        ✅ Pełna konfiguracja polityki
      </div>
      <a href="/create" style="display:block;margin-top:14px;background:#1a3a6a;color:white;text-align:center;padding:8px;border-radius:6px;font-weight:700;font-size:13px;text-decoration:none">Otwórz →</a>
    </div>

    <div style="background:#1a1020;border:2px solid #3a2050;border-radius:12px;padding:18px">
      <div style="font-size:24px;margin-bottom:8px">✨</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">Package Generator</div>
      <div class="muted" style="font-size:13px;line-height:1.7;margin-bottom:12px">
        Wizard do tworzenia paczek tools wielokrotnego użytku. Definiujesz tools, politykę i środowisko — generuje Package JSON gotowy do instalacji.
      </div>
      <div style="font-size:12px;color:#c084fc;line-height:1.8">
        ✅ Wizualny kreator z podglądem JSON<br>
        ✅ Shell + HTTP tools w jednej paczce<br>
        ✅ Własna baza obrazu Docker<br>
        ✅ Eksport / import / share
      </div>
      <a href="/tool-packages/generate" style="display:block;margin-top:14px;background:#3a1060;color:white;text-align:center;padding:8px;border-radius:6px;font-weight:700;font-size:13px;text-decoration:none">Otwórz →</a>
    </div>

    <div style="background:#0a1a10;border:2px solid #1a5040;border-radius:12px;padding:18px">
      <div style="font-size:24px;margin-bottom:8px">📄</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">OpenAPI Auto-MCP <span style="font-size:11px;background:#1a4a30;color:#5ce89a;border-radius:4px;padding:2px 6px;margin-left:6px;vertical-align:middle">nowość</span></div>
      <div class="muted" style="font-size:13px;line-height:1.7;margin-bottom:12px">
        Masz serwis z dokumentacją REST (openapi.json)? Podaj URL — platforma automatycznie generuje osobny tool dla każdego endpointu. Zero definiowania narzędzi.
      </div>
      <div style="font-size:12px;color:#5ce89a;line-height:1.8">
        ✅ Każdy endpoint REST = osobny tool MCP<br>
        ✅ Nazwy i opisy z dokumentacji spec<br>
        ✅ Wsparcie dla Bearer token / custom header<br>
        ✅ Dostępne w Kreatorze zaawansowanym
      </div>
      <a href="/create" style="display:block;margin-top:14px;background:#1a5040;color:white;text-align:center;padding:8px;border-radius:6px;font-weight:700;font-size:13px;text-decoration:none">Kreator zaawansowany →</a>
    </div>

  </div>
</section>

<!-- Section: Szybki start vs Kreator zaawansowany -->
<section>
  <h2>⚡ vs 🛠️ Kiedy użyć Szybkiego startu, a kiedy Kreatora zaawansowanego?</h2>

  <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:12px;padding:20px 24px;margin-bottom:16px">
    <div style="font-size:13px;color:var(--muted);line-height:1.8">
      Oba kreatory robią to samo — tworzą serwer MCP i uruchamiają kontener Docker.<br>
      Różnica jest w tym <b style="color:white">ile możesz skonfigurować</b> i <b style="color:white">ile czasu to zajmuje</b>.
    </div>
  </div>

  <div class="doc-grid2" style="gap:0;border:1px solid var(--line);border-radius:12px;overflow:hidden">

    <!-- Header -->
    <div style="background:#0a1e10;border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:22px;margin-bottom:4px">⚡</div>
      <div style="font-weight:800;color:white;font-size:16px">Szybki start</div>
      <div style="color:#5ce89a;font-size:12px;margin-top:4px">Gotowy serwer w 30 sekund</div>
    </div>
    <div style="background:#0a1520;border-bottom:1px solid var(--line);padding:14px 20px">
      <div style="font-size:22px;margin-bottom:4px">🛠️</div>
      <div style="font-weight:800;color:white;font-size:16px">Kreator zaawansowany</div>
      <div style="color:#7dd3fc;font-size:12px;margin-top:4px">Pełna kontrola, 4 kroki</div>
    </div>

    <!-- Dla kogo -->
    <div style="background:#0d1822;border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Dla kogo</div>
      <div style="font-size:13px;color:var(--text);line-height:1.7">
        Dla każdego. Nie musisz rozumieć jak działa platforma — wypełniasz formularz i klikasz <b>Uruchom</b>.
      </div>
    </div>
    <div style="background:#0d1822;border-bottom:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Dla kogo</div>
      <div style="font-size:13px;color:var(--text);line-height:1.7">
        Dla osób które chcą dobrać środowisko, politykę bezpieczeństwa i silnik wykonania ręcznie.
      </div>
    </div>

    <!-- Typy serwerów -->
    <div style="background:#0d1822;border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Typy serwerów</div>
      <div style="font-size:13px;color:var(--text);line-height:1.9">
        🌐 REST API — wpisz URL i metodę<br>
        🐚 Komenda shell — wpisz komendę<br>
        📦 Gotowy zestaw — wybierz z katalogu<br>
        📥 Import — z URL / pliku JSON / Gita
      </div>
    </div>
    <div style="background:#0d1822;border-bottom:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Typy serwerów</div>
      <div style="font-size:13px;color:var(--text);line-height:1.9">
        📦 Gotowa paczka — instaluje wszystkie tools z katalogu<br>
        🔧 Od zera — sam definiujesz tools po uruchomieniu<br>
        <span style="color:var(--muted)">+ pełny wybór silnika i obrazu Docker</span>
      </div>
    </div>

    <!-- Środowisko Docker -->
    <div style="background:#0d1822;border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Środowisko Docker</div>
      <div style="font-size:13px;line-height:1.7">
        <span style="color:#f4c163">⚠️ Automatyczne</span> — platforma dobiera obraz domyślny dla wybranego typu. Nie możesz zmienić bazy obrazu w tym widoku.
      </div>
    </div>
    <div style="background:#0d1822;border-bottom:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Środowisko Docker</div>
      <div style="font-size:13px;line-height:1.7">
        <span style="color:#5ce89a">✅ Pełny wybór</span> — wybierasz obraz bazowy (np. z <code>postgresql-client</code>, <code>curl</code>, <code>jq</code>), możesz też zbudować własny przez Runtime Image Builder.
      </div>
    </div>

    <!-- Polityka bezpieczeństwa -->
    <div style="background:#0d1822;border-bottom:1px solid var(--line);border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Polityka bezpieczeństwa</div>
      <div style="font-size:13px;line-height:1.7">
        <span style="color:#f4c163">⚠️ Uproszczona</span> — tylko denylist komend (co ma być zablokowane). Resztę ustawiasz później w widoku serwera.
      </div>
    </div>
    <div style="background:#0d1822;border-bottom:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Polityka bezpieczeństwa</div>
      <div style="font-size:13px;line-height:1.7">
        <span style="color:#5ce89a">✅ Pełna konfiguracja</span> — allowed binaries, blocked commands, limity payloadu, tryb read-only — wszystko w kroku 3 kreatora.
      </div>
    </div>

    <!-- Czas -->
    <div style="background:#0d1822;border-right:1px solid var(--line);padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Czas tworzenia</div>
      <div style="font-size:13px;color:#5ce89a;font-weight:700">~30 sekund</div>
      <div style="font-size:12px;color:var(--muted);margin-top:4px">2-3 pola do wypełnienia</div>
    </div>
    <div style="background:#0d1822;padding:14px 20px">
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Czas tworzenia</div>
      <div style="font-size:13px;color:#f4c163;font-weight:700">~2-5 minut</div>
      <div style="font-size:12px;color:var(--muted);margin-top:4px">4 kroki z pełną konfiguracją</div>
    </div>

  </div>

  <div style="background:#0b1505;border:1px solid #1a4a10;border-radius:10px;padding:14px 18px;margin-top:12px">
    <div style="font-weight:800;color:#5ce89a;margin-bottom:6px;font-size:13px">💡 Wskazówka</div>
    <div style="font-size:13px;color:var(--muted);line-height:1.7">
      Zacznij od <b style="color:white">Szybkiego startu</b> — jeśli serwer działa i chcesz zmienić obraz Docker lub politykę, zawsze możesz wejść w szczegóły serwera i zmienić ustawienia.<br>
      <b style="color:white">Kreator zaawansowany</b> używaj wtedy gdy wiesz z góry że potrzebujesz niestandardowego środowiska (np. własny obraz z <code>psql</code>) albo ścisłej polityki bezpieczeństwa od początku.
    </div>
  </div>

</section>

<!-- Section: OpenAPI Auto-MCP -->
<section>
  <h2>📄 OpenAPI Auto-MCP — MCP z dokumentacji REST API</h2>

  <div style="background:#061810;border:1px solid #1a4a30;border-radius:12px;padding:18px 22px;margin-bottom:16px">
    <div style="font-size:13px;color:var(--muted);line-height:1.9">
      <b style="color:white">Jak to działa?</b><br>
      Zamiast ręcznie definiować tools, podajesz URL serwisu który ma dokumentację OpenAPI (<code>openapi.json</code>).
      Platforma uruchamia kontener z silnikiem <b style="color:#5ce89a">FastMCP.from_openapi()</b> który:<br>
      <span style="margin-left:16px">1. Pobiera spec z <code>BACKEND_BASE_URL/openapi.json</code> lub <code>OPENAPI_SPEC_URL</code></span><br>
      <span style="margin-left:16px">2. Automatycznie tworzy osobny tool MCP dla każdego endpointu REST</span><br>
      <span style="margin-left:16px">3. Kieruje wywołania narzędzi bezpośrednio do serwisu backendowego</span><br>
      Żadna ręczna konfiguracja tools nie jest wymagana — nazwy, opisy i parametry pochodzi z dokumentacji spec.
    </div>
  </div>

  <div class="doc-grid2" style="gap:14px;margin-bottom:16px">

    <div class="doc-card" style="background:#0a1a10;border-color:#1a4a20">
      <h3 style="color:#5ce89a">Kiedy używać?</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        ✅ Serwis ma gotową dokumentację <code>openapi.json</code> / <code>swagger.json</code><br>
        ✅ Chcesz udostępnić <b>wiele endpointów</b> bez pisania każdego ręcznie<br>
        ✅ API zmienia się często — spec auto-odświeża tools przy restarcie<br>
        ✅ Zewnętrzne serwisy z publicznym spec (GitLab, Jira, własne API)<br><br>
        ❌ Serwis nie ma dokumentacji OpenAPI → użyj HTTP Gateway lub Shell
      </div>
    </div>

    <div class="doc-card" style="background:#0a1520;border-color:#1a3a50">
      <h3 style="color:#7dd3fc">Jak uruchomić?</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        1. Idź do <a href="/create" style="color:#7dd3fc">Kreator zaawansowany</a><br>
        2. Krok 1 — wybierz silnik <b>📄 OpenAPI Spec</b><br>
        3. Wpisz <b>URL serwisu</b> (np. <code>http://moja-api:8000</code>)<br>
        4. Opcjonalnie: URL do spec, token autoryzacji<br>
        5. Krok 2 → 3 → 4 — reszta jak zwykle<br><br>
        Kontener startuje z obrazem <code>mcp-runtime-openapi:latest</code>.
      </div>
    </div>

  </div>

  <!-- Env vars table -->
  <div style="font-weight:700;color:white;margin-bottom:10px;font-size:14px">⚙️ Zmienne środowiskowe (konfiguracja kontenera)</div>
  <div style="background:#060e18;border:1px solid #1a2e45;border-radius:10px;overflow:hidden;font-size:13px">
    <div style="display:grid;grid-template-columns:220px 1fr 120px;background:#0a1830;padding:8px 14px;font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px">
      <div>Zmienna</div><div>Opis</div><div>Wymagana</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45">
      <code style="color:#5ce89a">BACKEND_BASE_URL</code>
      <div style="color:var(--muted);padding-left:12px">Bazowy URL serwisu backendowego (np. <code>http://moja-api:8000</code>). Używany do kierowania wywołań narzędzi.</div>
      <div style="color:#f4c163;padding-left:8px">✅ wymagana</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45;background:#080e18">
      <code style="color:#7dd3fc">OPENAPI_SPEC_URL</code>
      <div style="color:var(--muted);padding-left:12px">Pełny URL do pliku <code>openapi.json</code>. Domyślnie: <code>BACKEND_BASE_URL/openapi.json</code></div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45">
      <code style="color:#7dd3fc">OPENAPI_SPEC_FILE</code>
      <div style="color:var(--muted);padding-left:12px">Ścieżka do lokalnego pliku spec (nadpisuje URL). Przydatne gdy spec jest zamontowany jako plik.</div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45;background:#080e18">
      <code style="color:#7dd3fc">BACKEND_AUTH_TOKEN</code>
      <div style="color:var(--muted);padding-left:12px">Token autoryzacji do serwisu (Bearer token lub inny). Bezpiecznie przechowywany tylko w kontenerze.</div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45">
      <code style="color:#7dd3fc">BACKEND_AUTH_HEADER</code>
      <div style="color:var(--muted);padding-left:12px">Nazwa nagłówka autoryzacji. Domyślnie: <code>Authorization</code></div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45;background:#080e18">
      <code style="color:#7dd3fc">BACKEND_AUTH_PREFIX</code>
      <div style="color:var(--muted);padding-left:12px">Prefix wartości nagłówka autoryzacji. Domyślnie: <code>Bearer</code></div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
    <div style="display:grid;grid-template-columns:220px 1fr 120px;padding:10px 14px;border-top:1px solid #1a2e45">
      <code style="color:#7dd3fc">SERVER_NAME</code>
      <div style="color:var(--muted);padding-left:12px">Nazwa serwera MCP widoczna dla klientów AI. Domyślnie: <code>openapi-mcp</code></div>
      <div style="color:var(--muted);padding-left:8px">opcjonalna</div>
    </div>
  </div>

  <div style="background:#0a1a10;border:1px solid #1a4a20;border-radius:8px;padding:12px 16px;margin-top:14px;font-size:13px">
    💡 <b style="color:#5ce89a">Auto-detekcja spec:</b> Jeśli serwis to runtime tej platformy, kontener najpierw próbuje pobrać spec z <code>/openwebui/openapi.json</code> (tylko user-defined tools, czyste nazwy). Jeśli nie ma — pobiera standardowy <code>/openapi.json</code>. Dotyczy to scenariusza "MCP z MCP" — czyli gdy AI używa OpenAPI Auto-MCP do sterowania innym serwerem MCP z tej platformy.
  </div>

</section>

<!-- Section: Schemat architektury -->
<section>
  <h2>🏗️ Schemat — jak platforma działa pod spodem</h2>

  <div style="background:#060e18;border:1px solid #1a2e45;border-radius:14px;padding:28px 24px;overflow-x:auto">

    <!-- Row 1: AI Clients -->
    <div style="text-align:center;margin-bottom:6px">
      <div style="display:inline-flex;gap:10px;flex-wrap:wrap;justify-content:center">
        <div style="background:#1a1030;border:1px solid #3a2060;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:700;color:#c084fc">🤖 Claude / ChatGPT</div>
        <div style="background:#1a1030;border:1px solid #3a2060;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:700;color:#c084fc">💬 Continue.dev</div>
        <div style="background:#1a1030;border:1px solid #3a2060;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:700;color:#c084fc">🌐 OpenWebUI</div>
        <div style="background:#1a1030;border:1px solid #3a2060;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:700;color:#c084fc">⚙️ Dowolny klient MCP</div>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-top:6px">Klienci AI — wklejasz tam adres endpointu MCP</div>
    </div>

    <!-- Arrow down -->
    <div style="text-align:center;font-size:22px;color:#3a5a7a;margin:4px 0">↓ <span style="font-size:11px;color:var(--muted);vertical-align:middle">JSON-RPC 2.0 / HTTP</span></div>

    <!-- Row 2: MCP Containers -->
    <div style="border:2px solid #1a3a5a;border-radius:12px;padding:16px;margin-bottom:4px">
      <div style="font-size:11px;font-weight:800;color:#7dd3fc;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px;text-align:center">
        🐳 Kontenery Docker — MCP Runtime
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">

        <div style="background:#0a1a2a;border:1px solid #1a3a4a;border-radius:8px;padding:12px">
          <div style="font-size:11px;font-weight:800;color:#5ce89a;margin-bottom:6px">HTTP Gateway Runtime</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.7">
            Wywołuje zewnętrzne API<br>
            <code style="color:#7dd3fc">http_request</code> adapter<br>
            Port: 8080 → <code>/mcp</code>
          </div>
          <div style="margin-top:8px;font-size:10px;background:#061018;border-radius:4px;padding:4px 7px;color:#3a7a5a">
            🔒 read-only FS · cap_drop ALL<br>
            user 1000:1000 · 512MB RAM
          </div>
        </div>

        <div style="background:#0a1a2a;border:1px solid #1a3a4a;border-radius:8px;padding:12px">
          <div style="font-size:11px;font-weight:800;color:#f4c163;margin-bottom:6px">Shell Runtime</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.7">
            Wykonuje komendy shell<br>
            <code style="color:#7dd3fc">shell</code> adapter<br>
            Port: 8080 → <code>/mcp</code>
          </div>
          <div style="margin-top:8px;font-size:10px;background:#061018;border-radius:4px;padding:4px 7px;color:#3a7a5a">
            🔒 read-only FS · cap_drop ALL<br>
            policy check przed exec
          </div>
        </div>

        <div style="background:#061810;border:1px solid #1a4a30;border-radius:8px;padding:12px">
          <div style="font-size:11px;font-weight:800;color:#34d399;margin-bottom:6px">OpenAPI Runtime</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.7">
            Auto-tools z OpenAPI spec<br>
            <code style="color:#7dd3fc">FastMCP.from_openapi()</code><br>
            Port: 8080 → <code>/mcp</code>
          </div>
          <div style="margin-top:8px;font-size:10px;background:#061018;border-radius:4px;padding:4px 7px;color:#3a7a5a">
            🔒 read-only FS · cap_drop ALL<br>
            spec → tools przy starcie
          </div>
        </div>

        <div style="background:#0a1a2a;border:1px dashed #2a3a4a;border-radius:8px;padding:12px">
          <div style="font-size:11px;font-weight:800;color:var(--muted);margin-bottom:6px">Własny Runtime</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.7">
            Zbudowany przez Runtime<br>
            Image Builder (APT + pip)<br>
            <span style="color:#7dd3fc">np. z psql, awscli...</span>
          </div>
          <div style="margin-top:8px;font-size:10px;background:#061018;border-radius:4px;padding:4px 7px;color:#3a7a5a">
            🔒 Te same ograniczenia<br>
            + własne narzędzia
          </div>
        </div>

      </div>

      <!-- Config files injected -->
      <div style="margin-top:10px;border-top:1px solid #1a2e40;padding-top:10px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
        <div style="font-size:11px;color:var(--muted)">📁 Konfiguracja wstrzykiwana do kontenera:</div>
        <code style="font-size:11px;background:#0d1a2a;padding:2px 7px;border-radius:4px;color:#7dd3fc">tools.json</code>
        <code style="font-size:11px;background:#0d1a2a;padding:2px 7px;border-radius:4px;color:#7dd3fc">policy.json</code>
        <code style="font-size:11px;background:#0d1a2a;padding:2px 7px;border-radius:4px;color:#7dd3fc">runtime-config.json</code>
      </div>
    </div>

    <!-- Arrow up from operator -->
    <div style="text-align:center;font-size:22px;color:#3a5a7a;margin:4px 0">↑ <span style="font-size:11px;color:var(--muted);vertical-align:middle">docker run / stop / inspect</span></div>

    <!-- Row 3: Control Plane + Operator -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:4px">

      <div style="background:#0a1a10;border:2px solid #1a4a20;border-radius:12px;padding:16px">
        <div style="font-size:11px;font-weight:800;color:#5ce89a;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">🖥️ Control Plane (FastAPI)</div>
        <div style="font-size:12px;color:var(--muted);line-height:1.9">
          • UI — kreatory, widoki serwerów<br>
          • REST API — zarządzanie runtimeami<br>
          • Zapis konfiguracji do <code>tools.json</code><br>
          • Kolejka <code>deployment_requests</code><br>
          • RBAC — sesje, role, rejestracja<br>
          • Audit log każdej operacji
        </div>
      </div>

      <div style="background:#1a0a10;border:2px solid #4a1a20;border-radius:12px;padding:16px">
        <div style="font-size:11px;font-weight:800;color:#f47a80;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">⚙️ Operator (reconciler)</div>
        <div style="font-size:12px;color:var(--muted);line-height:1.9">
          • Polling co 5s — szuka nowych zadań<br>
          • Docker SDK — uruchamia kontenery<br>
          • Bezpieczeństwo baseline:<br>
          &nbsp;&nbsp;<code style="font-size:11px">read_only=True</code> · <code style="font-size:11px">cap_drop=ALL</code><br>
          &nbsp;&nbsp;<code style="font-size:11px">mem_limit=512m</code> · <code style="font-size:11px">user=1000</code><br>
          • Raportuje status z powrotem do DB
        </div>
      </div>

    </div>

    <!-- Arrow down to DB -->
    <div style="text-align:center;font-size:22px;color:#3a5a7a;margin:4px 0">↕ <span style="font-size:11px;color:var(--muted);vertical-align:middle">SQLite WAL</span></div>

    <!-- Row 4: Storage -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">

      <div style="background:#0d1420;border:1px solid #1a2a40;border-radius:10px;padding:12px">
        <div style="font-size:11px;font-weight:800;color:#7dd3fc;margin-bottom:6px">🗄️ SQLite — mcp_platform.db</div>
        <div style="font-size:11px;color:var(--muted);line-height:1.8">
          runtimes · tools · policies<br>
          deployment_requests · audit_log<br>
          users · sessions · tool_packages
        </div>
      </div>

      <div style="background:#0d1420;border:1px solid #1a2a40;border-radius:10px;padding:12px">
        <div style="font-size:11px;font-weight:800;color:#7dd3fc;margin-bottom:6px">📂 /data/configs/</div>
        <div style="font-size:11px;color:var(--muted);line-height:1.8">
          Po jednym katalogu na runtime<br>
          <code>tools.json</code> · <code>policy.json</code><br>
          Montowane jako volume do kontenera
        </div>
      </div>

    </div>

  </div>

  <!-- Legend -->
  <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;padding:10px 14px;background:var(--panel-2);border-radius:8px;font-size:11px;color:var(--muted)">
    <span>🟣 Klient AI — inicjuje zapytanie</span>
    <span>🔵 Kontener Docker — izolowane środowisko wykonania</span>
    <span>🟢 Control Plane — mózg platformy</span>
    <span>🔴 Operator — ręce platformy (Docker API)</span>
  </div>

</section>

<!-- Section: Bezpieczeństwo w kreatorach -->
<section>
  <h2>🔒 Bezpieczeństwo — co możesz kontrolować i gdzie</h2>

  <div style="background:#060e18;border:1px solid #1a2e45;border-radius:12px;overflow:hidden;margin-bottom:12px">

    <!-- Header row -->
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;background:#0a1a28;border-bottom:1px solid #1a2e45">
      <div style="padding:10px 16px;font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px">Zabezpieczenie</div>
      <div style="padding:10px 16px;font-size:11px;font-weight:800;color:#5ce89a;text-transform:uppercase;letter-spacing:1px;text-align:center">⚡ Szybki start</div>
      <div style="padding:10px 16px;font-size:11px;font-weight:800;color:#7dd3fc;text-transform:uppercase;letter-spacing:1px;text-align:center">🛠️ Kreator</div>
      <div style="padding:10px 16px;font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;text-align:center">Widok serwera</div>
    </div>

    <!-- Rows -->
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Allowed binaries<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">tylko ta binarka może być uruchamiana</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#f4c163">auto z komendy</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ ręczna lista</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Allowed prefix<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">AI może tylko oc get ..., nie oc delete</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ jedno pole</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pełna lista</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Blocked commands / denylist<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">konkretne komendy zawsze zablokowane</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ wieloliniowy</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pełna lista</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Tryb read-only<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">blokuje wszystkie narzędzia write/destructive</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ checkbox</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ checkbox</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ toggle</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Limit czasu (timeout)<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">max ile sekund może działać komenda</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pole (s)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pole (s)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Max rozmiar odpowiedzi<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">ile KB/MB AI może dostać</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pole (KB)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ pole (KB)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Max payload (request)<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">max rozmiar danych wejściowych od AI</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#3a9aba">— (256KB auto)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ konfigurowalne</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr;border-bottom:1px solid #111e2c">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Block write tools<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">blokuje narzędzia w trybie write</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#3a9aba">— (przez read-only)</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ osobny checkbox</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ edytor</div>
    </div>
    <div style="display:grid;grid-template-columns:1.8fr 1fr 1fr 1fr">
      <div style="padding:10px 16px;font-size:12px;color:white;font-weight:600">Bezpieczeństwo kontenera<div style="font-size:11px;color:var(--muted);font-weight:400;margin-top:2px">read-only FS, cap_drop ALL, user 1000, 512MB</div></div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ zawsze</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ zawsze</div>
      <div style="padding:10px 16px;font-size:12px;text-align:center;color:#5ce89a">✅ zawsze</div>
    </div>

  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">

    <div style="background:#0a1505;border:1px solid #1a4a10;border-radius:10px;padding:14px 16px">
      <div style="font-weight:800;color:#5ce89a;font-size:13px;margin-bottom:8px">💡 Jak działa Allowed Prefix?</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.8">
        Wpisujesz prefix np. <code style="color:#7dd3fc">oc get</code><br>
        → AI może wywołać <code>oc get pods -n prod</code> ✅<br>
        → AI <b>nie może</b> wywołać <code>oc delete pod xyz</code> ❌<br>
        → AI <b>nie może</b> wywołać <code>oc exec</code> ❌<br><br>
        Działa nawet gdy komenda ma <code>${'{'}*args{'}'}</code> — platforma sprawdza prefix <b>po</b> podstawieniu argumentów.
      </div>
    </div>

    <div style="background:#150a05;border:1px solid #4a2a10;border-radius:10px;padding:14px 16px">
      <div style="font-weight:800;color:#f4c163;font-size:13px;margin-bottom:8px">⚠️ Bezpieczeństwo kontenera jest zawsze włączone</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.8">
        Niezależnie od tego co skonfigurujesz w polityce, <b>każdy</b> kontener uruchamia się z:<br>
        🔒 <code>read_only=True</code> — filesystem tylko do odczytu<br>
        🔒 <code>cap_drop=ALL</code> — zero uprawnień systemowych<br>
        🔒 <code>user=1000:1000</code> — nie jako root<br>
        🔒 <code>mem_limit=512MB</code> — limit pamięci<br>
        🔒 <code>no-new-privileges</code> — nie może eskalować uprawnień
      </div>
    </div>

  </div>

</section>

<!-- Section: Przykłady -->
<section>
  <h2>💡 Przykłady zastosowań</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
    <div class="doc-scenario">
      <div style="font-size:22px;margin-bottom:8px">🌐</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">REST API firmy</div>
      <div class="muted" style="font-size:13px;line-height:1.7">Masz wewnętrzne API (<code>api.firma.pl</code>). Tworzysz serwer MCP → AI może pytać "znajdź umowy z 2024" → kontener wywołuje API → AI dostaje wyniki. Token jest tylko w kontenerze, AI go nie widzi.</div>
    </div>
    <div class="doc-scenario shell">
      <div style="font-size:22px;margin-bottom:8px">🔴</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">OpenShift / Kubernetes</div>
      <div class="muted" style="font-size:13px;line-height:1.7">Tool: <code>oc get ${'{'}*args{'}'}</code> z prefixem <code>oc get</code> → AI może zapytać "jakie pody działają w prod?" → wykonuje <code>oc get pods -n production</code>. Nie może <code>oc delete</code> — zablokowane policy.</div>
    </div>
    <div class="doc-scenario ext">
      <div style="font-size:22px;margin-bottom:8px">🗄️</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">Baza danych (psql)</div>
      <div class="muted" style="font-size:13px;line-height:1.7">Budujesz własny obraz z <code>postgresql-client</code> (Runtime Image Builder) → tool: <code>psql -h db.firma.pl -U user -c "${'{'}query{'}'}"</code> → AI może czytać dane z DB bez dostępu do hosta.</div>
    </div>
    <div class="doc-scenario" style="background:#061810;border-color:#1a4a30">
      <div style="font-size:22px;margin-bottom:8px">📄</div>
      <div style="font-weight:800;color:white;margin-bottom:6px">OpenAPI Auto-MCP (GitLab / Jira / własne API)</div>
      <div class="muted" style="font-size:13px;line-height:1.7">
        Masz serwis z <code>openapi.json</code> (np. GitLab CE, Jira, własne FastAPI). Kreator zaawansowany → silnik <b>OpenAPI Spec</b> → wpisz URL → platforma automatycznie tworzy tool dla każdego endpointu. AI może od razu pytać o zasoby — zero ręcznej konfiguracji tools.
      </div>
    </div>
  </div>
</section>

<!-- Section: Typy zmiennych -->
<section>
  <h2>⌨️ Jak pisać komendy shell — zmienne</h2>
  <div class="doc-grid2" style="gap:14px">
    <div class="doc-card" style="background:#0a1520;border-color:#1a3a50">
      <h3 style="color:#7dd3fc">${'{'}zmienna{'}'} — jeden parametr</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        Każde <code>${'{'}var{'}'}</code> = jeden argument. AI podaje konkretną wartość.<br><br>
        <b style="color:white">Przykład:</b><br>
        Tool: <code>oc get pods -n ${'{'}namespace{'}'}</code><br>
        AI wywołuje: <code>namespace = "production"</code><br>
        Wynik: <code>oc get pods -n production</code>
      </div>
    </div>
    <div class="doc-card" style="background:#1a1000;border-color:#3a2a00">
      <h3 style="color:#f4c163">${'{'}*args{'}'} — pełny dostęp (multi-arg)</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        <code>${'{'}*args{'}'}</code> = AI podaje wszystkie argumenty naraz. Runtime rozdziela je przez <code>shlex.split</code>.<br><br>
        <b style="color:white">Przykład:</b><br>
        Tool: <code>oc get ${'{'}*args{'}'}</code><br>
        AI wywołuje: <code>args = "pods -n production -o json"</code><br>
        Wynik: <code>oc get pods -n production -o json</code>
      </div>
    </div>
  </div>
  <div style="background:#0a1a0a;border:1px solid #1a4a1a;border-radius:8px;padding:12px 14px;margin-top:12px;font-size:13px">
    🛡️ <b style="color:#5ce89a">Bezpieczeństwo:</b> Runtime używa <code>subprocess.run()</code> bez <code>shell=True</code> — żadna iniekcja przez znaki specjalne nie przejdzie. Dodatkowo policy sprawdza prefix komendy przed wykonaniem.
  </div>
</section>

<!-- Section: RBAC -->
<section>
  <h2>👥 Role użytkowników (RBAC)</h2>
  <div class="doc-grid3">
    <div class="role-card" style="background:#1e252e;border:1px solid #2b394a">
      <div style="font-weight:800;color:#7a92a8;font-size:15px;margin-bottom:8px">👁️ read_only</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.8">
        ✅ Podgląd dashboard<br>
        ✅ Lista serwerów MCP<br>
        ✅ Audit i logi<br>
        ✅ Bezpieczeństwo (widok)<br>
        ❌ Tworzenie serwerów<br>
        ❌ Deploy / modyfikacje
      </div>
    </div>
    <div class="role-card" style="background:#0e2e1e;border:1px solid #1a5a38">
      <div style="font-weight:800;color:#5ce89a;font-size:15px;margin-bottom:8px">✏️ read_write</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.8">
        ✅ Wszystko z read_only<br>
        ✅ Szybki start<br>
        ✅ Kreator zaawansowany<br>
        ✅ Deploy / stop / restart<br>
        ❌ Package Generator<br>
        ❌ Image Builder<br>
        ❌ Silniki / Typy środowisk
      </div>
    </div>
    <div class="role-card" style="background:#2a1040;border:1px solid #5a2a80">
      <div style="font-weight:800;color:#c084fc;font-size:15px;margin-bottom:8px">👑 admin</div>
      <div style="font-size:13px;color:var(--muted);line-height:1.8">
        ✅ Pełny dostęp<br>
        ✅ Package Generator<br>
        ✅ Runtime Image Builder<br>
        ✅ Silniki / Typy środowisk<br>
        ✅ Panel użytkowników<br>
        ✅ Akceptacja rejestracji
      </div>
    </div>
  </div>
  <div style="background:#0d1e2e;border:1px solid #1a3a50;border-radius:8px;padding:12px 14px;margin-top:12px;font-size:13px;color:#7ab8d8">
    ℹ️ <b>Rejestracja:</b> Użytkownik zgłasza konto przez <code>/register</code> → admin akceptuje w <a href="/admin/users">Panelu użytkowników</a> i nadaje rolę. Pierwsze konto: login <code>admin</code>, hasło <code>admin</code> — zmień po pierwszym logowaniu.
  </div>
</section>

<!-- Section: Środowiska Docker -->
<section>
  <h2>🐳 Środowiska wykonania (obrazy Docker)</h2>
  <div class="doc-grid2">
    <div class="doc-card">
      <h3>🐚 mcp-runtime-shell:latest</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        Baza: <code>python:3.12-slim</code> (Debian)<br>
        Zawiera: <code>oc</code> <code>kubectl</code> <code>curl</code> <code>jq</code> <code>bash</code> <code>grep</code> <code>sed</code> <code>awk</code><br>
        Użyj gdy: komendy CLI — OpenShift, Kubernetes, HTTP przez curl
      </div>
    </div>
    <div class="doc-card">
      <h3>🌐 mcp-runtime-http-gateway:latest</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        Baza: <code>python:3.12-slim</code> (Debian)<br>
        Zawiera: runtime HTTP do wywoływania REST API<br>
        Użyj gdy: wywołania REST API (GitLab, Jira, własny serwis)
      </div>
    </div>
    <div class="doc-card" style="background:#061810;border-color:#1a4a30">
      <h3 style="color:#34d399">📄 mcp-runtime-openapi:latest</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        Baza: <code>python:3.12-slim</code> (Debian)<br>
        Zawiera: <code>fastmcp</code>, <code>httpx</code>, <code>uvicorn</code> — auto-MCP z OpenAPI spec<br>
        Użyj gdy: silnik OpenAPI w Kreatorze zaawansowanym — podajesz URL serwisu i dostajesz tools automatycznie
      </div>
    </div>
    <div class="doc-card" style="grid-column:1/-1;background:#1a1000;border-color:#3a2a00">
      <h3 style="color:#f4c163">🛠️ Własny obraz (Runtime Image Builder)</h3>
      <div class="muted" style="font-size:13px;line-height:1.8">
        Potrzebujesz <code>psql</code>, <code>terraform</code>, <code>awscli</code> lub innych narzędzi? Idź do <b>Paczki tools → Runtime Image Builder</b> lub do <b>Szybki start → Komenda → Własne narzędzia</b>.<br>
        Wpisujesz pakiety APT (np. <code>postgresql-client</code>) → platforma buduje obraz na bazie standardowego (~2-5 min) → nowy obraz dostępny jako opcja przy tworzeniu serwera.
      </div>
    </div>
  </div>
</section>

<!-- Section: FAQ -->
<section>
  <h2>❓ Najczęstsze pytania</h2>
  <div>
    <div class="qa-item">
      <div class="qa-q">Wpisałem <code>postgres-client</code> w Image Builder i dostałem błąd 100.</div>
      <div class="qa-a">Błąd 100 z apt-get = paczka nie istnieje. Na Debianie prawidłowa nazwa to <code>postgresql-client</code> (nie postgres-client). Zawsze sprawdzaj nazwy na <code>packages.debian.org</code>.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Mam repo GitHub z gotowym serwerem MCP w C# / Node.js — czy mogę go zaimportować?</div>
      <div class="qa-a">Nie bezpośrednio. <b>Import JSON</b> w Szybkim starcie działa tylko z Package JSON tej platformy (format z polami <code>tools</code>, <code>runtime_class</code>, <code>policy</code>). Dla zewnętrznych serwerów MCP: uruchom go osobno i zarejestruj endpoint w <b>Zewnętrzne MCP</b>. Jeśli repo ma Dockerfile, użyj Runtime Image Builder.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Jak dać AI dostęp do pełnego <code>oc get</code> bez definiowania 20 komend?</div>
      <div class="qa-a">Użyj składni <code>oc get ${'{'}*args{'}'}</code> — AI podaje wszystkie argumenty naraz (np. <code>"pods -n production -o json"</code>). W kroku bezpieczeństwa ustaw <b>Dozwolony prefix: oc get</b> — AI może TYLKO wykonywać <code>oc get ...</code>, nie <code>oc delete</code> ani inne komendy.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Czy AI może zrobić cokolwiek chce na moim serwerze?</div>
      <div class="qa-a">Nie. Trzy warstwy ochrony: (1) <b>Policy</b> — sprawdza prefix komendy i dozwolone binarki; (2) <b>subprocess bez shell=True</b> — żadna iniekcja; (3) <b>Hardening kontenera</b> — rootless, read-only FS, cap_drop ALL, izolacja sieciowa.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Jak zmienić tools bez restartu serwera?</div>
      <div class="qa-a">Edytuj tool na stronie serwera → kliknij <b>♻️ Reload Config</b>. Kontener przeładuje <code>tools.json</code> i <code>policy.json</code> bez restartu — zmiana zajmuje sekundy.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Jak podłączyć serwer MCP do Continue lub OpenWebUI?</div>
      <div class="qa-a">Na stronie uruchomionego serwera (Moje serwery → kliknij serwer) znajdziesz sekcję <b>🔌 Jak podłączyć do klienta AI?</b> z gotowymi snippetami dla Continue, OpenWebUI i innych klientów. Każdy snippet jest klikalny — kopiuje się do schowka.</div>
    </div>
    <div class="qa-item">
      <div class="qa-q">Jak zarejestrować nowe konto?</div>
      <div class="qa-a">Idź na <a href="/register">/register</a>, wpisz login, hasło i żądaną rolę. Konto jest nieaktywne do momentu akceptacji przez administratora. Admin akceptuje w <b>👥 Użytkownicy</b> i nadaje rolę.</div>
    </div>
  </div>
</section>

<!-- Section: Gdzie zacząć -->
<section style="background:linear-gradient(135deg,#0d1e2e,#0d2a1a);border-color:#1a5a3a">
  <h2 style="color:#5ce89a">🚀 Gdzie zacząć?</h2>
  <div class="doc-grid3" style="gap:12px">
    <a href="/quick-start" style="display:flex;flex-direction:column;gap:8px;background:#0a1e10;border:1px solid #1a5a20;border-radius:10px;padding:16px;text-decoration:none">
      <div style="font-size:26px">⚡</div>
      <div style="font-weight:800;color:white">Szybki start</div>
      <div class="muted" style="font-size:12px">Wypełnij 2-3 pola → serwer gotowy w 30 sekund</div>
    </a>
    <a href="/tool-packages/generate" style="display:flex;flex-direction:column;gap:8px;background:#0a1520;border:1px solid #1a3a50;border-radius:10px;padding:16px;text-decoration:none">
      <div style="font-size:26px">✨</div>
      <div style="font-weight:800;color:white">Package Generator</div>
      <div class="muted" style="font-size:12px">Wizard do tworzenia paczek tools wielokrotnego użytku</div>
    </a>
    <a href="/external-mcp" style="display:flex;flex-direction:column;gap:8px;background:#1a1020;border:1px solid #3a2050;border-radius:10px;padding:16px;text-decoration:none">
      <div style="font-size:26px">🔗</div>
      <div style="font-weight:800;color:white">Zewnętrzne MCP</div>
      <div class="muted" style="font-size:12px">Masz gotowy serwer MCP? Zarejestruj endpoint i monitoruj</div>
    </a>
  </div>
</section>
"""
    return page_shell("docs", body)




async def _probe_mcp_server(url: str, auth_type: str, auth_token: str) -> dict[str, Any]:
    """Probe an external MCP server — tries /health, /tools REST, then MCP protocol."""
    if not _is_safe_fetch_url(url):
        return {"status": "error", "tools": [], "error": f"URL not allowed: private/internal addresses are blocked"}
    headers: dict[str, str] = {}
    if auth_type == "bearer" and auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif auth_type == "api_key" and auth_token:
        headers["X-API-Key"] = auth_token
    elif auth_type == "basic" and auth_token:
        import base64
        headers["Authorization"] = "Basic " + base64.b64encode(auth_token.encode()).decode()

    mcp_url = url.rstrip("/")
    base_url = mcp_url[:-4] if mcp_url.endswith("/mcp") else mcp_url

    tools: list[dict] = []
    errors: list[str] = []
    status = "unknown"

    async with httpx.AsyncClient(timeout=10, headers=headers, follow_redirects=True) as client:
        try:
            r = await client.get(f"{base_url}/health")
            status = "healthy" if r.status_code == 200 else "unhealthy"
            if r.status_code != 200:
                errors.append(f"health HTTP {r.status_code}")
        except Exception as exc:
            errors.append(f"health: {exc}")

        try:
            r = await client.get(f"{base_url}/tools")
            if r.status_code == 200:
                data = r.json()
                rest_tools = data.get("tools", [])
                if rest_tools:
                    tools = rest_tools
                    status = "healthy"
        except Exception:
            pass

        if not tools:
            try:
                r = await client.post(mcp_url if mcp_url.endswith("/mcp") else f"{base_url}/mcp", json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "MCP Platform", "version": "0.1"}},
                })
                if r.status_code == 200:
                    r2 = await client.post(mcp_url if mcp_url.endswith("/mcp") else f"{base_url}/mcp", json={
                        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
                    })
                    if r2.status_code == 200:
                        result = r2.json().get("result", {})
                        tools = result.get("tools", [])
                    status = "healthy"
            except Exception as exc:
                errors.append(f"mcp: {exc}")

    if status == "unknown":
        status = "unreachable"

    return {
        "ok": status == "healthy",
        "status": status,
        "tools": tools,
        "error": "; ".join(errors) if errors and status != "healthy" else None,
    }


@app.get("/external-mcp", response_class=HTMLResponse)
def external_mcp_page(error: str = "", ok: str = "") -> str:
    servers = store.rows("SELECT * FROM external_mcp_servers ORDER BY name")
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    success = f'<div class="alert" style="border-color:#1a7a3f;background:#0d2e1a;color:#8ee7b3">{escape(ok)}</div>' if ok else ""

    rows_html = ""
    for srv in servers:
        tools = json.loads(srv["tools_json"] or "[]")
        tool_names = [escape(t.get("name", "?")) for t in tools]
        tool_preview = ", ".join(tool_names[:6]) + (f" +{len(tools) - 6} więcej" if len(tools) > 6 else "")
        tool_rows = "".join(
            f'<tr><td><b>{escape(t.get("name","?"))}</b></td><td class="muted">{escape(t.get("description","")[:100])}</td></tr>'
            for t in tools
        )
        tool_section = f"""
          <details style="margin-top:8px">
            <summary class="muted" style="font-size:12px">{len(tools)} tools — rozwiń</summary>
            <table style="margin-top:6px;font-size:12px">
              <thead><tr><th>Tool</th><th>Opis</th></tr></thead>
              <tbody>{tool_rows}</tbody>
            </table>
          </details>
        """ if tools else '<span class="muted">brak odkrytych tools</span>'

        status_css = "running" if srv["status"] == "healthy" else ("failed" if srv["status"] in {"unreachable","unhealthy"} else "")
        rows_html += f"""
        <tr>
          <td>
            <b>{escape(srv['name'])}</b>
            <div class="muted" style="font-size:12px">{escape(srv['description'])}</div>
          </td>
          <td><code style="font-size:12px;word-break:break-all">{escape(srv['endpoint_url'])}</code></td>
          <td><span class="badge {status_css}">{escape(srv['status'])}</span>
            {"<div class='muted' style='font-size:11px;margin-top:2px'>" + escape(srv['last_error'][:80]) + "</div>" if srv.get('last_error') else ""}
          </td>
          <td>
            {tool_section}
          </td>
          <td class="muted" style="font-size:12px">{escape(srv['last_checked_at'] or 'nigdy')}</td>
          <td>
            <div class="actions compact">
              <form method="post" action="/api/external-mcp/{srv['id']}/check">
                <button title="Sprawdź status i odkryj tools">Check</button>
              </form>
              <form method="post" action="/api/external-mcp/{srv['id']}/delete"
                    onsubmit="return confirm('Usunąć ten external MCP server z rejestru?')">
                <button class="delete">Usuń</button>
              </form>
            </div>
          </td>
        </tr>
        """

    body = f"""
    {alert}{success}
    <section>
      <h2>External MCP Servers</h2>
      <p class="muted">
        Zewnętrzne MCP servery — działające poza platformą, niedeployowane przez operatora.
        Platforma odkrywa ich tools i monitoruje status. Możesz np. podłączyć:
        GitHub MCP, serwery z innej infrastruktury, lokalne dev servery, serwery teammates.
      </p>
      {"<p class='muted'>Brak zarejestrowanych external MCP servers. Dodaj poniżej.</p>" if not servers else ""}
      {"<table><thead><tr><th>Nazwa</th><th>Endpoint</th><th>Status</th><th>Tools</th><th>Ostatni check</th><th>Akcja</th></tr></thead><tbody>" + rows_html + "</tbody></table>" if servers else ""}
    </section>
    <section>
      <h2>Zarejestruj External MCP Server</h2>
      <p class="muted">Po rejestracji platforma automatycznie sprawdzi status i odkryje tools przez MCP protocol.</p>
      <form method="post" action="/api/external-mcp">
        <div class="grid">
          <label>Nazwa<input name="name" placeholder="GitHub MCP" required></label>
          <label>Endpoint URL
            <input name="endpoint_url" placeholder="http://hostname:8080/mcp" required>
          </label>
          <label>Auth
            <select name="auth_type" id="auth-type-sel" onchange="document.getElementById('auth-tok').style.display=this.value==='none'?'none':''">
              <option value="none">None</option>
              <option value="bearer">Bearer Token</option>
              <option value="api_key">API Key (X-API-Key)</option>
              <option value="basic">Basic (user:pass)</option>
            </select>
          </label>
          <label id="auth-tok" style="display:none">Token / Key
            <input name="auth_token" type="password" placeholder="secret value">
          </label>
        </div>
        <label>Opis (opcjonalny)<input name="description" placeholder="np. GitLab MCP dev team"></label>
        <div class="actions" style="margin-top:12px">
          <button>Zarejestruj i sprawdź status</button>
        </div>
      </form>
    </section>
    <section>
      <h2>Jak używać z Continue / OpenWebUI?</h2>
      <p class="muted">Po wykryciu tools, skopiuj endpoint URL i dodaj go do konfiguracji klienta MCP:</p>
      <pre style="font-size:12px"># Continue (config.json)
{{
  "mcpServers": [
    {{
      "name": "My External MCP",
      "transport": {{
        "type": "http",
        "url": "http://hostname:8080/mcp"
      }}
    }}
  ]
}}</pre>
    </section>
    """
    return page_shell("external", body)


@app.post("/api/external-mcp")
async def register_external_mcp(request: Request):
    form = await request.form()
    name = str(form.get("name") or "").strip()
    url = str(form.get("endpoint_url") or "").strip()
    auth_type = str(form.get("auth_type") or "none")
    auth_token = str(form.get("auth_token") or "")
    description = str(form.get("description") or "")
    if not name or not url:
        return RedirectResponse(f"/external-mcp?error={quote('Nazwa i URL są wymagane')}", status_code=303)
    server_id = slug(name) + "-" + uuid.uuid4().hex[:6]
    now = store.now_iso()
    probe = await _probe_mcp_server(url, auth_type, auth_token)
    store.execute(
        """INSERT INTO external_mcp_servers(id, name, description, endpoint_url, auth_type, auth_token,
           status, last_checked_at, last_error, tools_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (server_id, name, description, url, auth_type, auth_token,
         probe["status"], now, probe["error"], json.dumps(probe["tools"]), now, now),
    )
    store.audit("admin", "register_external_mcp", "external_mcp", server_id,
                {"url": url, "status": probe["status"], "tools": len(probe["tools"])})
    msg = f"Zarejestrowano: {name} | status: {probe['status']} | tools: {len(probe['tools'])}"
    if probe["error"]:
        msg += f" | błąd: {probe['error'][:120]}"
    return RedirectResponse(f"/external-mcp?ok={quote(msg)}", status_code=303)


@app.post("/api/external-mcp/{server_id}/check")
async def check_external_mcp(server_id: str):
    server = store.one("SELECT * FROM external_mcp_servers WHERE id = ?", (server_id,))
    if not server:
        raise HTTPException(status_code=404, detail="External MCP server not found")
    probe = await _probe_mcp_server(server["endpoint_url"], server["auth_type"], server["auth_token"])
    now = store.now_iso()
    store.execute(
        "UPDATE external_mcp_servers SET status=?, last_checked_at=?, last_error=?, tools_json=?, updated_at=? WHERE id=?",
        (probe["status"], now, probe["error"], json.dumps(probe["tools"]), now, server_id),
    )
    store.audit("admin", "check_external_mcp", "external_mcp", server_id,
                {"status": probe["status"], "tools": len(probe["tools"])})
    msg = f"{server['name']} | status: {probe['status']} | tools: {len(probe['tools'])}"
    if probe["error"]:
        msg += f" | {probe['error'][:120]}"
    return RedirectResponse(f"/external-mcp?ok={quote(msg)}", status_code=303)


@app.post("/api/external-mcp/{server_id}/delete")
def delete_external_mcp(server_id: str):
    server = store.one("SELECT name FROM external_mcp_servers WHERE id = ?", (server_id,))
    store.execute("DELETE FROM external_mcp_servers WHERE id = ?", (server_id,))
    store.audit("admin", "delete_external_mcp", "external_mcp", server_id,
                {"name": server["name"] if server else ""})
    return RedirectResponse("/external-mcp", status_code=303)


def _auth_page(title: str, content: str) -> str:
    return f"""<!doctype html><html><head><title>{escape(title)} — MCP Platform</title>
    <style>
    * {{ box-sizing:border-box; }}
    body {{ font-family:Arial,system-ui,sans-serif; margin:0; background:#111820; color:#dce7f3; display:flex; align-items:center; justify-content:center; min-height:100vh; }}
    .auth-box {{ background:#182230; border:1px solid #2b394a; border-radius:14px; padding:36px 40px; width:100%; max-width:420px; }}
    .auth-logo {{ font-size:22px; font-weight:800; color:white; margin-bottom:4px; }}
    .auth-sub {{ color:#8ea2b8; font-size:13px; margin-bottom:28px; }}
    .auth-field {{ margin-bottom:16px; }}
    .auth-field label {{ display:block; font-weight:700; font-size:13px; color:#aac8e0; margin-bottom:5px; }}
    .auth-field input {{ width:100%; padding:11px 13px; border:1px solid #34465b; border-radius:7px; background:#0d1420; color:#dce7f3; font-size:14px; }}
    .auth-field input:focus {{ outline:none; border-color:#1f9bd1; box-shadow:0 0 0 2px rgba(31,155,209,.15); }}
    .auth-btn {{ width:100%; padding:13px; font-size:15px; font-weight:800; border:none; border-radius:8px; background:#1f9bd1; color:white; cursor:pointer; margin-top:6px; }}
    .auth-btn:hover {{ background:#157aa8; }}
    .auth-link {{ text-align:center; margin-top:16px; font-size:13px; color:#8ea2b8; }}
    .auth-link a {{ color:#5db7ee; }}
    .auth-err {{ background:#2c0e10; border:1px solid #5a2025; color:#f47a80; padding:10px 13px; border-radius:7px; margin-bottom:16px; font-size:13px; }}
    .auth-ok {{ background:#0e2e1e; border:1px solid #1a5a38; color:#5ce89a; padding:10px 13px; border-radius:7px; margin-bottom:16px; font-size:13px; }}
    </style></head><body>
    <div class="auth-box">
      <div class="auth-logo">🤖 MCP Platform</div>
      <div class="auth-sub">Platforma MCP serverów</div>
      {content}
    </div></body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = "", next: str = "/") -> str:
    err = f'<div class="auth-err">{escape(error)}</div>' if error else ""
    return _auth_page("Logowanie", f"""
    {err}
    <form method="post" action="/login">
      <input type="hidden" name="next" value="{escape(next)}">
      <div class="auth-field"><label>Login</label><input name="username" autofocus placeholder="admin"></div>
      <div class="auth-field"><label>Hasło</label><input type="password" name="password" placeholder="••••••••"></div>
      <button class="auth-btn">Zaloguj się →</button>
    </form>
    <div class="auth-link">Nie masz konta? <a href="/register">Zarejestruj się</a></div>""")


@app.post("/login")
async def login_post(request: Request) -> Any:
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    next_url = safe_return_to(str(form.get("next") or ""), "/")
    user = store.one("SELECT * FROM users WHERE username=? AND active=1", (username,))
    if not user or not _verify_pw(password, user["password_hash"]):
        return RedirectResponse(f"/login?error={quote('Nieprawidłowy login lub hasło')}&next={quote(next_url)}", status_code=303)
    token = _create_session(user["id"], user["username"], user["role"])
    resp = RedirectResponse(next_url, status_code=303)
    _secure = os.getenv("MCP_HTTPS_ONLY", "").lower() in ("1", "true", "yes")
    resp.set_cookie(AUTH_COOKIE, token, httponly=True, samesite="lax",
                    max_age=SESSION_TTL_H * 3600, secure=_secure)
    return resp


@app.post("/logout")
async def logout(request: Request) -> Any:
    token = request.cookies.get(AUTH_COOKIE, "")
    if token:
        _delete_session(token)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(AUTH_COOKIE)
    return resp


@app.get("/register", response_class=HTMLResponse)
def register_page(error: str = "", ok: str = "") -> str:
    err = f'<div class="auth-err">{escape(error)}</div>' if error else ""
    ok_msg = f'<div class="auth-ok">{escape(ok)}</div>' if ok else ""
    return _auth_page("Rejestracja", f"""
    {err}{ok_msg}
    <form method="post" action="/register">
      <div class="auth-field"><label>Wybierz login</label><input name="username" autofocus placeholder="jan.kowalski" pattern="[a-zA-Z0-9._-]+" title="Litery, cyfry, kropki, myślniki"></div>
      <div class="auth-field"><label>Hasło</label><input type="password" name="password" placeholder="min. 6 znaków" minlength="6"></div>
      <div class="auth-field"><label>Potwierdź hasło</label><input type="password" name="password2" placeholder="••••••••"></div>
      <div class="auth-field">
        <label>Żądana rola</label>
        <select name="requested_role" style="width:100%;padding:10px 12px;border:1px solid #34465b;border-radius:7px;background:#0d1420;color:#dce7f3;font-size:14px">
          <option value="read_write">read_write — tworzenie serwerów MCP</option>
          <option value="read_only">read_only — tylko podgląd</option>
        </select>
      </div>
      <button class="auth-btn">Wyślij prośbę o konto →</button>
    </form>
    <div class="auth-link">Masz już konto? <a href="/login">Zaloguj się</a></div>
    <div style="margin-top:16px;padding:12px;background:#0d1e2e;border-radius:8px;font-size:12px;color:#7ab8d8">
      ℹ️ Administrator musi zaakceptować Twoje konto zanim będziesz mógł się zalogować.
    </div>""")


@app.post("/register")
async def register_post(request: Request) -> Any:
    form = await request.form()
    username = re.sub(r"[^a-zA-Z0-9._-]", "", str(form.get("username") or "")).strip()
    password = str(form.get("password") or "")
    password2 = str(form.get("password2") or "")
    role = str(form.get("requested_role") or "read_write")
    if role not in {"read_only", "read_write"}:
        role = "read_write"
    if not username or len(username) < 2:
        return RedirectResponse(f"/register?error={quote('Login musi mieć min. 2 znaki')}", status_code=303)
    if len(password) < 6:
        return RedirectResponse(f"/register?error={quote('Hasło musi mieć min. 6 znaków')}", status_code=303)
    if password != password2:
        return RedirectResponse(f"/register?error={quote('Hasła nie są zgodne')}", status_code=303)
    if store.one("SELECT id FROM users WHERE username=?", (username,)):
        return RedirectResponse(f"/register?error={quote('Ten login jest już zajęty')}", status_code=303)
    if store.one("SELECT id FROM registration_requests WHERE username=? AND status='pending'", (username,)):
        return RedirectResponse(f"/register?error={quote('Prośba o ten login już oczekuje na akceptację')}", status_code=303)
    store.execute(
        "INSERT INTO registration_requests(username,password_hash,status,requested_role,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (username, _hash_pw(password), "pending", role, store.now_iso(), store.now_iso()),
    )
    store.audit("system", "registration_request", "user", username, {"role": role})
    return RedirectResponse(f"/register?ok={quote('Prośba wysłana! Administrator otrzyma powiadomienie i wkrótce aktywuje Twoje konto.')}", status_code=303)


@app.get("/user/settings", response_class=HTMLResponse)
def user_settings_page(error: str = "", ok: str = "") -> str:
    user = _current_user.get() or {}
    err = f'<div class="alert">{escape(error)}</div>' if error else ""
    ok_msg = f'<div class="success">{escape(ok)}</div>' if ok else ""
    body = f"""
    {err}{ok_msg}
    <section style="max-width:480px">
      <h2>⚙️ Ustawienia konta</h2>
      <p class="muted">Zalogowany jako: <b>{escape(user.get("username","?"))}</b> · Rola: <b>{escape(user.get("role","?"))}</b></p>
      <form method="post" action="/api/user/change-password">
        <div class="gen-field">
          <label>Aktualne hasło</label>
          <input type="password" name="current_password" required style="padding:10px 12px;border:1px solid #34465b;border-radius:6px;background:#0d1420;color:#dce7f3">
        </div>
        <div class="gen-field">
          <label>Nowe hasło (min. 6 znaków)</label>
          <input type="password" name="new_password" minlength="6" required style="padding:10px 12px;border:1px solid #34465b;border-radius:6px;background:#0d1420;color:#dce7f3">
        </div>
        <div class="gen-field">
          <label>Potwierdź nowe hasło</label>
          <input type="password" name="new_password2" required style="padding:10px 12px;border:1px solid #34465b;border-radius:6px;background:#0d1420;color:#dce7f3">
        </div>
        <button style="background:#1a7a3f;padding:10px 18px;border:none;border-radius:8px;color:white;font-weight:700;cursor:pointer">Zmień hasło</button>
      </form>
    </section>"""
    return page_shell("settings", body)


@app.post("/api/user/change-password")
async def change_password(request: Request) -> Any:
    user = _current_user.get()
    if not user:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    current_pw = str(form.get("current_password") or "")
    new_pw = str(form.get("new_password") or "")
    new_pw2 = str(form.get("new_password2") or "")
    db_user = store.one("SELECT * FROM users WHERE id=?", (user["user_id"],))
    if not db_user or not _verify_pw(current_pw, db_user["password_hash"]):
        return RedirectResponse(f"/user/settings?error={quote('Nieprawidłowe aktualne hasło')}", status_code=303)
    if len(new_pw) < 6:
        return RedirectResponse(f"/user/settings?error={quote('Nowe hasło musi mieć min. 6 znaków')}", status_code=303)
    if new_pw != new_pw2:
        return RedirectResponse(f"/user/settings?error={quote('Hasła nie są zgodne')}", status_code=303)
    store.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (_hash_pw(new_pw), store.now_iso(), db_user["id"]))
    store.audit("admin", "change_password", "user", db_user["username"], {})
    return RedirectResponse(f"/user/settings?ok={quote('Hasło zostało zmienione!')}", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(ok: str = "") -> str:
    users = store.rows("SELECT * FROM users ORDER BY role, username")
    requests = store.rows("SELECT * FROM registration_requests WHERE status='pending' ORDER BY created_at")
    ok_msg = f'<div class="success">{escape(ok)}</div>' if ok else ""

    pending_html = ""
    for r in requests:
        pending_html += f"""
        <tr>
          <td><b>{escape(r['username'])}</b></td>
          <td><span class="badge">{escape(r['requested_role'])}</span></td>
          <td class="muted" style="font-size:12px">{escape(r['created_at'][:16].replace('T',' '))}</td>
          <td>
            <div style="display:flex;gap:6px">
              <form method="post" action="/admin/users/approve/{r['id']}">
                <input type="hidden" name="role" value="{escape(r['requested_role'])}">
                <button style="background:#1a7a3f;border:none;padding:5px 10px;border-radius:5px;color:white;font-size:12px;cursor:pointer">✅ Akceptuj</button>
              </form>
              <form method="post" action="/admin/users/approve/{r['id']}">
                <input type="hidden" name="role" value="read_only">
                <button style="background:#263548;border:none;padding:5px 10px;border-radius:5px;color:#c9d7e6;font-size:12px;cursor:pointer">👁 Akceptuj jako read_only</button>
              </form>
              <form method="post" action="/admin/users/reject/{r['id']}">
                <button class="delete" style="padding:5px 10px;font-size:12px">❌ Odrzuć</button>
              </form>
            </div>
          </td>
        </tr>"""

    users_html = ""
    for u in users:
        role_sel = "".join(
            f'<option value="{r}" {"selected" if r == u["role"] else ""}>{r}</option>'
            for r in ["read_only", "read_write", "admin"]
        )
        users_html += f"""
        <tr>
          <td><b>{escape(u['username'])}</b></td>
          <td>
            <form method="post" action="/admin/users/role/{u['id']}" style="display:flex;gap:6px">
              <select name="role" style="padding:5px 8px;font-size:12px;background:#0d1420;border:1px solid #34465b;border-radius:5px;color:#dce7f3">{role_sel}</select>
              <button style="background:#263548;border:none;padding:5px 10px;border-radius:5px;color:#c9d7e6;font-size:12px;cursor:pointer">Zmień</button>
            </form>
          </td>
          <td class="muted" style="font-size:12px">{escape(u['created_at'][:16].replace('T',' '))}</td>
          <td>
            <form method="post" action="/admin/users/toggle/{u['id']}">
              <button style="background:{'#263548' if u['active'] else '#1a7a3f'};border:none;padding:5px 10px;border-radius:5px;color:#c9d7e6;font-size:12px;cursor:pointer">
                {'⛔ Dezaktywuj' if u['active'] else '✅ Aktywuj'}
              </button>
            </form>
          </td>
        </tr>"""

    body = f"""
    {ok_msg}
    {f'''
    <section style="border-color:#5a420f;background:#1a1000">
      <h2>⏳ Oczekujące prośby o konto ({len(requests)})</h2>
      {"<p class='muted'>Brak oczekujących próśb.</p>" if not requests else f"""
      <table>
        <thead><tr><th>Login</th><th>Żądana rola</th><th>Data</th><th>Akcja</th></tr></thead>
        <tbody>{pending_html}</tbody>
      </table>"""}
    </section>''' if requests else ''}

    <section>
      <h2>👥 Wszyscy użytkownicy ({len(users)})</h2>
      <table>
        <thead><tr><th>Login</th><th>Rola</th><th>Utworzony</th><th>Status</th></tr></thead>
        <tbody>{users_html}</tbody>
      </table>
    </section>"""
    return page_shell("admin", body)


@app.post("/admin/users/approve/{req_id}")
async def approve_registration(req_id: int, request: Request) -> Any:
    form = await request.form()
    role = str(form.get("role") or "read_only")
    if role not in {"read_only", "read_write", "admin"}:
        role = "read_only"
    req = store.one("SELECT * FROM registration_requests WHERE id=?", (req_id,))
    if not req:
        raise HTTPException(404, "Request not found")
    store.execute(
        "INSERT OR IGNORE INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,1,?,?)",
        (req["username"], req["password_hash"], role, store.now_iso(), store.now_iso()),
    )
    store.execute("UPDATE registration_requests SET status='approved',updated_at=? WHERE id=?", (store.now_iso(), req_id))
    store.audit("admin", "approve_registration", "user", req["username"], {"role": role})
    msg = f"Konto {req['username']} aktywowane z rolą {role}"
    return RedirectResponse(f"/admin/users?ok={quote(msg)}", status_code=303)


@app.post("/admin/users/reject/{req_id}")
async def reject_registration(req_id: int) -> Any:
    req = store.one("SELECT username FROM registration_requests WHERE id=?", (req_id,))
    store.execute("UPDATE registration_requests SET status='rejected',updated_at=? WHERE id=?", (store.now_iso(), req_id))
    store.audit("admin", "reject_registration", "user", (req or {}).get("username", "?"), {})
    return RedirectResponse(f"/admin/users?ok={quote('Prośba odrzucona.')}", status_code=303)


@app.post("/admin/users/role/{user_id}")
async def change_user_role(user_id: int, request: Request) -> Any:
    form = await request.form()
    role = str(form.get("role") or "read_only")
    if role not in {"read_only", "read_write", "admin"}:
        raise HTTPException(400, "Invalid role")
    u = store.one("SELECT username FROM users WHERE id=?", (user_id,))
    store.execute("UPDATE users SET role=?,updated_at=? WHERE id=?", (role, store.now_iso(), user_id))
    # Invalidate existing sessions for this user
    store.execute(sql.DELETE_SESSIONS_BY_USER, (user_id,))
    store.audit("admin", "change_role", "user", (u or {}).get("username", "?"), {"role": role})
    return RedirectResponse(f"/admin/users?ok={quote('Rola zmieniona.')}", status_code=303)


@app.post("/admin/users/toggle/{user_id}")
async def toggle_user(user_id: int) -> Any:
    u = store.one("SELECT username, active FROM users WHERE id=?", (user_id,))
    if not u:
        raise HTTPException(404)
    new_active = 0 if u["active"] else 1
    store.execute("UPDATE users SET active=?,updated_at=? WHERE id=?", (new_active, store.now_iso(), user_id))
    if not new_active:
        store.execute(sql.DELETE_SESSIONS_BY_USER, (user_id,))
    store.audit("admin", "toggle_user", "user", u["username"], {"active": new_active})
    return RedirectResponse(f"/admin/users?ok={quote('Status użytkownika zmieniony.')}", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    runtimes = store.rows(sql.SELECT_RUNTIMES_ACTIVE)
    adapters = store.rows(sql.SELECT_ADAPTERS_ALL)
    audit = store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8")
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 8")
    running = len([r for r in runtimes if r["status"] == "running"])
    failed = len([r for r in runtimes if r["status"] in {"failed", "unhealthy", "missing", "exited"} or (r.get("last_error") and r["status"] not in {"running", "deleted"})])
    implemented_adapters = len([a for a in adapters if a["implemented"]])
    action_icons_dash = {"deploy_runtime": "🚀", "stop_runtime": "⏹️", "delete_runtime": "🗑️", "reload_runtime": "♻️",
                    "build_runtime_image": "🔨", "action_failed": "❌", "create_runtime": "➕", "health_refresh": "🩺"}
    audit_html = "".join(
        f'<li style="padding:6px 0;border-bottom:1px solid var(--line);font-size:12px;display:flex;gap:8px;align-items:baseline">'
        f'<span style="color:var(--muted);flex-shrink:0">{escape(a["created_at"][11:19])}</span>'
        f'<span>{action_icons_dash.get(a["action"],"📌")} <b>{escape(a["action"])}</b></span>'
        f'<span class="muted" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(a["target_id"][:28])}</span>'
        f'</li>'
        for a in audit)
    level_colors_dash = {"error": "#f47a80", "warn": "#f4c163", "info": "#7dd3fc"}
    logs_html = "".join(
        f'<li style="padding:6px 0;border-bottom:1px solid var(--line);font-size:12px;display:flex;gap:8px;align-items:baseline">'
        f'<span style="color:var(--muted);flex-shrink:0">{escape(l["created_at"][11:19])}</span>'
        f'<span style="color:{level_colors_dash.get(l["level"],"#8ea2b8")};flex-shrink:0;font-weight:700">{escape(l["level"].upper())}</span>'
        f'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(l["message"][:80])}</span>'
        f'</li>'
        for l in logs)
    body = f"""
      <div class="cards">
        <a class="card" href="/runtimes">
          <div class="metric">{len(runtimes)}</div>
          <div style="font-weight:700;color:white;margin-bottom:2px">Serwery MCP</div>
          <div class="muted">wszystkie środowiska</div>
        </a>
        <a class="card" href="/runtimes?status=running">
          <div class="metric" style="color:#5ce89a">{running}</div>
          <div style="font-weight:700;color:white;margin-bottom:2px">Działające</div>
          <div class="muted">status: running</div>
        </a>
        <a class="card" href="/runtimes?status=problem">
          <div class="metric" style="color:{'#f47a80' if failed else '#5ce89a'}">{failed}</div>
          <div style="font-weight:700;color:white;margin-bottom:2px">Z problemami</div>
          <div class="muted">failed / unhealthy</div>
        </a>
        <a class="card" href="/external-mcp">
          <div class="metric" style="color:#c084fc">{len(store.rows("SELECT id FROM external_mcp_servers"))}</div>
          <div style="font-weight:700;color:white;margin-bottom:2px">Zewnętrzne MCP</div>
          <div class="muted">zarejestrowane serwery</div>
        </a>
      </div>
      {f"""
      <div style="background:linear-gradient(135deg,#0d1a2a,#0a1220);border:2px dashed var(--blue);border-radius:12px;padding:36px;text-align:center;margin-top:8px">
        <div style="font-size:48px;margin-bottom:12px">🚀</div>
        <div style="font-size:22px;font-weight:800;color:white;margin-bottom:8px">Witaj w MCP Platform!</div>
        <div style="color:var(--muted);font-size:15px;margin-bottom:24px;max-width:480px;margin-left:auto;margin-right:auto">
          Nie masz jeszcze żadnego serwera MCP. Zacznij od kreatora — zajmie to mniej niż minutę.
        </div>
        <a href="/quick-start" style="display:inline-block;background:var(--blue);color:white;padding:14px 28px;border-radius:8px;font-weight:800;font-size:16px;text-decoration:none">
          ⚡ Stwórz pierwszy serwer MCP
        </a>
        <div style="margin-top:16px;color:var(--muted);font-size:13px">
          lub <a href="/tool-packages">przeglądaj gotowe zestawy</a> &nbsp;·&nbsp; <a href="/docs">jak to działa?</a>
        </div>
      </div>
      """ if not runtimes else ""}
      <div class="grid">
        <section>
          <h2><a href="/audit" style="color:white">📋 Historia operacji</a></h2>
          <ul style="list-style:none;margin:0;padding:0">{audit_html}</ul>
          <a href="/audit" class="muted" style="font-size:12px;display:block;margin-top:10px">→ Pełna historia</a>
        </section>
        <section>
          <h2><a href="/logs" style="color:white">🔎 Ostatnie logi</a></h2>
          <ul style="list-style:none;margin:0;padding:0">{logs_html}</ul>
          <a href="/logs" class="muted" style="font-size:12px;display:block;margin-top:10px">→ Wszystkie logi</a>
        </section>
      </div>
    """
    return page_shell("dashboard", body)


@app.get("/create", response_class=HTMLResponse)
def create_page(error: str = "") -> str:
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    _cu = _current_user.get()
    _can_shell = (_cu or {}).get("role") == "admin"
    packages = store.rows("SELECT id, name, description FROM tool_packages WHERE enabled=1 ORDER BY category, name")
    runtime_classes = store.rows("SELECT name, runtime_image FROM runtime_classes WHERE enabled=1 ORDER BY name")
    # Available images for env picker
    _adv_builtin = [
        ("mcp-runtime-shell:latest", "🐚 Standardowe — oc, kubectl, curl, jq (Python 3.12 Debian) [zalecane]"),
        ("mcp-runtime-http-gateway:latest", "🌐 HTTP Gateway — REST API calls"),
        ("python:3.12-slim", "🐍 Python 3.12 czysty Debian"),
        ("debian:bookworm-slim", "📦 Debian czysty"),
    ]
    _adv_custom_images = store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' AND runtime_image NOT IN ('mcp-runtime-shell:latest','mcp-runtime-http-gateway:latest') ORDER BY runtime_image"
    )
    _adv_base_opts = "".join(
        f'<option value="{escape(v)}"{"selected" if v=="mcp-runtime-shell:latest" else ""}>{escape(l)}</option>'
        for v, l in _adv_builtin
    ) + ("".join(
        f'<option value="{escape(r["runtime_image"])}">{escape(r["runtime_image"])} — własny zbudowany</option>'
        for r in _adv_custom_images
    )) + '<option value="__custom__">⌨️ Inny — wpisz ręcznie (zaawansowane)</option>'

    pkg_cards = "".join(f"""
        <label class="qs-pkg-card" onclick="pkgChosen('{p['id']}', this)">
          <input type="radio" name="package_id" value="{escape(p['id'])}" form="adv-form" style="display:none">
          <div class="qs-pkg-inner">
            <div style="display:flex;align-items:center;gap:8px">
              <span class="pkg-check" style="display:none;color:#4caf50;font-size:16px;flex-shrink:0">&#10003;</span>
              <div style="font-weight:800;font-size:14px;color:white">{escape(p['name'])}</div>
            </div>
            <div style="color:var(--muted);font-size:12px;margin-top:4px">{escape((p['description'] or '')[:80])}</div>
          </div>
        </label>""" for p in packages)

    rc_opts = "".join(
        f'<option value="{escape(r["name"])}">{escape(r["name"])} — {escape(r["runtime_image"])}</option>'
        for r in runtime_classes)

    body = f"""
<style>
.adv-wrap {{ max-width:740px; margin:0 auto; display:grid; gap:18px; }}
.adv-step {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:26px 28px; display:none; }}
.adv-step.active {{ display:block; }}
.adv-step h2 {{ margin:0 0 6px; font-size:20px; font-weight:800; }}
.adv-step .sub {{ color:var(--muted); font-size:14px; margin-bottom:20px; }}
.adv-field {{ margin-bottom:14px; }}
.adv-field label {{ display:block; font-weight:700; font-size:13px; color:#aac8e0; margin-bottom:5px; }}
.adv-field input, .adv-field select, .adv-field textarea {{ width:100%; box-sizing:border-box; padding:10px 12px; border:1px solid #34465b; border-radius:6px; background:#0d1420; color:var(--text); font-size:14px; }}
.adv-field .hint {{ color:var(--muted); font-size:12px; margin-top:4px; }}
.adv-big-btn {{ width:100%; padding:14px; font-size:16px; font-weight:800; border:none; border-radius:8px; background:var(--blue); color:white; cursor:pointer; margin-top:8px; }}
.adv-big-btn:hover {{ background:var(--blue-dark); }}
.adv-back {{ background:#263548; color:#c9d7e6; border:none; padding:8px 14px; border-radius:6px; cursor:pointer; font-size:13px; margin-bottom:16px; }}
.adv-type-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
.adv-type-btn {{ background:#0d1822; border:2px solid var(--line); border-radius:10px; padding:20px 16px; cursor:pointer; text-align:center; transition:.15s; color:var(--text); }}
.adv-type-btn:hover {{ border-color:var(--blue); background:#0d2a40; }}
.adv-type-btn .icon {{ font-size:34px; margin-bottom:10px; }}
.adv-type-btn .name {{ font-weight:800; font-size:15px; margin-bottom:6px; }}
.adv-type-btn .desc {{ color:var(--muted); font-size:12px; line-height:1.5; }}
.prog-bar {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-bottom:4px; }}
.prog-step {{ padding:10px; border-radius:8px; text-align:center; background:var(--panel-2); border:1px solid var(--line); font-size:12px; font-weight:700; color:var(--muted); transition:.2s; }}
.prog-step.done {{ background:#0e2e1e; color:#5ce89a; border-color:#1a5a38; }}
.prog-step.current {{ background:#0d3a55; color:white; border-color:var(--blue); }}
.qs-pkg-card {{ display:block; cursor:pointer; margin-bottom:8px; }}
.qs-pkg-inner {{ background:#0d1822; border:2px solid var(--line); border-radius:8px; padding:12px 16px; transition:.15s; }}
.qs-pkg-inner:hover {{ border-color:var(--blue); }}
.qs-pkg-card input:checked + .qs-pkg-inner {{ border-color:var(--blue); background:rgba(0,120,212,0.13); box-shadow:0 0 0 2px var(--blue); }}
</style>

{alert}

<!-- Progress bar -->
<div class="adv-wrap">
  <div class="prog-bar" id="prog" style="grid-template-columns:repeat(5,1fr)">
    <div class="prog-step current" id="p1">1. Źródło tools</div>
    <div class="prog-step" id="p2">2. Podstawy</div>
    <div class="prog-step" id="p3">3. Narzędzie</div>
    <div class="prog-step" id="p4">4. Bezpieczeństwo</div>
    <div class="prog-step" id="p5">5. Utwórz</div>
  </div>

  <form id="adv-form" method="post" action="/api/runtimes">
    <input type="hidden" name="package_id" id="pkg-hidden" value="">
    <input type="hidden" name="runtime_class" id="rc-hidden" value="http-gateway">
    <input type="hidden" name="adapter_names" id="adapter-hidden" value="http_request">

    <!-- STEP 1: Źródło tools -->
    <div class="adv-step active" id="s1">
      <h2>Skąd pochodzą tools?</h2>
      <div class="sub">Wybierz czy używasz gotowej paczki (najszybciej) czy budujesz serwer od zera.</div>
      <div class="adv-type-grid">
        <button type="button" class="adv-type-btn" onclick="chooseSource('package')">
          <div class="icon">📦</div>
          <div class="name">Gotowa paczka</div>
          <div class="desc">Wybierz z katalogu — tools, silnik i polityka konfigurują się automatycznie</div>
        </button>
        {"" if not _can_shell else """
        <button type="button" class="adv-type-btn" onclick="chooseSource('blank')">
          <div class="icon">🔧</div>
          <div class="name">Od zera</div>
          <div class="desc">Wybierz silnik wykonania i zdefiniuj tools ręcznie po utworzeniu</div>
        </button>"""}
        {'' if _can_shell else '<div class="adv-type-btn" style="opacity:.45;cursor:not-allowed;border-color:#3a2020;pointer-events:none"><div class="icon">🔒</div><div class="name">Od zera</div><div class="desc" style="color:#8a6060">Niedostępne dla roli read_write — tylko gotowe paczki</div></div>'}
      </div>

      <!-- Package picker (hidden until "package" chosen) -->
      <div id="pkg-picker" style="display:none;margin-top:16px">
        <div style="font-weight:700;font-size:13px;color:#aac8e0;margin-bottom:8px">Wybierz paczkę:</div>
        <div style="display:grid;gap:8px;max-height:340px;overflow-y:auto;padding-right:4px">{pkg_cards}</div>
        <button type="button" class="adv-big-btn" id="pkg-next-btn" onclick="goStep(2)" style="display:none;margin-top:14px">
          Dalej →
        </button>
      </div>

      <!-- Blank engine picker (hidden until "blank" chosen) -->
      <div id="engine-picker" style="display:none;margin-top:16px">
        <div style="font-weight:700;font-size:13px;color:#aac8e0;margin-bottom:10px">Wybierz silnik wykonania:</div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
          <button type="button" class="adv-type-btn" onclick="chooseEngine('http_request','http-gateway')" id="eng-http">
            <div class="icon">🌐</div>
            <div class="name">HTTP Request</div>
            <div class="desc">Wywołuje REST API — GitLab, Jira, własny serwis</div>
          </button>
          <button type="button" class="adv-type-btn" onclick="chooseEngine('shell','shell-readonly')" id="eng-shell">
            <div class="icon">⌨️</div>
            <div class="name">Shell</div>
            <div class="desc">Wykonuje komendy — curl, oc, kubectl, dowolne CLI</div>
          </button>
          <button type="button" class="adv-type-btn" onclick="chooseEngine('openapi','openapi')" id="eng-openapi">
            <div class="icon">📄</div>
            <div class="name">OpenAPI Spec</div>
            <div class="desc">Auto-generuje tools z dokumentacji REST API (openapi.json) — zero definiowania narzędzi</div>
          </button>
        </div>

        <!-- OpenAPI config (shown when OpenAPI engine chosen) -->
        <div id="openapi-cfg" style="display:none;margin-top:16px;background:#0a1a2a;border:1px solid #1a4060;border-radius:10px;padding:16px 18px">
          <div style="font-weight:800;color:#7dd3fc;font-size:14px;margin-bottom:4px">📄 Konfiguracja OpenAPI</div>
          <div style="color:var(--muted);font-size:12px;margin-bottom:14px">Podaj URL serwisu — tools zostaną wygenerowane automatycznie ze specyfikacji OpenAPI przy starcie kontenera.</div>
          <div class="adv-field" style="margin-bottom:10px">
            <label>🔗 URL serwisu (base URL) <span style="color:#f47a80">*</span></label>
            <input id="oa-backend-url" name="openapi_backend_url" form="adv-form"
                   placeholder="http://moja-api:8000" autocomplete="off"
                   style="font-family:monospace;font-size:13px">
            <div class="hint">Adres bazowy usługi REST API którą chcesz wyeksponować jako MCP</div>
          </div>
          <div class="adv-field" style="margin-bottom:10px">
            <label>📋 URL do openapi.json (opcjonalny)</label>
            <input id="oa-spec-url" name="openapi_spec_url" form="adv-form"
                   placeholder="https://moja-api.com/openapi.json"
                   autocomplete="off" style="font-family:monospace;font-size:13px">
            <div class="hint">Zostaw puste — platforma automatycznie wykryje spec. Dla zewnętrznych API podaj dokładny URL ich dokumentacji OpenAPI.</div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
            <div class="adv-field" style="margin:0">
              <label>🔑 Token autoryzacyjny (opcjonalny)</label>
              <input type="password" id="oa-auth-token" name="openapi_auth_token" form="adv-form"
                     placeholder="ghp_xxx / Bearer token" autocomplete="new-password" style="font-size:13px">
            </div>
            <div class="adv-field" style="margin:0">
              <label>📛 Nagłówek auth (opcjonalny)</label>
              <input id="oa-auth-header" name="openapi_auth_header" form="adv-form"
                     placeholder="Authorization" autocomplete="off" style="font-size:13px">
              <div class="hint">Domyślnie: <code>Authorization</code> z prefixem <code>Bearer</code></div>
            </div>
          </div>
          <button type="button" class="adv-big-btn" onclick="openapiGoNext()">Dalej →</button>
        </div>
      </div>
    </div>

    <!-- STEP 2: Podstawy -->
    <div class="adv-step" id="s2">
      <button type="button" class="adv-back" onclick="goStep(1)">← Wróć</button>
      <h2>Podstawowe informacje</h2>
      <div class="sub">Nazwij serwer i opcjonalnie dostosuj typ środowiska.</div>

      <div class="adv-field">
        <label>Nazwa serwera MCP</label>
        <input name="name" id="adv-name" placeholder="GitLab Assistant" required>
        <div class="hint">Dowolna nazwa — pojawi się na liście serwerów i w Continue / OpenWebUI</div>
      </div>
      <div class="adv-field">
        <label>Opis (opcjonalny)</label>
        <input name="description" placeholder="Asystent do przeszukiwania GitLab issues i MR">
      </div>
      <div class="adv-field" id="rc-field" style="display:none">
        <label>Typ środowiska (Runtime Class)</label>
        <select id="rc-select" onchange="document.getElementById('rc-hidden').value=this.value">
          {rc_opts}
        </select>
        <div class="hint">Określa jaki obraz Docker zostanie uruchomiony</div>
      </div>

      <!-- Shell env builder (shown when shell engine selected) -->
      <div id="adv-shell-env" style="display:none;background:#0d1a0a;border:1px solid #2a4a1a;border-radius:10px;padding:16px 18px;margin-top:12px">
        <div style="font-weight:800;color:#5ce89a;margin-bottom:4px;font-size:14px">🛠️ Dostępne narzędzia w kontenerze</div>
        <div class="muted" style="font-size:12px;margin-bottom:12px">Standardowy obraz ma już: <code>oc</code> <code>kubectl</code> <code>curl</code> <code>jq</code>. Potrzebujesz innych? Zbuduj własny obraz poniżej.</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
          <div class="adv-field" style="margin:0">
            <label>Baza obrazu</label>
            <select id="adv-build-base" style="font-size:13px" onchange="advUpdateBaseHint()">
              {_adv_base_opts}
            </select>
            <input id="adv-build-base-custom" placeholder="np. ubuntu:22.04" style="display:none;font-size:13px;margin-top:6px">
            <div id="adv-base-hint" class="hint" style="color:#7dd3fc">✅ Zawiera oc, kubectl, curl, jq + Python 3.12 Debian</div>
          </div>
          <div class="adv-field" style="margin:0">
            <label>Dodatkowe pakiety APT (spacja)</label>
            <input id="adv-build-apt" placeholder="postgresql-client terraform" style="font-size:13px" list="adv-apt-list">
            <datalist id="adv-apt-list">
              <option value="postgresql-client"><option value="mysql-client"><option value="redis-tools">
              <option value="git"><option value="python3-pip"><option value="awscli">
              <option value="openssh-client"><option value="unzip wget">
            </datalist>
          </div>
        </div>
        <div class="adv-field" style="margin:0 0 10px">
          <label>Pakiety pip (opcjonalne)</label>
          <input id="adv-build-pip" placeholder="boto3 kubernetes psycopg2-binary" style="font-size:13px">
        </div>
        <div style="display:flex;gap:10px;align-items:center">
          <button type="button" id="adv-build-btn" onclick="advStartBuild()"
                  style="background:#1a7a3f;color:white;border:none;padding:9px 16px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">
            🔨 Zbuduj własne środowisko
          </button>
          <span class="muted" style="font-size:12px">lub pomiń i użyj standardowego</span>
        </div>
        <div id="adv-build-progress" style="display:none;margin-top:10px;padding:10px 12px;background:#0b1420;border-radius:6px;font-size:13px">
          <span id="adv-build-spinner">⏳</span> <span id="adv-build-status">Budowanie...</span>
        </div>
      </div>

      <button type="button" class="adv-big-btn" onclick="goStep(3)" id="step2-next" style="margin-top:14px">Dalej →</button>
    </div>

    <!-- STEP 3: Narzędzia -->
    <div class="adv-step" id="s3">
      <button type="button" class="adv-back" onclick="goStep(2)">← Wróć</button>
      <h2>🔧 Zdefiniuj narzędzia</h2>
      <div class="sub" id="s3-sub">Dodaj jedno lub więcej narzędzi — AI użyje ich definicji do wywołań.</div>

      <!-- OpenAPI auto-gen info (shown only in openapi mode) -->
      <div id="s3-openapi-info" style="display:none;background:#0a1a2a;border:1px solid #1a4060;border-radius:10px;padding:18px 20px;margin-bottom:16px">
        <div style="font-size:22px;margin-bottom:8px">📄</div>
        <div style="font-weight:800;color:#7dd3fc;font-size:15px;margin-bottom:6px">Tools generowane automatycznie z OpenAPI spec</div>
        <div style="color:var(--muted);font-size:13px;line-height:1.6">
          Przy starcie kontenera runtime pobierze <code>openapi.json</code> z podanego serwisu
          i automatycznie wygeneruje z niego wszystkie narzędzia MCP.<br><br>
          <span id="s3-oa-summary" style="color:#5ce89a;font-family:monospace;font-size:12px"></span>
        </div>
      </div>

      <!-- Dynamic tool list -->
      <div id="s3-tools-list" style="display:grid;gap:12px;margin-bottom:12px"></div>

      <button type="button" onclick="s3AddTool()" style="background:#1a2e1a;border:1px dashed #2a5a2a;color:#5ce89a;padding:10px 18px;border-radius:8px;font-size:13px;cursor:pointer;width:100%;margin-bottom:16px">
        + Dodaj kolejne narzędzie
      </button>

      <!-- Hidden fields — first tool (for backend compat) + extra tools JSON -->
      <input type="hidden" name="shell_cmd_adv"       id="s3-cmd-hidden"  form="adv-form" value="">
      <input type="hidden" name="shell_tool_name_adv" id="s3-name-hidden" form="adv-form" value="">
      <input type="hidden" name="first_tool_desc_adv" id="s3-desc-hidden" form="adv-form" value="">
      <input type="hidden" name="first_tool_url"      id="s3-url-hidden"  form="adv-form" value="">
      <input type="hidden" name="first_tool_method"   id="s3-method-hidden" form="adv-form" value="POST">
      <input type="hidden" name="first_tool_name"     id="s3-fname-hidden" form="adv-form" value="">
      <input type="hidden" name="extra_tools_json"    id="s3-extra-json"  form="adv-form" value="[]">

      <button type="button" class="adv-big-btn" onclick="s3Proceed()">Dalej → Bezpieczeństwo</button>
    </div>

    <!-- STEP 4: Bezpieczeństwo -->
    <div class="adv-step" id="s4">
      <button type="button" class="adv-back" onclick="goStep(3)">← Wróć</button>
      <h2>🔒 Ustawienia bezpieczeństwa</h2>
      <div class="sub">Pełna kontrola nad tym co serwer może robić. Domyślnie — maksymalna ochrona.</div>

      <!-- Tryby -->
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Tryb dostępu</div>
      <div style="display:grid;gap:10px;margin-bottom:20px">
        <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px">
          <input type="checkbox" name="policy_read_only" value="1" checked form="adv-form" style="width:auto;margin-top:2px;flex-shrink:0">
          <div>
            <div style="font-weight:700;font-size:13px;color:white">🔒 Tylko odczyt</div>
            <div style="color:var(--muted);font-size:12px;margin-top:2px">Serwer może tylko czytać dane — nie modyfikuje ani nie usuwa niczego</div>
          </div>
        </label>
        <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px">
          <input type="checkbox" name="policy_block_write" value="1" form="adv-form" style="width:auto;margin-top:2px;flex-shrink:0">
          <div>
            <div style="font-weight:700;font-size:13px;color:white">🚫 Blokuj zapis</div>
            <div style="color:var(--muted);font-size:12px;margin-top:2px">Blokuje narzędzia w trybie <code>write</code> — zapis do baz, API PUT/POST/DELETE</div>
          </div>
        </label>
        <label style="display:flex;align-items:flex-start;gap:12px;cursor:pointer;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px">
          <input type="checkbox" name="policy_block_destructive" value="1" form="adv-form" style="width:auto;margin-top:2px;flex-shrink:0">
          <div>
            <div style="font-weight:700;font-size:13px;color:white">⛔ Blokuj destruktywne</div>
            <div style="color:var(--muted);font-size:12px;margin-top:2px">Zapobiega usuwaniu danych i operacjom nieodwracalnym (<code>delete</code>, <code>drop</code>)</div>
          </div>
        </label>
      </div>

      <!-- Limity -->
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Limity</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px">
        <div class="adv-field" style="margin:0">
          <label>⏱️ Timeout (s)</label>
          <input type="number" name="timeout_seconds" value="30" min="5" max="300" form="adv-form">
          <div class="hint">Max czas wykonania komendy</div>
        </div>
        <div class="adv-field" style="margin:0">
          <label>📏 Maks. odpowiedź (KB)</label>
          <input type="number" name="max_response_kb" value="5120" min="64" max="51200" form="adv-form">
          <div class="hint">Max rozmiar danych zwracanych AI</div>
        </div>
        <div class="adv-field" style="margin:0">
          <label>📥 Maks. payload (KB)</label>
          <input type="number" name="max_payload_kb" value="256" min="16" max="10240" form="adv-form">
          <div class="hint">Max rozmiar danych od AI</div>
        </div>
      </div>

      <!-- Kontrola komend (shell) -->
      <div style="font-size:11px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Kontrola komend <span style="color:#3a6a8a;font-weight:400;text-transform:none">(dla shell tools)</span></div>
      <div style="display:grid;gap:12px;margin-bottom:20px">
        <div class="adv-field" style="margin:0">
          <label>✅ Dozwolone binarki</label>
          <input name="allowed_binaries" placeholder="curl jq oc kubectl" form="adv-form">
          <div class="hint">Spacja — tylko te binarki mogą być uruchamiane. Puste = brak ograniczeń.</div>
        </div>
        <div class="adv-field" style="margin:0">
          <label>🎯 Dozwolony prefix komendy</label>
          <input name="allowed_prefix" placeholder="oc get" form="adv-form">
          <div class="hint">AI może wywołać tylko komendy zaczynające się od tego prefiksu. Np. <code>oc get</code> → nie może <code>oc delete</code>.</div>
        </div>
        <div class="adv-field" style="margin:0">
          <label>🚫 Zablokowane komendy (denylist)</label>
          <textarea name="blocked_prefixes" rows="3" placeholder="kubectl delete&#10;kubectl exec&#10;oc delete" form="adv-form"
            style="width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #34465b;border-radius:6px;background:#0d1420;color:var(--text);font-size:13px;resize:vertical;font-family:monospace"></textarea>
          <div class="hint">Jedna komenda na linię. Każda komenda <b>zaczynająca się</b> od tego prefiksu zostanie zablokowana.</div>
        </div>
      </div>

      <!-- ENV vars -->
      <div style="font-size:11px;font-weight:800;color:#f59e0b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">🔑 Zmienne środowiskowe (ENV) <span style="color:var(--muted);font-weight:400;text-transform:none">— tokeny, klucze API, hasła</span></div>
      <div style="background:#1a1200;border:1px solid #3a2800;border-radius:8px;padding:10px 14px;margin-bottom:10px;font-size:12px;color:#d4a820">
        Zmienne ENV są dostępne wewnątrz kontenera jako zmienne środowiskowe. Użyj ich dla tokenów API, kluczy SSH, URL baz danych — wszystkiego co nie powinno być w kodzie.
      </div>
      <div id="adv-env-list" style="display:grid;gap:6px;margin-bottom:8px"></div>
      <button type="button" onclick="advAddEnv()" style="background:#1a1200;border:1px solid #3a2800;color:#d4a820;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer">+ Dodaj zmienną ENV</button>

      <div style="background:#0a1a0a;border:1px solid #1a3a1a;border-radius:8px;padding:10px 14px;margin:16px 0">
        <div style="color:#4ac86a;font-size:12px;font-weight:700;margin-bottom:4px">🛡️ Zawsze aktywne (nie można wyłączyć):</div>
        <div style="color:#7ab890;font-size:12px;line-height:1.8">
          ✅ user 1000:1000 (bez roota) &nbsp;·&nbsp; ✅ read-only filesystem &nbsp;·&nbsp; ✅ cap_drop ALL &nbsp;·&nbsp; ✅ 512MB RAM limit &nbsp;·&nbsp; ✅ no-new-privileges
        </div>
      </div>

      <button type="button" class="adv-big-btn" onclick="goStep(5)">Dalej →</button>
    </div>

    <!-- STEP 5: Podsumowanie + Utwórz -->
    <div class="adv-step" id="s5">
      <button type="button" class="adv-back" onclick="goStep(4)">← Wróć</button>
      <h2>✅ Gotowe do utworzenia</h2>
      <div class="sub">Sprawdź podsumowanie i kliknij Utwórz serwer MCP.</div>

      <div id="summary" style="background:#0d1822;border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px;font-size:13px;line-height:2"></div>

      <div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:12px 14px;margin-bottom:14px">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13px">
          <input type="checkbox" name="deploy_after_create" value="true" form="adv-form" checked style="width:auto">
          <div>
            <div style="font-weight:700;color:white">🚀 Uruchom od razu po utworzeniu</div>
            <div style="color:var(--muted);font-size:12px">Serwer zostanie automatycznie zdeplojowany — będzie działać za kilka sekund</div>
          </div>
        </label>
      </div>

      <button type="submit" class="adv-big-btn" style="background:#1a7a3f">🚀 Utwórz serwer MCP</button>
      <p style="text-align:center;color:var(--muted);font-size:12px;margin-top:8px">
        Możesz edytować tools i politykę po utworzeniu na stronie serwera.
      </p>
    </div>

  </form>
</div>

<script>
(function() {{
  var source = null;

  // ── multi-tool state for step 3 ──────────────────────────────
  var _s3Tools = [];   // [{{cmd,name,desc,url,method,isShell}}]
  var _s3IsShell = true;
  var _s3IsPkg = false;
  var _s3IsOpenAPI = false;

  var _s3ShellPresets = [
    ['psql ${{*args}}','🐘 psql'],
    ['curl ${{*args}}','🌐 curl'],
    ['curl -s ${{url}}','🌐 curl GET'],
    ['oc get ${{*args}}','🔴 oc get'],
    ['kubectl get ${{*args}}','☸️ kubectl']
  ];

  function s3ToolHtml(idx, isShell) {{
    var presets = '';
    if (isShell) {{
      var _pLabel = (localStorage.getItem('mcp_lang')==='en') ? 'Patterns:' : 'Wzorce:';
      presets = '<div style="font-size:11px;color:#7dd3fc;font-weight:700;margin-bottom:6px">⚡ '+_pLabel+'</div><div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">';
      for (var pi=0; pi<_s3ShellPresets.length; pi++) {{
        var pcmd = _s3ShellPresets[pi][0], plbl = _s3ShellPresets[pi][1];
        presets += '<button type="button" onclick="s3ToolPreset('+idx+',this.dataset.cmd)" data-cmd="'+pcmd+'" style="background:#1a2a3a;border:1px solid #2a4a6a;color:#7dd3fc;padding:3px 9px;border-radius:5px;font-size:11px;cursor:pointer">'+plbl+'</button>';
      }}
      presets += '</div>';
    }}
    var inputStyle = 'width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px';
    var cmdField = isShell
      ? '<label style="font-size:12px;color:var(--muted)">Komenda</label>' + presets +
        '<input id="s3t-cmd-'+idx+'" placeholder="curl -s ${{url}}" style="'+inputStyle+';font-family:monospace;margin-bottom:4px">' +
        '<div style="font-size:11px;color:var(--muted);margin-bottom:8px"><code style="background:#0d1420;padding:1px 5px;border-radius:3px">${{zmienna}}</code> = jeden parametr &nbsp;|&nbsp; <code style="background:#0d1420;padding:1px 5px;border-radius:3px">${{*args}}</code> = AI podaje wszystkie argumenty naraz</div>'
      : '<div style="display:grid;grid-template-columns:80px 1fr;gap:8px;margin-bottom:8px">' +
        '<div><label style="font-size:12px;color:var(--muted)">Metoda</label>' +
        '<select id="s3t-method-'+idx+'" style="'+inputStyle+'"><option>POST</option><option>GET</option></select></div>' +
        '<div><label style="font-size:12px;color:var(--muted)">URL</label>' +
        '<input id="s3t-url-'+idx+'" placeholder="https://api.example.com/v1/search" style="'+inputStyle+'"></div></div>';
    var delBtn = idx > 0
      ? '<button type="button" onclick="s3RemoveTool('+idx+')" style="background:none;border:none;color:#f47a80;font-size:20px;cursor:pointer;padding:0;line-height:1">×</button>'
      : '';
    return '<div id="s3-card-'+idx+'" style="background:#0d1822;border:1px solid #2a3a4a;border-radius:10px;padding:14px 16px">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">' +
      '<span style="font-weight:700;font-size:13px;color:#7dd3fc">Narzędzie '+(idx+1)+'</span>'+delBtn+'</div>' +
      cmdField +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
      '<div><label style="font-size:12px;color:var(--muted)">Nazwa</label>' +
      '<input id="s3t-name-'+idx+'" placeholder="run_command" value="'+(idx===0?'run_command':'')+'" style="'+inputStyle+'"></div>' +
      '<div><label style="font-size:12px;color:var(--muted)">Opis (dla AI)</label>' +
      '<input id="s3t-desc-'+idx+'" placeholder="Pobiera dane / wykonuje komendę" style="'+inputStyle+'"></div>' +
      '</div></div>';
  }}

  function s3SaveValues() {{
    for (var i = 0; i < _s3Tools.length; i++) {{
      var cmd = document.getElementById('s3t-cmd-'+i);
      var name = document.getElementById('s3t-name-'+i);
      var desc = document.getElementById('s3t-desc-'+i);
      var url = document.getElementById('s3t-url-'+i);
      var method = document.getElementById('s3t-method-'+i);
      if (cmd) _s3Tools[i].cmd = cmd.value;
      if (name) _s3Tools[i].name = name.value;
      if (desc) _s3Tools[i].desc = desc.value;
      if (url) _s3Tools[i].url = url.value;
      if (method) _s3Tools[i].method = method.value;
    }}
  }}
  function s3RestoreValues() {{
    for (var i = 0; i < _s3Tools.length; i++) {{
      var t = _s3Tools[i];
      var cmd = document.getElementById('s3t-cmd-'+i);
      var name = document.getElementById('s3t-name-'+i);
      var desc = document.getElementById('s3t-desc-'+i);
      var url = document.getElementById('s3t-url-'+i);
      var method = document.getElementById('s3t-method-'+i);
      if (cmd && t.cmd) cmd.value = t.cmd;
      if (name && t.name) name.value = t.name;
      if (desc && t.desc) desc.value = t.desc;
      if (url && t.url) url.value = t.url;
      if (method && t.method) method.value = t.method;
    }}
  }}
  function s3Render() {{
    s3SaveValues();
    var list = document.getElementById('s3-tools-list');
    if (!list) return;
    list.innerHTML = _s3Tools.map(function(_,i){{ return s3ToolHtml(i, _s3IsShell); }}).join('');
    s3RestoreValues();
    var lang = localStorage.getItem('mcp_lang');
    if (lang === 'en' && typeof applyLang === 'function') applyLang('en');
  }}

  window.s3AddTool = function() {{
    _s3Tools.push({{}});
    s3Render();
  }};

  window.s3RemoveTool = function(idx) {{
    if (_s3Tools.length <= 1) return;
    _s3Tools.splice(idx, 1);
    s3Render();
  }};

  window.s3ToolPreset = function(idx, cmd) {{
    var c = document.getElementById('s3t-cmd-'+idx);
    if (c) c.value = cmd;
    var n = document.getElementById('s3t-name-'+idx);
    if (n && (!n.value || n.value === 'run_command')) {{
      n.value = cmd.split(' ')[0].replace(/[^a-z0-9]/gi,'') + '_command';
    }}
  }};

  window.s3Proceed = function() {{
    if (_s3IsOpenAPI) {{ goStep(4); return; }}
    var tools = [];
    for (var i=0; i<_s3Tools.length; i++) {{
      var name = (document.getElementById('s3t-name-'+i)||{{}}).value || ('tool_'+i);
      var desc = (document.getElementById('s3t-desc-'+i)||{{}}).value || '';
      if (_s3IsShell) {{
        var cmd = (document.getElementById('s3t-cmd-'+i)||{{}}).value || '';
        tools.push({{cmd:cmd, name:name, desc:desc, isShell:true}});
      }} else {{
        var url = (document.getElementById('s3t-url-'+i)||{{}}).value || '';
        var method = (document.getElementById('s3t-method-'+i)||{{}}).value || 'POST';
        tools.push({{url:url, method:method, name:name, desc:desc, isShell:false}});
      }}
    }}
    if (tools.length === 0 && !_s3IsPkg) {{ alert('Dodaj co najmniej jedno narzędzie.'); return; }}
    // Write first tool to legacy hidden fields
    if (tools.length > 0) {{
      var t0 = tools[0];
      if (t0.isShell) {{
        document.getElementById('s3-cmd-hidden').value  = t0.cmd;
        document.getElementById('s3-name-hidden').value = t0.name;
        document.getElementById('s3-desc-hidden').value = t0.desc;
      }} else {{
        document.getElementById('s3-url-hidden').value    = t0.url;
        document.getElementById('s3-method-hidden').value = t0.method;
        document.getElementById('s3-fname-hidden').value  = t0.name;
        document.getElementById('s3-desc-hidden').value   = t0.desc;
      }}
    }}
    // Extra tools (idx 1+)
    document.getElementById('s3-extra-json').value = JSON.stringify(tools.slice(1));
    goStep(4);
  }};

  window.goStep = function(n) {{
    if (n === 3) {{
      var name = document.getElementById('adv-name').value.trim();
      if (!name) {{ document.getElementById('adv-name').focus(); return; }}
      var adapter = document.getElementById('adapter-hidden').value;
      _s3IsShell   = adapter === 'shell';
      _s3IsPkg     = source === 'package';
      _s3IsOpenAPI = adapter === 'openapi';
      var hideTools = _s3IsPkg || _s3IsOpenAPI;
      if (!hideTools && _s3Tools.length === 0) _s3Tools.push({{}});
      if (!hideTools) s3Render();
      var sub = document.getElementById('s3-sub');
      if (sub) {{
        if (_s3IsOpenAPI)    sub.textContent = 'Tools zostaną wygenerowane automatycznie z OpenAPI spec — nie musisz nic definiować.';
        else if (_s3IsPkg)   sub.textContent = 'Narzędzia są już zdefiniowane w wybranej paczce — przejdź dalej.';
        else if (_s3IsShell) sub.textContent = 'Zdefiniuj komendy które AI będzie wykonywać w kontenerze.';
        else                 sub.textContent = 'Podaj adresy API które AI ma wywoływać.';
      }}
      var oaInfo = document.getElementById('s3-openapi-info');
      if (oaInfo) {{
        oaInfo.style.display = _s3IsOpenAPI ? 'block' : 'none';
        if (_s3IsOpenAPI) {{
          var oaSummEl = document.getElementById('s3-oa-summary');
          if (oaSummEl) {{
            var backUrl = (document.getElementById('oa-backend-url')||{{}}).value || '';
            var specUrl = (document.getElementById('oa-spec-url')||{{}}).value || (backUrl ? backUrl.replace(/\/$/, '') + '/openapi.json' : '');
            oaSummEl.textContent = 'Backend: ' + backUrl + (specUrl ? '\nSpec: ' + specUrl : '');
          }}
        }}
      }}
      var addBtn = document.querySelector('#s3 > button[onclick="s3AddTool()"]') || document.querySelector('#s3 button[onclick="s3AddTool()"]');
      if (addBtn) addBtn.style.display = hideTools ? 'none' : '';
      var toolList = document.getElementById('s3-tools-list');
      if (toolList) toolList.style.display = hideTools ? 'none' : '';
    }}
    [1,2,3,4,5].forEach(function(i) {{
      var s = document.getElementById('s'+i);
      if (s) s.classList.toggle('active', i===n);
      var p = document.getElementById('p'+i);
      if (p) p.className = 'prog-step' + (i<n ? ' done' : (i===n ? ' current' : ''));
    }});
    if (n === 5) buildSummary();
    window.scrollTo(0,0);
    var lang = localStorage.getItem('mcp_lang');
    if (lang === 'en' && typeof applyLang === 'function') setTimeout(function(){{ applyLang('en'); }}, 50);
  }};

  window.s3Preset = function(cmd, desc) {{
    s3ToolPreset(0, cmd);
    var d = document.getElementById('s3t-desc-0');
    if (d && !d.value) d.value = desc;
  }};

  window.chooseSource = function(src) {{
    source = src;
    document.getElementById('pkg-picker').style.display = (src==='package') ? 'block' : 'none';
    document.getElementById('engine-picker').style.display = (src==='blank') ? 'block' : 'none';
    if (src==='package') {{
      document.getElementById('pkg-hidden').value = '';
    }}
    // Highlight selected button
    document.querySelectorAll('.adv-type-grid .adv-type-btn').forEach(function(btn) {{
      btn.style.borderColor = '';
      btn.style.background = '';
    }});
    var idx = src === 'package' ? 0 : 1;
    var btns = document.querySelectorAll('.adv-type-grid .adv-type-btn');
    if (btns[idx]) {{
      btns[idx].style.borderColor = 'var(--blue)';
      btns[idx].style.background = '#0d2a40';
    }}
  }};

  window.pkgChosen = function(pkgId, labelEl) {{
    document.getElementById('pkg-hidden').value = pkgId;
    var radio = labelEl.querySelector('input[type="radio"]');
    if (radio) radio.checked = true;
    document.querySelectorAll('.pkg-check').forEach(function(el) {{ el.style.display = 'none'; }});
    var chk = labelEl.querySelector('.pkg-check');
    if (chk) chk.style.display = 'inline';
    document.getElementById('pkg-next-btn').style.display = 'block';
  }};

  window.chooseEngine = function(adapter, rc) {{
    document.getElementById('adapter-hidden').value = adapter;
    document.getElementById('rc-hidden').value = rc;
    document.getElementById('pkg-hidden').value = '';
    ['http','shell','openapi'].forEach(function(e) {{
      var el = document.getElementById('eng-'+e);
      if (el) el.style.borderColor = '';
    }});
    var key = adapter === 'http_request' ? 'http' : (adapter === 'openapi' ? 'openapi' : 'shell');
    var selBtn = document.getElementById('eng-'+key);
    if (selBtn) selBtn.style.borderColor = 'var(--blue)';
    // OpenAPI: show inline config form, stay on step 1
    _s3IsOpenAPI = (adapter === 'openapi');
    var oaCfg = document.getElementById('openapi-cfg');
    if (oaCfg) oaCfg.style.display = _s3IsOpenAPI ? 'block' : 'none';
    if (_s3IsOpenAPI) return;
    document.getElementById('rc-field').style.display = 'block';
    // Show shell env builder only for shell
    var envBox = document.getElementById('adv-shell-env');
    if (envBox) envBox.style.display = adapter === 'shell' ? 'block' : 'none';
    var sel = document.getElementById('rc-select');
    for (var i=0; i<sel.options.length; i++) {{
      if (sel.options[i].value === rc) {{ sel.selectedIndex = i; break; }}
    }}
    goStep(2);
  }};

  window.openapiGoNext = function() {{
    var url = (document.getElementById('oa-backend-url')||{{}}).value || '';
    if (!url.trim()) {{
      var el = document.getElementById('oa-backend-url');
      if (el) {{ el.style.borderColor = '#f47a80'; el.focus(); }}
      return;
    }}
    document.getElementById('rc-field').style.display = 'none';
    var envBox = document.getElementById('adv-shell-env');
    if (envBox) envBox.style.display = 'none';
    goStep(2);
  }};

  // Advanced Creator env builder
  window.advUpdateBaseHint = function() {{
    var sel = document.getElementById('adv-build-base');
    var custom = document.getElementById('adv-build-base-custom');
    var hint = document.getElementById('adv-base-hint');
    var hints = {{
      'mcp-runtime-shell:latest': '✅ Zawiera oc, kubectl, curl, jq + Python 3.12 Debian',
      'mcp-runtime-http-gateway:latest': '✅ HTTP gateway, Python 3.12',
      'python:3.12-slim': '⚠️ Czysty Python — dodaj curl w APT jeśli potrzebny',
      'debian:bookworm-slim': '⚠️ Czysty Debian — dodaj wszystkie potrzebne paczki',
      '__custom__': '⚠️ UWAGA: Czysty obraz OS (ubuntu, debian, alpine) nie zadziała! Obraz musi być zbudowany na bazie mcp-runtime-shell:latest lub mcp-runtime-http-gateway:latest — tylko te mają wbudowany serwer MCP. Przykład Dockerfile: FROM mcp-runtime-shell:latest'
    }};
    if (custom) custom.style.display = sel.value === '__custom__' ? 'block' : 'none';
    if (hint) hint.innerHTML = hints[sel.value] || '';
  }};

  window.advBuildReset = function() {{
    document.getElementById('adv-build-progress').style.display = 'none';
    document.getElementById('adv-build-btn').disabled = false;
    document.getElementById('adv-build-btn').textContent = '🔨 Spróbuj ponownie';
  }};

  window.advStartBuild = function() {{
    var apt = (document.getElementById('adv-build-apt').value || '').trim();
    var pip = (document.getElementById('adv-build-pip').value || '').trim();
    if (!apt && !pip) {{ document.getElementById('adv-build-apt').focus(); return; }}
    var sel = document.getElementById('adv-build-base');
    var baseImg = sel && sel.value !== '__custom__' ? sel.value : (document.getElementById('adv-build-base-custom').value.trim() || 'mcp-runtime-shell:latest');
    var basePart = baseImg.split('/').pop().replace(/[^a-z0-9]/gi,'-').replace(/-+/g,'-').replace(/^-|-$/g,'').toLowerCase().replace(/:[^:]*$/,'');
    var aptPart = apt.split(/\s+/).slice(0,3).map(function(p){{return p.replace(/[^a-z0-9]/g,'').substring(0,12);}}).filter(Boolean).join('-');
    var namePart = (aptPart || pip.split(/\s+/)[0].replace(/[^a-z0-9]/g,'').substring(0,12) || 'env');
    var rcName = basePart + '-' + namePart;
    var imgTag = 'mcp-runtime-' + rcName + ':latest';
    document.getElementById('adv-build-btn').disabled = true;
    document.getElementById('adv-build-progress').style.display = 'block';
    document.getElementById('adv-build-status').textContent = 'Budowanie ' + imgTag + '...';
    var body = new URLSearchParams({{
      image: imgTag, base_image: baseImg, runtime_class: rcName,
      apt_packages: apt, pip_packages: pip,
      allowed_execution_types: 'shell', risk_level: 'low', security_profile: 'restricted'
    }});
    fetch('/api/runtime-images/build', {{ method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, body: body.toString(), redirect:'manual' }})
    .then(function() {{
      var polls = 0;
      var t = setInterval(function() {{
        polls++;
        fetch('/api/runtime-image-builds/latest?rc=' + encodeURIComponent(rcName))
        .then(function(r){{return r.json();}}).then(function(d) {{
          if (d.status === 'done') {{
            clearInterval(t);
            document.getElementById('adv-build-spinner').textContent = '✅';
            document.getElementById('adv-build-status').textContent = 'Gotowe! Środowisko ' + imgTag + ' zbudowane.';
            // Update rc-hidden and rc-select with new image
            document.getElementById('rc-hidden').value = rcName;
            document.getElementById('adapter-hidden').value = 'shell';
            // Add new option to rc-select
            var rcSel = document.getElementById('rc-select');
            var opt = new Option(imgTag + ' (nowy)', rcName, true, true);
            rcSel.add(opt);
          }} else if (d.status === 'failed') {{
            clearInterval(t);
            document.getElementById('adv-build-spinner').textContent = '❌';
            var errMsg = (d.error || 'nieznany błąd');
            var hint = '';
            if (errMsg.indexOf('non-zero code: 100') !== -1 || errMsg.indexOf('Unable to locate package') !== -1) {{
              hint = '<br><br>💡 <b>Błąd 100 = paczka nie istnieje w Debian APT.</b><br>Sprawdź nazwę — np. <code>postgres-client</code> ❌ → <code>postgresql-client</code> ✅<br>Szukaj na <a href="https://packages.debian.org" target="_blank" style="color:#7dd3fc">packages.debian.org</a>';
            }} else if (errMsg.indexOf('non-zero code: 1') !== -1) {{
              hint = '<br><br>💡 Sprawdź nazwy pakietów na <a href="https://packages.debian.org" target="_blank" style="color:#7dd3fc">packages.debian.org</a>';
            }}
            document.getElementById('adv-build-progress').innerHTML =
              '<div style="background:#2a0a0a;border:2px solid #8a2020;border-radius:8px;padding:14px 16px">' +
              '<div style="font-weight:800;color:#f47a80;margin-bottom:6px">❌ Budowanie nie powiodło się</div>' +
              '<code style="font-size:11px;color:#f4c163;word-break:break-all;line-height:1.6">' + errMsg.slice(0, 300) + '</code>' +
              hint +
              '<br><br><button type="button" onclick="advBuildReset()" ' +
              'style="background:#1a3a5a;border:none;color:white;padding:8px 14px;border-radius:6px;font-size:12px;cursor:pointer;margin-top:8px">← Popraw i spróbuj ponownie</button>' +
              '</div>';
          }} else if (polls > 90) {{ clearInterval(t); document.getElementById('adv-build-status').textContent = 'Timeout — odśwież stronę i sprawdź Runtime Image Builds.'; }}
        }}).catch(function(){{}});
      }}, 3000);
    }});
  }};

  var _advEnvCount = 0;
  window.advAddEnv = function(key, val) {{
    var i = _advEnvCount++;
    var row = document.createElement('div');
    row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:center';
    row.innerHTML =
      '<input placeholder="NAZWA_ZMIENNEJ" value="'+(key||'')+'" style="padding:8px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:13px;font-family:monospace" oninput="syncEnvHidden('+i+',this,null)">' +
      '<input type="password" placeholder="wartość / token / klucz" value="'+(val||'')+'" style="padding:8px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:13px" oninput="syncEnvHidden('+i+',null,this)">' +
      '<button type="button" onclick="this.parentNode.remove()" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:6px 10px;border-radius:6px;font-size:12px;cursor:pointer">✕</button>';
    document.getElementById('adv-env-list').appendChild(row);
    // hidden inputs for form submit
    var hk = document.createElement('input'); hk.type='hidden'; hk.name='env_key_'+i; hk.id='env_hk_'+i; hk.value=key||'';
    var hv = document.createElement('input'); hv.type='hidden'; hv.name='env_val_'+i; hv.id='env_hv_'+i; hv.value=val||'';
    hk.setAttribute('form','adv-form'); hv.setAttribute('form','adv-form');
    document.getElementById('adv-env-list').appendChild(hk);
    document.getElementById('adv-env-list').appendChild(hv);
  }};
  window.syncEnvHidden = function(i, keyEl, valEl) {{
    if (keyEl) {{ var h=document.getElementById('env_hk_'+i); if(h) h.value=keyEl.value; }}
    if (valEl) {{ var h=document.getElementById('env_hv_'+i); if(h) h.value=valEl.value; }}
  }};

  function buildSummary() {{
    var name = document.getElementById('adv-name').value || '(brak nazwy)';
    var pkgId = document.getElementById('pkg-hidden').value;
    var adapter = document.getElementById('adapter-hidden').value;
    var rc = document.getElementById('rc-hidden').value;
    var pkgName = pkgId ? (document.querySelector('input[name="package_id"][value="'+pkgId+'"]')?.closest('.qs-pkg-card')?.querySelector('[style*="font-weight:800"]')?.textContent || pkgId) : '— brak paczki (blank)';
    var ro = document.querySelector('input[name="policy_read_only"]')?.checked;
    var bw = document.querySelector('input[name="policy_block_write"]')?.checked;
    var bd = document.querySelector('input[name="policy_block_destructive"]')?.checked;
    var to = document.querySelector('input[name="timeout_seconds"]')?.value;
    var toolLine = '';
    if (_s3IsOpenAPI) {{
      var oaBack = (document.getElementById('oa-backend-url')||{{}}).value || '';
      var oaSpec = (document.getElementById('oa-spec-url')||{{}}).value || (oaBack ? oaBack.replace(/\/$/, '') + '/openapi.json' : '');
      toolLine = '📄 <b>Backend URL:</b> <code>' + oaBack + '</code><br>📋 <b>OpenAPI spec:</b> <code>' + oaSpec + '</code><br>';
    }} else {{
      var cmd = (document.getElementById('s3-cmd')||{{}}).value || '';
      var toolUrl = (document.querySelector('input[name="first_tool_url"]')||{{}}).value || '';
      toolLine = cmd ? ('🔧 <b>Komenda:</b> <code>' + cmd + '</code><br>') : (toolUrl ? ('🌐 <b>URL:</b> <code>' + toolUrl + '</code><br>') : '');
    }}
    var envKeys = document.querySelectorAll('#adv-env-list input[name^="env_key_"]');
    var envLine = envKeys.length ? ('🔑 <b>ENV vars:</b> ' + envKeys.length + ' zdefiniowanych<br>') : '';
    document.getElementById('summary').innerHTML =
      '🖥️ <b>Serwer:</b> ' + name + '<br>' +
      (pkgId ? '📦 <b>Paczka:</b> ' + pkgName + '<br>' : toolLine) +
      '⚙️ <b>Silnik:</b> ' + (adapter||'—') + ' &nbsp; 🏗️ <b>Środowisko:</b> ' + (rc||'—') + '<br>' +
      '🔒 <b>Tylko odczyt:</b> ' + (ro?'✅':'❌') + ' &nbsp; ' +
      '🚫 <b>Blokuj zapis:</b> ' + (bw?'✅':'❌') + ' &nbsp; ' +
      '⛔ <b>Blokuj destruktywne:</b> ' + (bd?'✅':'❌') + '<br>' +
      '⏱️ <b>Timeout:</b> ' + to + 's<br>' + envLine;
  }}
}})();
</script>
"""
    return page_shell("create", body)



@app.get("/runtimes", response_class=HTMLResponse)
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
        empty = """
        <div style="text-align:center;padding:60px 20px">
          <div style="font-size:52px;margin-bottom:16px">🖥️</div>
          <div style="font-size:20px;font-weight:800;color:white;margin-bottom:8px">Brak serwerów MCP</div>
          <div class="muted" style="margin-bottom:24px">Utwórz pierwszy serwer przez kreator Szybki start.</div>
          <a href="/quick-start" style="background:var(--blue);color:white;padding:12px 24px;border-radius:8px;font-weight:800;font-size:15px">⚡ Szybki start</a>
        </div>"""
        return page_shell("runtimes", empty)

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

    cards_html = ""
    for r in runtimes:
        s = r["status"]
        s_class = "running" if s == "running" else ("failed" if s in {"failed","unhealthy","missing"} else ("deploying" if s in {"deploying","pending"} else "stopped"))
        endpoint = r["endpoint_url"] or ""
        endpoint_html = f'<div class="srv-card-endpoint">🔗 <a href="{escape(endpoint)}" target="_blank">{escape(endpoint)}</a></div>' if endpoint else '<div class="srv-card-endpoint" style="color:var(--muted)">brak endpointu</div>'
        rid = r['id']
        is_running = s == "running"
        is_stopped = s in {"stopped", "missing", "draft"}
        # Audit log ostatniej aktywności
        last_audit = audit_by_rid.get(rid)
        if last_audit:
            _icon = _action_icons_card.get(last_audit["action"], "📌")
            _time = last_audit["created_at"][:16].replace("T", " ")
            _actor = last_audit["actor"]
            _act = last_audit["action"].replace("_", " ")
            audit_strip = f'<div style="border-top:1px solid var(--line);margin-top:8px;padding-top:7px;display:flex;gap:6px;align-items:center;font-size:11px;color:var(--muted)">' \
                          f'<span>{_icon}</span>' \
                          f'<span style="color:#6a8aa8">{escape(_time)}</span>' \
                          f'<span style="color:#5a7a9a">{escape(_actor)}</span>' \
                          f'<span>·</span>' \
                          f'<span>{escape(_act)}</span>' \
                          f'</div>'
        else:
            audit_strip = '<div style="border-top:1px solid var(--line);margin-top:8px;padding-top:7px;font-size:11px;color:var(--muted)">Brak historii operacji</div>'
        cards_html += f"""
        <div class="srv-card" id="card-{rid}" onclick="if(!event.target.closest('button,a,form'))location.href='/runtimes/{rid}'" style="cursor:pointer">
          <div class="srv-card-top">
            <div>
              <a href="/runtimes/{rid}" class="srv-card-name">{escape(r['name'])}</a>
              <div class="srv-card-meta">⚙️ {escape(r['runtime_class'])} &nbsp;·&nbsp; <span class="risk {r['risk_level']}" style="font-size:11px;padding:2px 6px">{escape(r['risk_level'])}</span></div>
            </div>
            <span class="badge {s_class}" id="card-status-{rid}">{escape(s)}</span>
          </div>
          {endpoint_html}
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
            <a href="/runtimes/{rid}" style="padding:6px 10px;background:#263548;border-radius:6px;font-size:12px;font-weight:700;color:#c9d7e6;text-decoration:none">⚙️ Zarządzaj</a>
            {'<button onclick="cardAct(\''+rid+'\',\'deploy\')" style="padding:6px 10px;border:0;border-radius:6px;background:var(--blue);color:white;font-size:12px;font-weight:700;cursor:pointer">🚀 Deploy</button>' if not is_running else ''}
            {'<button onclick="cardAct(\''+rid+'\',\'stop\')" style="padding:6px 10px;border:0;border-radius:6px;background:#d9822b;color:white;font-size:12px;font-weight:700;cursor:pointer">⏹ Stop</button>' if is_running else ''}
            {'<button onclick="cardAct(\''+rid+'\',\'start\')" style="padding:6px 10px;border:0;border-radius:6px;background:#3d5268;color:white;font-size:12px;font-weight:700;cursor:pointer">▶️ Start</button>' if is_stopped else ''}
            {'<button onclick="cardAct(\''+rid+'\',\'restart\')" style="padding:6px 10px;border:0;border-radius:6px;background:#3d5268;color:white;font-size:12px;font-weight:700;cursor:pointer">🔄 Restart</button>' if is_running else ''}
            {'<button onclick="cardAct(\''+rid+'\',\'health\')" style="padding:6px 10px;border:0;border-radius:6px;background:#263548;color:#c9d7e6;font-size:12px;font-weight:700;cursor:pointer">🩺 Status</button>' if is_running else ''}
            <a href="/runtimes/{rid}?tab=logs" style="padding:6px 10px;background:#263548;border-radius:6px;font-size:12px;font-weight:700;color:#c9d7e6;text-decoration:none">📋 Logi</a>
            <a href="/runtimes/{rid}?tab=audit" style="padding:6px 10px;background:#263548;border-radius:6px;font-size:12px;font-weight:700;color:#c9d7e6;text-decoration:none">🤖 Wywołania</a>
            <button onclick="if(confirm('Usunąć?'))cardAct('{rid}','delete')" style="padding:6px 10px;border:0;border-radius:6px;background:#c43b3b;color:white;font-size:12px;font-weight:700;cursor:pointer">🗑️</button>
          </div>
          {audit_strip}
          <div id="cmsg-{rid}" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;font-size:12px;font-weight:600"></div>
        </div>"""

    empty_filter = f'<div style="text-align:center;padding:40px;color:var(--muted)">Brak serwerów w tym filtrze.</div>' if not runtimes else ""

    body = f"""
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
        <div class="filter-bar" style="margin-bottom:0">
          <a class="filter-pill {'active' if status=='all' else ''}" href="/runtimes">Wszystkie ({len(all_runtimes)})</a>
          <a class="filter-pill {'active' if status=='running' else ''}" href="/runtimes?status=running">🟢 Działające ({running_count})</a>
          <a class="filter-pill {'active' if status=='problem' else ''}" href="/runtimes?status=problem">🔴 Z problemami ({problem_count})</a>
        </div>
        <a href="/quick-start" style="background:var(--blue);color:white;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:700;white-space:nowrap">⚡ Nowy serwer</a>
      </div>
      <div class="srv-grid">{cards_html}</div>
      {empty_filter}
<script>
window.cardAct = function(rid, action) {{
  var box = document.getElementById('cmsg-' + rid);
  var statusBadge = document.getElementById('card-status-' + rid);
  var msgs = {{
    deploy:'🚀 Deployowanie...', stop:'⏹ Zatrzymywanie...', start:'▶️ Uruchamianie...',
    restart:'🔄 Restartowanie...', health:'🩺 Sprawdzam status...', delete:'🗑️ Usuwanie...'
  }};
  box.style.display = 'block';
  box.style.background = '#0d1e2e'; box.style.border = '1px solid #1a3a50'; box.style.color = '#7dd3fc';
  box.textContent = msgs[action] || 'Wykonuję...';

  fetch('/api/runtimes/' + rid + '/' + action, {{
    method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
    body:'return_to=/runtimes', redirect:'manual'
  }}).then(function() {{
    if (action === 'delete') {{
      box.style.background='#0e2e1e'; box.style.border='1px solid #1a5a38'; box.style.color='#5ce89a';
      box.textContent = '✅ Usunięto.';
      setTimeout(function() {{ var card=document.getElementById('card-'+rid); if(card) card.remove(); }}, 800);
      return;
    }}
    if (action === 'health') {{
      setTimeout(function() {{
        fetch('/api/runtimes/' + rid + '/status').then(function(r){{return r.json();}}).then(function(d) {{
          var ok = d.status === 'running';
          box.style.background = ok ? '#0e2e1e' : '#2c0e10';
          box.style.border = ok ? '1px solid #1a5a38' : '1px solid #5a2025';
          box.style.color = ok ? '#5ce89a' : '#f47a80';
          box.textContent = ok
            ? '✅ Kontener żyje! Status: running'
            : '❌ Problem! Status: ' + (d.status||'?') + (d.last_error ? ' — ' + d.last_error.slice(0,60) : '');
          if (statusBadge) statusBadge.textContent = d.status;
        }});
      }}, 1500);
      return;
    }}
    // poll for stable status after deploy/start/restart
    if (['deploy','start','restart'].includes(action)) {{
      var polls = 0;
      var t = setInterval(function() {{
        polls++;
        fetch('/api/runtimes/' + rid + '/status').then(function(r){{return r.json();}}).then(function(d) {{
          if (statusBadge) statusBadge.textContent = d.status;
          if (d.status === 'running') {{
            clearInterval(t);
            box.style.background='#0e2e1e'; box.style.border='1px solid #1a5a38'; box.style.color='#5ce89a';
            box.textContent = '✅ Działa! ' + (d.endpoint_url || '');
          }} else if (d.status === 'failed' || d.status === 'missing') {{
            clearInterval(t);
            box.style.background='#2c0e10'; box.style.border='1px solid #5a2025'; box.style.color='#f47a80';
            box.textContent = '❌ Błąd: ' + (d.last_error || d.status);
          }} else if (polls > 30) clearInterval(t);
        }});
      }}, 2000);
      return;
    }}
    if (action === 'stop') {{
      box.style.background='#1e252e'; box.style.border='1px solid #2b394a'; box.style.color='#7a92a8';
      box.textContent = '⏹ Serwer zatrzymany.';
      if (statusBadge) statusBadge.textContent = 'stopped';
      return;
    }}
  }}).catch(function(e) {{
    box.style.background='#2c0e10'; box.style.color='#f47a80';
    box.textContent = '❌ Błąd: ' + e;
  }});
}};
</script>
    """
    return page_shell("runtimes", body)


def adapter_toggle_html(adapter: dict[str, Any]) -> str:
    if not adapter["implemented"]:
        return '<button class="disabled" disabled title="This tool type is planned, but no runtime plugin exists yet.">Planned</button>'
    label = "Disable" if adapter["enabled"] else "Enable"
    return f'<form method="post" action="/api/adapters/{adapter["name"]}/toggle"><button>{label}</button></form>'


@app.get("/tool-types", response_class=HTMLResponse)
@app.get("/adapters", response_class=HTMLResponse)
def adapters_page(implemented: int | None = None, error: str = "") -> str:
    all_adapters = store.rows(sql.SELECT_ADAPTERS_ALL)
    adapters = [adapter for adapter in all_adapters if adapter["implemented"]] if implemented == 1 else all_adapters
    title = "Działające silniki wykonania" if implemented == 1 else "Silniki wykonania"
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    adapter_icons = {"http_request": "🌐", "shell": "⌨️", "ssh": "🔐", "python": "🐍", "openshift": "🔴", "workflow": "🔗"}
    active_html = ""
    planned_html = ""
    for item in adapters:
        contract = adapter_contract(item["name"])
        disp = escape(contract.get("display_name") or item["name"])
        icon = adapter_icons.get(item["name"], "⚙️")
        if item["implemented"]:
            active_html += f"""
            <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:16px 18px">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
                <div style="flex:1">
                  <div style="font-weight:800;font-size:14px;color:white">{icon} {disp}</div>
                  <div class="muted" style="font-size:12px;margin-top:3px">{escape(item['description'])}</div>
                  <div style="margin-top:6px;display:flex;gap:6px">
                    <span class="risk {item['risk_level']}" style="font-size:11px;padding:2px 7px">{escape(item['risk_level'])}</span>
                    <span class="badge" style="font-size:11px;padding:2px 7px">{escape(item['mode'])}</span>
                    {'<span class="badge running" style="font-size:11px;padding:2px 7px">aktywny</span>' if item['enabled'] else '<span class="badge stopped" style="font-size:11px;padding:2px 7px">wyłączony</span>'}
                  </div>
                </div>
                <div style="display:flex;gap:8px;flex-shrink:0">
                  <button onclick="toggleAdapterEdit('{escape(item['name'])}')"
                    style="background:#1a2a3a;border:1px solid #2a4a6a;color:#7dd3fc;padding:6px 12px;border-radius:6px;font-size:12px;cursor:pointer">
                    ✏️ Edytuj
                  </button>
                  {adapter_toggle_html(item)}
                  <form method="post" action="/api/adapters/{escape(item['name'])}/delete"
                        onsubmit="return confirm('Usunąć silnik {escape(item['name'])}? Może to uszkodzić runtimey które go używają.')">
                    <button class="delete" style="padding:6px 12px;font-size:12px">🗑️</button>
                  </form>
                </div>
              </div>
              <!-- Inline edit form -->
              <div id="edit-{escape(item['name'])}" style="display:none;margin-top:14px;border-top:1px solid var(--line);padding-top:14px">
                <form method="post" action="/api/adapters/{escape(item['name'])}/update">
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Ryzyko</label>
                      <select name="risk_level" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                        <option {'selected' if item['risk_level']=='low' else ''} value="low">niski (low)</option>
                        <option {'selected' if item['risk_level']=='medium' else ''} value="medium">średni (medium)</option>
                        <option {'selected' if item['risk_level']=='high' else ''} value="high">wysoki (high)</option>
                      </select>
                    </div>
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Tryb</label>
                      <select name="mode" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                        <option {'selected' if item['mode']=='read-only' else ''} value="read-only">read-only</option>
                        <option {'selected' if item['mode']=='read-write' else ''} value="read-write">read-write</option>
                        <option {'selected' if item['mode']=='write' else ''} value="write">write</option>
                      </select>
                    </div>
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Obraz Docker</label>
                      <input name="runtime_image" value="{escape(item['runtime_image'])}" style="width:100%;box-sizing:border-box;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:12px;font-family:monospace">
                    </div>
                  </div>
                  <div style="margin-bottom:10px">
                    <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Opis</label>
                    <input name="description" value="{escape(item['description'])}" style="width:100%;box-sizing:border-box;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                  </div>
                  <div style="display:flex;gap:8px">
                    <button type="submit" style="background:var(--blue);border:none;color:white;padding:7px 16px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer">💾 Zapisz</button>
                    <button type="button" onclick="toggleAdapterEdit('{escape(item['name'])}')" style="background:#263548;border:none;color:#c9d7e6;padding:7px 12px;border-radius:6px;font-size:12px;cursor:pointer">Anuluj</button>
                  </div>
                </form>
              </div>
            </div>"""
        else:
            planned_html += f"""
            <div style="background:#0b1420;border:1px solid #1e2d3d;border-radius:10px;padding:14px 18px">
              <div style="display:flex;gap:12px;align-items:center">
                <span style="font-size:24px;opacity:.5">{icon}</span>
                <div style="flex:1;opacity:.7">
                  <div style="font-weight:700;font-size:13px;color:#607083">{disp}</div>
                  <div style="color:#3d5268;font-size:12px;margin-top:2px">{escape(item['description'] or 'planowany — jeszcze nie zaimplementowany')}</div>
                  <div style="margin-top:4px;display:flex;gap:6px">
                    <span class="risk {item['risk_level']}" style="font-size:10px;padding:2px 6px">{escape(item['risk_level'])}</span>
                    <span style="background:#1e2d3d;color:#607083;padding:2px 7px;border-radius:999px;font-size:10px">planowany</span>
                  </div>
                </div>
                <div style="display:flex;gap:6px;flex-shrink:0">
                  <button onclick="toggleAdapterEdit('p-{escape(item['name'])}')"
                    style="background:#1a2030;border:1px solid #2a3a50;color:#607083;padding:5px 10px;border-radius:6px;font-size:11px;cursor:pointer">
                    ✏️ Edytuj
                  </button>
                  <form method="post" action="/api/adapters/{escape(item['name'])}/toggle">
                    <button style="background:#1a2a1a;border:1px solid #2a4a2a;color:#4a8a4a;padding:5px 10px;border-radius:6px;font-size:11px;cursor:pointer">✅ Aktywuj</button>
                  </form>
                  <form method="post" action="/api/adapters/{escape(item['name'])}/delete"
                        onsubmit="return confirm('Usunąć silnik {escape(item['name'])}?')">
                    <button class="delete" style="padding:5px 10px;font-size:11px">🗑️</button>
                  </form>
                </div>
              </div>
              <!-- Inline edit form for planned -->
              <div id="edit-p-{escape(item['name'])}" style="display:none;margin-top:14px;border-top:1px solid #1e2d3d;padding-top:14px">
                <form method="post" action="/api/adapters/{escape(item['name'])}/update">
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Ryzyko</label>
                      <select name="risk_level" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                        <option {'selected' if item['risk_level']=='low' else ''} value="low">niski</option>
                        <option {'selected' if item['risk_level']=='medium' else ''} value="medium">średni</option>
                        <option {'selected' if item['risk_level']=='high' else ''} value="high">wysoki</option>
                      </select>
                    </div>
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Tryb</label>
                      <select name="mode" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                        <option {'selected' if item['mode']=='read-only' else ''} value="read-only">read-only</option>
                        <option {'selected' if item['mode']=='read-write' else ''} value="read-write">read-write</option>
                      </select>
                    </div>
                    <div>
                      <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Obraz Docker</label>
                      <input name="runtime_image" value="{escape(item['runtime_image'])}" style="width:100%;box-sizing:border-box;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:12px;font-family:monospace">
                    </div>
                  </div>
                  <div style="margin-bottom:10px">
                    <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Opis</label>
                    <input name="description" value="{escape(item['description'])}" style="width:100%;box-sizing:border-box;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                  </div>
                  <div style="display:flex;gap:8px">
                    <button type="submit" style="background:var(--blue);border:none;color:white;padding:7px 16px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer">💾 Zapisz</button>
                    <button type="button" onclick="toggleAdapterEdit('p-{escape(item['name'])}')" style="background:#263548;border:none;color:#c9d7e6;padding:7px 12px;border-radius:6px;font-size:12px;cursor:pointer">Anuluj</button>
                  </div>
                </form>
              </div>
            </div>"""
    body = f"""
      {alert}
      <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:10px;padding:14px 18px;margin-bottom:4px;font-size:13px;color:#7ab8d8">
        ℹ️ <b>To NIE jest miejsce do tworzenia tools</b> dla serwera MCP.
        Tutaj widoczne są globalne silniki platformy (http_request, shell…).
        Żeby dodać tool — użyj <a href="/tool-packages/generate">Package Generator</a> lub <a href="/quick-start">Szybkiego startu</a>.
      </div>

      <section>
        <h2>Działające silniki</h2>
        <div style="display:grid;gap:10px">{active_html or '<p class="muted">Brak aktywnych silników.</p>'}</div>
      </section>

      {f'<section><h2>Planowane silniki</h2><div style="display:grid;gap:8px">{planned_html}</div></section>' if planned_html else ''}

<script>
function toggleAdapterEdit(name) {{
  var el = document.getElementById('edit-' + name);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}
</script>

      <section>
        <h2>➕ Dodaj nowy silnik</h2>
        <div style="background:#0a1520;border:1px solid #1a3a50;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--muted)">
          💡 <b style="color:white">Kiedy dodawać nowy silnik?</b> Gdy masz własny obraz Docker który implementuje protokół MCP lub chcesz zarejestrować nowy typ adaptera do użycia w pączkach. Zaznacz <b>Zaimplementowany</b> jeśli obraz już działa — wtedy silnik pojawi się w sekcji "Działające".
        </div>
        <div style="background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:20px 22px">
          <form method="post" action="/api/adapters">
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px">
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Nazwa (id)</label>
                <input name="name" placeholder="my_adapter" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                <div style="font-size:11px;color:var(--muted);margin-top:3px">Małe litery, bez spacji</div>
              </div>
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Typ adaptera</label>
                <select name="adapter_type" style="width:100%;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                  <option value="http">http — REST API</option>
                  <option value="shell">shell — komendy CLI</option>
                  <option value="python">python — skrypty Python</option>
                  <option value="ssh">ssh — zdalny SSH</option>
                  <option value="openshift">openshift — OCP/K8s</option>
                  <option value="workflow">workflow — sekwencje</option>
                </select>
              </div>
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Poziom ryzyka</label>
                <select name="risk_level" style="width:100%;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                  <option value="low">niski (low)</option>
                  <option value="medium">średni (medium)</option>
                  <option value="high">wysoki (high)</option>
                </select>
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Opis</label>
                <input name="description" placeholder="Opis działania silnika" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
              </div>
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Obraz Docker</label>
                <input name="runtime_image" placeholder="mcp-runtime-shell:latest" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px;font-family:monospace">
              </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Tryb dostępu</label>
                <select name="mode" style="width:100%;padding:9px 11px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                  <option value="read-only">read-only</option>
                  <option value="read-write">read-write</option>
                </select>
              </div>
              <div>
                <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:8px">Status</label>
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:10px 12px">
                  <input type="checkbox" name="implemented" value="1" style="width:16px;height:16px">
                  <div>
                    <div style="font-weight:700;font-size:13px;color:white">✅ Zaimplementowany</div>
                    <div style="font-size:11px;color:var(--muted)">Zaznacz jeśli obraz Docker już działa — silnik pojawi się w "Działające"</div>
                  </div>
                </label>
              </div>
            </div>
            <button type="submit" style="background:var(--blue);border:none;color:white;padding:10px 22px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer">➕ Dodaj silnik</button>
          </form>
        </div>
      </section>
    """
    return page_shell("adapters", body)


@app.get("/tool-packages/generate", response_class=HTMLResponse)
def package_generator_page(error: str = "") -> str:
    images = [r["runtime_image"] for r in store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' ORDER BY runtime_image")]
    image_options = "".join(f'<option value="{escape(img)}">{escape(img)}</option>' for img in images)
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""

    body = f"""
<style>
.gen-wrap {{ max-width:820px; margin:0 auto; display:grid; gap:18px; }}
.gen-step {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:26px 28px; display:none; }}
.gen-step.active {{ display:block; }}
.gen-step h2 {{ margin:0 0 4px; font-size:20px; font-weight:800; }}
.gen-step .sub {{ color:var(--muted); font-size:14px; margin-bottom:20px; }}
.gen-field {{ margin-bottom:14px; }}
.gen-field label {{ display:block; font-weight:700; font-size:13px; color:#aac8e0; margin-bottom:5px; }}
.gen-field input,.gen-field select,.gen-field textarea {{ width:100%; box-sizing:border-box; padding:10px 12px; border:1px solid #34465b; border-radius:6px; background:#0d1420; color:var(--text); font-size:14px; }}
.gen-field textarea {{ min-height:80px; font-family:monospace; font-size:13px; }}
.gen-field .hint {{ color:var(--muted); font-size:12px; margin-top:4px; }}
.gen-next {{ width:100%; padding:13px; font-size:15px; font-weight:800; border:none; border-radius:8px; background:var(--blue); color:white; cursor:pointer; margin-top:10px; }}
.gen-next:hover {{ background:var(--blue-dark); }}
.gen-back {{ background:#263548; color:#c9d7e6; border:none; padding:8px 14px; border-radius:6px; cursor:pointer; font-size:13px; margin-bottom:16px; }}
.gen-prog {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-bottom:4px; }}
.gen-p {{ padding:10px; border-radius:8px; text-align:center; background:var(--panel-2); border:1px solid var(--line); font-size:12px; font-weight:700; color:var(--muted); transition:.2s; }}
.gen-p.done {{ background:#0e2e1e; color:#5ce89a; border-color:#1a5a38; }}
.gen-p.cur {{ background:#0d3a55; color:white; border-color:var(--blue); }}
.tool-card {{ background:#0d1420; border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:12px; }}
.tool-card h4 {{ margin:0 0 12px; font-size:14px; color:#7dd3fc; display:flex; justify-content:space-between; }}
.ptype-btn {{ background:#0d1822; border:2px solid var(--line); border-radius:10px; padding:18px 14px; cursor:pointer; text-align:center; transition:.15s; color:var(--text); width:100%; }}
.ptype-btn:hover,.ptype-btn.sel {{ border-color:var(--blue); background:#0d2a40; }}
.ptype-btn .pi {{ font-size:30px; margin-bottom:8px; }}
.ptype-btn .pn {{ font-weight:800; font-size:14px; margin-bottom:5px; }}
.ptype-btn .pd {{ color:var(--muted); font-size:12px; line-height:1.5; }}
</style>

{alert}

<div class="gen-wrap">
  <!-- Progress bar -->
  <div class="gen-prog" id="gprog">
    <div class="gen-p cur" id="gp1">1. Typ narzędzi</div>
    <div class="gen-p" id="gp2">2. Narzędzia (tools)</div>
    <div class="gen-p" id="gp3">3. Bezpieczeństwo</div>
    <div class="gen-p" id="gp4">4. Metadane i install</div>
  </div>

  <!-- STEP 1: Typ -->
  <div class="gen-step active" id="gs1">
    <h2>Jakiego typu narzędzia chcesz stworzyć?</h2>
    <div class="sub">Wybór określa jakiego obrazu Docker użyjemy i jak tools będą działać.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <button type="button" class="ptype-btn" id="pt-shell" onclick="pickType('shell')">
        <div class="pi">⌨️</div>
        <div class="pn">Shell / CLI</div>
        <div class="pd">Komendy: curl, oc, kubectl, dowolne CLI dostępne w kontenerze</div>
      </button>
      <button type="button" class="ptype-btn" id="pt-http" onclick="pickType('http')">
        <div class="pi">🌐</div>
        <div class="pn">REST API</div>
        <div class="pd">Wywołania HTTP do zewnętrznych API: GitLab, Jira, własny serwis</div>
      </button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
      <button type="button" class="ptype-btn" id="pt-mixed" onclick="pickType('mixed')">
        <div class="pi">🔀</div>
        <div class="pn">Shell + HTTP</div>
        <div class="pd">Mieszane narzędzia — część shell, część REST API</div>
      </button>
      <button type="button" class="ptype-btn" id="pt-custom" onclick="pickType('custom')">
        <div class="pi">🛠️</div>
        <div class="pn">Custom (własny obraz)</div>
        <div class="pd">Masz własny Docker image z narzędziami — wpisz ręcznie</div>
      </button>
    </div>
    <div id="custom-image-row" style="display:none;margin-top:14px">
      <div class="gen-field">
        <label>Własny obraz Docker</label>
        <input id="custom-image-input" list="image-list" placeholder="mcp-runtime-custom:latest" oninput="gUpdate()">
        <datalist id="image-list">{image_options}</datalist>
        <div class="hint">Obraz musi być zbudowany przez Runtime Image Builder lub dostępny lokalnie w Docker</div>
      </div>
    </div>
  </div>

  <!-- STEP 2: Tools -->
  <div class="gen-step" id="gs2">
    <button type="button" class="gen-back" onclick="gStep(1)">← Wróć</button>
    <h2>Definiuj narzędzia (tools)</h2>
    <div class="sub">Każdy tool to jedna komenda lub endpoint. AI może wywoływać każdy z nich niezależnie.</div>

    <div id="tools-container"></div>

    <button type="button" onclick="addTool()" style="background:#263548;color:#c9d7e6;border:none;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700">
      + Dodaj kolejne narzędzie
    </button>

    <button type="button" class="gen-next" onclick="gStep(3)" style="margin-top:16px">Dalej → Bezpieczeństwo 🔒</button>
  </div>

  <!-- STEP 3: Bezpieczeństwo -->
  <div class="gen-step" id="gs3">
    <button type="button" class="gen-back" onclick="gStep(2)">← Wróć</button>
    <h2>🔒 Bezpieczeństwo i ograniczenia</h2>
    <div class="sub">Określ co AI może, a czego nie może robić. Domyślnie maksymalna ochrona.</div>

    <div style="display:grid;gap:10px;margin-bottom:16px">
      <label style="display:flex;align-items:flex-start;gap:12px;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px;cursor:pointer">
        <input type="checkbox" id="pol-readonly" checked onchange="gUpdate()" style="width:auto;margin-top:2px;flex-shrink:0">
        <div><div style="font-weight:700;font-size:13px;color:white">🔒 Tylko odczyt</div>
        <div style="color:var(--muted);font-size:12px;margin-top:2px">Tools mogą tylko czytać dane</div></div>
      </label>
      <label style="display:flex;align-items:flex-start;gap:12px;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px;cursor:pointer">
        <input type="checkbox" id="pol-nowrite" checked onchange="gUpdate()" style="width:auto;margin-top:2px;flex-shrink:0">
        <div><div style="font-weight:700;font-size:13px;color:white">🚫 Blokuj zapis</div>
        <div style="color:var(--muted);font-size:12px;margin-top:2px">Blokada operacji zapisu</div></div>
      </label>
      <label style="display:flex;align-items:flex-start;gap:12px;background:#0d1822;border:1px solid var(--line);border-radius:8px;padding:12px 14px;cursor:pointer">
        <input type="checkbox" id="pol-nodestr" checked onchange="gUpdate()" style="width:auto;margin-top:2px;flex-shrink:0">
        <div><div style="font-weight:700;font-size:13px;color:white">⛔ Blokuj destruktywne</div>
        <div style="color:var(--muted);font-size:12px;margin-top:2px">Blokada usuwania, resetowania, drop</div></div>
      </label>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="gen-field" style="margin:0">
        <label>Dozwolone binarki (spacja)</label>
        <input id="pol-bins" placeholder="oc jq curl kubectl" oninput="gUpdate()">
        <div class="hint">Zostaw puste = wszystkie. Wpisz np. <code>oc jq</code> = tylko te</div>
      </div>
      <div class="gen-field" style="margin:0">
        <label>⏱️ Timeout (sekundy)</label>
        <input type="number" id="pol-timeout" value="30" min="5" max="300" oninput="gUpdate()">
      </div>
    </div>

    <div class="gen-field">
      <label>Dozwolone prefixy komend (jedna na linię)</label>
      <textarea id="pol-pfx" placeholder="oc get&#10;oc describe&#10;oc logs" oninput="gUpdate()" style="min-height:70px"></textarea>
      <div class="hint">Np. <code>oc get</code> = AI może TYLKO uruchamiać komendy zaczynające się od <code>oc get</code></div>
    </div>

    <div class="gen-field">
      <label>Zablokowane komendy / prefixy (jedna na linię)</label>
      <textarea id="pol-blk" placeholder="kubectl delete&#10;kubectl apply&#10;oc delete&#10;oc adm" oninput="gUpdate()" style="min-height:70px"></textarea>
      <div class="hint">Komendy zaczynające się od tych prefiksów będą odrzucane przez runtime</div>
    </div>

    <button type="button" class="gen-next" onclick="gStep(4)">Dalej → Metadane i instalacja →</button>
  </div>

  <!-- STEP 4: Metadane + preview + install -->
  <div class="gen-step" id="gs4">
    <button type="button" class="gen-back" onclick="gStep(3)">← Wróć</button>
    <h2>Metadane i instalacja</h2>
    <div class="sub">Nadaj paczce nazwę i opis — pojawi się w katalogu Paczki tools.</div>

    <div class="gen-field">
      <label>Nazwa paczki</label>
      <input id="pkg-name" placeholder="OpenShift ReadOnly Assistant" oninput="gUpdate()">
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
      <div class="gen-field" style="margin:0">
        <label>Kategoria</label>
        <select id="pkg-category" oninput="gUpdate()">
          <option value="other" selected>other</option>
          <option value="http">http</option>
          <option value="openshift">openshift</option>
          <option value="kubernetes">kubernetes</option>
          <option value="rag">rag</option>
          <option value="system">system</option>
        </select>
      </div>
      <div class="gen-field" style="margin:0">
        <label>Poziom ryzyka</label>
        <select id="pkg-risk" oninput="gUpdate()">
          <option value="low">low — read-only, bezpieczne</option>
          <option value="medium" selected>medium — operacje na infrastrukturze</option>
          <option value="high">high — operacje destruktywne</option>
        </select>
      </div>
    </div>
    <div class="gen-field">
      <label>Opis (opcjonalny)</label>
      <input id="pkg-desc" placeholder="Read-only OCP tools via oc CLI." oninput="gUpdate()">
    </div>

    <div style="margin-bottom:14px">
      <div style="font-weight:700;font-size:13px;color:#aac8e0;margin-bottom:8px">Podgląd JSON paczki:</div>
      <textarea id="json-preview" readonly style="height:280px;font-family:monospace;font-size:12px;color:#c9d7e6;background:#0b1420;border:1px solid var(--line);border-radius:8px;padding:12px;width:100%;box-sizing:border-box"></textarea>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <button type="button" onclick="installPackage()" style="background:#1a7a3f;color:white;border:none;padding:14px;border-radius:8px;font-size:15px;font-weight:800;cursor:pointer">
        🚀 Zainstaluj paczkę
      </button>
      <button type="button" id="copy-btn" onclick="copyJSON()" style="background:#263548;color:#c9d7e6;border:none;padding:14px;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer">
        📋 Kopiuj JSON
      </button>
    </div>
  </div>

</div>

<form id="install-form" method="post" action="/api/tool-packages/import" style="display:none">
  <input type="hidden" id="install-json" name="package_json">
</form>

<script>
// ── State ──────────────────────────────────────────────────
let gType = 'shell';
let toolId = 0;
let fieldCounters = {{}};

// ── Step navigation ────────────────────────────────────────
function gStep(n) {{
  if (n === 3 && document.querySelectorAll('.tool-card').length === 0) {{
    addTool(); // ensure at least one tool
  }}
  [1,2,3,4].forEach(function(i) {{
    document.getElementById('gs'+i).classList.toggle('active', i===n);
    var p = document.getElementById('gp'+i);
    p.className = 'gen-p' + (i<n?' done':(i===n?' cur':''));
  }});
  window.scrollTo(0,0);
  gUpdate();
}}

// ── Type selection ─────────────────────────────────────────
function pickType(t) {{
  gType = t;
  ['shell','http','mixed','custom'].forEach(function(k) {{
    document.getElementById('pt-'+k).classList.toggle('sel', k===t);
  }});
  document.getElementById('custom-image-row').style.display = t==='custom' ? '' : 'none';
  gStep(2);
  // Pre-populate with one tool if container empty
  if (document.querySelectorAll('.tool-card').length === 0) addTool();
}}

// ── Tool builder ───────────────────────────────────────────
function addTool() {{
  toolId++;
  fieldCounters[toolId] = 0;
  const c = document.getElementById('tools-container');
  const d = document.createElement('div');
  d.id = 'tool-'+toolId;
  d.className = 'tool-card';
  d.dataset.toolId = toolId;
  const showShell = (gType === 'shell' || gType === 'mixed' || gType === 'custom');
  const showHttp  = (gType === 'http'  || gType === 'mixed');
  d.innerHTML = toolHTML(toolId, showShell, showHttp);
  c.appendChild(d);
  gUpdate();
}}

function toolHTML(tid, showShell, showHttp) {{
  const defType = showShell ? 'shell' : 'http_request';
  return `<div>
    <h4>🔧 Narzędzie #${{tid}}
      <button type="button" onclick="removeTool(${{tid}})" style="background:#c43b3b;border:none;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:12px;color:white">Usuń</button>
    </h4>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
      <div class="gen-field" style="margin:0">
        <label>Nazwa narzędzia</label>
        <input id="tool-name-${{tid}}" placeholder="oc_get_pods" oninput="gUpdate()">
      </div>
      <div class="gen-field" style="margin:0">
        <label>Typ</label>
        <select id="tool-type-${{tid}}" onchange="toggleToolType(${{tid}})">
          ${{showShell ? '<option value="shell" selected>shell — komenda CLI</option>' : ''}}
          ${{showHttp  ? '<option value="http_request" '+(showShell?'':'selected')+'>http_request — REST API</option>' : ''}}
        </select>
      </div>
    </div>
    <div class="gen-field">
      <label>Opis (wyświetlany AI)</label>
      <input id="tool-desc-${{tid}}" placeholder="Pobiera listę podów w podanym namespace" oninput="gUpdate()">
    </div>

    <div id="shell-cfg-${{tid}}" style="${{showShell?'':'display:none'}}">
      <div class="gen-field">
        <label>Komenda (użyj <code>\${{variable}}</code> lub <code>\${{*args}}</code>)</label>
        <input id="tool-cmd-${{tid}}" placeholder="oc get ${{*args}}" oninput="gUpdate()">
        <div class="hint">
          <code>\${{namespace}}</code> = jeden parametr &nbsp;|&nbsp; <code>\${{*args}}</code> = AI podaje wszystkie argumenty naraz
        </div>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
        <span style="font-size:11px;color:var(--muted);align-self:center">Presety:</span>
        <button type="button" class="preset-btn" onclick="setToolCmd(${{tid}},'oc get \${{*args}}','Wykonaj dowolne oc get')">🔴 oc get</button>
        <button type="button" class="preset-btn" onclick="setToolCmd(${{tid}},'oc logs \${{pod}} -n \${{namespace}} --tail \${{lines}}','Logi z poda OC')">🔴 oc logs</button>
        <button type="button" class="preset-btn" onclick="setToolCmd(${{tid}},'kubectl get \${{*args}}','Wykonaj dowolne kubectl get')">☸️ kubectl get</button>
        <button type="button" class="preset-btn" onclick="setToolCmd(${{tid}},'curl -s -L --max-time 30 \${{url}}','GET na URL')">🌐 curl GET</button>
        <button type="button" class="preset-btn" onclick="setToolCmd(${{tid}},'curl \${{*args}}','Dowolna komenda curl')">🌐 curl (wszystko)</button>
      </div>
    </div>

    <div id="http-cfg-${{tid}}" style="${{showHttp&&!showShell?'':'display:none'}}">
      <div style="display:grid;grid-template-columns:120px 1fr;gap:10px">
        <div class="gen-field" style="margin:0">
          <label>Metoda</label>
          <select id="tool-method-${{tid}}" oninput="gUpdate()">
            <option>GET</option><option selected>POST</option><option>PUT</option><option>PATCH</option>
          </select>
        </div>
        <div class="gen-field" style="margin:0">
          <label>URL</label>
          <input id="tool-url-${{tid}}" placeholder="https://api.example.com/v1/search" oninput="gUpdate()">
        </div>
      </div>
      <div class="gen-field">
        <label>Body template JSON</label>
        <textarea id="tool-body-${{tid}}" style="min-height:60px" oninput="gUpdate()">{{"query":"\${{query}}"}}</textarea>
      </div>
    </div>

    <div style="margin-top:10px">
      <div style="font-weight:700;font-size:12px;color:#7dd3fc;margin-bottom:6px">Parametry (input schema):</div>
      <div id="fields-${{tid}}"></div>
      <button type="button" onclick="addField(${{tid}})" style="background:#1a2a3a;border:1px solid var(--line);color:#b0c8e0;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600">+ Dodaj parametr</button>
    </div>
  </div>`;
}}

function setToolCmd(tid, cmd, desc) {{
  const c = document.getElementById('tool-cmd-'+tid);
  const d = document.getElementById('tool-desc-'+tid);
  if (c) c.value = cmd;
  if (d && !d.value) d.value = desc;
  // Auto-detect params and add fields
  gUpdate();
}}

function removeTool(tid) {{
  const el = document.getElementById('tool-'+tid);
  if (el) el.remove();
  gUpdate();
}}

function toggleToolType(tid) {{
  const t = document.getElementById('tool-type-'+tid).value;
  document.getElementById('shell-cfg-'+tid).style.display = t==='shell' ? '' : 'none';
  document.getElementById('http-cfg-'+tid).style.display  = t==='http_request' ? '' : 'none';
  gUpdate();
}}

function addField(tid) {{
  if (!fieldCounters[tid]) fieldCounters[tid] = 0;
  fieldCounters[tid]++;
  const fid = fieldCounters[tid];
  const c = document.getElementById('fields-'+tid);
  const d = document.createElement('div');
  d.id = 'field-'+tid+'-'+fid;
  d.style.cssText = 'display:grid;grid-template-columns:1fr 90px 2fr 80px 70px 36px;gap:6px;align-items:end;margin-bottom:6px';
  d.innerHTML = `
    <label style="font-size:12px">Nazwa<input class="fname" placeholder="namespace" oninput="gUpdate()"></label>
    <label style="font-size:12px">Typ<select class="ftype" oninput="gUpdate()">
      <option value="string" selected>string</option>
      <option value="integer">integer</option>
      <option value="boolean">boolean</option>
    </select></label>
    <label style="font-size:12px">Opis<input class="fdesc" placeholder="Target namespace" oninput="gUpdate()"></label>
    <label style="font-size:12px">Default<input class="fdefault" oninput="gUpdate()"></label>
    <label style="display:flex;gap:5px;align-items:center;font-size:12px;padding-top:16px">
      <input type="checkbox" class="freq" onchange="gUpdate()"> Req
    </label>
    <button type="button" onclick="removeField(${{tid}},${{fid}})" style="background:#c43b3b;border:none;padding:6px 8px;border-radius:6px;cursor:pointer;color:white">✕</button>`;
  c.appendChild(d);
  gUpdate();
}}

function removeField(tid, fid) {{
  const el = document.getElementById('field-'+tid+'-'+fid);
  if (el) el.remove();
  gUpdate();
}}

// ── JSON generation ────────────────────────────────────────
function val(id) {{ const el = document.getElementById(id); return el ? el.value : ''; }}
function slugify(s) {{ return (s||'').toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); }}
function safeJSON(s, def) {{ try {{ return JSON.parse(s||'null')||def; }} catch(e) {{ return def; }} }}

function resolveImage() {{
  if (gType === 'shell' || gType === 'mixed') return 'mcp-runtime-shell:latest';
  if (gType === 'http') return 'mcp-runtime-http-gateway:latest';
  return val('custom-image-input') || 'mcp-runtime-shell:latest';
}}
function resolveExecTypes() {{
  if (gType === 'shell') return ['shell'];
  if (gType === 'http')  return ['http_request'];
  if (gType === 'mixed') return ['shell','http_request'];
  return ['shell'];
}}

function generateJSON() {{
  const name = val('pkg-name') || 'My MCP Package';
  const execTypes = resolveExecTypes();
  const image = resolveImage();
  const rcName = slugify(name) || 'custom-runtime';

  const tools = [];
  document.querySelectorAll('.tool-card').forEach(function(block) {{
    const tid = block.dataset.toolId;
    const execType = val('tool-type-'+tid) || 'shell';
    let config = {{}};
    if (execType === 'shell') {{
      const raw = val('tool-cmd-'+tid).trim();
      config = {{ command: raw ? raw.split(/\s+/) : [], timeout_seconds: 30 }};
    }} else {{
      config = {{
        method: val('tool-method-'+tid)||'POST',
        url: val('tool-url-'+tid),
        body: safeJSON(val('tool-body-'+tid), {{}}),
        timeout_seconds: 30, max_response_bytes: 5242880
      }};
    }}
    const props = {{}};
    const req = [];
    block.querySelectorAll('.schema-field').forEach(function(f) {{
      const fname = f.querySelector('.fname').value.trim();
      if (!fname) return;
      const ftype = f.querySelector('.ftype').value;
      const prop = {{ type: ftype }};
      const fdesc = f.querySelector('.fdesc').value.trim();
      if (fdesc) prop.description = fdesc;
      const fdef = f.querySelector('.fdefault').value.trim();
      if (fdef) prop.default = ftype==='integer'?(parseInt(fdef)||0):fdef;
      props[fname] = prop;
      if (f.querySelector('.freq').checked) req.push(fname);
    }});
    const schema = {{ type:'object', properties:props }};
    if (req.length) schema.required = req;
    tools.push({{
      name: val('tool-name-'+tid),
      description: val('tool-desc-'+tid),
      execution_type: execType,
      enabled: true,
      risk_level: 'low',
      mode: 'read-only',
      category: val('pkg-category')||'other',
      config, input_schema: schema
    }});
  }});

  const pol = {{}};
  if (document.getElementById('pol-readonly')?.checked) pol.require_read_only = true;
  if (document.getElementById('pol-nowrite')?.checked) pol.block_write_tools = true;
  if (document.getElementById('pol-nodestr')?.checked) pol.block_destructive_tools = true;
  const bins = val('pol-bins').trim(); if (bins) pol.allowed_binaries = bins.split(/\s+/);
  const pfx = val('pol-pfx').trim(); if (pfx) pol.allowed_command_prefixes = pfx.split(/\n+/).filter(Boolean);
  const blk = val('pol-blk').trim(); if (blk) pol.blocked_command_prefixes = blk.split(/\n+/).filter(Boolean);
  pol.timeout_seconds = parseInt(val('pol-timeout'))||30;
  pol.max_payload_bytes = 262144;
  pol.max_response_bytes = 5242880;

  return JSON.stringify({{
    id: slugify(name)||'custom-package',
    name, description: val('pkg-desc'),
    category: val('pkg-category')||'other',
    risk_level: val('pkg-risk')||'low',
    runtime_class: {{
      name: rcName, runtime_image: image,
      allowed_execution_types: execTypes,
      risk_level: 'low', security_profile: 'restricted'
    }},
    adapters: execTypes.map(function(et) {{
      return {{ name:et, adapter_type:et==='http_request'?'http':et,
               implemented:true, enabled:true, risk_level:'low', mode:'read-only' }};
    }}),
    policy: pol, tools
  }}, null, 2);
}}

function gUpdate() {{
  const el = document.getElementById('json-preview');
  if (el) el.value = generateJSON();
}}

function installPackage() {{
  const name = val('pkg-name').trim();
  if (!name) {{ document.getElementById('pkg-name').focus(); return; }}
  document.getElementById('install-json').value = generateJSON();
  document.getElementById('install-form').submit();
}}

function copyJSON() {{
  navigator.clipboard.writeText(generateJSON()).then(function() {{
    const btn = document.getElementById('copy-btn');
    const orig = btn.textContent;
    btn.textContent = '✅ Skopiowano!';
    setTimeout(function() {{ btn.textContent = orig; }}, 2000);
  }});
}}

document.addEventListener('DOMContentLoaded', function() {{
  gUpdate();
}});
</script>
"""
    return page_shell("packages", body)



@app.get("/tool-packages", response_class=HTMLResponse)
def tool_packages_page(error: str = "") -> str:
    packages = store.rows("SELECT * FROM tool_packages ORDER BY category, name")
    image_builds = store.rows("SELECT * FROM runtime_image_builds ORDER BY created_at DESC LIMIT 50")
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    _cu = _current_user.get()
    is_admin = (_cu or {}).get("role") == "admin"
    pkg_cards_html = ""
    for package in packages:
        spec = json.loads(package["package_json"])
        runtime_class = spec.get("runtime_class") or {}
        tools_list = spec.get("tools") or []
        tools_count = len(tools_list)
        tool_names = ", ".join(t.get("name","?") for t in tools_list[:4]) + (" …" if tools_count > 4 else "")
        enabled = package.get("enabled", 1)
        rc_name = escape(runtime_class.get("name", "-"))
        cat_icons = {"http": "🌐", "shell": "⌨️", "openshift": "🔴", "kubernetes": "☸️", "other": "📦"}
        cat_icon = cat_icons.get(package.get("category", "other"), "📦")
        pkg_cards_html += f"""
        <div class="pkg-card" style="{'opacity:.55' if not enabled else ''}">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
              <div class="pkg-card-name">{cat_icon} {escape(package['name'])}</div>
              <span class="risk {package['risk_level']}" style="font-size:11px;padding:2px 7px;white-space:nowrap">{escape(package['risk_level'])}</span>
            </div>
            <div class="pkg-card-desc" style="margin-top:6px">{escape(package['description'] or 'Brak opisu.')}</div>
          </div>
          <div class="pkg-card-meta">
            <span class="badge" style="font-size:11px;padding:2px 7px">⚙️ {rc_name}</span>
            <span class="badge" style="font-size:11px;padding:2px 7px">🔧 {tools_count} tool{'e' if tools_count != 1 else ''}</span>
            {f'<span class="badge" style="font-size:11px;padding:2px 7px;background:#1a2a1a;color:#5a9a5a">✅ aktywna</span>' if enabled else '<span class="badge" style="font-size:11px;padding:2px 7px;background:#2a1a1a;color:#9a5a5a">⛔ wyłączona</span>'}
          </div>
          {f'<div class="muted" style="font-size:11px">{escape(tool_names)}</div>' if tool_names else ''}
          <div class="pkg-card-actions">
            <form method="post" action="/api/tool-packages/{package['id']}/create-runtime" style="flex:1;display:flex;gap:6px;align-items:center">
              <input name="name" value="{escape(package['name'])}" placeholder="Nazwa serwera" style="flex:1;padding:7px 10px;font-size:12px">
              <input type="hidden" name="deploy" value="true">
              <button {'disabled class="disabled"' if not enabled else ''} style="white-space:nowrap;padding:7px 12px;font-size:12px">🚀 Stwórz MCP</button>
            </form>
            <a href="/tool-packages/{package['id']}/edit" style="padding:7px 10px;font-size:12px;background:#1a2a3a;border:1px solid #2a4a6a;border-radius:6px;color:#7dd3fc;text-decoration:none;white-space:nowrap">✏️ Edytuj</a>
            <form method="post" action="/api/tool-packages/{package['id']}/toggle">
              <button class="secondary" style="padding:7px 10px;font-size:12px">{'Wyłącz' if enabled else 'Włącz'}</button>
            </form>
            {f'<form method="post" action="/api/tool-packages/{package["id"]}/delete" onsubmit="return confirm(\'Usunąć paczkę {escape(package["name"])}?\')"><button class="delete" style="padding:7px 10px;font-size:12px">🗑️ Usuń</button></form>' if is_admin else ''}
          </div>
        </div>"""
    example_package = json.dumps(
        {
            "id": "my-http-api",
            "name": "My HTTP API Assistant",
            "description": "Example package imported from UI.",
            "category": "http",
            "risk_level": "low",
            "runtime_class": {
                "name": "http-gateway",
                "runtime_image": "mcp-runtime-http-gateway:latest",
                "allowed_execution_types": ["http_request"],
                "risk_level": "low",
                "security_profile": "restricted",
            },
            "adapters": [
                {
                    "name": "http_request",
                    "adapter_type": "http",
                    "implemented": True,
                    "enabled": True,
                    "risk_level": "low",
                    "mode": "read-only",
                }
            ],
            "policy": {"block_write_tools": True, "block_destructive_tools": True, "require_read_only": True},
            "tools": [
                {
                    "name": "api_search",
                    "description": "Search external API.",
                    "execution_type": "http_request",
                    "enabled": True,
                    "risk_level": "low",
                    "mode": "read-only",
                    "category": "http",
                    "config": {"method": "POST", "url": "https://example/api/search", "body": {"query": "${query}"}},
                    "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
                    "output_schema": {"type": "object"},
                }
            ],
        },
        indent=2,
    )
    def _build_status_badge(s: str) -> str:
        color = {"done": "running", "failed": "failed", "pending": "deploying"}.get(s, "")
        return f'<span class="badge {color}">{escape(s)}</span>'

    image_build_rows = "".join(
        f"""
        <tr>
          <td><b style="font-size:13px">{escape(item['image'])}</b><div class="muted" style="font-size:11px">{escape(item['id'])}</div></td>
          <td style="font-size:12px">{escape(item['base_image'])}</td>
          <td style="font-size:12px">{escape(item['runtime_class'] or '-')}</td>
          <td>{_build_status_badge(item['status'])}</td>
          <td style="font-size:11px;color:#f47a80;max-width:200px;word-break:break-word">{escape((item['error'] or '')[:120]) or '<span class="muted">—</span>'}</td>
          <td style="font-size:11px;color:var(--muted)">{escape(item['created_at'][:16].replace('T',' '))}</td>
          {'<td><button onclick="delBuild(\'' + escape(item['id']) + '\',\'' + escape(item['image']) + '\')" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer">🗑️ Usuń</button></td>' if is_admin else '<td></td>'}
        </tr>
        """
        for item in image_builds
    )
    runtimes_deployed = store.rows("SELECT id, name FROM runtimes")
    runtime_names = {r["id"]: r["name"] for r in runtimes_deployed}
    cat_icons_big = {"openshift": "☁️", "kubernetes": "⎈", "database": "🗄️", "http": "🌐",
                     "shell": "🖥️", "ai": "🤖", "other": "📦", "monitoring": "📊", "security": "🔒"}
    deploy_cards = []
    for pkg in packages:
        if not pkg.get("enabled", 1):
            continue
        spec = json.loads(pkg["package_json"] or "{}")
        tools_list = spec.get("tools") or []
        cat = pkg["category"] or "other"
        icon = cat_icons_big.get(cat, "📦")
        is_custom = pkg["source"] in ("advanced-creator", "user")
        badge_text = "🛠️ Twój kreator" if is_custom else "✅ Wbudowany"
        badge_bg = "#1a2a0a" if is_custom else "#0a1a2a"
        badge_bd = "#3a5a1a" if is_custom else "#1a3a5a"
        deployed_name = runtime_names.get(pkg["id"], "")
        deploy_cards.append(
            f'<div style="background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:8px">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start"><span style="font-size:20px">{icon}</span>'
            f'<span style="background:{badge_bg};border:1px solid {badge_bd};color:#8ac840;font-size:10px;font-weight:700;padding:2px 8px;border-radius:999px">{badge_text}</span></div>'
            f'<div style="font-weight:800;font-size:14px;color:white">{escape(pkg["name"])}</div>'
            f'<div style="color:var(--muted);font-size:12px">{escape((pkg["description"] or "")[:90])}</div>'
            f'<div style="display:flex;gap:6px;flex-wrap:wrap"><span class="badge" style="font-size:11px">{escape(cat)}</span>'
            f'<span class="badge" style="font-size:11px;background:#0d1a2a">🔧 {len(tools_list)} tools</span></div>'
            + (f'<div style="font-size:11px;color:#4ac86a">✅ {escape(deployed_name)}</div>' if deployed_name else "")
            + f'<button onclick="mktDeploy(\'{escape(pkg["id"])}\',\'{escape(pkg["name"])}\')" '
            f'style="margin-top:auto;background:var(--blue);border:none;color:white;padding:8px;border-radius:6px;font-size:13px;font-weight:700;cursor:pointer">🚀 Wdróż</button>'
            f'</div>'
        )
    deploy_cards_html = "\n".join(deploy_cards) or '<p class="muted">Brak dostępnych paczek.</p>'
    body = f"""
      {alert}
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div>
          <div style="font-size:15px;font-weight:800;color:white">🏗️ Build</div>
          <div class="muted">Wbudowane szablony + serwery z Kreatora. Wdróż jednym kliknięciem lub zbuduj własny obraz Docker.</div>
        </div>
        <div style="display:flex;gap:8px">
          <a href="/create" style="background:var(--blue);color:white;padding:8px 14px;border-radius:8px;font-weight:700;font-size:13px;white-space:nowrap;text-decoration:none">+ Kreator zaawansowany</a>
          <a href="/tool-packages/generate" style="background:#1a7a3f;color:white;padding:8px 14px;border-radius:8px;font-weight:700;font-size:13px;white-space:nowrap;text-decoration:none">✨ Generuj paczkę</a>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px;margin-bottom:24px">
        {deploy_cards_html}
      </div>

      <details style="margin-bottom:8px">
        <summary style="font-size:14px;font-weight:700;padding:2px 0;cursor:pointer">📋 Zarządzaj paczkami (tabela)</summary>
        <div style="margin-top:12px">
      <div class="pkg-grid">{pkg_cards_html}</div>
        </div>
      </details>

      <details style="margin-top:4px">
        <summary>📥 Importuj paczkę z JSON lub URL</summary>
        <p class="muted" style="margin:0 0 14px">Wklej JSON paczki albo podaj URL. Paczka może wskazać własny runtime image z zainstalowanymi narzędziami.</p>
        <form method="post" action="/api/tool-packages/import" enctype="multipart/form-data">
          <div class="grid" style="margin-bottom:12px">
            <div>
              <label>URL do JSON paczki</label>
              <input name="package_url" placeholder="https://example.local/mcp-packages/openshift.json">
            </div>
            <div>
              <label>Plik JSON</label>
              <input type="file" name="package_file" accept="application/json,.json">
            </div>
          </div>
          <label>Lub wklej JSON bezpośrednio</label>
          <textarea name="package_json" style="min-height:120px;font-size:12px">{escape(example_package)}</textarea>
          <div style="margin-top:10px"><button>📥 Zainstaluj paczkę</button></div>
        </form>
      </details>

      <details>
        <summary>🏗️ Runtime Image Builder — zbuduj własny obraz Docker</summary>
        <p class="muted" style="margin:0 0 14px">Zbuduj custom obraz z narzędziami których nie ma w bazowych obrazach (terraform, awscli, własne binarki).</p>
        <form method="post" action="/api/runtime-images/build">
          <div class="grid3" style="margin-bottom:12px">
            <div><label>Image tag (wynikowy)</label><input name="image" value="mcp-runtime-custom:latest"></div>
            <div><label>Base image</label><select name="base_image"><option value="mcp-runtime-shell:latest" selected>mcp-runtime-shell:latest (shell, curl, jq, oc, kubectl)</option><option value="mcp-runtime-http-gateway:latest">mcp-runtime-http-gateway:latest (HTTP REST tools)</option></select><div class="muted" style="font-size:11px;margin-top:3px">Tylko te obrazy mają wbudowany serwer MCP — inne bazy nie będą działać.</div></div>
            <div><label>Nazwa klasy runtime</label><input name="runtime_class" placeholder="openshift-readonly"></div>
            <div><label>Silniki wykonania</label><input name="allowed_execution_types" value="shell" placeholder="http_request shell"></div>
            <div><label>Risk</label><select name="risk_level"><option>low</option><option>medium</option><option>high</option></select></div>
            <div><label>Security profile</label><input name="security_profile" value="restricted"></div>
          </div>
          <div class="grid" style="margin-bottom:12px">
            <div><label>APT packages</label><input name="apt_packages" placeholder="curl jq openssh-client"></div>
            <div><label>Pip packages</label><input name="pip_packages" placeholder="httpx pydantic kubernetes"></div>
          </div>
          <label>Extra Dockerfile fragment</label>
          <textarea name="extra_dockerfile" placeholder="RUN curl -L ... -o /usr/local/bin/oc&#10;RUN chmod +x /usr/local/bin/oc" style="min-height:80px"></textarea>
          <div style="margin-top:10px"><button>🔨 Zbuduj obraz</button></div>
        </form>
        {f"""
        <h3 style="margin:18px 0 10px">Zbudowane obrazy ({len(image_builds)})</h3>
        <table>
          <thead><tr><th>Obraz</th><th>Base</th><th>Klasa runtime</th><th>Status</th><th>Błąd</th><th>Data</th><th></th></tr></thead>
          <tbody>{image_build_rows}</tbody>
        </table>
        {'<div style="margin-top:8px;font-size:12px;color:var(--muted)">🔒 Usuwanie obrazów dostępne tylko dla admina</div>' if not is_admin else ''}
        """ if image_builds else ""}
      </details>
<!-- Deploy modal -->
<div id="mkt-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center">
  <div style="background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px;width:420px;max-width:95vw">
    <h3 style="margin:0 0 6px">🚀 Wdrażanie: <span id="mkt-pkg-name"></span></h3>
    <p class="muted" style="font-size:12px;margin-bottom:16px">Wpisz nazwę i opcjonalne zmienne ENV (tokeny, klucze API).</p>
    <label style="font-size:12px;font-weight:700;display:block;margin-bottom:4px">Nazwa serwera</label>
    <input id="mkt-name" placeholder="moj-serwer" style="width:100%;box-sizing:border-box;padding:9px 12px;border:1px solid var(--line);border-radius:6px;background:#0d1420;color:var(--text);font-size:13px;margin-bottom:14px">
    <label style="font-size:12px;font-weight:700;display:block;margin-bottom:4px">🔑 Zmienne ENV <span style="color:var(--muted);font-weight:400">(opcjonalne)</span></label>
    <div id="mkt-env-list" style="display:grid;gap:6px;margin-bottom:8px"></div>
    <button type="button" onclick="mktAddEnv()" style="background:#1a1200;border:1px solid #3a2800;color:#d4a820;padding:5px 12px;border-radius:6px;font-size:12px;cursor:pointer;margin-bottom:16px">+ Dodaj ENV</button>
    <div style="display:flex;gap:10px">
      <button onclick="mktDoDeploy()" style="flex:1;background:var(--blue);border:none;color:white;padding:10px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer">🚀 Wdróż</button>
      <button onclick="document.getElementById('mkt-modal').style.display='none'" style="flex:1;background:var(--panel-2);border:1px solid var(--line);color:var(--muted);padding:10px;border-radius:8px;font-size:14px;cursor:pointer">Anuluj</button>
    </div>
    <div id="mkt-status" style="margin-top:10px;font-size:12px;color:var(--muted)"></div>
  </div>
</div>
<script>
var _mktPkgId = '', _mktEnvCount = 0;
window.mktDeploy = function(pkgId, pkgName) {{
  _mktPkgId = pkgId; _mktEnvCount = 0;
  document.getElementById('mkt-pkg-name').textContent = pkgName;
  document.getElementById('mkt-name').value = pkgName.toLowerCase().replace(/[^a-z0-9]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'');
  document.getElementById('mkt-env-list').innerHTML = '';
  document.getElementById('mkt-status').textContent = '';
  document.getElementById('mkt-modal').style.display = 'flex';
}};
window.mktAddEnv = function() {{
  var i = _mktEnvCount++;
  var row = document.createElement('div');
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr auto;gap:6px;align-items:center';
  row.innerHTML = '<input placeholder="NAZWA_ZMIENNEJ" style="padding:7px 8px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px;font-family:monospace">' +
    '<input type="password" placeholder="wartość" style="padding:7px 8px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px">' +
    '<button type="button" onclick="this.parentNode.remove()" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:5px 8px;border-radius:5px;font-size:11px;cursor:pointer">✕</button>';
  document.getElementById('mkt-env-list').appendChild(row);
}};
window.mktDoDeploy = function() {{
  var name = document.getElementById('mkt-name').value.trim();
  if (!name) {{ document.getElementById('mkt-name').focus(); return; }}
  var env = {{}};
  document.querySelectorAll('#mkt-env-list > div').forEach(function(row, i) {{
    var k = row.querySelector('input:first-child').value.trim();
    var v = row.querySelector('input[type="password"]').value;
    if (k) env[k] = v;
  }});
  document.getElementById('mkt-status').textContent = '⏳ Tworzenie serwera...';
  var body = new URLSearchParams({{ name: name, package_id: _mktPkgId, deploy_after_create: 'true' }});
  Object.keys(env).forEach(function(k,i) {{ body.append('env_key_'+i, k); body.append('env_val_'+i, env[k]); }});
  fetch('/api/runtimes', {{ method:'POST', body: body, headers:{{'Content-Type':'application/x-www-form-urlencoded'}}, redirect:'manual' }})
    .then(function(r) {{
      if (r.status === 0 || r.status === 303 || r.ok) {{
        document.getElementById('mkt-status').textContent = '✅ Serwer tworzony! Przekierowuję...';
        setTimeout(function() {{ window.location.href = '/runtimes'; }}, 1200);
      }} else {{
        r.text().then(function(t) {{ document.getElementById('mkt-status').textContent = '❌ Błąd: ' + t; }});
      }}
    }}).catch(function() {{
      document.getElementById('mkt-status').textContent = '✅ Serwer tworzony! Przekierowuję...';
      setTimeout(function() {{ window.location.href = '/runtimes'; }}, 1200);
    }});
}};
function delBuild(id, img) {{
  if (!confirm('Usunąć obraz ' + img + '?\\nObraz zostanie usunięty z Docker i z listy buildów.')) return;
  fetch('/api/runtime-image-builds/' + encodeURIComponent(id), {{method:'DELETE'}})
  .then(r=>r.json()).then(d=>{{
    if (d.ok) location.reload();
    else alert('Błąd: ' + (d.detail||d.error||'nieznany'));
  }}).catch(()=>alert('Błąd połączenia'));
}}
</script>
    """
    return page_shell("packages", body)


@app.get("/runtime-classes", response_class=HTMLResponse)
def runtime_classes_page(error: str = "", ok: str = "") -> str:
    runtime_classes = store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)
    all_images = list({r["runtime_image"] for r in runtime_classes if r["runtime_image"]})
    implemented_adapters = store.rows("SELECT name FROM execution_adapters WHERE implemented=1 AND enabled=1 ORDER BY name")
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    success = f'<div class="alert" style="border-color:#1a7a3f;background:#0d2e1a;color:#8ee7b3">{escape(ok)}</div>' if ok else ""
    def _rc_adapter_checks(item: dict) -> str:
        current = set(json.loads(item["allowed_execution_types_json"] or "[]"))
        return "".join(
            f'<label style="display:inline-flex;gap:5px;align-items:center;margin-right:12px;font-size:12px">'
            f'<input type="checkbox" name="allowed_adapters" value="{escape(a["name"])}"'
            f'{" checked" if a["name"] in current else ""}> {escape(a["name"])}</label>'
            for a in implemented_adapters
        )

    class_rows_html = "".join(
        f"""
        <tr id="rcrow-{escape(item['name'])}">
          <td><b style="font-size:13px">{escape(item['name'])}</b></td>
          <td><code style="font-size:11px">{escape(item['runtime_image'])}</code></td>
          <td style="font-size:12px">{escape(", ".join(json.loads(item['allowed_execution_types_json'] or '[]')))}</td>
          <td><span class="risk {item['risk_level']}" style="font-size:11px">{escape(item['risk_level'])}</span></td>
          <td><span class="badge {'running' if item['enabled'] else 'stopped'}" style="font-size:11px">{'aktywny' if item['enabled'] else 'wyłączony'}</span></td>
          <td style="white-space:nowrap">
            <div style="display:flex;gap:6px">
              <button onclick="toggleRCEdit('{escape(item['name'])}')"
                style="background:#1a2a3a;border:1px solid #2a4a6a;color:#7dd3fc;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer">✏️ Edytuj</button>
              <form method="post" action="/api/runtime-classes/{escape(item['name'])}/toggle" style="display:inline">
                <button style="font-size:11px;padding:4px 8px;background:#263548;border:1px solid #34465b;border-radius:6px;cursor:pointer">
                  {'Wyłącz' if item['enabled'] else 'Włącz'}
                </button>
              </form>
              <form method="post" action="/api/runtime-classes/{escape(item['name'])}/delete" style="display:inline"
                    onsubmit="return confirm('Usunąć ten typ środowiska?')">
                <button class="delete" style="font-size:11px;padding:4px 8px">🗑️</button>
              </form>
            </div>
          </td>
        </tr>
        <tr id="rcedit-{escape(item['name'])}" style="display:none">
          <td colspan="6" style="padding:0">
            <div style="background:#0a1520;border-top:1px solid #1a3a50;padding:16px 18px">
              <form method="post" action="/api/runtime-classes/{escape(item['name'])}/update">
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px">
                  <div>
                    <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Obraz Docker</label>
                    <input name="runtime_image" value="{escape(item['runtime_image'])}" style="width:100%;box-sizing:border-box;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:12px;font-family:monospace">
                  </div>
                  <div>
                    <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Ryzyko</label>
                    <select name="risk_level" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                      <option {'selected' if item['risk_level']=='low' else ''} value="low">niski (low)</option>
                      <option {'selected' if item['risk_level']=='medium' else ''} value="medium">średni (medium)</option>
                      <option {'selected' if item['risk_level']=='high' else ''} value="high">wysoki (high)</option>
                    </select>
                  </div>
                  <div>
                    <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Security profile</label>
                    <select name="security_profile" style="width:100%;padding:8px 10px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:13px">
                      <option {'selected' if item['security_profile']=='restricted' else ''} value="restricted">restricted</option>
                      <option {'selected' if item['security_profile']=='standard' else ''} value="standard">standard</option>
                    </select>
                  </div>
                </div>
                <div style="margin-bottom:12px">
                  <label style="font-size:11px;font-weight:700;color:#aac8e0;display:block;margin-bottom:6px">Dozwolone silniki</label>
                  <div style="display:flex;flex-wrap:wrap;gap:4px">{_rc_adapter_checks(item)}</div>
                </div>
                <div style="display:flex;gap:8px">
                  <button type="submit" style="background:var(--blue);border:none;color:white;padding:7px 16px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer">💾 Zapisz</button>
                  <button type="button" onclick="toggleRCEdit('{escape(item['name'])}')" style="background:#263548;border:none;color:#c9d7e6;padding:7px 12px;border-radius:6px;font-size:12px;cursor:pointer">Anuluj</button>
                </div>
              </form>
            </div>
          </td>
        </tr>
        """
        for item in runtime_classes
    )
    adapter_checkboxes = "".join(
        f'<label style="display:inline-flex;gap:6px;align-items:center;margin-right:16px">'
        f'<input type="checkbox" name="allowed_adapters" value="{escape(a["name"])}"> {escape(a["name"])}</label>'
        for a in implemented_adapters
    )
    image_datalist = "".join(f'<option value="{escape(img)}">' for img in sorted(all_images))
    body = f"""
      {alert}{success}
      <section>
        <h2>Typy środowisk (Runtime Classes)</h2>
        <p class="muted">
          Typ środowiska określa <b>jaki Docker image jest uruchamiany</b> i <b>jakie silniki wykonania</b> są dozwolone.
          Nowe typy tworzone są automatycznie przez Runtime Image Builder w
          <a href="/tool-packages">Paczki tools</a>.
          Możesz też dodać ręcznie poniżej.
        </p>
        <table>
          <thead><tr><th>Nazwa</th><th>Obraz Docker</th><th>Dozwolone silniki</th><th>Ryzyko</th><th>Status</th><th></th></tr></thead>
          <tbody>{class_rows_html}</tbody>
        </table>
      </section>
      <section>
        <h2>Dodaj typ środowiska</h2>
        <p class="muted">
          Rejestruje nowy typ środowiska. Obraz musi już istnieć lokalnie w Docker
          (zbudowany przez Runtime Image Builder lub pulled ręcznie).<br>
          <b>Kiedy tego potrzebujesz:</b> masz własny Docker image z narzędziami (np. terraform, awscli)
          i chcesz go zarejestrować jako dostępny typ środowiska w kreatorze.
        </p>
        <form method="post" action="/api/runtime-classes">
          <div class="grid">
            <label>Nazwa typu
              <input name="name" placeholder="terraform-readonly" required>
            </label>
            <label>Obraz Docker
              <input name="runtime_image" list="img-list" placeholder="mcp-runtime-shell:latest" required>
              <datalist id="img-list">{image_datalist}</datalist>
            </label>
            <label>Risk
              <select name="risk_level">
                <option value="low">low</option>
                <option value="medium" selected>medium</option>
                <option value="high">high</option>
              </select>
            </label>
            <label>Security profile
              <input name="security_profile" value="restricted">
            </label>
          </div>
          <div style="margin:12px 0 6px;font-weight:700;font-size:13px">Dozwolone silniki wykonania</div>
          <div style="margin-bottom:14px">{adapter_checkboxes}</div>
          <button>Dodaj typ środowiska</button>
        </form>
      </section>
    """
    body += """
<script>
function toggleRCEdit(name) {
  var row = document.getElementById('rcedit-' + name);
  if (row) row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
}
</script>"""
    return page_shell("classes", body)


@app.post("/api/runtime-classes/{class_name}/update")
async def update_runtime_class(class_name: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    rc = store.one(sql.SELECT_RUNTIME_CLASS_BY_NAME, (class_name,))
    if not rc:
        raise HTTPException(status_code=404)
    form = await request.form()
    runtime_image = str(form.get("runtime_image") or rc["runtime_image"]).strip()
    risk_level = str(form.get("risk_level") or rc["risk_level"])
    security_profile = str(form.get("security_profile") or rc["security_profile"])
    allowed = list(form.getlist("allowed_adapters")) if hasattr(form, "getlist") else []
    store.execute(
        "UPDATE runtime_classes SET runtime_image=?, risk_level=?, security_profile=?, allowed_execution_types_json=?, updated_at=? WHERE name=?",
        (runtime_image, risk_level, security_profile, json.dumps(allowed), store.now_iso(), class_name),
    )
    store.audit(user["username"], "update_runtime_class", "runtime_class", class_name,
                {"image": runtime_image, "adapters": allowed})
    return RedirectResponse("/runtime-classes?ok=Zaktualizowano+typ+środowiska", status_code=303)


@app.post("/api/runtime-classes/{class_name}/delete")
async def delete_runtime_class(class_name: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    store.execute("DELETE FROM runtime_classes WHERE name = ?", (class_name,))
    store.audit(user["username"], "delete_runtime_class", "runtime_class", class_name)
    return RedirectResponse("/runtime-classes", status_code=303)


@app.post("/api/runtime-classes")
async def create_runtime_class(request: Request):
    form = await request.form()
    name = slug(str(form.get("name") or "")).strip()
    runtime_image = str(form.get("runtime_image") or "").strip()
    risk_level = str(form.get("risk_level") or "medium")
    security_profile = str(form.get("security_profile") or "restricted").strip() or "restricted"
    allowed = list(form.getlist("allowed_adapters")) if hasattr(form, "getlist") else []
    if not name:
        return RedirectResponse(f"/runtime-classes?error={quote('Nazwa jest wymagana')}", status_code=303)
    if not runtime_image:
        return RedirectResponse(f"/runtime-classes?error={quote('Obraz Docker jest wymagany')}", status_code=303)
    if not allowed:
        return RedirectResponse(f"/runtime-classes?error={quote('Wybierz co najmniej jeden silnik wykonania')}", status_code=303)
    now = store.now_iso()
    store.execute(
        """
        INSERT INTO runtime_classes(name, description, runtime_image, allowed_execution_types_json,
                                    enabled, risk_level, security_profile, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          runtime_image=excluded.runtime_image,
          allowed_execution_types_json=excluded.allowed_execution_types_json,
          risk_level=excluded.risk_level,
          security_profile=excluded.security_profile,
          updated_at=excluded.updated_at
        """,
        (name, f"Manually registered runtime class: {name}", runtime_image,
         json.dumps(allowed), risk_level, security_profile, now, now),
    )
    store.audit("admin", "create_runtime_class", "runtime_class", name,
                {"image": runtime_image, "adapters": allowed})
    return RedirectResponse(f"/runtime-classes?ok={quote(f'Dodano typ środowiska: {name}')}", status_code=303)


@app.post("/api/runtime-classes/{class_name}/toggle")
def toggle_runtime_class(class_name: str):
    rc = store.one(sql.SELECT_RUNTIME_CLASS_BY_NAME, (class_name,))
    if not rc:
        raise HTTPException(status_code=404, detail="Runtime class not found")
    enabled = 0 if rc["enabled"] else 1
    store.execute(
        "UPDATE runtime_classes SET enabled = ?, updated_at = ? WHERE name = ?",
        (enabled, store.now_iso(), class_name),
    )
    store.audit("admin", "toggle_runtime_class", "runtime_class", class_name, {"enabled": bool(enabled)})
    return RedirectResponse("/runtime-classes", status_code=303)


def _load_custom_templates() -> list[dict]:
    try:
        return json.loads(CUSTOM_TEMPLATES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_custom_templates(templates: list[dict]) -> None:
    store.CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    CUSTOM_TEMPLATES_FILE.write_text(json.dumps(templates, indent=2, ensure_ascii=False), encoding="utf-8")


@app.get("/runtime-images", response_class=HTMLResponse)
def runtime_images_page() -> str:
    builds = store.rows("SELECT * FROM runtime_image_builds ORDER BY created_at DESC")
    _cu = _current_user.get()
    is_admin = (_cu or {}).get("role") == "admin"

    # Builtin base images — always shown
    _base_images = [
        ("mcp-runtime-shell:latest", "ubuntu:24.04", "shell-readonly / shell-readwrite"),
        ("mcp-runtime-http-gateway:latest", "python:3.12-slim", "http-gateway"),
        ("mcp-platform-control-plane:latest", "python:3.12-slim", "—"),
        ("mcp-platform-operator:latest", "python:3.12-slim", "—"),
    ]
    builtin_rows = [
        {"image": img, "base_image": base, "runtime_class": rc,
         "status": "builtin", "error": None, "created_at": "—", "id": "builtin"}
        for img, base, rc in _base_images
    ]

    def _badge(s: str) -> str:
        color = {"done": "running", "failed": "failed", "pending": "deploying", "builtin": "running"}.get(s, "")
        label = {"builtin": "✅ wbudowany"}.get(s, s)
        return f'<span class="badge {color}" style="font-size:11px">{escape(label)}</span>'

    all_items = builtin_rows + list(builds)
    rows_html = "".join(f"""
        <tr>
          <td>
            <div style="font-weight:700;font-size:13px">{escape(item['image'])}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:2px">{'bazowy obraz platformy' if item['id'] == 'builtin' else escape(item['id'])}</div>
          </td>
          <td style="font-size:12px">{escape(item['base_image'])}</td>
          <td style="font-size:12px">{escape(item['runtime_class'] or '—')}</td>
          <td>{_badge(item['status'])}</td>
          <td style="font-size:11px;color:#f47a80;max-width:240px;word-break:break-word">{escape((item['error'] or '')[:150]) or '<span style="color:var(--muted)">—</span>'}</td>
          <td style="font-size:11px;color:var(--muted);white-space:nowrap">{escape(str(item['created_at'])[:16].replace('T',' '))}</td>
          <td>{"<button onclick=\"delBuild('" + escape(item['id']) + "','" + escape(item['image']) + "')\" style='background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:5px 12px;border-radius:6px;font-size:12px;cursor:pointer'>🗑️ Usuń</button>" if is_admin and item['id'] != 'builtin' else ""}</td>
        </tr>""" for item in all_items)

    stats_done = sum(1 for b in builds if b['status'] == 'done')
    stats_failed = sum(1 for b in builds if b['status'] == 'failed')

    body = f"""
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px">
      <div class="card" style="text-align:center">
        <div class="metric">{len(all_items)}</div>
        <div style="font-weight:700;color:white">Wszystkie obrazy</div>
      </div>
      <div class="card" style="text-align:center;border-color:#1a5a38;background:#0e2e1e">
        <div class="metric" style="color:#5ce89a">{stats_done + len(builtin_rows)}</div>
        <div style="font-weight:700;color:white">✅ Zbudowane</div>
      </div>
      <div class="card" style="text-align:center;border-color:#5a2025;background:#2c0e10">
        <div class="metric" style="color:#f47a80">{stats_failed}</div>
        <div style="font-weight:700;color:white">❌ Nieudane</div>
      </div>
    </div>

    <section>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 style="margin:0">Obrazy Docker ({len(all_items)})</h2>
        {"<div style='font-size:12px;color:var(--muted)'>🔒 Usuwanie dostępne tylko dla admina</div>" if not is_admin else ""}
      </div>
      <table><thead><tr><th>Obraz</th><th>Base</th><th>Klasa runtime</th><th>Status</th><th>Błąd</th><th>Data buildu</th><th></th></tr></thead><tbody>{rows_html}</tbody></table>
    </section>

<script>
function delBuild(id, img) {{
  if (!confirm('Usunąć obraz ' + img + '?\\nObraz zostanie usunięty z Docker i z listy.')) return;
  fetch('/api/runtime-image-builds/' + encodeURIComponent(id), {{
    method: 'DELETE',
    credentials: 'same-origin',
    headers: {{'Accept': 'application/json'}}
  }})
  .then(function(r) {{
    if (r.status === 403) {{ alert('Brak uprawnień — wymagana rola admin'); return null; }}
    if (!r.ok) {{ alert('Błąd serwera: ' + r.status); return null; }}
    return r.json();
  }})
  .then(function(d) {{
    if (!d) return;
    if (d.ok) location.reload();
    else alert('Błąd: ' + (d.detail || d.error || 'nieznany'));
  }})
  .catch(function(e) {{ alert('Błąd połączenia: ' + e); }});
}}
</script>
    """
    return page_shell("images", body)


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


@app.get("/webhooks", response_class=HTMLResponse)
def webhooks_page(ok: str = "") -> str:
    webhooks = store.rows("SELECT * FROM webhooks ORDER BY id DESC")
    runtimes = store.rows("SELECT id, name FROM runtimes WHERE status != 'deleted'")
    alert = f'<div class="success">{escape(ok)}</div>' if ok else ""
    wh_rows = "".join(
        f"""<tr>
          <td style="font-weight:700">{escape(wh['name'])}</td>
          <td style="font-size:12px;font-family:monospace;color:#7dd3fc;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(wh['url'])}</td>
          <td style="font-size:11px">{escape(wh['runtime_id'] or 'wszystkie')}</td>
          <td style="font-size:11px">{", ".join(json.loads(wh['events_json'] or "[]"))}</td>
          <td><span class="badge {'running' if wh['enabled'] else 'failed'}" style="font-size:11px">{'aktywny' if wh['enabled'] else 'wyłączony'}</span></td>
          <td style="font-size:11px;color:var(--muted)">{(wh['last_fired_at'] or '')[:16].replace('T',' ')} {('✅' if wh['last_status'] and 200<=int(wh['last_status'])<300 else '❌') if wh['last_status'] else ''}</td>
          <td><form method="post" action="/api/webhooks/{wh['id']}/delete" onsubmit="return confirm('Usunąć webhook?')">
            <button style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer">🗑️</button>
          </form></td>
        </tr>""" for wh in webhooks
    )
    rt_opts = "".join(f'<option value="{escape(r["id"])}">{escape(r["name"])}</option>' for r in runtimes)
    body = f"""
      {alert}
      <section>
        <h2>🔔 Webhooki powiadomień</h2>
        <p class="muted">Platforma wysyła POST do podanego URL gdy zajdzie zdarzenie. Payload: JSON z polem <code>event</code>, <code>runtime_id</code>, <code>timestamp</code>, <code>details</code>.</p>
        <form method="post" action="/api/webhooks" style="margin-bottom:20px">
          <div class="grid" style="grid-template-columns:1fr 2fr 1fr">
            <label>Nazwa<input name="name" placeholder="Slack alert" required></label>
            <label>URL<input name="url" placeholder="https://hooks.slack.com/..." required></label>
            <label>Serwer (opcjonalnie)
              <select name="runtime_id"><option value="">— wszystkie —</option>{rt_opts}</select>
            </label>
          </div>
          <div style="margin-bottom:10px">
            <div style="font-size:12px;font-weight:700;margin-bottom:6px">Zdarzenia:</div>
            <div style="display:flex;gap:16px;flex-wrap:wrap">
              <label style="display:flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="ev_runtime_failed" value="1" checked> Serwer padł (runtime_failed)</label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="ev_health_failed" value="1" checked> Health check fail (health_failed)</label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="ev_tool_error" value="1"> Tool zwrócił błąd (tool_error)</label>
              <label style="display:flex;align-items:center;gap:6px;font-size:13px"><input type="checkbox" name="ev_deploy_done" value="1"> Deploy gotowy (deploy_done)</label>
            </div>
          </div>
          <button>+ Dodaj webhook</button>
        </form>
        <table>
          <thead><tr><th>Nazwa</th><th>URL</th><th>Serwer</th><th>Zdarzenia</th><th>Status</th><th>Ostatnie wywołanie</th><th>Akcja</th></tr></thead>
          <tbody>{wh_rows or '<tr><td colspan="7" class="muted" style="text-align:center">Brak webhoków.</td></tr>'}</tbody>
        </table>
      </section>"""
    return page_shell("webhooks", body)


@app.post("/api/webhooks")
async def create_webhook(request: Request):
    form = await request.form()
    name = str(form.get("name") or "").strip()
    url = str(form.get("url") or "").strip()
    if not name or not url:
        raise HTTPException(status_code=400, detail="Nazwa i URL są wymagane")
    runtime_id = str(form.get("runtime_id") or "").strip()
    events = []
    if form.get("ev_runtime_failed") == "1": events.append("runtime_failed")
    if form.get("ev_health_failed") == "1": events.append("health_failed")
    if form.get("ev_tool_error") == "1": events.append("tool_error")
    if form.get("ev_deploy_done") == "1": events.append("deploy_done")
    now = store.now_iso()
    store.execute(
        "INSERT INTO webhooks(name,url,events_json,runtime_id,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
        (name, url, json.dumps(events), runtime_id, now, now),
    )
    return RedirectResponse(f"/webhooks?ok=Webhook+dodany", status_code=303)


@app.post("/api/webhooks/{webhook_id}/delete")
async def delete_webhook(webhook_id: int):
    store.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    return RedirectResponse("/webhooks?ok=Usunięto", status_code=303)


@app.get("/security", response_class=HTMLResponse)
def security_page(ok: str = "") -> str:
    runtimes = store.rows("SELECT r.id, r.name, r.status, r.runtime_class, r.risk_level, p.policy_json FROM runtimes r LEFT JOIN policies p ON r.id = p.runtime_id WHERE r.status != 'deleted' ORDER BY r.name")
    credentials = store.rows("SELECT runtime_id, COUNT(*) as cnt FROM runtime_credentials GROUP BY runtime_id")
    cred_by_rid = {c["runtime_id"]: c["cnt"] for c in credentials}

    # Parse each policy and compute a risk score
    def parse_policy(pol_json: str | None) -> dict:
        if not pol_json:
            return {}
        try:
            return json.loads(pol_json)
        except Exception:
            return {}

    def policy_level(p: dict) -> tuple[str, str]:
        """Returns (css_class, label) based on how strict the policy is."""
        if not p:
            return ("failed", "⚠️ brak")
        ro = p.get("require_read_only", False)
        bw = p.get("block_write_tools", False)
        bd = p.get("block_destructive_tools", False)
        if ro and bw and bd:
            return ("running", "🔒 ścisła")
        if ro or bw:
            return ("deploying", "🔶 częściowa")
        return ("failed", "🔓 luźna")

    runtime_rows = ""
    strict_count = moderate_count = loose_count = 0
    for r in runtimes:
        pol = parse_policy(r.get("policy_json"))
        level_cls, level_label = policy_level(pol)
        if level_cls == "running":
            strict_count += 1
        elif level_cls == "deploying":
            moderate_count += 1
        else:
            loose_count += 1
        timeout = pol.get("timeout_seconds", "—")
        max_resp_kb = pol.get("max_response_bytes", 0)
        max_resp_str = f"{max_resp_kb // 1024} KB" if max_resp_kb else "—"
        binaries = ", ".join(pol.get("allowed_binaries") or []) or "wszystkie"
        creds = cred_by_rid.get(r["id"], 0)
        bins_val = " ".join(pol.get("allowed_binaries") or [])
        timeout_val = pol.get("timeout_seconds", 30)
        max_kb_val = (pol.get("max_response_bytes") or 0) // 1024 or 5120
        rid = r['id']
        runtime_rows += f"""
        <tr id="row-{rid}">
          <td>
            <a href="/runtimes/{rid}" style="font-weight:700;color:white">{escape(r['name'])}</a>
            <div class="muted" style="font-size:11px">{escape(r['runtime_class'])}</div>
          </td>
          <td><span class="badge {r['status']}" style="font-size:11px">{escape(r['status'])}</span></td>
          <td><span class="badge {level_cls}" style="font-size:12px">{level_label}</span></td>
          <td style="font-size:12px;text-align:center">{'✅' if pol.get('require_read_only') else '❌'}</td>
          <td style="font-size:12px;text-align:center">{'✅' if pol.get('block_write_tools') else '❌'}</td>
          <td style="font-size:12px;text-align:center">{'✅' if pol.get('block_destructive_tools') else '❌'}</td>
          <td style="font-size:12px;color:var(--muted)">{timeout_val}s</td>
          <td style="font-size:12px;color:var(--muted)">{max_resp_str}</td>
          <td style="font-size:12px;color:var(--muted)">{escape(binaries[:40])}</td>
          <td style="text-align:center">{'🔑 ' + str(creds) if creds else '<span class="muted">—</span>'}</td>
          <td style="white-space:nowrap">
            <button type="button" onclick="togglePolicyEditor('{rid}')"
                    style="font-size:11px;padding:4px 8px;background:#263548">✏️ Edytuj</button>
          </td>
        </tr>
        <tr id="editor-{rid}" style="display:none">
          <td colspan="11" style="padding:0">
            <div style="background:#0d1e2e;border-top:2px solid var(--blue);padding:18px 20px">
              <div style="font-weight:800;color:#7dd3fc;margin-bottom:14px;font-size:13px">
                ✏️ Edytujesz politykę: <b style="color:white">{escape(r['name'])}</b>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:14px">
                <div>
                  <div style="font-weight:700;font-size:12px;color:#a0b8d0;margin-bottom:10px">Flagi bezpieczeństwa</div>
                  <div style="display:grid;gap:8px">
                    <label style="display:flex;gap:10px;align-items:center;cursor:pointer;font-size:13px">
                      <input type="checkbox" form="pol-{rid}" name="require_read_only" value="1" {'checked' if pol.get('require_read_only') else ''} style="width:auto">
                      🔒 Tylko odczyt
                    </label>
                    <label style="display:flex;gap:10px;align-items:center;cursor:pointer;font-size:13px">
                      <input type="checkbox" form="pol-{rid}" name="block_write_tools" value="1" {'checked' if pol.get('block_write_tools') else ''} style="width:auto">
                      🚫 Blokuj zapis
                    </label>
                    <label style="display:flex;gap:10px;align-items:center;cursor:pointer;font-size:13px">
                      <input type="checkbox" form="pol-{rid}" name="block_destructive_tools" value="1" {'checked' if pol.get('block_destructive_tools') else ''} style="width:auto">
                      ⛔ Blokuj destruktywne
                    </label>
                  </div>
                </div>
                <div>
                  <div style="font-weight:700;font-size:12px;color:#a0b8d0;margin-bottom:10px">Limity</div>
                  <div style="display:grid;gap:8px">
                    <label style="font-size:12px">Timeout (s)
                      <input form="pol-{rid}" name="timeout_seconds" type="number" value="{timeout_val}" min="5" max="300" style="margin-top:4px;padding:6px 8px">
                    </label>
                    <label style="font-size:12px">Maks. odpowiedź (KB)
                      <input form="pol-{rid}" name="max_response_kb" type="number" value="{max_kb_val}" min="64" max="51200" style="margin-top:4px;padding:6px 8px">
                    </label>
                    <label style="font-size:12px">Dozwolone binarki (spacja)
                      <input form="pol-{rid}" name="allowed_binaries" value="{escape(bins_val)}" placeholder="curl jq oc kubectl" style="margin-top:4px;padding:6px 8px">
                    </label>
                  </div>
                </div>
              </div>
              <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <form id="pol-{rid}" method="post" action="/api/security/policy/{rid}" style="display:none"></form>
                <button form="pol-{rid}" type="submit" style="background:#1a7a3f;padding:7px 14px;font-size:12px">💾 Zapisz politykę</button>
                <span style="color:var(--muted);font-size:12px">lub zastosuj szablon:</span>
                <form method="post" action="/api/security/policy/{rid}/apply-template" style="display:inline">
                  <input type="hidden" name="template" value="strict">
                  <button style="font-size:11px;padding:5px 10px;background:#0e2e1e;border:1px solid #1a5a38">🔒 Ścisła</button>
                </form>
                <form method="post" action="/api/security/policy/{rid}/apply-template" style="display:inline">
                  <input type="hidden" name="template" value="standard">
                  <button style="font-size:11px;padding:5px 10px;background:#2c2008;border:1px solid #5a420f">🔶 Standardowa</button>
                </form>
                <form method="post" action="/api/security/policy/{rid}/apply-template" style="display:inline">
                  <input type="hidden" name="template" value="dev">
                  <button style="font-size:11px;padding:5px 10px;background:#2c0e10;border:1px solid #5a2025">🧪 Deweloperska</button>
                </form>
                <button type="button" onclick="togglePolicyEditor('{rid}')" style="font-size:11px;padding:5px 10px;background:#263548;margin-left:auto">✕ Zamknij</button>
              </div>
            </div>
          </td>
        </tr>"""

    total = len(runtimes)

    templates = [
        {
            "name": "🔒 Ścisła (produkcja)",
            "desc": "Maksymalna ochrona — tylko odczyt, blokada zapisu i destruktywnych operacji. Zalecana dla wszystkich serwerów produkcyjnych.",
            "color": "#0e2e1e", "border": "#1a5a38",
            "policy": {"require_read_only": True, "block_write_tools": True, "block_destructive_tools": True, "timeout_seconds": 30, "max_payload_bytes": 262144, "max_response_bytes": 5242880},
        },
        {
            "name": "🔶 Standardowa",
            "desc": "Blokuje operacje destruktywne, ale pozwala na zapis. Przydatna dla serwerów zarządzających danymi (np. tworzenie ticketów).",
            "color": "#1a1400", "border": "#5a420f",
            "policy": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": True, "timeout_seconds": 60, "max_payload_bytes": 524288, "max_response_bytes": 10485760},
        },
        {
            "name": "🧪 Deweloperska",
            "desc": "Brak ograniczeń policy — tylko dla testów lokalnych. NIGDY nie używaj na produkcji.",
            "color": "#1a0a0a", "border": "#5a2025",
            "policy": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": False, "timeout_seconds": 120, "max_payload_bytes": 1048576, "max_response_bytes": 20971520},
        },
    ]
    custom_templates = _load_custom_templates()

    tpl_html = ""
    for t in templates:
        pol = t["policy"]
        tpl_html += f"""
        <div style="background:{t['color']};border:1px solid {t['border']};border-radius:12px;padding:18px 20px">
          <div style="font-size:11px;color:var(--muted);margin-bottom:4px">wbudowany</div>
          <div style="font-size:15px;font-weight:800;color:white;margin-bottom:6px">{t['name']}</div>
          <div class="muted" style="margin-bottom:14px;font-size:13px">{t['desc']}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;margin-bottom:14px">
            <div>{'✅' if pol['require_read_only'] else '❌'} Tylko odczyt</div>
            <div>{'✅' if pol['block_write_tools'] else '❌'} Blokuj zapis</div>
            <div>{'✅' if pol['block_destructive_tools'] else '❌'} Blokuj destruktywne</div>
            <div>⏱️ Timeout: {pol['timeout_seconds']}s</div>
          </div>
          <details style="background:rgba(0,0,0,.3);border:none;padding:8px 10px;border-radius:6px">
            <summary style="font-size:11px;color:var(--muted);margin-bottom:0">JSON policy</summary>
            <pre style="margin-top:8px;font-size:11px;max-height:120px">{escape(json.dumps(pol, indent=2))}</pre>
          </details>
        </div>"""

    for ct in custom_templates:
        pol = ct.get("policy", {})
        slug = ct.get("slug", "")
        tpl_html += f"""
        <div style="background:#0d1a2a;border:2px solid #1a4a6a;border-radius:12px;padding:18px 20px;position:relative">
          <div style="font-size:11px;color:#7dd3fc;margin-bottom:4px">własny szablon</div>
          <div style="font-size:15px;font-weight:800;color:white;margin-bottom:6px">{escape(ct.get('name',''))}</div>
          <div class="muted" style="margin-bottom:14px;font-size:13px">{escape(ct.get('desc',''))}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;margin-bottom:14px">
            <div>{'✅' if pol.get('require_read_only') else '❌'} Tylko odczyt</div>
            <div>{'✅' if pol.get('block_write_tools') else '❌'} Blokuj zapis</div>
            <div>{'✅' if pol.get('block_destructive_tools') else '❌'} Blokuj destruktywne</div>
            <div>⏱️ Timeout: {pol.get('timeout_seconds',30)}s</div>
            <div>📦 Max odpowiedź: {pol.get('max_response_bytes',5242880)//1024}KB</div>
            <div>📥 Max payload: {pol.get('max_payload_bytes',262144)//1024}KB</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <details style="flex:1;background:rgba(0,0,0,.3);border:none;padding:8px 10px;border-radius:6px">
              <summary style="font-size:11px;color:var(--muted);margin-bottom:0">JSON policy</summary>
              <pre style="margin-top:8px;font-size:11px;max-height:120px">{escape(json.dumps(pol, indent=2))}</pre>
            </details>
            <button onclick="deleteTpl('{escape(slug)}')" style="background:#4a1a1a;border:1px solid #8a2a2a;color:#f47a80;border-radius:6px;padding:6px 12px;font-size:12px;cursor:pointer;flex-shrink:0">🗑️ Usuń</button>
          </div>
        </div>"""

    ok_banner = '<div class="success" style="margin-bottom:0">✅ Polityka zapisana pomyślnie.</div>' if ok else ""
    body = f"""
      {ok_banner}
      <!-- Overview banner -->
      <section style="background:linear-gradient(135deg,#0a1a2a,#0d2a1a);border-color:#1a4a3a">
        <h2 style="margin-bottom:16px">🛡️ Hardening kontenerów (zawsze aktywne)</h2>
        <div class="grid3">
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">👤</div>
            <div style="font-weight:700;color:white">user 1000:1000</div>
            <div class="muted" style="font-size:12px">żaden kontener nie działa jako root</div>
          </div>
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">🔐</div>
            <div style="font-weight:700;color:white">cap_drop: ALL</div>
            <div class="muted" style="font-size:12px">brak wszystkich uprawnień systemowych</div>
          </div>
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">📁</div>
            <div style="font-weight:700;color:white">read_only filesystem</div>
            <div class="muted" style="font-size:12px">kontener nie może zapisywać do dysku</div>
          </div>
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">🚫</div>
            <div style="font-weight:700;color:white">no-new-privileges</div>
            <div class="muted" style="font-size:12px">blokada eskalacji uprawnień</div>
          </div>
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">💾</div>
            <div style="font-weight:700;color:white">512 MB RAM · 1 CPU</div>
            <div class="muted" style="font-size:12px">limit zasobów na każdy kontener</div>
          </div>
          <div style="text-align:center;padding:12px">
            <div style="font-size:28px;margin-bottom:4px">🌐</div>
            <div style="font-weight:700;color:white">ai-net tylko</div>
            <div class="muted" style="font-size:12px">izolacja sieciowa, brak dostępu do hosta</div>
          </div>
        </div>
      </section>

      <!-- Policy stats -->
      <div class="grid3">
        <div class="card" style="text-align:center;border-color:#1a5a38;background:#0e2e1e">
          <div class="metric" style="color:#5ce89a">{strict_count}</div>
          <div style="font-weight:700;color:white">🔒 Ścisłe polityki</div>
          <div class="muted">read-only + blokada zapisu</div>
        </div>
        <div class="card" style="text-align:center;border-color:#5a420f;background:#2c2008">
          <div class="metric" style="color:#f4c163">{moderate_count}</div>
          <div style="font-weight:700;color:white">🔶 Częściowe polityki</div>
          <div class="muted">tylko niektóre blokady</div>
        </div>
        <div class="card" style="text-align:center;border-color:#5a2025;background:#2c0e10">
          <div class="metric" style="color:#f47a80">{loose_count}</div>
          <div style="font-weight:700;color:white">🔓 Luźne polityki</div>
          <div class="muted">brak ograniczeń policy</div>
        </div>
      </div>

      <!-- Runtime policies table -->
      <section>
        <h2>Polityki runtimeów ({total})</h2>
        {'<p class="muted">Brak runtime\'ów.</p>' if not runtimes else f"""
        <table>
          <thead>
            <tr>
              <th>Serwer</th><th>Status</th><th>Poziom</th>
              <th>Tylko odczyt</th><th>Blokuj zapis</th><th>Blokuj destruktywne</th>
              <th>Timeout</th><th>Maks. odpowiedź</th><th>Dozwolone binarki</th>
              <th>Credentials</th><th></th>
            </tr>
          </thead>
          <tbody>{runtime_rows}</tbody>
        </table>"""}
      </section>

      <!-- Policy templates -->
      <section>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
          <h2 style="margin:0">Szablony polityk</h2>
          <button onclick="document.getElementById('new-tpl-box').style.display=document.getElementById('new-tpl-box').style.display==='none'?'block':'none'"
                  style="background:var(--blue);border:none;color:white;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">
            ➕ Nowy szablon
          </button>
        </div>
        <p class="muted" style="margin-bottom:16px">Gotowe konfiguracje — zastosuj do dowolnego serwera przyciskiem w tabeli polityk powyżej.</p>

        <!-- New template form -->
        <div id="new-tpl-box" style="display:none;background:#0a1a2a;border:2px solid var(--blue);border-radius:12px;padding:20px 22px;margin-bottom:20px">
          <div style="font-weight:800;color:white;font-size:15px;margin-bottom:16px">Nowy własny szablon</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
            <div>
              <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Nazwa szablonu</label>
              <input id="nt-name" placeholder="np. Produkcja API" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
            </div>
            <div>
              <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Opis (opcjonalny)</label>
              <input id="nt-desc" placeholder="Krótki opis zastosowania" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:14px">
            <label style="display:flex;align-items:center;gap:8px;background:#0d1822;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="nt-ro" style="width:16px;height:16px"> Tylko odczyt
            </label>
            <label style="display:flex;align-items:center;gap:8px;background:#0d1822;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="nt-bw" style="width:16px;height:16px"> Blokuj zapis
            </label>
            <label style="display:flex;align-items:center;gap:8px;background:#0d1822;border:1px solid #1a3a50;border-radius:8px;padding:10px 12px;cursor:pointer;font-size:13px">
              <input type="checkbox" id="nt-bd" style="width:16px;height:16px"> Blokuj destruktywne
            </label>
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
            <div>
              <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Timeout (s)</label>
              <input id="nt-timeout" type="number" value="30" min="5" max="300" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
            </div>
            <div>
              <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Max odpowiedź (KB)</label>
              <input id="nt-resp" type="number" value="5120" min="64" max="51200" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
            </div>
            <div>
              <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Max payload (KB)</label>
              <input id="nt-payload" type="number" value="256" min="16" max="10240" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
            </div>
          </div>
          <div style="display:flex;gap:10px;align-items:center">
            <button onclick="saveNewTpl()" style="background:var(--blue);border:none;color:white;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer">💾 Zapisz szablon</button>
            <button onclick="document.getElementById('new-tpl-box').style.display='none'" style="background:#263548;border:none;color:#c9d7e6;padding:10px 16px;border-radius:8px;font-size:13px;cursor:pointer">Anuluj</button>
            <span id="nt-msg" style="font-size:13px"></span>
          </div>
        </div>

        <div class="grid3" id="tpl-grid">{tpl_html}</div>
      </section>

      <!-- Info: what policy controls -->
      <details>
        <summary>📖 Jak działa policy? Co blokuje, a co nie?</summary>
        <div style="margin-top:12px;display:grid;gap:12px;font-size:13px">
          <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:8px;padding:14px 16px">
            <div style="font-weight:700;color:#7dd3fc;margin-bottom:8px">🔒 require_read_only</div>
            <div class="muted">Wymusza żeby każdy tool miał <code>mode: read-only</code>. Jeśli tool ma <code>read-write</code>, runtime odrzuca wywołanie z błędem policy.</div>
          </div>
          <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:8px;padding:14px 16px">
            <div style="font-weight:700;color:#7dd3fc;margin-bottom:8px">🚫 block_write_tools / block_destructive_tools</div>
            <div class="muted">Dodatkowe flagi sprawdzane przez runtime przed wykonaniem narzędzia. Można blokować klasy operacji bez edytowania każdego toola osobno.</div>
          </div>
          <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:8px;padding:14px 16px">
            <div style="font-weight:700;color:#7dd3fc;margin-bottom:8px">⌨️ allowed_binaries</div>
            <div class="muted">Tylko dla shell tools. Lista dozwolonych binarek — np. <code>["curl", "jq"]</code>. Runtime odrzuca wywołania używające innych komend. Pusta lista = brak ograniczeń.</div>
          </div>
          <div style="background:#0a1a2a;border:1px solid #1a3a50;border-radius:8px;padding:14px 16px">
            <div style="font-weight:700;color:#7dd3fc;margin-bottom:8px">⚠️ Co policy NIE kontroluje</div>
            <div class="muted">Policy działa na poziomie aplikacji. Hardening kontenerów (rootless, cap_drop, read-only FS) to osobna warstwa i jest <b>zawsze aktywna</b> niezależnie od ustawień policy.</div>
          </div>
        </div>
      </details>
    """
    body += """
<script>
function togglePolicyEditor(rid) {
  var row = document.getElementById('editor-' + rid);
  if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
}

function saveNewTpl() {
  var name = document.getElementById('nt-name').value.trim();
  if (!name) { document.getElementById('nt-msg').textContent = '⚠️ Wpisz nazwę szablonu'; return; }
  var policy = {
    require_read_only: document.getElementById('nt-ro').checked,
    block_write_tools: document.getElementById('nt-bw').checked,
    block_destructive_tools: document.getElementById('nt-bd').checked,
    timeout_seconds: parseInt(document.getElementById('nt-timeout').value) || 30,
    max_response_bytes: (parseInt(document.getElementById('nt-resp').value) || 5120) * 1024,
    max_payload_bytes: (parseInt(document.getElementById('nt-payload').value) || 256) * 1024,
  };
  var msg = document.getElementById('nt-msg');
  msg.textContent = 'Zapisywanie...';
  fetch('/api/security/templates', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name: name, desc: document.getElementById('nt-desc').value.trim(), policy: policy})})
  .then(r => r.json()).then(d => {
    if (d.ok) { msg.style.color='#5ce89a'; msg.textContent='✅ Zapisano — odświeżam...'; setTimeout(()=>location.reload(),800); }
    else { msg.style.color='#f47a80'; msg.textContent='❌ ' + (d.error||'Błąd'); }
  }).catch(()=>{ msg.style.color='#f47a80'; msg.textContent='❌ Błąd połączenia'; });
}

function deleteTpl(slug) {
  if (!confirm('Usunąć ten szablon?')) return;
  fetch('/api/security/templates/' + encodeURIComponent(slug), {method:'DELETE'})
  .then(r=>r.json()).then(d=>{ if(d.ok) location.reload(); });
}
</script>"""
    return page_shell("security", body)


@app.post("/api/security/templates")
async def create_policy_template(request: Request):
    user = _get_session(request)
    if not user or user["role"] not in ("admin", "read_write"):
        raise HTTPException(status_code=403)
    payload = await request.json()
    name = str(payload.get("name") or "").strip()
    if not name:
        return JSONResponse({"ok": False, "error": "Brak nazwy szablonu"})
    templates = _load_custom_templates()
    slug_val = slug(name) + "-" + uuid.uuid4().hex[:4]
    templates.append({
        "slug": slug_val,
        "name": name,
        "desc": str(payload.get("desc") or ""),
        "policy": payload.get("policy") or {},
    })
    _save_custom_templates(templates)
    store.audit(user["username"], "create_policy_template", "policy_template", slug_val)
    return JSONResponse({"ok": True, "slug": slug_val})


@app.delete("/api/security/templates/{tpl_slug}")
async def delete_policy_template(tpl_slug: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] not in ("admin", "read_write"):
        raise HTTPException(status_code=403)
    templates = _load_custom_templates()
    before = len(templates)
    templates = [t for t in templates if t.get("slug") != tpl_slug]
    if len(templates) == before:
        return JSONResponse({"ok": False, "error": "Nie znaleziono szablonu"})
    _save_custom_templates(templates)
    store.audit(user["username"], "delete_policy_template", "policy_template", tpl_slug)
    return JSONResponse({"ok": True})


@app.get("/audit", response_class=HTMLResponse)
def audit_page() -> str:
    audit = store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")
    tool_calls_all = store.rows(
        "SELECT tc.*, r.name AS runtime_name FROM tool_calls tc LEFT JOIN runtimes r ON r.id = tc.runtime_id ORDER BY tc.id DESC LIMIT 500"
    )
    action_icons = {"deploy_runtime": "🚀", "stop_runtime": "⏹️", "start_runtime": "▶️", "restart_runtime": "🔄",
                    "delete_runtime": "🗑️", "reload_runtime": "♻️", "build_runtime_image": "🔨", "action_failed": "❌",
                    "create_runtime": "➕", "health_refresh": "🩺", "sync_logs": "📋", "update_policy": "🔒",
                    "apply_policy_template": "🔒", "install_package": "📦", "clone_runtime": "🔁",
                    "view_runtime": "👁️", "update_adapter": "✏️", "delete_adapter": "🗑️",
                    "update_runtime_class": "✏️", "delete_runtime_class": "🗑️",
                    "create_tool_package": "📦", "update_tool_package": "✏️",
                    "create_policy_template": "🔒", "delete_policy_template": "🗑️",
                    "add_tool": "🔧", "delete_tool": "🗑️", "update_tool": "✏️",
                    "delete_image_build": "🗑️", "register_external_mcp": "🔗"}
    unique_actions = sorted({a["action"] for a in audit})
    unique_actors = sorted({a["actor"] for a in audit})
    action_opts = "".join(f'<option value="{escape(a)}">{action_icons.get(a,"📌")} {escape(a)}</option>' for a in unique_actions)
    actor_opts = "".join(f'<option value="{escape(a)}">{escape(a)}</option>' for a in unique_actors)
    unique_tc_runtimes = sorted({tc["runtime_id"] for tc in tool_calls_all})
    unique_tc_tools = sorted({tc["tool_name"] for tc in tool_calls_all})
    tc_runtime_opts = "".join(f'<option value="{escape(r)}">{escape(r)}</option>' for r in unique_tc_runtimes)
    tc_tool_opts = "".join(f'<option value="{escape(t)}">{escape(t)}</option>' for t in unique_tc_tools)
    rows_html = "".join(
        f"""<tr data-action="{escape(a['action'])}" data-actor="{escape(a['actor'])}" data-target="{escape(a['target_id'])}">
          <td style="font-size:12px;color:var(--muted);white-space:nowrap">{escape(a['created_at'][:19].replace('T',' '))}</td>
          <td><span class="badge" style="font-size:11px">{escape(a['actor'])}</span></td>
          <td style="white-space:nowrap">{action_icons.get(a['action'],'📌')} <b>{escape(a['action'])}</b></td>
          <td class="muted" style="font-size:12px">{escape(a['target_type'])}</td>
          <td style="font-size:12px;font-family:monospace;color:#7dd3fc">{escape(a['target_id'][:32])}</td>
          <td><details style="padding:6px;border:none;background:transparent"><summary style="font-size:11px;margin-bottom:0;color:var(--muted)">szczegóły</summary><pre style="margin-top:6px;font-size:11px;max-height:100px">{escape(a['details_json'])}</pre></details></td>
        </tr>""" for a in audit)
    tc_rows_html = "".join(
        f"""<tr data-runtime="{escape(tc['runtime_id'])}" data-tool="{escape(tc['tool_name'])}" data-ok="{tc['result_ok']}">
          <td style="font-size:12px;color:var(--muted);white-space:nowrap">{escape(tc['created_at'][:19].replace('T',' '))}</td>
          <td style="font-size:12px;font-family:monospace;color:#7dd3fc"><a href="/runtimes/{escape(tc['runtime_id'])}" style="color:#7dd3fc">{escape((tc.get('runtime_name') or tc['runtime_id'])[:28])}</a></td>
          <td style="font-weight:700;color:var(--blue)">{escape(tc['tool_name'])}</td>
          <td><span class="badge {'running' if tc['result_ok'] else 'failed'}" style="font-size:11px;padding:2px 7px">{"OK" if tc['result_ok'] else "ERR"}</span></td>
          <td class="muted" style="font-size:12px">{tc['duration_ms']} ms</td>
          <td class="muted" style="font-size:12px;font-family:monospace">{escape(tc.get('caller_ip','') or '—')}</td>
          <td class="muted" style="font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{escape(tc.get('model',''))}">{escape((tc.get('model','') or '—')[:24])}</td>
          <td><details style="padding:6px;border:none;background:transparent"><summary style="font-size:11px;margin-bottom:0;color:var(--muted)">argumenty</summary><pre style="margin-top:6px;font-size:11px;max-height:100px">{escape(tc['arguments_json'])}</pre></details></td>
        </tr>""" for tc in tool_calls_all)
    body = f"""
      <div style="display:flex;gap:4px;flex-wrap:wrap;border-bottom:2px solid var(--line);margin-bottom:20px">
        <button class="rt-tab rt-tab-active" onclick="auditTab('ops')" id="atab-ops">📋 Operacje adminów ({len(audit)})</button>
        <button class="rt-tab" onclick="auditTab('ai')" id="atab-ai">🤖 Wywołania AI ({len(tool_calls_all)})</button>
      </div>
      <style>
      .rt-tab{{background:none;border:none;border-bottom:3px solid transparent;padding:8px 14px;font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;margin-bottom:-2px;transition:.15s;border-radius:6px 6px 0 0}}
      .rt-tab:hover{{color:var(--text);background:var(--panel-2)}}
      .rt-tab.rt-tab-active{{color:white;border-bottom-color:var(--blue);background:var(--panel-2)}}
      .audit-pane{{display:none}}.audit-pane.active{{display:block}}
      </style>

      <!-- OPS tab -->
      <div class="audit-pane active" id="apane-ops">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:4px">
          <div>
            <label style="font-size:12px;margin-bottom:4px;display:block">Akcja</label>
            <select id="f-action" onchange="filterAudit()" style="width:220px;padding:8px 10px;font-size:13px">
              <option value="">— wszystkie akcje —</option>
              {action_opts}
            </select>
          </div>
          <div>
            <label style="font-size:12px;margin-bottom:4px;display:block">Aktor</label>
            <select id="f-actor" onchange="filterAudit()" style="width:140px;padding:8px 10px;font-size:13px">
              <option value="">— wszyscy —</option>
              {actor_opts}
            </select>
          </div>
          <div style="flex:1;min-width:200px">
            <label style="font-size:12px;margin-bottom:4px;display:block">Szukaj po celu / ID</label>
            <input id="f-target" oninput="filterAudit()" placeholder="wpisz fragment ID..." style="padding:8px 10px;font-size:13px">
          </div>
          <button onclick="clearFilters()" class="secondary" style="padding:8px 12px;font-size:12px;height:38px;align-self:flex-end">✕ Wyczyść</button>
          <span id="f-count" class="muted" style="font-size:12px;align-self:flex-end;padding-bottom:10px">{len(audit)} wpisów</span>
        </div>
        <section style="padding:0;overflow:auto">
          <table id="audit-table">
            <thead><tr><th>Czas</th><th>Aktor</th><th>Akcja</th><th>Typ</th><th>Cel</th><th>Szczegóły</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </section>
      </div>

      <!-- AI CALLS tab -->
      <div class="audit-pane" id="apane-ai">
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:4px">
          <div>
            <label style="font-size:12px;margin-bottom:4px;display:block">Serwer</label>
            <select id="tc-runtime" onchange="filterTC()" style="width:200px;padding:8px 10px;font-size:13px">
              <option value="">— wszystkie —</option>
              {tc_runtime_opts}
            </select>
          </div>
          <div>
            <label style="font-size:12px;margin-bottom:4px;display:block">Tool</label>
            <select id="tc-tool" onchange="filterTC()" style="width:180px;padding:8px 10px;font-size:13px">
              <option value="">— wszystkie —</option>
              {tc_tool_opts}
            </select>
          </div>
          <div>
            <label style="font-size:12px;margin-bottom:4px;display:block">Status</label>
            <select id="tc-ok" onchange="filterTC()" style="width:120px;padding:8px 10px;font-size:13px">
              <option value="">— wszystkie —</option>
              <option value="1">✅ OK</option>
              <option value="0">❌ Błąd</option>
            </select>
          </div>
          <button onclick="clearTC()" class="secondary" style="padding:8px 12px;font-size:12px;height:38px;align-self:flex-end">✕ Wyczyść</button>
          <span id="tc-count" class="muted" style="font-size:12px;align-self:flex-end;padding-bottom:10px">{len(tool_calls_all)} wywołań</span>
        </div>
        <section style="padding:0;overflow:auto">
          <table id="tc-table">
            <thead><tr><th>Czas</th><th>Serwer</th><th>Tool</th><th>Status</th><th>Czas ms</th><th>IP</th><th>Model</th><th>Argumenty</th></tr></thead>
            <tbody>{tc_rows_html}</tbody>
          </table>
        </section>
      </div>

<script>
function auditTab(name) {{
  document.querySelectorAll('.audit-pane').forEach(function(p) {{ p.classList.remove('active'); }});
  document.querySelectorAll('.rt-tab').forEach(function(t) {{ t.classList.remove('rt-tab-active'); }});
  document.getElementById('apane-' + name).classList.add('active');
  document.getElementById('atab-' + name).classList.add('rt-tab-active');
  try {{ localStorage.setItem('audit_tab', name); }} catch(e) {{}}
}}
var _savedAuditTab = 'ops';
try {{ _savedAuditTab = localStorage.getItem('audit_tab') || 'ops'; }} catch(e) {{}}
auditTab(_savedAuditTab);

function filterAudit() {{
  var action = document.getElementById('f-action').value.toLowerCase();
  var actor  = document.getElementById('f-actor').value.toLowerCase();
  var target = document.getElementById('f-target').value.toLowerCase();
  var rows = document.querySelectorAll('#audit-table tbody tr');
  var visible = 0;
  rows.forEach(function(r) {{
    var ok = true;
    if (action && r.dataset.action.toLowerCase().indexOf(action) === -1) ok = false;
    if (actor  && r.dataset.actor.toLowerCase()  !== actor)  ok = false;
    if (target && r.dataset.target.toLowerCase().indexOf(target) === -1) ok = false;
    r.style.display = ok ? '' : 'none';
    if (ok) visible++;
  }});
  document.getElementById('f-count').textContent = visible + ' / {len(audit)} wpisów';
}}
function clearFilters() {{
  document.getElementById('f-action').value = '';
  document.getElementById('f-actor').value  = '';
  document.getElementById('f-target').value = '';
  filterAudit();
}}
function filterTC() {{
  var runtime = document.getElementById('tc-runtime').value;
  var tool    = document.getElementById('tc-tool').value;
  var ok      = document.getElementById('tc-ok').value;
  var rows = document.querySelectorAll('#tc-table tbody tr');
  var visible = 0;
  rows.forEach(function(r) {{
    var show = true;
    if (runtime && r.dataset.runtime !== runtime) show = false;
    if (tool    && r.dataset.tool    !== tool)    show = false;
    if (ok      && r.dataset.ok      !== ok)      show = false;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  }});
  document.getElementById('tc-count').textContent = visible + ' / {len(tool_calls_all)} wywołań';
}}
function clearTC() {{
  document.getElementById('tc-runtime').value = '';
  document.getElementById('tc-tool').value    = '';
  document.getElementById('tc-ok').value      = '';
  filterTC();
}}
</script>"""
    return page_shell("audit", body)


@app.get("/logs", response_class=HTMLResponse)
def logs_page() -> str:
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 300")
    level_colors = {"error": "#f47a80", "warn": "#f4c163", "warning": "#f4c163", "info": "#7dd3fc", "debug": "#8ea2b8"}
    level_bg = {"error": "#2c0e10", "warn": "#2c2008", "warning": "#2c2008", "info": "#0a1a2a", "debug": "#141e2b"}
    rows_html = "".join(
        f"""<tr class="log-{escape(l['level'])}">
          <td style="font-size:12px;color:var(--muted);white-space:nowrap">{escape(l['created_at'][:19].replace('T',' '))}</td>
          <td style="font-size:12px;font-family:monospace;color:#7dd3fc">{escape(l['runtime_id'][:32])}</td>
          <td><span style="background:{level_bg.get(l['level'],'#141e2b')};color:{level_colors.get(l['level'],'#8ea2b8')};padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">{escape(l['level'].upper())}</span></td>
          <td style="font-size:13px">{escape(l['message'][:300])}</td>
        </tr>""" for l in logs)
    body = f"""
      <section>
        <h2>Logi platformy</h2>
        <p class="muted">Ostatnie 300 wpisów logów ze wszystkich runtimeów.</p>
        <table>
          <thead><tr><th>Czas</th><th>Runtime</th><th>Poziom</th><th>Wiadomość</th></tr></thead>
          <tbody>{rows_html}</tbody>
        </table>
      </section>"""
    return page_shell("logs", body)


@app.get("/legacy-all", response_class=HTMLResponse)
def legacy_all() -> str:
    runtimes = store.rows("SELECT * FROM runtimes ORDER BY created_at DESC")
    runtime_classes = store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)
    adapters = store.rows(sql.SELECT_ADAPTERS_ALL)
    audit = store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20")
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 30")
    rows_html = "".join(
        f"""
        <tr>
          <td><a href="/runtimes/{r['id']}">{r['name']}</a></td>
          <td><span class="badge {r['status']}">{r['status']}</span></td>
          <td>{r['runtime_class']}</td>
          <td><span class="risk {r['risk_level']}">{r['risk_level']}</span></td>
          <td>{r['endpoint_url'] or '-'}</td>
          <td>
            {action_forms(r['id'], compact=True, return_to='/runtimes')}
          </td>
        </tr>
        """
        for r in runtimes
    )
    class_rows_html = "".join(
        f"""
        <tr>
          <td>{item['name']}</td>
          <td>{item['runtime_image']}</td>
          <td>{", ".join(json.loads(item['allowed_execution_types_json'] or '[]'))}</td>
          <td><span class="risk {item['risk_level']}">{item['risk_level']}</span></td>
          <td>{'enabled' if item['enabled'] else 'disabled'}</td>
        </tr>
        """
        for item in runtime_classes
    )
    adapter_rows_html = "".join(
        f"""
        <tr>
          <td>{item['name']}</td>
          <td>{item['adapter_type']}</td>
          <td>{item['mode']}</td>
          <td><span class="risk {item['risk_level']}">{item['risk_level']}</span></td>
          <td>{'yes' if item['implemented'] else 'planned'}</td>
          <td>{'enabled' if item['enabled'] else 'disabled'}</td>
          <td>
            <form method="post" action="/api/adapters/{item['name']}/toggle"><button>{'Disable' if item['enabled'] else 'Enable'}</button></form>
          </td>
        </tr>
        """
        for item in adapters
    )
    audit_html = "".join(f"<li>{escape(a['created_at'])} {escape(a['actor'])} {escape(a['action'])} {escape(a['target_type'])}:{escape(a['target_id'])}</li>" for a in audit)
    logs_html = "".join(f"<li>{escape(l['created_at'])} [{escape(l['level'])}] {escape(l['runtime_id'])}: {escape(l['message'])}</li>" for l in logs)
    return f"""
    <!doctype html>
    <html><head><title>MCP Platform</title><style>
    {base_styles()}
    </style></head><body>
    <header><h1>MCP Platform</h1><div>Twórz i zarządzaj serwerami MCP</div></header>
    <main>
      <section>
        <h2>Nowy serwer MCP</h2>
        <div class="wizard">
          <div class="step"><b>1. Server</b><div class="muted">Name and runtime class</div></div>
          <div class="step"><b>2. First Tool</b><div class="muted">HTTP tool or empty server</div></div>
          <div class="step"><b>3. Policy</b><div class="muted">Risk and read-only defaults</div></div>
          <div class="step"><b>4. Uruchomienie</b><div class="muted">Tworzy kontener Docker i uruchamia serwer MCP</div></div>
        </div>
        <form method="post" action="/api/runtimes">
          <div class="grid">
            <label>Server name<input name="name" placeholder="GitLab Assistant"></label>
            <label>Runtime Class<select name="runtime_class">{runtime_class_options("http-gateway")}</select></label>
            <label>Risk<select name="risk_level"><option>low</option><option>medium</option><option>high</option></select></label>
            <label>Initial tool enabled<select name="first_tool_enabled"><option value="true">yes</option><option value="false">no</option></select></label>
          </div>
          <div class="grid">
            <label>First tool name<input name="first_tool_name" placeholder="gitlab_search"></label>
            <label>First tool URL<input name="first_tool_url" placeholder="https://gitlab.example/api/v4/search"></label>
            <label>Method<select name="first_tool_method"><option>POST</option><option>GET</option></select></label>
            <label>Body JSON<textarea name="first_tool_body_json">{{"query":"${{query}}"}}</textarea></label>
          </div>
          <p class="muted">You can leave first tool empty and add tools later on the server detail page.</p>
          <button>Create MCP Server</button>
        </form>
      </section>
      <section id="admin" class="admin-panel">
        <h2>Execution Adapters</h2>
        <form class="inline" method="post" action="/api/adapters">
          <label>Name<input name="name" placeholder="gitlab_api"></label>
          <label>Type<select name="adapter_type"><option>http</option><option>shell</option><option>python</option><option>openshift</option><option>workflow</option></select></label>
          <label>Risk<select name="risk_level"><option>low</option><option>medium</option><option>high</option></select></label>
          <button>Add Adapter</button>
        </form>
        <table><thead><tr><th>Nazwa</th><th>Typ</th><th>Tryb</th><th>Ryzyko</th><th>Zaimpl.</th><th>Status</th><th>Akcja</th></tr></thead><tbody>{adapter_rows_html}</tbody></table>
      </section>
      <section>
        <h2>Typy środowisk (Runtime Classes)</h2>
        <table><thead><tr><th>Nazwa</th><th>Obraz Docker</th><th>Dozwolone adaptery</th><th>Ryzyko</th><th>Status</th></tr></thead><tbody>{class_rows_html}</tbody></table>
      </section>
      <section>
        <h2>Runtime List</h2>
        <p><a href="#admin">Show platform adapter/runtime class catalog</a></p>
        <table><thead><tr><th>Nazwa</th><th>Status</th><th>Środowisko</th><th>Ryzyko</th><th>Endpoint</th><th>Akcja</th></tr></thead><tbody>{rows_html}</tbody></table>
      </section>
      <div class="grid">
        <section><h2>Audit</h2><ul>{audit_html}</ul></section>
        <section><h2>Logs</h2><ul>{logs_html}</ul></section>
      </div>
    </main></body></html>
    """


@app.post("/api/runtimes")
async def create_runtime(request: Request):
    form = await request.form()
    selected_adapters = list(form.getlist("adapter_names")) if hasattr(form, "getlist") else []
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

    _cu = _current_user.get()
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


@app.post("/api/auto-create")
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
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    return JSONResponse({
        "ok": True,
        "runtime_id": runtime_id,
        "name": server_name,
        "tools": len(package.get("tools", [])),
        "credentials": len(credentials),
        "deploy": auto_deploy,
        "message": f"MCP server '{server_name}' created with {len(package.get('tools', []))} tools. {'Deployment started.' if auto_deploy else 'Not deployed yet — call deploy manually.'}",
    })


@app.get("/api/platform-docs")
def platform_docs():
    """Returns instructions for AI models on how to create MCP servers."""
    return {
        "instruction": "You are creating MCP servers on MCP Platform. To create a server, call the create_mcp_server tool with a package JSON. Follow this structure exactly.",
        "package_structure": {
            "id": "unique-kebab-case-id",
            "name": "Human Readable Name",
            "description": "What this server does",
            "category": "one of: http, shell, openshift, database, other",
            "risk_level": "low | medium | high",
            "source": "auto-api",
            "runtime_class": {
                "name": "shell-readonly (for CLI tools) or http-gateway (for REST APIs)",
                "runtime_image": "mcp-runtime-shell:latest (for shell) or mcp-runtime-http-gateway:latest (for http)",
                "allowed_execution_types": ["shell"],
                "security_profile": "restricted"
            },
            "policy": {
                "allowed_binaries": ["list of allowed commands, e.g. curl, jq, oc, psql"],
                "blocked_commands": ["list of blocked words in commands"],
                "require_read_only": True,
                "timeout_seconds": 30
            },
            "tools": [
                {
                    "name": "tool_name_snake_case",
                    "description": "Clear description for AI - what this tool does and what parameters mean",
                    "execution_type": "shell",
                    "enabled": True,
                    "risk_level": "low",
                    "mode": "read-only",
                    "category": "same as package category",
                    "config": {
                        "command": ["binary", "arg1", "${variable}", "${*free_args}"],
                        "timeout_seconds": 30
                    },
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "variable": {"type": "string", "description": "What this parameter is for"},
                        },
                        "required": ["variable"]
                    }
                }
            ]
        },
        "variable_syntax": {
            "${variable}": "Single parameter — replaced with one value from AI arguments",
            "${*args}": "Splat parameter — AI provides full string, split by shlex into multiple arguments",
            "${ENV_VAR}": "UPPERCASE variables are resolved from container environment (credentials), NOT from AI arguments"
        },
        "credentials_note": "Pass credentials as UPPERCASE env vars (e.g. AWX_URL, API_TOKEN, DB_PASS). These are injected into the container environment and resolved in commands automatically. Do NOT add them to input_schema.",
        "examples": {
            "curl_with_auth": "curl -s -u ${API_USER}:${API_PASS} ${API_URL}/endpoint",
            "oc_get": "oc get ${*args}",
            "psql_query": "psql -h ${PGHOST} -U ${PGUSER} -d ${PGDATABASE} -c ${query}",
            "simple_curl": "curl -s ${url}"
        },
        "api_endpoint": "POST /api/auto-create with JSON body: {\"package\": {...}, \"name\": \"server-name\", \"credentials\": {\"KEY\": \"value\"}, \"deploy\": true}"
    }


@app.post("/api/tool-packages/import")
async def import_tool_package(request: Request):
    form = await request.form()
    package_url = str(form.get("package_url") or "").strip()
    raw_json = str(form.get("package_json") or "").strip()
    package_file = form.get("package_file")
    try:
        if package_url:
            if not _is_safe_fetch_url(package_url):
                raise HTTPException(status_code=400, detail="Package URL references a blocked address (private, loopback, or internal network)")
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.get(package_url)
                response.raise_for_status()
                package = response.json()
            source = package_url
        elif package_file is not None and getattr(package_file, "filename", ""):
            content = await package_file.read()
            package = json.loads(content.decode("utf-8"))
            source = f"upload:{package_file.filename}"
        elif raw_json:
            package = json.loads(raw_json)
            source = "ui-json"
        else:
            raise HTTPException(status_code=400, detail="Provide package URL or package JSON")
        package_id = install_tool_package(package, source=source)
    except json.JSONDecodeError as exc:
        return RedirectResponse(f"/tool-packages?error={quote(f'Invalid package JSON: {exc}')}", status_code=303)
    except httpx.HTTPError as exc:
        return RedirectResponse(f"/tool-packages?error={quote(f'Package URL fetch failed: {exc}')}", status_code=303)
    except HTTPException as exc:
        return RedirectResponse(f"/tool-packages?error={quote(str(exc.detail))}", status_code=303)
    return RedirectResponse(f"/tool-packages?error={quote(f'Package installed: {package_id}')}", status_code=303)


@app.get("/api/runtime-image-builds/latest")
def get_latest_build_status(rc: str = "") -> dict[str, Any]:
    """Poll latest build status for a given runtime class name."""
    if rc:
        row = store.one(
            "SELECT id, status, error, updated_at FROM runtime_image_builds WHERE runtime_class = ? ORDER BY created_at DESC LIMIT 1",
            (rc,),
        )
    else:
        row = store.one("SELECT id, status, error, updated_at FROM runtime_image_builds ORDER BY created_at DESC LIMIT 1")
    if not row:
        return {"status": "not_found"}
    return dict(row)


@app.delete("/api/runtime-image-builds/{build_id}")
async def delete_image_build(build_id: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Tylko admin może usuwać obrazy")
    row = store.one("SELECT * FROM runtime_image_builds WHERE id = ?", (build_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono buildu")
    # Try to remove Docker image
    image = row["image"]
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        client.images.remove(image, force=True)
    except Exception:
        pass  # Image may not exist locally or Docker unavailable — still remove from DB
    store.execute("DELETE FROM runtime_image_builds WHERE id = ?", (build_id,))
    store.execute("DELETE FROM runtime_classes WHERE runtime_image = ?", (image,))
    store.audit(user["username"], "delete_image_build", "runtime_image_build", build_id, {"image": image})
    return JSONResponse({"ok": True})


@app.post("/api/runtime-images/build")
async def build_runtime_image(request: Request):
    form = await request.form()
    try:
        image = validate_image_ref(str(form.get("image") or ""), "image tag")
        base_image = validate_image_ref(str(form.get("base_image") or ""), "base image")
        runtime_class = slug(str(form.get("runtime_class") or image.rsplit("/", 1)[-1].split(":", 1)[0]))
        apt_packages = clean_words(str(form.get("apt_packages") or ""), r"[a-zA-Z0-9][a-zA-Z0-9+._:-]*", "APT package")
        pip_packages = clean_words(str(form.get("pip_packages") or ""), r"[a-zA-Z0-9][a-zA-Z0-9+._:/<>=!~-]*", "pip package")
        allowed_execution_types = clean_words(
            str(form.get("allowed_execution_types") or ""),
            r"[a-zA-Z0-9_][a-zA-Z0-9_-]*",
            "execution type",
        ) or ["http_request"]
        risk_level = str(form.get("risk_level") or "low")
        if risk_level not in {"low", "medium", "high"}:
            raise HTTPException(status_code=400, detail="Invalid risk level")
        security_profile = str(form.get("security_profile") or "restricted").strip() or "restricted"
        extra_dockerfile = str(form.get("extra_dockerfile") or "")
        build_id = enqueue_runtime_image_build(image, base_image, apt_packages, pip_packages, extra_dockerfile, runtime_class)
        now = store.now_iso()
        store.execute(
            sql.UPSERT_RUNTIME_CLASS,
            (
                runtime_class,
                f"Custom runtime image built by MCP Platform: {image}",
                image,
                json.dumps(allowed_execution_types),
                1,
                risk_level,
                security_profile,
                now,
                now,
            ),
        )
        for execution_type in allowed_execution_types:
            contract = adapter_contracts().get(execution_type, {"name": execution_type, "config_schema": {}})
            store.execute(
                """
                INSERT INTO execution_adapters(name, description, adapter_type, runtime_image, config_schema_json,
                                               adapter_contract_json, enabled, implemented, risk_level, mode, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  runtime_image = excluded.runtime_image,
                  adapter_contract_json = excluded.adapter_contract_json,
                  enabled = excluded.enabled,
                  implemented = excluded.implemented,
                  risk_level = excluded.risk_level,
                  updated_at = excluded.updated_at
                """,
                (
                    execution_type,
                    f"{execution_type} execution adapter for custom runtime image {image}",
                    execution_type,
                    image,
                    json.dumps(contract.get("config_schema") or {}),
                    json.dumps(contract),
                    1,
                    1,
                    risk_level,
                    "read-only",
                    now,
                    now,
                ),
            )
        store.audit("admin", "upsert_runtime_class_from_image_build", "runtime_class", runtime_class, {"image": image, "build": build_id})
    except HTTPException as exc:
        return RedirectResponse(f"/tool-packages?error={quote(str(exc.detail))}", status_code=303)
    return RedirectResponse(f"/tool-packages?error={quote(f'Runtime image build queued: {build_id}')}", status_code=303)


@app.post("/api/tool-packages/{package_id}/create-runtime")
async def create_runtime_from_tool_package(package_id: str, request: Request):
    form = await request.form()
    try:
        runtime_id = create_runtime_from_package(
            package_id,
            str(form.get("name") or ""),
            str(form.get("deploy") or "false") == "true",
        )
    except HTTPException as exc:
        return RedirectResponse(f"/tool-packages?error={quote(str(exc.detail))}", status_code=303)
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@app.get("/tool-packages/{package_id}/edit", response_class=HTMLResponse)
def edit_package_page(package_id: str, error: str = "") -> str:
    package = store.one(sql.SELECT_TOOL_PACKAGE_BY_ID, (package_id,))
    if not package:
        raise HTTPException(status_code=404, detail="Nie znaleziono paczki")
    pkg_json = json.dumps(json.loads(package["package_json"]), indent=2, ensure_ascii=False)
    alert = f'<div class="alert">{escape(error)}</div>' if error else ""
    body = f"""
    {alert}
    <div style="max-width:860px;margin:0 auto">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
        <a href="/tool-packages" style="color:var(--muted);font-size:13px">← Katalog paczek</a>
        <span style="color:var(--muted)">/</span>
        <span style="font-weight:700">{escape(package['name'])}</span>
      </div>

      <form method="post" action="/api/tool-packages/{package_id}/update">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
          <div>
            <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Nazwa paczki</label>
            <input name="name" value="{escape(package['name'])}" style="width:100%;box-sizing:border-box;padding:10px 12px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:14px">
          </div>
          <div>
            <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Kategoria</label>
            <select name="category" style="width:100%;padding:10px 12px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:14px">
              {''.join(f'<option value="{c}" {"selected" if c==package["category"] else ""}>{c}</option>' for c in ['http','shell','openshift','kubernetes','database','other'])}
            </select>
          </div>
        </div>
        <div style="margin-bottom:14px">
          <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">Opis</label>
          <input name="description" value="{escape(package['description'] or '')}" style="width:100%;box-sizing:border-box;padding:10px 12px;background:#0d1420;border:1px solid #34465b;border-radius:6px;color:var(--text);font-size:14px">
        </div>
        <div style="margin-bottom:14px">
          <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:5px">
            Package JSON
            <span style="color:var(--muted);font-weight:400;font-size:11px;margin-left:8px">— pełna definicja: tools, silnik, polityka, obraz Docker</span>
          </label>
          <textarea name="package_json" rows="28" style="width:100%;box-sizing:border-box;padding:12px;background:#060e18;border:1px solid #1a3a50;border-radius:8px;color:#c9e8ff;font-size:12px;font-family:monospace;resize:vertical;line-height:1.6">{escape(pkg_json)}</textarea>
        </div>
        <div style="display:flex;gap:10px">
          <button type="submit" style="background:var(--blue);border:none;color:white;padding:11px 24px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer">💾 Zapisz zmiany</button>
          <a href="/tool-packages" style="padding:11px 18px;background:#263548;color:#c9d7e6;border-radius:8px;font-size:13px;text-decoration:none">Anuluj</a>
        </div>
      </form>
    </div>
    """
    return page_shell("packages", body)


@app.post("/api/tool-packages/{package_id}/update")
async def update_tool_package(package_id: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] not in ("admin", "read_write"):
        raise HTTPException(status_code=403)
    package = store.one(sql.SELECT_TOOL_PACKAGE_BY_ID, (package_id,))
    if not package:
        raise HTTPException(status_code=404)
    form = await request.form()
    name = str(form.get("name") or "").strip() or package["name"]
    description = str(form.get("description") or "").strip()
    category = str(form.get("category") or package["category"])
    raw_json = str(form.get("package_json") or "")
    try:
        pkg_data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        return RedirectResponse(f"/tool-packages/{package_id}/edit?error={quote(f'Błąd JSON: {exc}')}", status_code=303)
    if "tools" not in pkg_data:
        return RedirectResponse(f"/tool-packages/{package_id}/edit?error={quote('JSON musi zawierać pole \"tools\"')}", status_code=303)
    pkg_data["name"] = name
    pkg_data["description"] = description
    pkg_data["category"] = category
    store.execute(
        "UPDATE tool_packages SET name=?, description=?, category=?, package_json=?, updated_at=? WHERE id=?",
        (name, description, category, json.dumps(pkg_data, ensure_ascii=False), store.now_iso(), package_id),
    )
    store.audit(user["username"], "update_tool_package", "tool_package", package_id, {"name": name})
    return RedirectResponse("/tool-packages", status_code=303)


@app.post("/api/tool-packages/{package_id}/toggle")
def toggle_tool_package(package_id: str):
    package = store.one(sql.SELECT_TOOL_PACKAGE_BY_ID, (package_id,))
    if not package:
        raise HTTPException(status_code=404, detail="Tool package not found")
    enabled = 0 if package.get("enabled", 1) else 1
    store.execute(
        "UPDATE tool_packages SET enabled = ?, updated_at = ? WHERE id = ?",
        (enabled, store.now_iso(), package_id),
    )
    store.audit("admin", "toggle_tool_package", "tool_package", package_id, {"enabled": bool(enabled)})
    return RedirectResponse("/tool-packages", status_code=303)


@app.post("/api/tool-packages/{package_id}/delete")
def delete_tool_package(package_id: str):
    user = _current_user.get()
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete packages")
    if not store.one(sql.SELECT_TOOL_PACKAGE_ID_BY_ID, (package_id,)):
        raise HTTPException(status_code=404, detail="Tool package not found")
    store.execute("DELETE FROM tool_packages WHERE id = ?", (package_id,))
    store.audit(user.get("username","admin"), "delete_tool_package", "tool_package", package_id, {})
    return RedirectResponse("/tool-packages", status_code=303)


@app.post("/api/adapters")
async def create_adapter(request: Request):
    form = await request.form()
    name = slug(str(form.get("name") or "")).replace("-", "_")
    description = str(form.get("description") or "")
    adapter_type = str(form.get("adapter_type") or "http")
    risk_level = str(form.get("risk_level") or "low")
    runtime_image = str(form.get("runtime_image") or "").strip()
    mode = str(form.get("mode") or "read-only")
    implemented = 1 if form.get("implemented") == "1" else 0
    enabled = implemented  # auto-enable if implemented
    if not name:
        return RedirectResponse("/tool-types?error=Nazwa+jest+wymagana", status_code=303)
    if store.one(sql.SELECT_ADAPTER_NAME_BY_NAME, (name,)):
        return RedirectResponse(f"/tool-types?error=Adapter+{name}+już+istnieje", status_code=303)
    now = store.now_iso()
    store.execute(
        sql.INSERT_EXECUTION_ADAPTER,
        (
            name,
            description or f"Adapter {adapter_type}.",
            adapter_type,
            runtime_image,
            "{}",
            json.dumps({"name": name, "adapter_type": adapter_type, "config_schema": {}, "capabilities": []}),
            enabled,
            implemented,
            risk_level,
            mode,
            now,
            now,
        ),
    )
    store.audit("admin", "create_adapter", "adapter", data.name, data.model_dump())
    return RedirectResponse("/tool-types", status_code=303)


@app.post("/api/adapters/{adapter_name}/update")
async def update_adapter(adapter_name: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    adapter = store.one(sql.SELECT_ADAPTER_BY_NAME, (adapter_name,))
    if not adapter:
        raise HTTPException(status_code=404)
    form = await request.form()
    risk_level = str(form.get("risk_level") or adapter["risk_level"])
    mode = str(form.get("mode") or adapter["mode"])
    description = str(form.get("description") or adapter["description"])
    runtime_image = str(form.get("runtime_image") or adapter["runtime_image"])
    store.execute(
        "UPDATE execution_adapters SET risk_level=?, mode=?, description=?, runtime_image=?, updated_at=? WHERE name=?",
        (risk_level, mode, description, runtime_image, store.now_iso(), adapter_name),
    )
    store.audit(user["username"], "update_adapter", "adapter", adapter_name, {"risk_level": risk_level, "mode": mode})
    return RedirectResponse("/tool-types", status_code=303)


@app.post("/api/adapters/{adapter_name}/delete")
async def delete_adapter(adapter_name: str, request: Request):
    user = _get_session(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    store.execute("DELETE FROM execution_adapters WHERE name = ?", (adapter_name,))
    store.audit(user["username"], "delete_adapter", "adapter", adapter_name)
    return RedirectResponse("/tool-types", status_code=303)


@app.post("/api/adapters/{adapter_name}/toggle")
def toggle_adapter(adapter_name: str):
    adapter = store.one(sql.SELECT_ADAPTER_BY_NAME, (adapter_name,))
    if not adapter:
        raise HTTPException(status_code=404, detail="Adapter not found")
    enabled = 0 if adapter["enabled"] else 1
    if enabled and not adapter["implemented"]:
        message = "Ten typ toola jest tylko zaplanowany. Nie ma jeszcze zaimplementowanego pluginu runtime, więc nie można go włączyć."
        return RedirectResponse(f"/tool-types?error={quote(message)}", status_code=303)
    store.execute(
        "UPDATE execution_adapters SET enabled = ?, updated_at = ? WHERE name = ?",
        (enabled, store.now_iso(), adapter_name),
    )
    store.audit("admin", "toggle_adapter", "adapter", adapter_name, {"enabled": bool(enabled)})
    return RedirectResponse("/tool-types", status_code=303)


@app.get("/runtimes/{runtime_id}", response_class=HTMLResponse)
def runtime_detail(runtime_id: str, request: Request, welcome: str = "", tool_added: str = "") -> str:
    payload = runtime_payload(runtime_id)
    # Base URL without /mcp suffix — used for /openwebui and other non-MCP paths
    _ep = (payload.get("endpoint_url") or "").rstrip("/")
    _base_url = _ep[:-4] if _ep.endswith("/mcp") else _ep
    _platform_base = f"{request.url.scheme}://{request.url.netloc}"
    adapter_select = adapter_options("http_request")
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
    _tool_config_preview = "".join(
        f'<div style="margin-bottom:12px;padding:10px;background:#060e18;border-radius:6px">'
        f'<div style="font-weight:700;color:var(--blue);margin-bottom:4px">{escape(t["name"])}</div>'
        f'<div style="font-size:11px;color:var(--muted);margin-bottom:4px">{escape(t["description"][:80])}</div>'
        f'<pre style="font-size:11px;color:#8ea2b8;margin:0">{escape(t["config_json"][:300])}</pre>'
        f'</div>'
        for t in payload["tools"][:5]
    ) or '<p class="muted">Brak toolów.</p>'
    _cu = _current_user.get()
    _is_admin = (_cu or {}).get("role") == "admin"
    # Banner po dodaniu toola
    if tool_added:
        _existing_bins = ", ".join(payload["policy"].get("allowed_binaries") or []) or "brak"
        if tool_added == "shell":
            _banner_hint = (
                f'Dodałeś <b>shell tool</b>. Upewnij się że binarka jest w '
                f'<b>Polityka &rarr; Dozwolone binarki</b> (teraz: <code style="background:#0d0d00;padding:1px 5px;border-radius:3px">'
                f'{escape(_existing_bins)}</code>), inaczej tool będzie blokowany przez policy.'
            )
        else:
            _banner_hint = 'Dodałeś <b>HTTP tool</b>. Sprawdź URL i metodę w konfiguracji.'
        _tool_added_banner = (
            '<div style="background:linear-gradient(135deg,#1a1a00,#1a0d00);border:2px solid #8a7a00;'
            'border-radius:12px;padding:16px 20px;display:flex;gap:16px;align-items:flex-start;margin-bottom:16px" '
            'id="tool-added-banner">'
            '<div style="font-size:28px">🔧</div>'
            '<div style="flex:1">'
            '<div style="font-size:15px;font-weight:800;color:white;margin-bottom:6px">Tool dodany — sprawdź politykę</div>'
            f'<div style="color:#e0c060;font-size:13px;margin-bottom:10px">{_banner_hint}</div>'
            '<div style="display:flex;gap:8px;flex-wrap:wrap">'
            '<a href="#" onclick="rtTab(\'security\');return false;" style="background:#4a3a00;border:1px solid #8a7a00;color:#e0c060;padding:5px 12px;border-radius:6px;font-size:12px;text-decoration:none">🔒 Otwórz Politykę</a>'
            '<a href="#" onclick="rtTab(\'tools\');return false;" style="background:#1a2a1a;border:1px solid #2a5a2a;color:#80c880;padding:5px 12px;border-radius:6px;font-size:12px;text-decoration:none">🔧 Narzędzia</a>'
            '<button onclick="document.getElementById(\'tool-added-banner\').remove()" style="background:none;border:1px solid #4a4a00;color:#8a8a40;padding:5px 10px;border-radius:6px;font-size:12px;cursor:pointer">✕</button>'
            '</div></div></div>'
        )
    else:
        _tool_added_banner = ""
    # Audit: kto otworzył stronę serwera
    _actor = (_cu or {}).get("username") or "anonymous"
    store.audit(_actor, "view_runtime", "runtime", runtime_id, {"name": payload.get("name", runtime_id)})
    tools_rows = "".join(
        f"""<tr>
          <td><b>{escape(t['name'])}</b></td>
          <td style="font-size:12px">{escape(t['execution_type'])}</td>
          <td><span class="badge {'running' if t['enabled'] else 'failed'}" style="font-size:11px">{'enabled' if t['enabled'] else 'disabled'}</span></td>
          <td style="font-size:12px">{escape(t['risk_level'])}</td>
          <td style="font-size:12px">{escape(t['mode'])}</td>
          <td><a href="#tool-{t['id']}" style="font-size:12px">✏️ Edytuj</a></td>
          {'<td><form method="post" action="/api/runtimes/' + runtime_id + '/tools/' + str(t["id"]) + '/delete" onsubmit="return confirm(\'Usunąć tool ' + escape(t["name"]) + '? Operacja jest nieodwracalna.\')"><button style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer">🗑️ Usuń</button></form></td>' if _is_admin else '<td></td>'}
        </tr>"""
        for t in payload["tools"]
    )
    tool_forms = "".join(
        f'<section id="tool-{tool["id"]}"><h3>✏️ Edytuj tool</h3>{tool_edit_form(runtime_id, tool)}</section>'
        for tool in payload["tools"]
    )
    policy_json = json.dumps(payload["policy"], indent=2, ensure_ascii=False)
    logs_html = "\n".join(
        f"{escape(line['created_at'])} [{escape(line['level'])}] {escape(line['message'])}" for line in runtime_logs
    )
    audit_html = "".join(
        f"<li>{escape(a['created_at'])} {escape(a['actor'])} {escape(a['action'])} {escape(a['details_json'])}</li>" for a in runtime_audit
    )
    bound_adapter_names = {item['adapter_name'] for item in runtime_adapters}
    adapter_rows = "".join(
        f"""
        <tr>
          <td><b>{escape(item['adapter_name'])}</b></td>
          <td><pre style="font-size:11px;max-height:80px;overflow:auto">{escape(json.dumps(json.loads(item['config_json'] or '{}'), indent=2))}</pre></td>
          <td><pre style="font-size:11px;max-height:80px;overflow:auto">{escape(json.dumps(json.loads(item['policy_json'] or '{}'), indent=2))}</pre></td>
          <td>{'enabled' if item['enabled'] else 'disabled'}</td>
          <td>
            <form method="post" action="/api/runtimes/{runtime_id}/adapters/{item['adapter_name']}/unbind"
                  onsubmit="return confirm('Usunąć adapter?')">
              <button class="delete" style="font-size:11px;padding:4px 8px">Usuń</button>
            </form>
          </td>
        </tr>
        """
        for item in runtime_adapters
    )
    # Build dynamic adapter bind form — one hidden section per available adapter
    available_adapters = [a for a in store.rows("SELECT * FROM execution_adapters WHERE enabled=1 AND implemented=1 ORDER BY name")
                          if a['name'] not in bound_adapter_names]
    bind_adapter_forms = ""
    for adp in available_adapters:
        contract = adapter_contract(adp['name'])
        cfg_form = schema_form(contract.get('config_schema') or {}, f"adapter_config")
        pol_form = schema_form(contract.get('policy_schema') or {}, f"adapter_policy")
        bind_adapter_forms += f"""
        <div id="bind-form-{escape(adp['name'])}" class="bind-adapter-section" style="display:none;margin-top:12px">
          <p class="muted" style="font-size:13px">{escape(adp['description'])}</p>
          <h4>Config</h4>{cfg_form}
          <h4>Policy</h4>{pol_form}
        </div>
        """
    bind_adapter_options = "".join(
        f'<option value="{escape(a["name"])}">{escape(adapter_contract(a["name"]).get("display_name") or a["name"])}</option>'
        for a in available_adapters
    )
    bind_section = f"""
    <details style="margin-top:14px">
      <summary style="cursor:pointer;font-weight:700;color:var(--blue)">+ Dodaj adapter do tego runtime</summary>
      <form method="post" action="/api/runtimes/{runtime_id}/adapters" style="margin-top:12px">
        <label>Adapter
          <select name="adapter_name" id="bind-adapter-sel" onchange="
            document.querySelectorAll('.bind-adapter-section').forEach(function(el){{el.style.display='none'}});
            var v=this.value; if(v) document.getElementById('bind-form-'+v).style.display='';
          ">
            <option value="">— wybierz adapter —</option>
            {bind_adapter_options}
          </select>
        </label>
        {bind_adapter_forms}
        <div class="actions" style="margin-top:12px">
          <button>Dodaj adapter</button>
        </div>
      </form>
    </details>
    """ if available_adapters else '<p class="muted" style="margin-top:8px">Wszystkie dostępne adaptery są już dodane do tego runtime.</p>'
    target_rows = "".join(
        f"""
        <tr>
          <td>{escape(item['name'])}</td>
          <td>{escape(item['adapter_name'])}</td>
          <td><pre>{escape(json.dumps(json.loads(item['target_json'] or '{}'), indent=2))}</pre></td>
          <td><pre>{escape(json.dumps(json.loads(item['secret_refs_json'] or '{}'), indent=2))}</pre></td>
        </tr>
        """
        for item in targets
    )
    target_forms = "".join(
        f"""
        <details>
          <summary>Add target for {escape(item['adapter_name'])}</summary>
          <form method="post" action="/api/runtimes/{runtime_id}/targets">
            <input type="hidden" name="adapter_name" value="{escape(item['adapter_name'])}">
            {schema_form(adapter_contract(item['adapter_name']).get('target_schema') or {}, 'target')}
            <h4>Secret refs</h4>
            {schema_form(adapter_contract(item['adapter_name']).get('secret_schema') or {}, 'secret_refs')}
            <label>Tags JSON<textarea name="tags_json">[]</textarea></label>
            <button>Add Target</button>
          </form>
        </details>
        """
        for item in runtime_adapters
    )
    credential_rows = "".join(
        f"""
        <tr>
          <td>{escape(item['kind'])}</td>
          <td>{escape(item['name'])}</td>
          <td>{escape(item['env_name'] or '-')}</td>
          <td>{escape(item['mount_path'] or '-')}</td>
          <td>{escape(masked_secret(item['value']))}</td>
          <td>
            <form method="post" action="/api/runtimes/{runtime_id}/credentials/{item['id']}/delete">
              <button class="delete">Delete</button>
            </form>
          </td>
        </tr>
        """
        for item in credentials
    )
    return f"""
    <!doctype html><html><head><title>{escape(payload['name'])} — MCP Platform</title>{_FAVICON_TAG}<style>
    :root {{ --blue:#1f9bd1; --blue-dark:#157aa8; --line:#2b394a; --text:#dce7f3; --muted:#8ea2b8; --bg:#111820; --panel:#182230; --panel-2:#1d2a3a; --field:#101722; --danger:#d0343f; --warn:#b96521; }}
    body {{ font-family: Arial, system-ui, sans-serif; margin:0; background:var(--bg); color:var(--text); font-size:14px; }}
    header {{ background:#0f1722; color:var(--text); padding:18px 28px; border-bottom:1px solid var(--line); }}
    header h1 {{ margin:0 0 18px; font-size:28px; }}
    main {{ padding:24px; display:grid; gap:18px; }}
    section {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 1px 2px rgba(0,0,0,.25); }}
    input,select,textarea {{ width:100%; box-sizing:border-box; padding:9px; border:1px solid #34465b; border-radius:6px; background:var(--field); color:var(--text); }}
    textarea {{ min-height:84px; }}
    button {{ padding:8px 12px; border:0; border-radius:6px; background:var(--blue-dark); color:white; font-weight:600; cursor:pointer; }}
    button:hover {{ background:var(--blue); }}
    button.delete {{ background:var(--danger); }}
    button.stop {{ background:var(--warn); }}
    button.health, button.logs {{ background:#475569; }}
    .actions {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .actions form {{ display:inline; }}
    table {{ width:100%; border-collapse:collapse; }}
    th,td {{ text-align:left; border-bottom:1px solid var(--line); padding:10px; font-size:14px; }}
    th {{ color:#c6d7e8; background:#162232; text-transform:uppercase; font-size:12px; }}
    details {{ border:1px solid var(--line); border-radius:8px; padding:12px; background:var(--panel-2); }}
    summary {{ cursor:pointer; font-weight:700; margin-bottom:12px; }}
    .muted {{ color:var(--muted); font-size:14px; }}
    .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
    pre {{ background:#0b1420; color:#dce7f3; border:1px solid var(--line); padding:12px; border-radius:6px; overflow:auto; }}
    a {{ color:#5db7ee; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    @media (max-width:900px) {{ .grid {{ grid-template-columns:1fr; }} }}
    </style></head><body>
    <header><h1>{escape(payload['name'])}</h1><div>{escape(payload['status'])} | {escape(payload['runtime_class'])} | {escape(payload['endpoint_url'] or 'no endpoint yet')}</div></header>
    <main>
      <p><a href="/">← Powrót do dashboardu</a></p>
      {f"""
      <div style="background:linear-gradient(135deg,#0d2a1a,#0d1a2a);border:2px solid #2a8a4a;border-radius:12px;padding:20px 24px;display:flex;gap:20px;align-items:flex-start">
        <div style="font-size:36px">🎉</div>
        <div>
          <div style="font-size:18px;font-weight:800;color:white;margin-bottom:6px">Serwer MCP gotowy!</div>
          <div style="color:#a0c8b0;font-size:14px;margin-bottom:12px">Za chwilę uruchomi się automatycznie. Gdy status zmieni się na <b>running</b>, skopiuj adres endpointu i wklej do Continue lub OpenWebUI.</div>
          <div style="font-size:13px;color:#7ab0c0">
            💡 <b>Następny krok:</b> Znajdź pole <b>Endpoint</b> poniżej → skopiuj URL → wklej do konfiguracji AI jako <code style="background:#0d1a2a;padding:2px 6px;border-radius:4px">mcpServers</code>
          </div>
        </div>
      </div>
      """ if welcome else ""}

      {_tool_added_banner}

      <section>
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px;margin-bottom:14px">
          <div>
            <h2 style="margin:0 0 4px">Zarządzanie serwerem</h2>
            <div class="muted" style="font-size:12px">
              Kontener: <code id="rt-container">{escape(str(payload['container_name'] or '—'))}</code>
              &nbsp;·&nbsp; Endpoint: <code id="rt-endpoint" style="color:#3ab8f5">{escape(str(payload['endpoint_url'] or '—'))}</code>
              {"&nbsp;·&nbsp; <span style='color:#f47a80'>⚠️ " + escape(str(payload['last_error'])[:80]) + "</span>" if payload.get('last_error') else ""}
            </div>
          </div>
          <a href="/api/runtimes/{runtime_id}/export-package" style="padding:6px 12px;background:#263548;border-radius:6px;color:#dce7f3;font-size:12px;font-weight:600;white-space:nowrap">⬇ Export JSON</a>
        </div>
        {action_forms(runtime_id)}
      </section>

      <!-- TAB NAV -->
      <div style="display:flex;gap:4px;flex-wrap:wrap;border-bottom:2px solid var(--line);margin-bottom:20px;padding-bottom:0">
        <button class="rt-tab rt-tab-active" onclick="rtTab('connect')" id="tab-connect">🔌 Podłącz</button>
        <button class="rt-tab" onclick="rtTab('tools')" id="tab-tools">🔧 Narzędzia ({len(payload['tools'])})</button>
        <button class="rt-tab" onclick="rtTab('policy')" id="tab-policy">🔒 Polityka</button>
        <button class="rt-tab" onclick="rtTab('auth')" id="tab-auth">🔐 Auth {'<span style="background:#0a2a14;color:#22c55e;font-size:10px;padding:1px 5px;border-radius:999px;margin-left:4px">ON</span>' if payload.get('mcp_auth_token') else ''}</button>
        <button class="rt-tab" onclick="rtTab('creds')" id="tab-creds">🔑 Sekrety ({len(credentials)})</button>
        <button class="rt-tab" onclick="rtTab('adapters')" id="tab-adapters">⚙️ Silniki ({len(runtime_adapters)})</button>
        <button class="rt-tab" onclick="rtTab('logs')" id="tab-logs">📋 Logi</button>
        <button class="rt-tab" onclick="rtTab('audit')" id="tab-audit">🤖 Wywołania ({len(runtime_tool_calls)})</button>
        <button class="rt-tab" onclick="rtTab('test')" id="tab-test">🧪 Test</button>
        <button class="rt-tab" onclick="rtTab('clone')" id="tab-clone">🔁 Klonuj</button>
      </div>
<style>
.rt-tab{{background:none;border:none;border-bottom:3px solid transparent;padding:8px 14px;font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;margin-bottom:-2px;transition:.15s;border-radius:6px 6px 0 0}}
.rt-tab:hover{{color:var(--text);background:var(--panel-2)}}
.rt-tab.rt-tab-active{{color:white;border-bottom-color:var(--blue);background:var(--panel-2)}}
.rt-pane{{display:none}}.rt-pane.active{{display:block}}
</style>

      <!-- PANE: Podłącz -->
      <div class="rt-pane active" id="pane-connect">
      <details id="sec-connect" style="border-radius:12px;border-color:#1a4a6a;background:linear-gradient(135deg,#0d1e2e,#0a1a2a)" open>
        <summary style="font-size:16px;font-weight:800;padding:4px 0;color:#7dd3fc">
          🔌 Jak podłączyć do klienta AI?
          {(f'<code style="font-size:12px;background:#0b1520;padding:3px 10px;border-radius:5px;color:#3ab8f5;cursor:pointer;border:1px solid #1a3a50;margin-left:12px;font-weight:400" onclick="event.stopPropagation();navigator.clipboard.writeText(this.textContent).then(()=>{{this.style.background=\'#0d2a1a\';setTimeout(()=>this.style.background=\'\',1500)}})" title="Kliknij żeby skopiować">{escape(payload["endpoint_url"])}</code>'
            + f'<span style="margin-left:10px;font-size:11px;font-weight:400;color:var(--muted)">OpenWebUI: </span>'
            + f'<code style="font-size:12px;background:#060e06;padding:3px 10px;border-radius:5px;color:#4ac86a;cursor:pointer;border:1px solid #1a5a2a;font-weight:400" onclick="event.stopPropagation();navigator.clipboard.writeText(this.textContent).then(()=>{{this.style.background=\'#0d2a1a\';setTimeout(()=>this.style.background=\'\',1500)}})" title="Kliknij żeby skopiować">{escape(_base_url)}/openwebui</code>'
          ) if payload.get("endpoint_url") else '<span class="muted" style="font-size:13px;font-weight:400;margin-left:10px">— uruchom serwer żeby zobaczyć endpoint</span>'}
        </summary>
        <div style="margin-top:16px">
        {f"""
        <!-- OpenWebUI Tool Server -->
        <div style="background:#0b1e10;border:2px solid #1a5a2a;border-radius:10px;padding:14px;margin-bottom:12px">
          <div style="font-weight:800;color:white;margin-bottom:3px;font-size:13px">🌐 OpenWebUI <span style="color:#4ac86a;font-size:11px;font-weight:400">— Tool Server URL</span></div>
          <div class="muted" style="font-size:11px;margin-bottom:8px">Admin Panel → Settings → Tools → wklej poniższy URL</div>
          <pre style="font-size:12px;margin:0 0 6px;cursor:pointer;border-color:#1a5a2a;background:#060e06" onclick="copySnippet(this)" title="Kliknij żeby skopiować">{escape(_base_url)}/openwebui</pre>
          <div style="font-size:11px;color:#4ac86a;margin-bottom:10px">✅ OpenWebUI automatycznie doda <code>/openapi.json</code></div>
          <div style="border-top:1px solid #1a5a2a;padding-top:10px">
            <div style="font-weight:700;color:#a0d8b0;font-size:11px;margin-bottom:6px">📥 Albo importuj jako Python tool (Workspace → Narzędzia → Importuj z linku):</div>
            <div style="display:flex;align-items:center;gap:8px">
              <code style="font-size:11px;background:#060e06;border:1px solid #2a5a3a;border-radius:5px;padding:4px 8px;color:#5ce89a;flex:1;word-break:break-all;cursor:pointer"
                    onclick="navigator.clipboard.writeText(this.textContent).then(()=>{{this.style.background='#0d2a1a';setTimeout(()=>this.style.background='',1500)}})"
                    title="Kliknij żeby skopiować">{escape(_platform_base)}/api/runtimes/{escape(payload['id'])}/openwebui-tool.py</code>
              <a href="/api/runtimes/{escape(payload['id'])}/openwebui-tool.py" download
                 style="background:#1a5a2a;color:#5ce89a;border:1px solid #2a7a3a;border-radius:6px;padding:5px 10px;font-size:11px;font-weight:700;text-decoration:none;flex-shrink:0;white-space:nowrap">
                ⬇ Pobierz .py
              </a>
            </div>
          </div>
        </div>

        <!-- MCP JSON snippets: Streamable-HTTP + SSE -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div style="background:#0b1520;border:2px solid #1a5a6a;border-radius:10px;padding:14px">
            <div style="font-weight:800;color:#3ab8f5;margin-bottom:3px;font-size:14px">⚡ Streamable-HTTP <span style="font-size:11px;font-weight:400;color:#4ac86a">(zalecane)</span></div>
            <div class="muted" style="font-size:11px;margin-bottom:8px">Continue, Cline, Claude Code, Claude Desktop, OpenChamber i inne klienty MCP</div>
            <pre style="font-size:12px;margin:0;cursor:pointer;border-color:#1a5a6a" onclick="copySnippet(this)" title="Kliknij żeby skopiować">{{
  "mcpServers": {{
    "{escape(payload['name'].lower().replace(' ','-'))}": {{
      "url": "{escape(payload['endpoint_url'])}",
      "transport": "streamable-http"
    }}
  }}
}}</pre>
          </div>
          <div style="background:#0b1520;border:1px solid #3a3a50;border-radius:10px;padding:14px">
            <div style="font-weight:800;color:#b0a0d0;margin-bottom:3px;font-size:14px">📡 SSE</div>
            <div class="muted" style="font-size:11px;margin-bottom:8px">Starsze klienty lub gdy streamable-http nie działa</div>
            <pre style="font-size:12px;margin:0;cursor:pointer;border-color:#3a3a50" onclick="copySnippet(this)" title="Kliknij żeby skopiować">{{
  "mcpServers": {{
    "{escape(payload['name'].lower().replace(' ','-'))}": {{
      "url": "{escape(payload['endpoint_url'])}",
      "transport": "sse"
    }}
  }}
}}</pre>
          </div>
        </div>
        <details style="margin-top:10px;background:rgba(0,0,0,.2);border-color:#1a3a50">
          <summary style="font-size:12px;color:#7ab8d8">🔧 Pełny przykład .continue/config.json</summary>
          <pre style="font-size:11px;margin-top:8px;cursor:pointer" onclick="copySnippet(this)" title="Kliknij żeby skopiować">{{
  "models": [ ... ],
  "mcpServers": {{
    "{escape(payload['name'].lower().replace(' ','-'))}": {{
      "transport": "streamable-http",
      "url": "{escape(payload['endpoint_url'])}"
    }}
  }}
}}</pre>
        </details>
        """ if payload.get('endpoint_url') else """
        <div style="display:flex;align-items:center;gap:14px;padding:8px 0">
          <div style="font-size:28px">🔌</div>
          <div>
            <div style="font-weight:700;color:#607083;margin-bottom:3px">Endpoint pojawi się po uruchomieniu</div>
            <div class="muted" style="font-size:12px">Kliknij <b>Deploy</b> → status zmieni się na <b>running</b> → tutaj pojawi się config dla Continue i OpenWebUI</div>
          </div>
        </div>
        """}
        </div>
      </details>
      </div><!-- /pane-connect -->

      <!-- PANE: Narzędzia -->
      <div class="rt-pane" id="pane-tools">
      <details id="sec-tools" style="border-radius:12px" open>
        <summary style="font-size:16px;font-weight:800;padding:4px 0">🔧 Narzędzia (Tools) <span class="muted" style="font-size:13px;font-weight:400">— {len(payload['tools'])} zdefiniowanych</span></summary>
        <div style="margin-top:16px;display:grid;gap:14px">
          <section style="margin:0">
            <h2>Lista tools</h2>
            <table><tr><th>Nazwa</th><th>Silnik</th><th>Status</th><th>Ryzyko</th><th>Tryb</th><th></th>{'<th>Usuń</th>' if _is_admin else ''}</tr>{tools_rows}</table>
          </section>
          {tool_forms}
          <details style="border-radius:8px">
            <summary style="font-weight:700">➕ Dodaj nowe narzędzie</summary>
            <div style="margin-top:14px">
              <!-- Type selector -->
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
                <button type="button" id="nt-http-btn" onclick="ntSetType('http')"
                  style="background:#0d2a40;border:2px solid var(--blue);border-radius:8px;padding:12px;cursor:pointer;color:white;text-align:left">
                  <div style="font-size:16px;margin-bottom:4px">🌐</div>
                  <div style="font-weight:700;font-size:13px">HTTP Request</div>
                  <div style="color:var(--muted);font-size:11px">Wywołuje REST API — GitLab, Jira, własny serwis</div>
                </button>
                <button type="button" id="nt-shell-btn" onclick="ntSetType('shell')"
                  style="background:#0d1822;border:2px solid var(--line);border-radius:8px;padding:12px;cursor:pointer;color:white;text-align:left">
                  <div style="font-size:16px;margin-bottom:4px">⌨️</div>
                  <div style="font-weight:700;font-size:13px">Shell</div>
                  <div style="color:var(--muted);font-size:11px">Wykonuje komendy — psql, curl, oc, kubectl, własne CLI</div>
                </button>
              </div>

              <form method="post" action="/api/runtimes/{runtime_id}/tools" id="nt-form">
                <input type="hidden" name="execution_type" id="nt-exec-type" value="http_request">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
                  <div>
                    <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Nazwa toola</label>
                    <input name="name" placeholder="psql_query / call_api / get_pods" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                  </div>
                  <div>
                    <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Status</label>
                    <select name="enabled" style="width:100%;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                      <option value="true">✅ Aktywny</option>
                      <option value="false">⏸ Wyłączony</option>
                    </select>
                  </div>
                </div>

                <div style="margin-bottom:12px">
                  <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Opis (dla AI)</label>
                  <input name="description" placeholder="Wykonuje zapytanie SQL / Pobiera dane z API / Listuje zasoby" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                </div>

                <!-- HTTP fields -->
                <div id="nt-http-fields">
                  <div style="display:grid;grid-template-columns:1fr auto;gap:10px;margin-bottom:12px">
                    <div>
                      <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">URL endpointu</label>
                      <input name="url" placeholder="https://api.example.com/v1/search" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                    </div>
                    <div>
                      <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Metoda</label>
                      <select name="method" style="padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                        <option>POST</option><option>GET</option><option>PUT</option><option>DELETE</option>
                      </select>
                    </div>
                  </div>
                  <div>
                    <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Body JSON (parametry)</label>
                    <textarea name="body_json" rows="3" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:12px;font-family:monospace;resize:vertical">{{"query":"${{query}}"}}</textarea>
                    <div style="font-size:11px;color:var(--muted);margin-top:4px">Użyj <code>${{zmienna}}</code> dla parametrów które AI będzie podawać</div>
                  </div>
                  <div style="margin-top:10px">
                    <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Headers JSON (opcjonalnie)</label>
                    <textarea name="headers_json" rows="2" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:12px;font-family:monospace;resize:vertical" placeholder='{{"Authorization": "Bearer ${{API_TOKEN}}"}}'></textarea>
                    <div style="font-size:11px;color:var(--muted);margin-top:4px">Wartości <code>${{ZMIENNA}}</code> podstawiane z ENV kontenera (zakładka 🔑 Sekrety) — np. tokeny API</div>
                  </div>
                </div>

                <!-- Shell fields -->
                <div id="nt-shell-fields" style="display:none">
                  <div style="margin-bottom:12px">
                    <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Komenda</label>
                    <input id="nt-cmd" name="cmd" placeholder='psql -h ${{host}} -U ${{user}} -d ${{database}} -c "${{query}}"'
                      style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px;font-family:monospace">
                    <div style="font-size:11px;color:var(--muted);margin-top:4px"><code>${{zmienna}}</code> = jeden parametr &nbsp;|&nbsp; <code>${{*args}}</code> = wiele argumentów naraz</div>
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">
                    <div>
                      <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Timeout (s)</label>
                      <input name="timeout_seconds" type="number" value="30" min="5" max="300" style="width:100%;box-sizing:border-box;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                    </div>
                    <div>
                      <label style="font-size:12px;font-weight:700;color:#aac8e0;display:block;margin-bottom:4px">Ryzyko</label>
                      <select name="risk_level" style="width:100%;padding:9px 11px;background:#0d1420;border:1px solid #2a4a6a;border-radius:6px;color:var(--text);font-size:13px">
                        <option value="low">niski</option><option value="medium">średni</option><option value="high">wysoki</option>
                      </select>
                    </div>
                  </div>
                  <!-- Quick presets for shell -->
                  <div style="margin-bottom:10px">
                    <div style="font-size:11px;color:#7dd3fc;font-weight:700;margin-bottom:6px">⚡ Szybkie wzorce:</div>
                    <div style="display:flex;flex-wrap:wrap;gap:6px">
                      <button type="button" onclick="ntPreset('psql -h ${{host}} -U ${{user}} -d ${{database}} -c \"${{query}}\"','Wykonaj zapytanie SQL na bazie PostgreSQL')" class="preset-btn">🐘 psql query</button>
                      <button type="button" onclick="ntPreset('psql ${{*args}}','Wykonaj dowolne polecenie psql')" class="preset-btn">🐘 psql (pełny)</button>
                      <button type="button" onclick="ntPreset('curl -s ${{*args}}','Wykonaj dowolną komendę curl')" class="preset-btn">🌐 curl</button>
                      <button type="button" onclick="ntPreset('oc get ${{*args}}','Pobierz zasoby OpenShift — AI podaje zasób i flagi')" class="preset-btn">🔴 oc get</button>
                      <button type="button" onclick="ntPreset('kubectl get ${{*args}}','Pobierz zasoby Kubernetes — AI podaje zasób i flagi')" class="preset-btn">☸️ kubectl get</button>
                    </div>
                  </div>
                </div>

                <button type="submit" style="background:var(--blue);border:none;color:white;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;margin-top:8px">➕ Dodaj narzędzie</button>
              </form>
            </div>

<script>
function ntSetType(t) {{
  var isShell = t === 'shell';
  document.getElementById('nt-exec-type').value = isShell ? 'shell' : 'http_request';
  document.getElementById('nt-http-fields').style.display = isShell ? 'none' : 'block';
  document.getElementById('nt-shell-fields').style.display = isShell ? 'block' : 'none';
  document.getElementById('nt-http-btn').style.background = isShell ? '#0d1822' : '#0d2a40';
  document.getElementById('nt-http-btn').style.borderColor = isShell ? 'var(--line)' : 'var(--blue)';
  document.getElementById('nt-shell-btn').style.background = isShell ? '#0d2a40' : '#0d1822';
  document.getElementById('nt-shell-btn').style.borderColor = isShell ? 'var(--blue)' : 'var(--line)';
}}
function ntPreset(cmd, desc) {{
  document.getElementById('nt-cmd').value = cmd;
  var d = document.querySelector('#nt-form input[name="description"]');
  if (d && !d.value) d.value = desc;
}}
</script>
          </details>
        </div>
      </details>

      </div><!-- /pane-tools -->

      <!-- PANE: Silniki -->
      <div class="rt-pane" id="pane-adapters">
      <details id="sec-adapters" style="border-radius:12px" open>
        <summary style="font-size:16px;font-weight:800;padding:4px 0">⚙️ Silniki wykonania <span class="muted" style="font-size:13px;font-weight:400">— {len(runtime_adapters)} aktywnych</span></summary>
        <div style="margin-top:16px">
          <p class="muted"><b>shell</b> = komendy CLI &nbsp;|&nbsp; <b>http_request</b> = HTTP calls. Po redeploy runtime załaduje nową konfigurację.</p>
          {"<table><tr><th>Adapter</th><th>Konfiguracja</th><th>Polityka</th><th>Status</th><th></th></tr>" + adapter_rows + "</table>" if runtime_adapters else '<p class="muted">Brak adapterów — dodaj poniżej.</p>'}
          {bind_section}
        </div>
      </details>

      </div><!-- /pane-adapters -->

      <!-- PANE: Auth -->
      <div class="rt-pane" id="pane-auth">
        <h2>🔐 Bearer Token Authentication</h2>
        <p class="muted">Włącz uwierzytelnianie Bearer Token, aby wymagać klucza API od klientów AI (Claude Desktop, Cline, Continue). Po wygenerowaniu tokenu podaj go jako nagłówek <code>Authorization: Bearer &lt;token&gt;</code> lub <code>X-API-Key: &lt;token&gt;</code>.</p>

        {'<div style="background:#0a2a14;border:1px solid #155228;border-radius:10px;padding:20px;margin-bottom:20px">' if payload.get('mcp_auth_token') else '<div style="background:#1a1000;border:1px solid #3a2800;border-radius:10px;padding:20px;margin-bottom:20px">'}
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
            {'<span style="background:#155228;color:#4ade80;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">● AKTYWNE</span>' if payload.get('mcp_auth_token') else '<span style="background:#2a1800;color:#a06020;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700">○ WYŁĄCZONE</span>'}
            <span style="color:var(--muted);font-size:13px">{'Token wygenerowany — uwierzytelnianie włączone' if payload.get('mcp_auth_token') else 'Brak tokenu — serwer MCP jest otwarty dla wszystkich klientów'}</span>
          </div>
          {'<div style="display:flex;align-items:center;gap:8px;margin-bottom:14px"><code id="auth-token-display" data-secret="' + escape(payload.get("mcp_auth_token","")) + '" style="flex:1;padding:9px 12px;background:#0d1a0d;border:1px solid #1a5f2e;border-radius:6px;font-size:13px;color:#4ade80;letter-spacing:1px">••••••••••••••••••••••••</code><button onclick="toggleSecret(this.previousElementSibling)" title="Pokaż/ukryj" style="background:none;border:1px solid #1a5f2e;color:#4ade80;padding:7px 12px;border-radius:6px;cursor:pointer">👁</button><button onclick="navigator.clipboard.writeText(document.getElementById(\'auth-token-display\').dataset.secret).then(()=>{{let b=event.target;let t=b.textContent;b.textContent=\'✓\';setTimeout(()=>b.textContent=t,1500)}})" style="background:#155228;border:1px solid #1a5f2e;color:#4ade80;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:13px">Kopiuj</button></div>' if payload.get('mcp_auth_token') else ''}
          <div style="display:flex;gap:10px;flex-wrap:wrap">
            <form method="post" action="/api/runtimes/{runtime_id}/generate-mcp-token" style="display:inline">
              <button type="submit" style="background:#1f6b35;border:1px solid #27a147;color:#d1fae5;padding:8px 18px;border-radius:7px;cursor:pointer;font-size:13px">{'↻ Regeneruj token' if payload.get('mcp_auth_token') else '+ Generuj token'}</button>
            </form>
            {'<form method="post" action="/api/runtimes/' + runtime_id + '/revoke-mcp-token" style="display:inline" onsubmit="return confirm(\'Usunąć token? Klienci z obecnym tokenem stracą dostęp.\')"><button type="submit" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:8px 18px;border-radius:7px;cursor:pointer;font-size:13px">✕ Usuń token</button></form>' if payload.get('mcp_auth_token') else ''}
          </div>
        </div>

        {'<div style="background:#0d1117;border:1px solid #30363d;border-radius:10px;padding:20px"><h3 style="margin-top:0;font-size:15px;color:var(--text)">Konfiguracja klientów</h3><p class="muted" style="font-size:13px">Skopiuj poniższe konfiguracje do swojego klienta AI.</p><div style="margin-bottom:18px"><div style="font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.5px;margin-bottom:6px">CLAUDE DESKTOP (~/.claude.json)</div><pre style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin:0;overflow-x:auto;font-size:12px;color:#e6edf3">{\'{\'}\n  "mcpServers": {\'{\'}\n    "' + escape(payload.get("name","runtime")) + '": {\'{\'}\n      "type": "http",\n      "url": "' + escape(payload.get("endpoint_url") or "") + '/mcp",\n      "headers": {\'{\'}\n        "Authorization": "Bearer <TWÓJ_TOKEN>"\n      {\'}\'}\n    {\'}\'}\n  {\'}\'}\n{\'}\'}</pre></div><div style="margin-bottom:18px"><div style="font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.5px;margin-bottom:6px">CLINE / CONTINUE (settings.json)</div><pre style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin:0;overflow-x:auto;font-size:12px;color:#e6edf3">{\'{\'}\n  "mcp.servers": [{\'{\'}\n    "name": "' + escape(payload.get("name","runtime")) + '",\n    "transport": "streamable-http",\n    "url": "' + escape(payload.get("endpoint_url") or "") + '/mcp",\n    "headers": {\'{\'}\n      "Authorization": "Bearer <TWÓJ_TOKEN>"\n    {\'}\'}\n  {\'}\'}]\n{\'}\'}</pre></div><div><div style="font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.5px;margin-bottom:6px">CURL (testowanie)</div><pre style="background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;margin:0;overflow-x:auto;font-size:12px;color:#e6edf3">curl -H "Authorization: Bearer &lt;TWÓJ_TOKEN&gt;" ' + escape(payload.get("endpoint_url") or "") + '/health</pre></div></div>' if payload.get('mcp_auth_token') else ''}

      </div><!-- /pane-auth -->

      <!-- PANE: Sekrety -->
      <div class="rt-pane" id="pane-creds">

        <!-- ENV VARS section -->
        <h2>🔑 Zmienne środowiskowe (ENV)</h2>
        <p class="muted">Zmienne są wstrzykiwane do kontenera przy następnym deploy. Po zmianie kliknij <b>Redeploy</b>.</p>
        <div style="background:#1a1200;border:1px solid #3a2800;border-radius:8px;padding:14px;margin-bottom:16px">
          <div id="env-rows" style="display:grid;gap:6px;margin-bottom:10px">
            {"".join(f'''<div style="display:grid;grid-template-columns:160px 1fr auto auto;gap:8px;align-items:center">
              <code style="padding:6px 10px;background:#0d1000;border:1px solid #3a2800;border-radius:6px;font-size:12px;color:#d4a820">{escape(k)}</code>
              <span data-secret="{escape(v)}" style="padding:6px 10px;background:#0d1000;border:1px solid #3a2800;border-radius:6px;font-size:12px;color:var(--muted)">{'*' * min(len(v),8) if v else '(puste)'}</span>
              <button onclick="toggleSecret(this)" title="Pokaż/ukryj" style="background:none;border:1px solid #3a2800;color:var(--muted);padding:4px 8px;border-radius:6px;font-size:13px;cursor:pointer">👁</button>
              <button onclick="delEnvVar('{escape(runtime_id)}','{escape(k)}')" style="background:#3a1010;border:1px solid #6a2020;color:#f47a80;padding:4px 10px;border-radius:6px;font-size:11px;cursor:pointer">✕</button>
            </div>''' for k,v in _env_vars.items()) or '<p class="muted" style="margin:0">Brak zmiennych ENV — dodaj poniżej.</p>'}
          </div>
          <div style="display:grid;grid-template-columns:160px 1fr auto auto;gap:8px;align-items:center">
            <input id="new-env-key" placeholder="NAZWA_ZMIENNEJ" style="padding:7px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px;font-family:monospace">
            <input id="new-env-val" type="password" placeholder="wartość / token" style="padding:7px 10px;border:1px solid #3a2800;border-radius:6px;background:#0d1000;color:var(--text);font-size:12px">
            <button onclick="var i=document.getElementById('new-env-val');i.type=i.type==='password'?'text':'password'" title="Pokaż/ukryj" style="background:none;border:1px solid #3a2800;color:var(--muted);padding:7px 8px;border-radius:6px;font-size:13px;cursor:pointer">👁</button>
            <button onclick="addEnvVar('{escape(runtime_id)}')" style="background:#1a2800;border:1px solid #3a5000;color:#8ac840;padding:7px 12px;border-radius:6px;font-size:12px;cursor:pointer">+ Dodaj</button>
          </div>
        </div>

        <!-- Sekrety (pliki/montowania) -->
        <details style="border-radius:8px;border:1px solid var(--line);margin-top:8px">
          <summary style="font-size:14px;font-weight:700;padding:10px 14px;cursor:pointer">📁 Sekrety zaawansowane (pliki, mounty) — {len(credentials)} wpisów</summary>
          <div style="padding:14px">
            <p class="muted" style="font-size:12px"><b>env</b> = zmienna środowiskowa &nbsp;|&nbsp; <b>file</b> = plik montowany w kontenerze</p>
            <form method="post" action="/api/runtimes/{runtime_id}/credentials" style="margin-bottom:14px">
              <div class="grid">
                <label>Kind<select name="kind"><option value="env">env</option><option value="file">file</option></select></label>
                <label>Name<input name="name" placeholder="OC_TOKEN"></label>
                <label>Env name<input name="env_name" placeholder="opcjonalne"></label>
                <label>Mount path<input name="mount_path" placeholder="/config/secrets/kubeconfig"></label>
              </div>
              <label>Value<textarea name="value" placeholder="secret value, kubeconfig, token"></textarea></label>
              <button>Dodaj sekret</button>
            </form>
            <table><tr><th>Typ</th><th>Nazwa</th><th>Zmienna env</th><th>Ścieżka mount</th><th>Wartość</th><th>Akcja</th></tr>{credential_rows}</table>
          </div>
        </details>

      </div><!-- /pane-creds -->

      <!-- PANE: Polityka -->
      <div class="rt-pane" id="pane-policy">
      <details id="sec-policy" style="border-radius:12px" open>
        <summary style="font-size:16px;font-weight:800;padding:4px 0">🔒 Polityka bezpieczeństwa</summary>
        <div style="margin-top:16px;display:grid;gap:14px">
          <form id="shell-policy-form" method="post" action="/api/runtimes/{runtime_id}/policy/shell-preset">
            <div class="grid">
              <label>Dozwolone binarki<input name="allowed_binaries" value="{escape(' '.join(payload['policy'].get('allowed_binaries') or []))}" placeholder="oc kubectl jq"></label>
              <label>Zablokowane tokeny<input name="blocked_commands" value="{escape(' '.join(payload['policy'].get('blocked_commands') or []))}" placeholder="delete apply patch"></label>
              <label>Dozwolone prefixy (jeden/linię)<textarea name="allowed_command_prefixes" placeholder="oc get&#10;oc describe&#10;oc logs">{escape(chr(10).join(payload['policy'].get('allowed_command_prefixes') or []))}</textarea></label>
              <label>Zablokowane prefixy (jeden/linię)<textarea name="blocked_command_prefixes" placeholder="oc delete&#10;oc apply&#10;oc patch">{escape(chr(10).join(payload['policy'].get('blocked_command_prefixes') or []))}</textarea></label>
            </div>
          </form>
          <details style="border-radius:6px;border:1px solid var(--line);padding:14px;margin-top:4px" {'open' if payload['policy'].get('require_approval_for') else ''}>
            <summary style="font-size:14px;font-weight:700;cursor:pointer;color:var(--text)">✅ Zatwierdzenia (Human-in-the-Loop)</summary>
            <div style="margin-top:14px;display:grid;gap:12px">
              <p class="muted" style="font-size:12px;margin:0">Gdy AI wywoła narzędzie wymagające zatwierdzenia, narzędzie zwraca komunikat z prośbą o potwierdzenie. AI pyta użytkownika w chacie — po odpowiedzi "tak" wywołuje narzędzie ponownie z <code>__confirm="yes"</code>.</p>
              <label style="display:grid;gap:6px;font-size:13px;font-weight:600">
                Wymagaj zatwierdzenia dla
                <select name="require_approval_for" form="shell-policy-form" style="padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--text);font-size:13px">
                  <option value="" {"selected" if not payload["policy"].get("require_approval_for") else ""}>Wyłączone — brak zatwierdzeń</option>
                  <option value="auto" {"selected" if payload["policy"].get("require_approval_for") == "auto" else ""}>Auto — narzędzia write/destructive + słowa kluczowe (delete, create, apply…)</option>
                  <option value="destructive" {"selected" if payload["policy"].get("require_approval_for") == ["destructive"] or payload["policy"].get("require_approval_for") == "destructive" else ""}>Tylko destructive (delete, destroy, purge…)</option>
                  <option value="write_destructive" {"selected" if payload["policy"].get("require_approval_for") in [["write","destructive"],["destructive","write"]] else ""}>Write + Destructive (create, apply, delete…)</option>
                </select>
              </label>
              <label style="display:grid;gap:6px;font-size:13px;font-weight:600">
                Prefiksy wymagające zatwierdzenia (jeden/linię)
                <textarea name="require_approval_for_prefixes" form="shell-policy-form" placeholder="oc delete&#10;oc apply&#10;kubectl delete" style="min-height:80px;font-family:monospace;font-size:12px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--text)">{escape(chr(10).join(payload['policy'].get('require_approval_for_prefixes') or []))}</textarea>
                <span style="font-size:11px;color:var(--muted)">Komendy pasujące do tych prefiksów zatrzymają się i poczekają na zatwierdzenie. <strong>Nie dodawaj ich do Zablokowanych prefiksów</strong> — zatwierdzenie działa zamiast blokady.</span>
              </label>
              <label style="display:grid;gap:6px;font-size:13px;font-weight:600">
                Limit czasu zatwierdzenia (sekundy)
                <input type="number" name="approval_timeout_seconds" form="shell-policy-form" min="30" max="3600" value="{payload['policy'].get('approval_timeout_seconds', 300)}" style="padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--text);font-size:13px;width:140px">
              </label>
            </div>
          </details>
          <div style="padding:8px 0">
            <button type="submit" form="shell-policy-form" style="background:#1a7a3f;padding:9px 20px;font-size:13px;font-weight:700;border-radius:8px;border:none;color:#fff;cursor:pointer">💾 Zapisz politykę shell</button>
          </div>
          <details style="border-radius:6px">
            <summary style="font-size:13px;color:var(--muted)">Zaawansowane: edytuj policy JSON bezpośrednio</summary>
            <form method="post" action="/api/runtimes/{runtime_id}/policy/update" style="margin-top:10px">
              <label>Policy JSON<textarea name="policy_json">{escape(policy_json)}</textarea></label>
              <div class="actions"><button>Zapisz JSON</button></div>
            </form>
          </details>
          <p class="muted" style="font-size:12px">Po zmianie polityki kliknij <b>Reload Config</b> (nie trzeba redeploy).</p>
        </div>
      </details>

      </div><!-- /pane-policy -->

      <!-- PANE: Logi -->
      <div class="rt-pane" id="pane-logs">
        <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
          <h2 style="margin:0">📋 Logi kontenera</h2>
          <button onclick="doAct('{runtime_id}','logs')" style="background:#263548;border:1px solid #34465b;color:#c9d7e6;padding:6px 12px;border-radius:6px;font-size:12px;cursor:pointer">🔄 Odśwież logi</button>
        </div>
        <pre style="max-height:600px;overflow:auto;background:#060e18;border:1px solid #1a2e45;border-radius:8px;padding:14px;font-size:12px;line-height:1.7">{logs_html or '<span style="color:var(--muted)">Brak logów — uruchom serwer i odśwież.</span>'}</pre>
      </div>

      <!-- PANE: Wywołania AI -->
      <div class="rt-pane" id="pane-audit">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h2 style="margin:0">🤖 Wywołania narzędzi przez AI</h2>
          <span class="muted" style="font-size:12px">{len(runtime_tool_calls)} ostatnich wywołań</span>
        </div>
        <div id="tc-live-container" style="display:grid;gap:4px">
          {"".join(f'''<div style="display:grid;grid-template-columns:140px 150px 60px 65px 110px 120px 1fr;gap:8px;align-items:center;padding:8px 12px;background:var(--panel-2);border-radius:8px;border:1px solid var(--line);font-size:12px">
            <span style="color:var(--muted);white-space:nowrap">{escape(tc["created_at"][:19].replace("T"," "))}</span>
            <span style="font-weight:700;color:var(--blue)">{escape(tc["tool_name"])}</span>
            <span class="badge {'running' if tc['result_ok'] else 'failed'}" style="font-size:11px;padding:2px 7px">{"OK" if tc["result_ok"] else "ERR"}</span>
            <span style="color:var(--muted)">{tc["duration_ms"]} ms</span>
            <span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{escape(tc.get("caller_ip",""))}">{escape(tc.get("caller_ip","") or "—")}</span>
            <span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{escape(tc.get("model",""))}">{escape((tc.get("model","") or "—")[:18])}</span>
            <span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{escape(tc["arguments_json"])}">{escape(tc["arguments_json"][:120])}</span>
          </div>''' for tc in runtime_tool_calls) or '<p class="muted" id="tc-empty-msg">Brak wywołań — AI jeszcze nie używał tego serwera.</p>'}
        </div>
        <details style="margin-top:20px;border-top:1px solid var(--line);padding-top:12px">
          <summary style="font-size:12px;color:var(--muted);cursor:pointer">📋 Historia operacji adminów ({len(runtime_audit)})</summary>
          <div style="display:grid;gap:4px;margin-top:8px">
            {"".join(f'<div style="display:flex;gap:10px;align-items:center;padding:6px 10px;background:var(--bg);border-radius:6px;font-size:11px"><span style="color:var(--muted);white-space:nowrap">{escape(a["created_at"][:16].replace("T"," "))}</span><span class="badge" style="font-size:10px;padding:1px 6px">{escape(a["actor"])}</span><span>{escape(a["action"])}</span><span style="color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{escape(a["details_json"][:60])}</span></div>' for a in runtime_audit) or '<p class="muted">Brak.</p>'}
          </div>
        </details>
      </div>

      <!-- PANE: Test -->
      <div class="rt-pane" id="pane-test">
        <h2>🧪 Testuj tool</h2>

        {"" if payload["status"] == "running" else f'''
        <!-- Pre-deploy dry-run mode -->
        <div style="background:#1a1000;border:1px solid #3a2800;border-radius:8px;padding:12px 16px;margin-bottom:16px">
          <div style="font-weight:700;color:#d4a820;margin-bottom:6px">⚠️ Serwer nie jest uruchomiony (status: {escape(payload["status"])})</div>
          <p class="muted" style="font-size:12px;margin:0">Tryb <b>dry-run</b>: możesz sprawdzić konfigurację toola lub wywołać go przez własny endpoint.</p>
        </div>
        <details style="margin-bottom:16px;border:1px solid var(--line);border-radius:8px">
          <summary style="padding:10px 14px;cursor:pointer;font-weight:700;font-size:13px">🔍 Podgląd konfiguracji toolów</summary>
          <div style="padding:14px">
            {_tool_config_preview}
          </div>
        </details>
        <div style="background:#0a1520;border:1px solid var(--line);border-radius:8px;padding:14px;margin-bottom:16px">
          <div style="font-weight:700;font-size:13px;margin-bottom:8px">🌐 Test przez własny endpoint</div>
          <div class="grid" style="grid-template-columns:1fr auto;gap:8px;margin-bottom:8px">
            <input id="tt-ext-url" placeholder="http://localhost:8080/tools/my_tool" style="padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:#0d1420;color:var(--text);font-size:13px">
            <button onclick="runExtTest()" style="background:var(--blue);border:none;color:white;padding:8px 14px;border-radius:6px;font-size:13px;cursor:pointer">Test</button>
          </div>
          <label style="font-size:12px">Payload JSON<textarea id="tt-ext-body" style="width:100%;box-sizing:border-box;min-height:60px;font-family:monospace;font-size:12px;padding:8px;border:1px solid var(--line);border-radius:6px;background:#0d1420;color:var(--text)">{{}}</textarea></label>
        </div>
        '''}

        <p class="muted" style="font-size:12px">{'Wywołaj tool przez platformę — serwer odpowie bezpośrednio.' if payload['status'] == 'running' else 'Wdróż serwer żeby używać poniższego testera.'}</p>
        <div class="grid">
          <label>Tool<select id="tt-tool" {'disabled' if payload['status'] != 'running' else ''}>
            {"".join(f'<option value="{escape(t["name"])}">{escape(t["name"])}</option>' for t in payload["tools"] if t["enabled"])}
          </select></label>
          <label>Arguments JSON<textarea id="tt-args" style="min-height:56px;font-family:monospace;font-size:13px">{{}}</textarea></label>
        </div>
        <div class="actions" style="margin-top:8px">
          <button type="button" onclick="runTest()" {'disabled' if payload['status'] != 'running' else ''}>▶ Run Tool</button>
          <span class="muted" id="tt-status" style="margin-left:8px"></span>
        </div>
        <pre id="tt-result" style="min-height:48px;margin-top:10px"></pre>
      </div><!-- /pane-test -->

      <!-- PANE: Klonuj -->
      <div class="rt-pane" id="pane-clone">
        <h2>🔁 Klonuj serwer</h2>
        <p class="muted">Tworzy kopię z tymi samymi toolami, polityką i silnikami. Sekrety trzeba dodać osobno.</p>
        <form method="post" action="/api/runtimes/{runtime_id}/clone" class="inline" style="grid-template-columns:1fr auto">
          <label>Nowa nazwa<input name="name" placeholder="{escape(payload['name'])}-copy"></label>
          <button style="align-self:end">Klonuj</button>
        </form>
      </div><!-- /pane-clone -->

    </main>
    <script>
    (function() {{
      const TRANSITIONAL = new Set(['deploying','building','starting','stopping','restarting','deleting','checking','syncing_logs','draft']);
      const rid = '{escape(runtime_id)}';
      let currentStatus = '{escape(payload["status"])}';

      var _tcMaxId = {(runtime_tool_calls[0]["id"] if runtime_tool_calls else 0)};
      var _tcPollTimer = null;

      function renderToolCall(tc) {{
        var ok = tc.result_ok;
        var args = tc.arguments_json || '{{}}';
        if (args.length > 120) args = args.substring(0, 120) + '…';
        var ip = tc.caller_ip || '—';
        var model = (tc.model || '—').substring(0, 18);
        return '<div style="display:grid;grid-template-columns:140px 150px 60px 65px 110px 120px 1fr;gap:8px;align-items:center;padding:8px 12px;background:var(--panel-2);border-radius:8px;border:1px solid var(--line);font-size:12px">' +
          '<span style="color:var(--muted);white-space:nowrap">' + tc.created_at.substring(0,19).replace('T',' ') + '</span>' +
          '<span style="font-weight:700;color:var(--blue)">' + tc.tool_name + '</span>' +
          '<span class="badge ' + (ok?'running':'failed') + '" style="font-size:11px;padding:2px 7px">' + (ok?'OK':'ERR') + '</span>' +
          '<span style="color:var(--muted)">' + tc.duration_ms + ' ms</span>' +
          '<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + ip + '">' + ip + '</span>' +
          '<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + (tc.model||'') + '">' + model + '</span>' +
          '<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + args + '">' + args + '</span></div>';
      }}

      function pollToolCalls() {{
        fetch('/api/runtimes/' + rid + '/tool-calls?since_id=' + _tcMaxId)
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{
            if (d.calls && d.calls.length > 0) {{
              _tcMaxId = d.max_id;
              var container = document.getElementById('tc-live-container');
              if (container) {{
                var html = d.calls.map(renderToolCall).join('');
                container.insertAdjacentHTML('afterbegin', html);
                var tabEl = document.getElementById('tab-audit');
                if (tabEl) {{
                  var m = tabEl.textContent.match(/\((\d+)\)/);
                  var cur = m ? parseInt(m[1]) : 0;
                  tabEl.textContent = tabEl.textContent.replace(/\(\d+\)/, '(' + (cur + d.calls.length) + ')');
                }}
              }}
            }}
          }})
          .catch(function() {{}});
      }}

      window.rtTab = function(name) {{
        document.querySelectorAll('.rt-pane').forEach(function(p) {{ p.classList.remove('active'); }});
        document.querySelectorAll('.rt-tab').forEach(function(t) {{ t.classList.remove('rt-tab-active'); }});
        var pane = document.getElementById('pane-' + name);
        if (pane) pane.classList.add('active');
        var tab = document.getElementById('tab-' + name);
        if (tab) tab.classList.add('rt-tab-active');
        try {{ localStorage.setItem('rt_tab_' + rid, name); }} catch(e) {{}}
        // Start/stop live polling for Wywołania tab
        if (_tcPollTimer) {{ clearInterval(_tcPollTimer); _tcPollTimer = null; }}
        if (name === 'audit') {{
          _tcPollTimer = setInterval(pollToolCalls, 5000);
        }}
      }};
      var savedTab = 'connect';
      try {{ savedTab = localStorage.getItem('rt_tab_' + rid) || 'connect'; }} catch(e) {{}}
      var _urlParams = new URLSearchParams(window.location.search);
      if (_urlParams.get('tool_added')) savedTab = 'tools';
      else if (_urlParams.get('tab')) savedTab = _urlParams.get('tab');
      else if (window.location.hash === '#pane-tools') savedTab = 'tools';
      rtTab(savedTab);

      function poll() {{
        fetch('/api/runtimes/' + rid + '/status')
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{
            if (d.status !== currentStatus) {{ location.reload(); return; }}
            if (TRANSITIONAL.has(d.status)) setTimeout(poll, 2500);
          }})
          .catch(function() {{ if (TRANSITIONAL.has(currentStatus)) setTimeout(poll, 5000); }});
      }}
      if (TRANSITIONAL.has(currentStatus)) setTimeout(poll, 2000);

      window.runExtTest = function() {{
        var url = (document.getElementById('tt-ext-url')||{{}}).value;
        var body = (document.getElementById('tt-ext-body')||{{}}).value || '{{}}';
        var result = document.getElementById('tt-result');
        var status = document.getElementById('tt-status');
        if (!url) return;
        status.textContent = 'Calling…';
        result.textContent = '';
        try {{ body = JSON.parse(body); }} catch(e) {{ result.textContent = 'Invalid JSON'; return; }}
        fetch(url, {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(body) }})
          .then(function(r) {{ return r.json(); }})
          .then(function(d) {{ result.textContent = JSON.stringify(d, null, 2); status.textContent = '✅ OK'; }})
          .catch(function(e) {{ result.textContent = String(e); status.textContent = '❌ Error'; }});
      }};

      window.runTest = function() {{
        const name = document.getElementById('tt-tool').value;
        const args = document.getElementById('tt-args').value;
        const status = document.getElementById('tt-status');
        const result = document.getElementById('tt-result');
        if (!name) {{ result.textContent = 'Wybierz tool.'; return; }}
        status.textContent = 'Running…';
        result.textContent = '';
        fetch('/api/runtimes/' + rid + '/test-tool', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{tool_name: name, args_json: args}})
        }})
        .then(function(r) {{ return r.json(); }})
        .then(function(d) {{
          result.textContent = JSON.stringify(d, null, 2);
          status.textContent = d.ok ? 'OK (' + (d.status_code || 200) + ')' : 'Error';
        }})
        .catch(function(e) {{ result.textContent = String(e); status.textContent = ''; }});
      }};
      window.toggleSecret = function(btn) {{
        var span = btn.parentElement.querySelector('[data-secret]');
        if (!span) return;
        if (span.dataset.revealed === '1') {{
          span.textContent = '*'.repeat(Math.min(span.dataset.secret.length, 8)) || '(puste)';
          span.dataset.revealed = '0';
        }} else {{
          span.textContent = span.dataset.secret;
          span.dataset.revealed = '1';
        }}
      }};
      window.addEnvVar = function(rid) {{
        var k = document.getElementById('new-env-key').value.trim();
        var v = document.getElementById('new-env-val').value;
        if (!k) {{ document.getElementById('new-env-key').focus(); return; }}
        fetch('/api/runtimes/' + rid + '/env', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{key: k, value: v}})
        }}).then(function(r) {{ if(r.ok) location.reload(); else r.text().then(function(t){{ alert('Błąd: ' + t); }}); }});
      }};
      window.delEnvVar = function(rid, key) {{
        if (!confirm('Usunąć zmienną ' + key + '?')) return;
        fetch('/api/runtimes/' + rid + '/env/' + encodeURIComponent(key), {{method:'DELETE'}})
          .then(function(r) {{ if(r.ok) location.reload(); }});
      }};

      window.copySnippet = function(el) {{
        var text = el.textContent || el.innerText;
        navigator.clipboard.writeText(text).then(function() {{
          var orig = el.style.background;
          el.style.background = '#0d2a1a';
          el.title = '✅ Skopiowano!';
          setTimeout(function() {{ el.style.background = orig; el.title = 'Kliknij żeby skopiować'; }}, 1500);
        }});
      }};
    }})();
    </script>
    <script src="/api/lang.js"></script>
    </body></html>
    """


@app.post("/api/runtimes/{runtime_id}/tools")
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
        endpoint = (runtime.get("endpoint_url") or "").rstrip("/")
        base = endpoint[:-4] if endpoint.endswith("/mcp") else endpoint
        if base:
            import httpx as _httpx
            _httpx.post(f"{base}/reload", timeout=5)
    except Exception:
        pass
    return RedirectResponse(f"/runtimes/{runtime_id}?tool_added={execution_type}#pane-tools", status_code=303)


@app.post("/api/runtimes/{runtime_id}/adapters")
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


@app.post("/api/runtimes/{runtime_id}/adapters/{adapter_name}/unbind")
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


@app.post("/api/runtimes/{runtime_id}/targets")
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


@app.post("/api/runtimes/{runtime_id}/env")
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


@app.delete("/api/runtimes/{runtime_id}/env/{key}")
async def delete_env_var(runtime_id: str, key: str):
    runtime = store.one(sql.SELECT_RUNTIME_BY_ID, (runtime_id,))
    if not runtime:
        raise HTTPException(status_code=404)
    store.execute("DELETE FROM runtime_credentials WHERE runtime_id = ? AND name = ? AND kind = 'env'", (runtime_id, key))
    write_runtime_config(runtime_id)
    store.audit("admin", "delete_env_var", "runtime", runtime_id, {"key": key})
    return {"ok": True}


@app.post("/api/runtimes/{runtime_id}/credentials")
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


@app.post("/api/runtimes/{runtime_id}/credentials/{credential_id}/delete")
def delete_credential(runtime_id: str, credential_id: int):
    store.execute("DELETE FROM runtime_credentials WHERE id = ? AND runtime_id = ?", (credential_id, runtime_id))
    store.audit("admin", "delete_runtime_credential", "runtime", runtime_id, {"credential_id": credential_id})
    store.log(runtime_id, "Credential deleted")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@app.post("/api/runtimes/{runtime_id}/tools/{tool_id}/update")
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


@app.post("/api/runtimes/{runtime_id}/tools/{tool_id}/delete")
def delete_tool(runtime_id: str, tool_id: int):
    tool = store.one(sql.SELECT_TOOL_BY_ID_AND_RUNTIME, (tool_id, runtime_id))
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    store.execute("DELETE FROM tools WHERE id = ? AND runtime_id = ?", (tool_id, runtime_id))
    store.audit("admin", "delete_tool", "runtime", runtime_id, {"tool_id": tool_id, "tool": tool["name"]})
    store.log(runtime_id, f"Tool deleted: {tool['name']}")
    return RedirectResponse(f"/runtimes/{runtime_id}", status_code=303)


@app.post("/api/security/policy/{runtime_id}")
async def security_update_policy(runtime_id: str, request: Request):
    """Update policy from the Security page — form fields instead of raw JSON."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    current = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    try:
        policy: dict[str, Any] = json.loads(current["policy_json"] if current else "{}")
    except Exception:
        policy = {}
    policy["require_read_only"] = form.get("require_read_only") == "1"
    policy["block_write_tools"] = form.get("block_write_tools") == "1"
    policy["block_destructive_tools"] = form.get("block_destructive_tools") == "1"
    try:
        policy["timeout_seconds"] = max(5, min(300, int(form.get("timeout_seconds") or 30)))
    except (ValueError, TypeError):
        policy["timeout_seconds"] = 30
    try:
        max_kb = max(64, min(51200, int(form.get("max_response_kb") or 5120)))
        policy["max_response_bytes"] = max_kb * 1024
    except (ValueError, TypeError):
        pass
    bins_raw = str(form.get("allowed_binaries") or "").strip()
    policy["allowed_binaries"] = [b.strip() for b in re.split(r"[\s,]+", bins_raw) if b.strip()] if bins_raw else []
    store.execute(
        sql.UPSERT_POLICY_COMPACT,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "update_policy", "runtime", runtime_id, {"source": "security_page"})
    store.log(runtime_id, "Policy updated from Security page")
    return RedirectResponse("/security?ok=1", status_code=303)


@app.post("/api/security/policy/{runtime_id}/apply-template")
async def security_apply_template(runtime_id: str, request: Request):
    """Apply a named policy template to a runtime."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    tpl = str(form.get("template") or "strict")
    templates: dict[str, dict[str, Any]] = {
        "strict":   {"require_read_only": True,  "block_write_tools": True,  "block_destructive_tools": True,  "timeout_seconds": 30,  "max_payload_bytes": 262144,  "max_response_bytes": 5242880},
        "standard": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": True,  "timeout_seconds": 60,  "max_payload_bytes": 524288,  "max_response_bytes": 10485760},
        "dev":      {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": False, "timeout_seconds": 120, "max_payload_bytes": 1048576, "max_response_bytes": 20971520},
    }
    policy = templates.get(tpl, templates["strict"])
    # Preserve allowed_binaries from current policy
    current = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    if current:
        try:
            existing = json.loads(current["policy_json"])
            if existing.get("allowed_binaries"):
                policy["allowed_binaries"] = existing["allowed_binaries"]
        except Exception:
            pass
    store.execute(
        sql.UPSERT_POLICY_COMPACT,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "apply_policy_template", "runtime", runtime_id, {"template": tpl})
    store.log(runtime_id, f"Policy template '{tpl}' applied")
    return RedirectResponse("/security?ok=1", status_code=303)


@app.post("/api/runtimes/{runtime_id}/policy/update")
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


@app.post("/api/runtimes/{runtime_id}/policy/shell-preset")
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


@app.post("/api/runtimes/{runtime_id}/generate-mcp-token")
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
    # Re-write runtime-config.json so the running container picks up the new token on /reload
    try:
        write_runtime_config(runtime_id)
        enqueue_runtime_action(runtime_id, "reload")
    except Exception:
        pass
    user = _current_user.get() or {}
    store.audit(user.get("username", "admin"), "generate_mcp_token", "runtime", runtime_id, {})
    return RedirectResponse(return_to, status_code=303)


@app.post("/api/runtimes/{runtime_id}/revoke-mcp-token")
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
    try:
        write_runtime_config(runtime_id)
        enqueue_runtime_action(runtime_id, "reload")
    except Exception:
        pass
    user = _current_user.get() or {}
    store.audit(user.get("username", "admin"), "revoke_mcp_token", "runtime", runtime_id, {})
    return RedirectResponse(return_to, status_code=303)


@app.post("/api/runtimes/{runtime_id}/deploy")
async def deploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), "/runtimes")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "deploy")
    return RedirectResponse(return_to, status_code=303)


@app.post("/api/runtimes/{runtime_id}/redeploy")
async def redeploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "redeploy")
    return RedirectResponse(return_to, status_code=303)


@app.post("/api/runtimes/{runtime_id}/rebuild-redeploy")
async def rebuild_redeploy_runtime(runtime_id: str, request: Request):
    form = await request.form()
    return_to = safe_return_to(str(form.get("return_to") or ""), f"/runtimes/{runtime_id}")
    config_path = write_runtime_config(runtime_id)
    store.audit("admin", "config_written", "runtime", runtime_id, {"config_path": config_path})
    enqueue_runtime_action(runtime_id, "rebuild_redeploy")
    return RedirectResponse(return_to, status_code=303)


@app.post("/api/runtimes/{runtime_id}/{action}")
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


@app.get("/api/runtimes/{runtime_id}/status")
def runtime_status(runtime_id: str):
    row = store.one(
        "SELECT id, status, endpoint_url, container_name, last_error FROM runtimes WHERE id = ?",
        (runtime_id,),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Runtime not found")
    return dict(row)


@app.post("/api/runtimes/{runtime_id}/clone")
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


@app.get("/api/runtimes/{runtime_id}/export-package")
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


@app.post("/api/runtimes/{runtime_id}/test-tool")
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
    # Używamy nazwy kontenera (sieć Docker) zamiast publicznego URL
    container = runtime.get("container_name")
    if container:
        base_url = f"http://{container}:8080"
    elif runtime.get("endpoint_url"):
        base_url = runtime["endpoint_url"].replace("/mcp", "")
    else:
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


@app.get("/api/runtimes/{runtime_id}/openwebui-tool.py")
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


@app.get("/api/runtimes")
def list_runtimes():
    return store.rows(sql.SELECT_RUNTIMES_ACTIVE)


@app.get("/api/runtimes/{runtime_id}")
def get_runtime(runtime_id: str):
    return runtime_payload(runtime_id)


@app.get("/api/adapters")
def list_adapters():
    return store.rows(sql.SELECT_ADAPTERS_ALL)


@app.get("/api/runtime-classes")
def list_runtime_classes():
    return store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)


@app.get("/api/tool-packages")
def list_tool_packages():
    return store.rows("SELECT id, name, description, category, risk_level, source, enabled, created_at, updated_at FROM tool_packages ORDER BY category, name")


@app.get("/api/audit")
def audit_log():
    return store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")


@app.get("/api/logs")
def runtime_logs():
    return store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 200")


@app.post("/api/webhook-event")
async def webhook_event(request: Request):
    """Internal endpoint — operator posts runtime lifecycle events here."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    event = str(data.get("event") or "")
    runtime_id = str(data.get("runtime_id") or "")
    details = data.get("details") or {}
    if event and runtime_id:
        _dispatch_webhooks(event, runtime_id, details)
    return {"ok": True}


@app.get("/api/runtimes/{runtime_id}/tool-calls")
def get_tool_calls(runtime_id: str, since_id: int = 0):
    calls = store.rows(
        "SELECT * FROM tool_calls WHERE runtime_id = ? AND id > ? ORDER BY id DESC LIMIT 50",
        (runtime_id, since_id),
    )
    return {"calls": calls, "max_id": calls[0]["id"] if calls else since_id}


@app.post("/api/tool-call")
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


@app.get("/api/lang.js")
def lang_js():
    """Serves the PL→EN translation script for pages outside page_shell."""
    return Response(content=_cached_lang_js(), media_type="application/javascript")


@app.get("/api/health")
async def platform_health():
    runtimes = store.rows("SELECT id, endpoint_url FROM runtimes WHERE endpoint_url IS NOT NULL")
    checked = []
    async with httpx.AsyncClient(timeout=3) as client:
        for runtime in runtimes:
            endpoint = runtime["endpoint_url"].rstrip("/")
            try:
                response = await client.get(endpoint.replace("/mcp", "/health"))
                checked.append({"runtime_id": runtime["id"], "status": response.status_code})
            except Exception as exc:
                checked.append({"runtime_id": runtime["id"], "error": str(exc)})
    return {"status": "ok", "runtimes": checked}


# ──────────────────────────────────────────────────────────────────────────────
# APPROVAL SYSTEM — Human-in-the-Loop for write/destructive tool calls
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/api/approval-request")
async def create_approval_request(request: Request) -> JSONResponse:
    """Called by runtime containers (no auth). Creates a pending approval."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    req_id = str(payload.get("id") or _secrets_mod.token_urlsafe(16))
    now = store.now_iso()
    store.execute(
        """INSERT OR IGNORE INTO approval_requests
           (id, runtime_id, tool_name, arguments_json, mode, status, caller_ip, model, created_at)
           VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
        (
            req_id,
            str(payload.get("runtime_id", "")),
            str(payload.get("tool_name", "")),
            json.dumps(payload.get("arguments") or {}),
            str(payload.get("mode", "write")),
            str(payload.get("caller_ip", "")),
            str(payload.get("model", "")),
            now,
        ),
    )
    return JSONResponse({"id": req_id, "status": "pending"})


@app.get("/api/approval-status/{req_id}")
def get_approval_status(req_id: str) -> JSONResponse:
    """Polled by runtime containers (no auth). Returns current status."""
    row = store.one(
        "SELECT status, reject_reason FROM approval_requests WHERE id = ?", (req_id,)
    )
    if not row:
        return JSONResponse({"status": "not_found"}, status_code=404)
    return JSONResponse({"status": row["status"], "reject_reason": row.get("reject_reason")})


@app.post("/api/approval/{req_id}/approve")
async def approve_request(req_id: str) -> Any:
    user = _current_user.get() or {}
    now = store.now_iso()
    store.execute(
        "UPDATE approval_requests SET status='approved', decided_at=?, decided_by=? WHERE id=? AND status='pending'",
        (now, user.get("username", "admin"), req_id),
    )
    store.audit(user.get("username", "admin"), "approve_tool_call", "approval", req_id, {})
    return RedirectResponse("/approvals?ok=Zatwierdzone", status_code=303)


@app.post("/api/approval/{req_id}/reject")
async def reject_request(req_id: str, request: Request) -> Any:
    user = _current_user.get() or {}
    form = await request.form()
    reason = str(form.get("reason") or "Odrzucono przez administratora")
    now = store.now_iso()
    store.execute(
        """UPDATE approval_requests
           SET status='rejected', decided_at=?, decided_by=?, reject_reason=?
           WHERE id=? AND status='pending'""",
        (now, user.get("username", "admin"), reason, req_id),
    )
    store.audit(user.get("username", "admin"), "reject_tool_call", "approval", req_id, {"reason": reason})
    return RedirectResponse("/approvals?ok=Odrzucono", status_code=303)


@app.get("/approvals")
def approvals_page(request: Request) -> HTMLResponse:
    ok_msg = request.query_params.get("ok", "")
    pending = store.rows(
        """SELECT ar.*, r.name AS runtime_name
           FROM approval_requests ar
           LEFT JOIN runtimes r ON r.id = ar.runtime_id
           WHERE ar.status = 'pending'
           ORDER BY ar.created_at DESC"""
    )
    recent = store.rows(
        """SELECT ar.*, r.name AS runtime_name
           FROM approval_requests ar
           LEFT JOIN runtimes r ON r.id = ar.runtime_id
           WHERE ar.status != 'pending'
           ORDER BY ar.decided_at DESC LIMIT 50"""
    )

    def _mode_badge(mode: str) -> str:
        colors = {
            "destructive": ("#ff4444", "#3a0a0a"),
            "write": ("#f59e0b", "#2a1e08"),
            "read-only": ("#22c55e", "#0a2a14"),
        }
        fg, bg = colors.get(mode, ("#8ea2b8", "#1e2530"))
        return f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700">{escape(mode)}</span>'

    def _status_badge(status: str) -> str:
        colors = {
            "pending": ("#f59e0b", "#2a1e08"),
            "approved": ("#22c55e", "#0a2a14"),
            "rejected": ("#ff4444", "#3a0a0a"),
            "timeout": ("#8ea2b8", "#1e2530"),
        }
        fg, bg = colors.get(status, ("#8ea2b8", "#1e2530"))
        return f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700">{escape(status)}</span>'

    def _pending_card(row: dict) -> str:
        args = json.loads(row.get("arguments_json") or "{}")
        args_html = "".join(
            f'<tr><td style="color:#7a9db8;padding:3px 8px;font-size:12px">{escape(k)}</td>'
            f'<td style="padding:3px 8px;font-size:12px;word-break:break-all"><code style="color:#e2e8f0">{escape(str(v)[:500])}</code></td></tr>'
            for k, v in args.items()
        )
        caller_info = ""
        if row.get("caller_ip"):
            caller_info += f' | IP: <code>{escape(row["caller_ip"])}</code>'
        if row.get("model"):
            caller_info += f' | Model: <code>{escape(row["model"])}</code>'
        return f"""
        <div style="background:#0d1a2a;border:1px solid #1a3a5a;border-radius:10px;padding:18px;margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
            <span style="font-size:16px;font-weight:700;color:#e2e8f0">{escape(row["tool_name"])}</span>
            {_mode_badge(row.get("mode","write"))}
            <span style="color:#7a9db8;font-size:12px">Runtime: <b>{escape(row.get("runtime_name") or row["runtime_id"])}</b></span>
            <span style="color:#7a9db8;font-size:12px">{escape(row["created_at"])}{caller_info}</span>
          </div>
          <table style="width:100%;border-collapse:collapse;margin-bottom:14px">
            <tr><th style="text-align:left;padding:3px 8px;font-size:11px;color:#4a7a9b;border-bottom:1px solid #1a3a5a" colspan="2">Argumenty</th></tr>
            {args_html if args_html else '<tr><td colspan="2" style="color:#7a9db8;padding:3px 8px;font-size:12px">(brak)</td></tr>'}
          </table>
          <div style="display:flex;gap:10px;align-items:center">
            <form method="post" action="/api/approval/{escape(row['id'])}/approve" style="display:inline">
              <button style="background:#0a2a14;color:#22c55e;border:1px solid #22c55e;padding:7px 20px;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer">
                ✅ Zatwierdź
              </button>
            </form>
            <form method="post" action="/api/approval/{escape(row['id'])}/reject" style="display:inline;display:flex;gap:6px;align-items:center">
              <input name="reason" placeholder="Powód odrzucenia (opcjonalnie)" style="background:#0d1a2a;border:1px solid #1a3a5a;color:#e2e8f0;padding:6px 10px;border-radius:6px;font-size:13px;width:280px">
              <button style="background:#3a0a0a;color:#ff4444;border:1px solid #ff4444;padding:7px 20px;border-radius:6px;font-size:14px;font-weight:700;cursor:pointer">
                ❌ Odrzuć
              </button>
            </form>
          </div>
        </div>"""

    def _recent_row(row: dict) -> str:
        args = json.loads(row.get("arguments_json") or "{}")
        args_short = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(args.items())[:3])
        reason_cell = f'<td style="font-size:12px;color:#ff8888;padding:6px 10px">{escape(row.get("reject_reason") or "")}</td>' if row["status"] == "rejected" else '<td></td>'
        return f"""<tr>
          <td style="padding:6px 10px;font-size:13px"><code>{escape(row["tool_name"])}</code></td>
          <td style="padding:6px 10px">{_mode_badge(row.get("mode","write"))}</td>
          <td style="padding:6px 10px;font-size:12px;color:#7a9db8">{escape(row.get("runtime_name") or row["runtime_id"])}</td>
          <td style="padding:6px 10px">{_status_badge(row["status"])}</td>
          <td style="padding:6px 10px;font-size:12px;color:#7a9db8">{escape(row.get("decided_by") or "")}</td>
          <td style="padding:6px 10px;font-size:12px;color:#7a9db8">{escape(row.get("decided_at") or "")}</td>
          {reason_cell}
        </tr>"""

    pending_html = "".join(_pending_card(r) for r in pending) if pending else (
        '<div style="color:#4a7a9b;padding:24px;text-align:center">Brak oczekujących zatwierdzeń ✓</div>'
    )
    recent_html = "".join(_recent_row(r) for r in recent) if recent else (
        '<tr><td colspan="7" style="color:#4a7a9b;padding:16px;text-align:center">Brak historii</td></tr>'
    )
    ok_banner = f'<div style="background:#0a2a14;color:#22c55e;border:1px solid #22c55e;padding:10px 16px;border-radius:8px;margin-bottom:16px">{escape(ok_msg)}</div>' if ok_msg else ""

    body = f"""
    {ok_banner}
    <div style="max-width:900px;margin:0 auto">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
        <h2 style="margin:0;color:#e2e8f0">Zatwierdzenia wywołań narzędzi</h2>
        <span style="color:#4a7a9b;font-size:13px">Odświeżaj co 10s lub przeładuj stronę</span>
      </div>

      <div style="background:#0a1520;border:1px solid #1a3a5a;border-radius:8px;padding:14px 18px;margin-bottom:24px;font-size:13px;color:#8ea2b8">
        Narzędzia z trybem <b style="color:#f59e0b">write</b> lub <b style="color:#ff4444">destructive</b>
        mogą wymagać ręcznego zatwierdzenia zanim zostaną wykonane.
        Aktywuj to w ustawieniach polityki serwera: <code>"require_approval_for": ["write", "destructive"]</code>.
      </div>

      <h3 style="color:#f59e0b;margin:0 0 14px">⏳ Oczekujące ({len(pending)})</h3>
      {pending_html}

      <h3 style="color:#7a9db8;margin:24px 0 14px">📋 Historia (ostatnie 50)</h3>
      <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="border-bottom:1px solid #1a3a5a">
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Narzędzie</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Tryb</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Serwer</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Status</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Przez</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Kiedy</th>
              <th style="text-align:left;padding:6px 10px;font-size:12px;color:#4a7a9b">Powód</th>
            </tr>
          </thead>
          <tbody>{recent_html}</tbody>
        </table>
      </div>
    </div>
    <script>
      // Auto-refresh every 10 seconds when there are pending approvals
      if ({len(pending)} > 0) {{
        setTimeout(() => location.reload(), 10000);
      }}
    </script>
    """
    return HTMLResponse(page_shell("approvals", body))

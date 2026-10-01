"""Dashboard, docs, audit and logs pages, health and misc JSON endpoints."""
import httpx
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from .. import queries as sql
from .. import store
from ..rendering import render
from ..services import _runtime_internal_base, enabled_runtime_classes
from ..web import _cached_lang_js, render_page


router = APIRouter()


@router.get("/docs", response_class=HTMLResponse)
def docs_page() -> str:
    return render_page('docs', "pages/docs.html")


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    runtimes = store.rows(sql.SELECT_RUNTIMES_ACTIVE)
    audit = store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 8")
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 8")
    running = len([r for r in runtimes if r["status"] == "running"])
    failed = len([r for r in runtimes if r["status"] in {"failed", "unhealthy", "missing", "exited"} or (r.get("last_error") and r["status"] not in {"running", "deleted"})])
    external_count = len(store.rows("SELECT id FROM external_mcp_servers"))
    action_icons_dash = {"deploy_runtime": "🚀", "stop_runtime": "⏹️", "delete_runtime": "🗑️", "reload_runtime": "♻️",
                    "build_runtime_image": "🔨", "action_failed": "❌", "create_runtime": "➕", "health_refresh": "🩺"}
    level_colors_dash = {"error": "var(--danger)", "warn": "var(--warning)", "info": "var(--info)"}
    return render_page('dashboard', "pages/dashboard.html", action_icons_dash=action_icons_dash, audit=audit, external_count=external_count, failed=failed, level_colors_dash=level_colors_dash, logs=logs, running=running, runtimes=runtimes)


@router.get("/audit", response_class=HTMLResponse)
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
    unique_tc_runtimes = sorted({tc["runtime_id"] for tc in tool_calls_all})
    unique_tc_tools = sorted({tc["tool_name"] for tc in tool_calls_all})
    return render_page('audit', "pages/audit.html", action_icons=action_icons, audit=audit, tool_calls_all=tool_calls_all, unique_actions=unique_actions, unique_actors=unique_actors, unique_tc_runtimes=unique_tc_runtimes, unique_tc_tools=unique_tc_tools)


@router.get("/logs", response_class=HTMLResponse)
def logs_page() -> str:
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 300")
    level_colors = {"error": "var(--danger)", "warn": "var(--warning)", "warning": "var(--warning)", "info": "var(--info)", "debug": "var(--muted)"}
    level_bg = {"error": "var(--danger-bg)", "warn": "var(--warning-bg)", "warning": "var(--warning-bg)", "info": "var(--primary-bg)", "debug": "var(--surface-3)"}
    return render_page('logs', "pages/logs.html", level_bg=level_bg, level_colors=level_colors, logs=logs)


@router.get("/legacy-all", response_class=HTMLResponse)
def legacy_all() -> str:
    runtimes = store.rows("SELECT * FROM runtimes ORDER BY created_at DESC")
    runtime_classes = store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)
    adapters = store.rows(sql.SELECT_ADAPTERS_ALL)
    audit = store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20")
    logs = store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 30")
    return render("pages/legacy_all.html", adapters=adapters, audit=audit, logs=logs, runtime_classes=runtime_classes, runtimes=runtimes, runtime_class_names=[c["name"] for c in enabled_runtime_classes()])


@router.get("/api/platform-docs")
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


@router.get("/api/audit")
def audit_log():
    return store.rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")


@router.get("/api/logs")
def runtime_logs():
    return store.rows("SELECT * FROM runtime_logs ORDER BY id DESC LIMIT 200")


@router.get("/api/lang.js")
def lang_js():
    """Serves the PL→EN translation script for pages outside base.html."""
    return Response(content=_cached_lang_js(), media_type="application/javascript")


@router.get("/api/health")
async def platform_health():
    runtimes = store.rows(
        "SELECT id, endpoint_url, container_name FROM runtimes WHERE endpoint_url IS NOT NULL"
    )
    checked = []
    async with httpx.AsyncClient(timeout=3) as client:
        for runtime in runtimes:
            base = _runtime_internal_base(runtime)
            if not base:
                continue
            try:
                response = await client.get(f"{base}/health")
                checked.append({"runtime_id": runtime["id"], "status": response.status_code})
            except Exception as exc:
                checked.append({"runtime_id": runtime["id"], "error": str(exc)})
    return {"status": "ok", "runtimes": checked}

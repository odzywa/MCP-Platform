"""
OpenAPI-to-MCP runtime.

Reads an OpenAPI spec from a URL or file and auto-generates an MCP server
from it using FastMCP.from_openapi(). No tool definitions needed.

Required env vars (at least one spec source + backend URL):
  BACKEND_BASE_URL      - Base URL of the upstream HTTP service
  OPENAPI_SPEC_URL      - Full URL to openapi.json (default: BACKEND_BASE_URL/openapi.json)
  OPENAPI_SPEC_FILE     - Path to a local openapi.json file (overrides URL)

Optional:
  SERVER_NAME           - MCP server name (default: openapi-mcp)
  BACKEND_AUTH_TOKEN    - Bearer token for the upstream service
  BACKEND_AUTH_HEADER   - Auth header name (default: Authorization)
  BACKEND_AUTH_PREFIX   - Auth header value prefix (default: Bearer)
"""
import json
import os
import pathlib
import secrets
from typing import Any

import httpx
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

# ── Config ─────────────────────────────────────────────────────────────────────
_CONFIG_DIR = pathlib.Path(os.getenv("RUNTIME_CONFIG_DIR", "/config"))

BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL", "")
OPENAPI_SPEC_URL = os.getenv("OPENAPI_SPEC_URL", "")
OPENAPI_SPEC_FILE = os.getenv("OPENAPI_SPEC_FILE", "")
SERVER_NAME = os.getenv("SERVER_NAME", "openapi-mcp")
BACKEND_AUTH_TOKEN = os.getenv("BACKEND_AUTH_TOKEN", "")
BACKEND_AUTH_HEADER = os.getenv("BACKEND_AUTH_HEADER", "Authorization")
BACKEND_AUTH_PREFIX = os.getenv("BACKEND_AUTH_PREFIX", "Bearer")


def _runtime_auth_token() -> str:
    try:
        cfg = json.loads((_CONFIG_DIR / "runtime-config.json").read_text(encoding="utf-8"))
        return cfg.get("auth_token", "")
    except Exception:
        return ""


def _auth_headers() -> dict[str, str]:
    if not BACKEND_AUTH_TOKEN:
        return {}
    prefix = BACKEND_AUTH_PREFIX.strip()
    value = f"{prefix} {BACKEND_AUTH_TOKEN}".strip() if prefix else BACKEND_AUTH_TOKEN
    return {BACKEND_AUTH_HEADER: value}


def _load_spec() -> dict:
    if OPENAPI_SPEC_FILE:
        with open(OPENAPI_SPEC_FILE) as f:
            return json.load(f)
    if OPENAPI_SPEC_URL:
        spec_url = OPENAPI_SPEC_URL
    else:
        # Prefer /openwebui/openapi.json (platform runtimes — user-defined tools only).
        # Fall back to /openapi.json for standard external REST APIs.
        base = BACKEND_BASE_URL.rstrip("/")
        preferred = f"{base}/openwebui/openapi.json"
        try:
            r = httpx.get(preferred, headers=_auth_headers(), follow_redirects=True, timeout=10.0)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        spec_url = f"{base}/openapi.json"
    resp = httpx.get(spec_url, headers=_auth_headers(), follow_redirects=True, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


def _base_url(spec: dict) -> str:
    if BACKEND_BASE_URL:
        return BACKEND_BASE_URL
    for server in spec.get("servers") or []:
        url = server.get("url", "")
        if url.startswith("http"):
            return url.rstrip("/")
    return ""


def _tools_from_spec(spec: dict) -> list[dict[str, Any]]:
    """Extract tool metadata from OpenAPI spec for /tools and /openwebui endpoints."""
    tools: list[dict[str, Any]] = []
    for path, path_item in (spec.get("paths") or {}).items():
        for method, op in path_item.items():
            if method.upper() not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
                continue
            if not isinstance(op, dict):
                continue
            raw_id = op.get("operationId") or f"{method}_{path}"
            op_id = raw_id.replace("/", "_").replace("{", "").replace("}", "")
            description = op.get("summary") or op.get("description") or ""
            schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
            for param in op.get("parameters") or []:
                pname = param.get("name", "")
                pschema = param.get("schema") or {"type": "string"}
                schema["properties"][pname] = {**pschema, "description": param.get("description", "")}
                if param.get("required"):
                    schema.setdefault("required", []).append(pname)
            body = op.get("requestBody") or {}
            json_schema = ((body.get("content") or {}).get("application/json") or {}).get("schema") or {}
            if json_schema:
                schema = json_schema
            tools.append({"name": op_id, "description": description, "inputSchema": schema})
    return tools


# ── Bootstrap (at import time so failures surface before uvicorn accepts traffic) ─
_spec = _load_spec()
_base = _base_url(_spec)
_tools = _tools_from_spec(_spec)

_http_client = httpx.AsyncClient(base_url=_base, headers=_auth_headers(), timeout=30.0)
mcp = FastMCP.from_openapi(openapi_spec=_spec, client=_http_client, name=SERVER_NAME)
_mcp_asgi = mcp.http_app(path="/mcp")


# ── Route handlers ──────────────────────────────────────────────────────────────
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "name": SERVER_NAME, "tools": len(_tools), "backend": _base})


async def list_tools(request: Request) -> JSONResponse:
    return JSONResponse({"tools": _tools})


async def openwebui_openapi(request: Request) -> JSONResponse:
    paths: dict[str, Any] = {}
    for tool in _tools:
        paths[f"/tools/{tool['name']}"] = {
            "post": {
                "operationId": tool["name"],
                "summary": tool["description"],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": tool["inputSchema"]}},
                },
                "responses": {"200": {"description": "Result"}},
            }
        }
    return JSONResponse({
        "openapi": "3.0.3",
        "info": {"title": SERVER_NAME, "version": "0.1.0"},
        "servers": [{"url": "/"}],
        "paths": paths,
    })


async def mcp_info(request: Request) -> JSONResponse:
    return JSONResponse({
        "name": SERVER_NAME,
        "transport": "streamable-http",
        "endpoint": "/mcp",
        "tools": len(_tools),
        "backend": _base,
    })


class _McpAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in ("/health",):
            return await call_next(request)
        token = _runtime_auth_token()
        if not token:
            return await call_next(request)
        auth = request.headers.get("Authorization", "")
        api_key = request.headers.get("X-API-Key", "")
        bearer_ok = auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], token)
        key_ok = bool(api_key) and secrets.compare_digest(api_key, token)
        if bearer_ok or key_ok:
            return await call_next(request)
        return JSONResponse({"error": "Unauthorized"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})


# ── App ─────────────────────────────────────────────────────────────────────────
# Named routes are matched first; Mount("/") catches everything else (including /mcp).
app = Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", list_tools),
        Route("/openwebui/openapi.json", openwebui_openapi),
        Route("/openwebui", openwebui_openapi),
        Route("/mcp", mcp_info, methods=["GET"]),
        Mount("/", _mcp_asgi),
    ],
    lifespan=_mcp_asgi.lifespan,
)
app.add_middleware(_McpAuthMiddleware)

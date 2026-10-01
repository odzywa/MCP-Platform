"""External MCP servers registered and probed by the platform."""
import json
import uuid
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import store
from ..services import _is_safe_fetch_url
from ..strings import slug
from ..web import render_page


router = APIRouter()


async def _probe_mcp_server(url: str, auth_type: str, auth_token: str) -> dict[str, Any]:
    """Probe an external MCP server — tries /health, /tools REST, then MCP protocol."""
    if not _is_safe_fetch_url(url):
        return {"status": "error", "tools": [], "error": "URL not allowed: private/internal addresses are blocked"}
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


@router.get("/external-mcp", response_class=HTMLResponse)
def external_mcp_page(error: str = "", ok: str = "") -> str:
    servers = store.rows("SELECT * FROM external_mcp_servers ORDER BY name")

    return render_page('external', 'pages/external_mcp.html', error=error, ok=ok, servers=servers)


@router.post("/api/external-mcp")
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


@router.post("/api/external-mcp/{server_id}/check")
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


@router.post("/api/external-mcp/{server_id}/delete")
def delete_external_mcp(server_id: str):
    server = store.one("SELECT name FROM external_mcp_servers WHERE id = ?", (server_id,))
    store.execute("DELETE FROM external_mcp_servers WHERE id = ?", (server_id,))
    store.audit("admin", "delete_external_mcp", "external_mcp", server_id,
                {"name": server["name"] if server else ""})
    return RedirectResponse("/external-mcp", status_code=303)

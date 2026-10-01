"""Tool Packages: catalog page, generator, import/edit/toggle/delete, create runtime from package."""
import json
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..auth import current_user
from ..services import _is_safe_fetch_url, create_runtime_from_package, install_tool_package
from ..web import render_page


router = APIRouter()


@router.get("/tool-packages/generate", response_class=HTMLResponse)
def package_generator_page(error: str = "") -> str:
    images = [r["runtime_image"] for r in store.rows(
        "SELECT DISTINCT runtime_image FROM runtime_classes WHERE runtime_image != '' ORDER BY runtime_image")]

    return render_page('packages', "pages/package_generator.html", error=error, images=images)


@router.get("/tool-packages", response_class=HTMLResponse)
def tool_packages_page(error: str = "") -> str:
    packages = store.rows("SELECT * FROM tool_packages ORDER BY category, name")
    _cu = current_user.get()
    is_admin = (_cu or {}).get("role") == "admin"
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
    runtimes_deployed = store.rows("SELECT id, name FROM runtimes")
    runtime_names = {r["id"]: r["name"] for r in runtimes_deployed}
    cat_icons_big = {"openshift": "☁️", "kubernetes": "⎈", "database": "🗄️", "http": "🌐",
                     "shell": "🖥️", "ai": "🤖", "other": "📦", "monitoring": "📊", "security": "🔒"}
    deploy_packages = [pkg for pkg in packages if pkg.get("enabled", 1)]
    return render_page('packages', 'pages/tool_packages.html', cat_icons_big=cat_icons_big, deploy_packages=deploy_packages, error=error, example_package=example_package, is_admin=is_admin, packages=packages, runtime_names=runtime_names)


@router.post("/api/tool-packages/import")
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


@router.post("/api/tool-packages/{package_id}/create-runtime")
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


@router.get("/tool-packages/{package_id}/edit", response_class=HTMLResponse)
def edit_package_page(package_id: str, error: str = "") -> str:
    package = store.one(sql.SELECT_TOOL_PACKAGE_BY_ID, (package_id,))
    if not package:
        raise HTTPException(status_code=404, detail="Nie znaleziono paczki")
    pkg_json = json.dumps(json.loads(package["package_json"]), indent=2, ensure_ascii=False)
    return render_page('packages', "pages/edit_package.html", error=error, package=package, package_id=package_id, pkg_json=pkg_json)


@router.post("/api/tool-packages/{package_id}/update")
async def update_tool_package(package_id: str, request: Request):
    user = current_user.get()
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


@router.post("/api/tool-packages/{package_id}/toggle")
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


@router.post("/api/tool-packages/{package_id}/delete")
def delete_tool_package(package_id: str):
    user = current_user.get()
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete packages")
    if not store.one(sql.SELECT_TOOL_PACKAGE_ID_BY_ID, (package_id,)):
        raise HTTPException(status_code=404, detail="Tool package not found")
    store.execute("DELETE FROM tool_packages WHERE id = ?", (package_id,))
    store.audit(user.get("username","admin"), "delete_tool_package", "tool_package", package_id, {})
    return RedirectResponse("/tool-packages", status_code=303)


@router.get("/api/tool-packages")
def list_tool_packages():
    return store.rows("SELECT id, name, description, category, risk_level, source, enabled, created_at, updated_at FROM tool_packages ORDER BY category, name")

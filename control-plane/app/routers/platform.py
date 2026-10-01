"""Platform catalog: execution adapters, runtime classes and runtime image builds."""
import json
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..auth import current_user
from ..strings import slug
from ..web import render_page


router = APIRouter()


@router.get("/tool-types", response_class=HTMLResponse)
@router.get("/adapters", response_class=HTMLResponse)
def adapters_page(implemented: int | None = None, error: str = "") -> str:
    all_adapters = store.rows(sql.SELECT_ADAPTERS_ALL)
    adapters = [adapter for adapter in all_adapters if adapter["implemented"]] if implemented == 1 else all_adapters
    adapter_icons = {"http_request": "🌐", "shell": "⌨️", "ssh": "🔐", "python": "🐍", "openshift": "🔴", "workflow": "🔗"}
    return render_page(
        "adapters",
        "pages/adapters.html",
        active=[a for a in adapters if a["implemented"]],
        planned=[a for a in adapters if not a["implemented"]],
        adapter_icons=adapter_icons,
        error=error,
    )


@router.get("/runtime-classes", response_class=HTMLResponse)
def runtime_classes_page(error: str = "", ok: str = "") -> str:
    runtime_classes = store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)
    all_images = list({r["runtime_image"] for r in runtime_classes if r["runtime_image"]})
    implemented_adapters = store.rows("SELECT name FROM execution_adapters WHERE implemented=1 AND enabled=1 ORDER BY name")
    return render_page('classes', "pages/runtime_classes.html", all_images=all_images, error=error, implemented_adapters=implemented_adapters, ok=ok, runtime_classes=runtime_classes)


@router.post("/api/runtime-classes/{class_name}/update")
async def update_runtime_class(class_name: str, request: Request):
    user = current_user.get()
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


@router.post("/api/runtime-classes/{class_name}/delete")
async def delete_runtime_class(class_name: str, request: Request):
    user = current_user.get()
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    store.execute("DELETE FROM runtime_classes WHERE name = ?", (class_name,))
    store.audit(user["username"], "delete_runtime_class", "runtime_class", class_name)
    return RedirectResponse("/runtime-classes", status_code=303)


@router.post("/api/runtime-classes")
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


@router.post("/api/runtime-classes/{class_name}/toggle")
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


@router.post("/api/adapters")
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
    store.audit("admin", "create_adapter", "adapter", name, {
        "description": description, "adapter_type": adapter_type, "risk_level": risk_level,
        "runtime_image": runtime_image, "mode": mode, "implemented": implemented,
    })
    return RedirectResponse("/tool-types", status_code=303)


@router.post("/api/adapters/{adapter_name}/update")
async def update_adapter(adapter_name: str, request: Request):
    user = current_user.get()
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


@router.post("/api/adapters/{adapter_name}/delete")
async def delete_adapter(adapter_name: str, request: Request):
    user = current_user.get()
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403)
    store.execute("DELETE FROM execution_adapters WHERE name = ?", (adapter_name,))
    store.audit(user["username"], "delete_adapter", "adapter", adapter_name)
    return RedirectResponse("/tool-types", status_code=303)


@router.post("/api/adapters/{adapter_name}/toggle")
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


@router.get("/api/adapters")
def list_adapters():
    return store.rows(sql.SELECT_ADAPTERS_ALL)


@router.get("/api/runtime-classes")
def list_runtime_classes():
    return store.rows(sql.SELECT_RUNTIME_CLASSES_ALL)

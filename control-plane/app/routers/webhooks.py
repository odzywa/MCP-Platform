"""Outgoing webhook configuration and incoming webhook events."""
import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import store
from ..services import _dispatch_webhooks
from ..web import render_page


router = APIRouter()


@router.get("/webhooks", response_class=HTMLResponse)
def webhooks_page(ok: str = "") -> str:
    webhooks = store.rows("SELECT * FROM webhooks ORDER BY id DESC")
    runtimes = store.rows("SELECT id, name FROM runtimes WHERE status != 'deleted'")
    return render_page('webhooks', "pages/webhooks.html", ok=ok, runtimes=runtimes, webhooks=webhooks)


@router.post("/api/webhooks")
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
    return RedirectResponse("/webhooks?ok=Webhook+dodany", status_code=303)


@router.post("/api/webhooks/{webhook_id}/delete")
async def delete_webhook(webhook_id: int):
    store.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    return RedirectResponse("/webhooks?ok=Usunięto", status_code=303)


@router.post("/api/webhook-event")
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

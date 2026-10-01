"""Human approval of tool calls (requests from runtimes, decisions in UI)."""
import json
import secrets as _secrets_mod
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import store
from ..auth import current_user
from ..web import render_page


router = APIRouter()


@router.post("/api/approval-request")
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


@router.get("/api/approval-status/{req_id}")
def get_approval_status(req_id: str) -> JSONResponse:
    """Polled by runtime containers (no auth). Returns current status."""
    row = store.one(
        "SELECT status, reject_reason, decided_at FROM approval_requests WHERE id = ?", (req_id,)
    )
    if not row:
        return JSONResponse({"status": "not_found"}, status_code=404)
    # decided_at pozwala runtime'owi odrzucić zatwierdzenie sprzed godzin —
    # bez tego jedna zgoda działałaby bezterminowo dla tej samej komendy.
    return JSONResponse({
        "status": row["status"],
        "reject_reason": row.get("reject_reason"),
        "decided_at": row.get("decided_at"),
    })


@router.post("/api/approval/{req_id}/approve")
async def approve_request(req_id: str) -> Any:
    user = current_user.get() or {}
    now = store.now_iso()
    store.execute(
        "UPDATE approval_requests SET status='approved', decided_at=?, decided_by=? WHERE id=? AND status='pending'",
        (now, user.get("username", "admin"), req_id),
    )
    store.audit(user.get("username", "admin"), "approve_tool_call", "approval", req_id, {})
    return RedirectResponse("/approvals?ok=Zatwierdzone", status_code=303)


@router.post("/api/approval/{req_id}/reject")
async def reject_request(req_id: str, request: Request) -> Any:
    user = current_user.get() or {}
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


@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(ok: str = "") -> str:
    pending = store.rows(
        "SELECT * FROM approval_requests WHERE status='pending' ORDER BY created_at DESC"
    )
    decided = store.rows(
        "SELECT * FROM approval_requests WHERE status!='pending' ORDER BY decided_at DESC LIMIT 30"
    )
    names = {r["id"]: r["name"] for r in store.rows("SELECT id, name FROM runtimes")}

    def _cmd_preview(raw: str) -> str:
        """Runtime dokłada do argumentów _command z podglądem komendy."""
        try:
            args = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return ""
        return str(args.get("_command") or "") if isinstance(args, dict) else ""

    # Wywołujący jest zablokowany do approval_timeout_seconds, więc strona musi
    # sama się odświeżać — inaczej operator nie zobaczy żądania na czas.

    return render_page('approvals', 'pages/approvals.html', _cmd_preview=_cmd_preview, decided=decided, names=names, ok=ok, pending=pending)

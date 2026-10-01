"""Human approval of tool calls.

A runtime that hits an operation requiring approval registers a request here and shows the
user a link. The decision is made on that page by a logged-in user — never by the model:
the decision endpoint is outside /api/ (the service API token does not work there), needs a
session cookie and a POST, and an approval can be used for exactly one execution.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import store, totp
from ..auth import current_user
from ..web import render_page


router = APIRouter()

# Public address of the control plane, used to build approval links shown in the chat.
PUBLIC_URL = os.getenv("MCP_PLATFORM_PUBLIC_URL", "http://localhost:18100").rstrip("/")
# A request nobody decided on within this time can no longer be approved.
PENDING_MAX_AGE_SECONDS = 3600
_ID_RE = re.compile(r"[a-f0-9]{16,64}")
# Guessing protection for one-time codes: after this many wrong codes for a runtime,
# code approval is locked for the window (the approval link keeps working).
CODE_MAX_FAILURES = 5
CODE_LOCK_SECONDS = 900
_APPROVER_ROLES = ("admin", "read_write")


def approval_url(req_id: str) -> str:
    return f"{PUBLIC_URL}/approve/{req_id}"


def _age_seconds(iso: str | None) -> float:
    try:
        ts = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
    except ValueError:
        return float("inf")
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds()


def _code_approvers() -> list[dict[str, Any]]:
    """Active users who can approve and have an authenticator app configured."""
    return store.rows(
        "SELECT id, username, totp_secret, totp_last_step FROM users "
        "WHERE active=1 AND totp_enabled=1 AND totp_secret != '' AND role IN (?, ?)",
        _APPROVER_ROLES,
    )


def _recent_code_failures(runtime_id: str) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=CODE_LOCK_SECONDS)).isoformat()
    row = store.one(
        "SELECT COUNT(*) AS n FROM approval_code_failures WHERE runtime_id=? AND created_at > ?", (runtime_id, cutoff)
    )
    return int(row["n"]) if row else 0


def _request(req_id: str) -> dict[str, Any]:
    row = store.one("SELECT * FROM approval_requests WHERE id = ?", (req_id,)) if _ID_RE.fullmatch(req_id) else None
    if not row:
        raise HTTPException(status_code=404, detail="Nie ma takiej prośby o zatwierdzenie")
    return row


# ── Called by runtime containers (no cookie; ids are unguessable hashes) ───────

@router.post("/api/approval-request")
async def create_approval_request(request: Request) -> JSONResponse:
    """Register (or re-open) an approval request. Returns the link the user has to open."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    req_id = str(payload.get("id") or "")
    runtime_id = str(payload.get("runtime_id") or "")
    if not _ID_RE.fullmatch(req_id):
        raise HTTPException(status_code=400, detail="invalid id")
    if not store.one("SELECT id FROM runtimes WHERE id = ? AND status != 'deleted'", (runtime_id,)):
        raise HTTPException(status_code=404, detail="unknown runtime")
    now = store.now_iso()
    values = (
        runtime_id,
        str(payload.get("tool_name", "")),
        json.dumps(payload.get("arguments") or {}, ensure_ascii=False),
        str(payload.get("mode", "write")),
        str(payload.get("caller_ip", "")),
        str(payload.get("model", "")),
        now,
    )
    existing = store.one("SELECT status FROM approval_requests WHERE id = ?", (req_id,))
    if not existing:
        store.execute(
            """INSERT INTO approval_requests
               (id, runtime_id, tool_name, arguments_json, mode, status, caller_ip, model, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (req_id, *values),
        )
    elif existing["status"] != "pending":
        # Same tool + arguments asked again after the previous decision was used, expired or
        # rejected — a new decision is needed.
        store.execute(
            """UPDATE approval_requests
               SET runtime_id=?, tool_name=?, arguments_json=?, mode=?, status='pending', caller_ip=?, model=?,
                   created_at=?, decided_at=NULL, decided_by=NULL, reject_reason=NULL
               WHERE id=?""",
            (*values, req_id),
        )
    return JSONResponse({
        "id": req_id, "status": "pending", "url": approval_url(req_id),
        # tells the runtime whether it makes sense to ask the user for a one-time code
        "code_allowed": bool(_code_approvers()),
    })


@router.get("/api/approval-status/{req_id}")
def get_approval_status(req_id: str) -> JSONResponse:
    row = store.one(
        "SELECT status, reject_reason, decided_at FROM approval_requests WHERE id = ?", (req_id,)
    )
    if not row:
        return JSONResponse({"status": "not_found"}, status_code=404)
    return JSONResponse({
        "status": row["status"],
        "reject_reason": row.get("reject_reason"),
        # lets the runtime ignore an approval granted long ago
        "decided_at": row.get("decided_at"),
        "url": approval_url(req_id),
        "code_allowed": bool(_code_approvers()),
    })


@router.post("/api/approval-consume/{req_id}")
def consume_approval(req_id: str) -> JSONResponse:
    """Mark an approval as used. Atomic, so one approval allows exactly one execution."""
    with store.db() as conn:
        used = conn.execute(
            "UPDATE approval_requests SET status='used' WHERE id=? AND status='approved'", (req_id,)
        ).rowcount
    return JSONResponse({"ok": used == 1})


@router.post("/api/approval-code/{req_id}")
async def approve_with_code(req_id: str, request: Request) -> JSONResponse:
    """
    Approve a pending request with a one-time code from an authenticator app.
    The user types the code in the chat and the runtime forwards it here. A code is valid
    for one approval only (replay is refused) and wrong codes are rate limited per runtime.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    code = re.sub(r"\D", "", str(payload.get("code") or ""))
    row = store.one("SELECT * FROM approval_requests WHERE id = ?", (req_id,))
    if not row or row["status"] != "pending" or _age_seconds(row["created_at"]) > PENDING_MAX_AGE_SECONDS:
        return JSONResponse({"ok": False, "reason": "not_pending"})
    failures = _recent_code_failures(row["runtime_id"])
    if failures >= CODE_MAX_FAILURES:
        return JSONResponse({"ok": False, "reason": "locked", "retry_after_seconds": CODE_LOCK_SECONDS})
    for user in _code_approvers():
        step = totp.verify(user["totp_secret"], code, last_step=user["totp_last_step"])
        if step is None:
            continue
        with store.db() as conn:
            # The step is burned first: even if two requests race, one code approves one request.
            burned = conn.execute(
                "UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step < ?", (step, user["id"], step)
            ).rowcount
            approved = burned and conn.execute(
                """UPDATE approval_requests SET status='approved', decided_at=?, decided_by=?, reject_reason=NULL
                   WHERE id=? AND status='pending'""",
                (store.now_iso(), f"{user['username']} (kod)", req_id),
            ).rowcount
        if approved:
            store.audit(
                user["username"], "approve_tool_call", "runtime", row["runtime_id"],
                {"tool": row["tool_name"], "approval": req_id, "method": "one-time code"},
            )
            return JSONResponse({"ok": True, "approved_by": user["username"]})
        break
    store.execute(
        "INSERT INTO approval_code_failures(runtime_id, created_at) VALUES (?, ?)", (row["runtime_id"], store.now_iso())
    )
    return JSONResponse({
        "ok": False, "reason": "invalid", "attempts_left": max(0, CODE_MAX_FAILURES - failures - 1),
    })


# ── Decision page (logged-in users only) ───────────────────────────────────────

@router.get("/approve/{req_id}", response_class=HTMLResponse)
def approval_page(req_id: str, ok: str = "") -> str:
    row = _request(req_id)
    runtime = store.one("SELECT id, name FROM runtimes WHERE id = ?", (row["runtime_id"],))
    try:
        arguments = json.loads(row["arguments_json"] or "{}")
    except json.JSONDecodeError:
        arguments = {}
    command = str(arguments.pop("_command", "")) if isinstance(arguments, dict) else ""
    role = (current_user.get() or {}).get("role", "")
    return render_page(
        "",
        "pages/approve.html",
        req=row,
        ok=ok,
        runtime_name=(runtime or {}).get("name") or row["runtime_id"],
        command=command,
        arguments=json.dumps(arguments, indent=2, ensure_ascii=False),
        expired=row["status"] == "pending" and _age_seconds(row["created_at"]) > PENDING_MAX_AGE_SECONDS,
        can_decide=role in ("admin", "read_write"),
    )


@router.post("/approve/{req_id}")
async def decide_approval(req_id: str, request: Request) -> Any:
    user = current_user.get() or {}
    # id == 0 is the service API token; it never reaches a non-/api/ path, but approvals must
    # come from a person, so check explicitly.
    if user.get("role") not in ("admin", "read_write") or not user.get("user_id"):
        raise HTTPException(status_code=403, detail="Brak uprawnień do zatwierdzania")
    row = _request(req_id)
    form = await request.form()
    decision = str(form.get("decision") or "")
    if decision not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Nieznana decyzja")
    if row["status"] != "pending" or _age_seconds(row["created_at"]) > PENDING_MAX_AGE_SECONDS:
        return RedirectResponse(f"/approve/{req_id}", status_code=303)
    with store.db() as conn:
        changed = conn.execute(
            """UPDATE approval_requests SET status=?, decided_at=?, decided_by=?, reject_reason=?
               WHERE id=? AND status='pending'""",
            (
                "approved" if decision == "approve" else "rejected",
                store.now_iso(),
                user.get("username", "?"),
                (str(form.get("reason") or "").strip()[:300] or "odrzucone przez użytkownika") if decision == "reject" else None,
                req_id,
            ),
        ).rowcount
    if changed:
        store.audit(
            user.get("username", "?"),
            "approve_tool_call" if decision == "approve" else "reject_tool_call",
            "runtime",
            row["runtime_id"],
            {"tool": row["tool_name"], "approval": req_id},
        )
    return RedirectResponse(f"/approve/{req_id}?ok=1", status_code=303)

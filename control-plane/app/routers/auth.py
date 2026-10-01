"""Login, logout, registration, user settings and user administration."""
import os
import re
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..auth import create_session, current_user, delete_session, hash_password, verify_password
from ..config import AUTH_COOKIE, SESSION_TTL_H
from ..rendering import render
from ..services import safe_return_to
from ..web import render_page


router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(error: str = "", next: str = "/") -> str:
    return render("auth/login.html", title='Logowanie', error=error, next=next)


@router.post("/login")
async def login_post(request: Request) -> Any:
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    next_url = safe_return_to(str(form.get("next") or ""), "/")
    user = store.one("SELECT * FROM users WHERE username=? AND active=1", (username,))
    if not user or not verify_password(password, user["password_hash"]):
        return RedirectResponse(f"/login?error={quote('Nieprawidłowy login lub hasło')}&next={quote(next_url)}", status_code=303)
    token = create_session(user["id"], user["username"], user["role"])
    resp = RedirectResponse(next_url, status_code=303)
    _secure = os.getenv("MCP_HTTPS_ONLY", "").lower() in ("1", "true", "yes")
    resp.set_cookie(AUTH_COOKIE, token, httponly=True, samesite="lax",
                    max_age=SESSION_TTL_H * 3600, secure=_secure)
    return resp


@router.post("/logout")
async def logout(request: Request) -> Any:
    token = request.cookies.get(AUTH_COOKIE, "")
    if token:
        delete_session(token)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(AUTH_COOKIE)
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_page(error: str = "", ok: str = "") -> str:
    return render("auth/register.html", title='Rejestracja', error=error, ok=ok)


@router.post("/register")
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
        (username, hash_password(password), "pending", role, store.now_iso(), store.now_iso()),
    )
    store.audit("system", "registration_request", "user", username, {"role": role})
    return RedirectResponse(f"/register?ok={quote('Prośba wysłana! Administrator otrzyma powiadomienie i wkrótce aktywuje Twoje konto.')}", status_code=303)


@router.get("/user/settings", response_class=HTMLResponse)
def user_settings_page(error: str = "", ok: str = "") -> str:
    user = current_user.get() or {}
    return render_page('settings', "pages/user_settings.html", error=error, ok=ok, user=user)


@router.post("/api/user/change-password")
async def change_password(request: Request) -> Any:
    user = current_user.get()
    if not user:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    current_pw = str(form.get("current_password") or "")
    new_pw = str(form.get("new_password") or "")
    new_pw2 = str(form.get("new_password2") or "")
    db_user = store.one("SELECT * FROM users WHERE id=?", (user["user_id"],))
    if not db_user or not verify_password(current_pw, db_user["password_hash"]):
        return RedirectResponse(f"/user/settings?error={quote('Nieprawidłowe aktualne hasło')}", status_code=303)
    if len(new_pw) < 6:
        return RedirectResponse(f"/user/settings?error={quote('Nowe hasło musi mieć min. 6 znaków')}", status_code=303)
    if new_pw != new_pw2:
        return RedirectResponse(f"/user/settings?error={quote('Hasła nie są zgodne')}", status_code=303)
    store.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (hash_password(new_pw), store.now_iso(), db_user["id"]))
    store.audit("admin", "change_password", "user", db_user["username"], {})
    return RedirectResponse(f"/user/settings?ok={quote('Hasło zostało zmienione!')}", status_code=303)


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(ok: str = "") -> str:
    users = store.rows("SELECT * FROM users ORDER BY role, username")
    requests = store.rows("SELECT * FROM registration_requests WHERE status='pending' ORDER BY created_at")

    return render_page('admin', 'pages/admin_users.html', ok=ok, requests=requests, users=users)


@router.post("/admin/users/approve/{req_id}")
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


@router.post("/admin/users/reject/{req_id}")
async def reject_registration(req_id: int) -> Any:
    req = store.one("SELECT username FROM registration_requests WHERE id=?", (req_id,))
    store.execute("UPDATE registration_requests SET status='rejected',updated_at=? WHERE id=?", (store.now_iso(), req_id))
    store.audit("admin", "reject_registration", "user", (req or {}).get("username", "?"), {})
    return RedirectResponse(f"/admin/users?ok={quote('Prośba odrzucona.')}", status_code=303)


@router.post("/admin/users/role/{user_id}")
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


@router.post("/admin/users/toggle/{user_id}")
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

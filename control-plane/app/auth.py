"""Authentication: password hashing, DB-backed sessions, service API token, current user."""
import hashlib
import os
import secrets
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Request

from . import store
from .config import API_TOKEN_HEADER, SESSION_TTL_H
from .rendering import render

# Set by AuthMiddleware for every request; read by pages and audit logging.
current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)


def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000)
    return f"{salt}:{dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split(":", 1)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_session(user_id: int, username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_H)).isoformat()
    store.execute(
        "INSERT INTO sessions(token,user_id,username,role,expires_at,created_at) VALUES(?,?,?,?,?,?)",
        (token, user_id, username, role, expires, store.now_iso()),
    )
    return token


def get_session(token: str) -> dict | None:
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


def delete_session(token: str) -> None:
    store.execute("DELETE FROM sessions WHERE token=?", (token,))


def ensure_admin() -> None:
    """Create default admin:admin if no users exist."""
    if not store.one("SELECT id FROM users LIMIT 1"):
        store.execute(
            "INSERT INTO users(username,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            ("admin", hash_password("admin"), "admin", 1, store.now_iso(), store.now_iso()),
        )


def access_denied_html(user: dict, msg: str) -> str:
    return render("access_denied.html", msg=msg, username=user.get("username", "?"), role=user.get("role", "?"))


# Token serwisowy: pozwala runtime'om i skryptom wołać /api/ bez cookie.
# Ustawiany przez MCP_PLATFORM_API_TOKEN; pusty = mechanizm wyłączony.
_API_TOKEN = os.getenv("MCP_PLATFORM_API_TOKEN", "").strip()
_API_TOKEN_ROLE = os.getenv("MCP_PLATFORM_API_ROLE", "read_write").strip() or "read_write"


def api_token_user(request: Request) -> dict[str, Any] | None:
    """Uwierzytelnienie nagłówkiem X-API-Key — tylko dla ścieżek /api/."""
    if not _API_TOKEN or not request.url.path.startswith("/api/"):
        return None
    presented = request.headers.get(API_TOKEN_HEADER, "")
    if not presented:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[7:]
    # Starlette dekoduje nagłówki jako latin-1; compare_digest wymaga ASCII
    # i na bajcie >127 rzuciłoby TypeError z middleware → 500 zamiast 401.
    if not presented or not presented.isascii():
        return None
    if not secrets.compare_digest(presented, _API_TOKEN):
        return None
    return {"id": 0, "username": "api-token", "role": _API_TOKEN_ROLE}

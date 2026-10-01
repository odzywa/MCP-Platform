"""HTTP middleware: authentication and role-based access control (RBAC)."""
import re
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import access_denied_html, api_token_user, current_user, get_session
from .config import _ADMIN_ONLY, _PUBLIC, AUTH_COOKIE


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Any) -> Any:
        path = request.url.path

        # Always allow public paths and static assets
        if _PUBLIC.match(path) or path.startswith("/static/"):
            user = get_session(request.cookies.get(AUTH_COOKIE, ""))
            current_user.set(user)
            return await call_next(request)

        token = request.cookies.get(AUTH_COOKIE, "")
        user = get_session(token) or api_token_user(request)

        if not user:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not authenticated"}, status_code=401)
            return RedirectResponse("/login", status_code=303)

        current_user.set(user)
        role = user["role"]
        method = request.method

        # read_only: block all POST/PUT/DELETE except change-password and logout
        if role == "read_only" and method not in ("GET", "HEAD"):
            if not re.match(r"^/api/user/|^/logout", path):
                return HTMLResponse(access_denied_html(user, "Twoja rola (tylko odczyt) nie pozwala na modyfikacje."), status_code=403)

        # read_write and read_only: block admin-only paths
        if role != "admin" and _ADMIN_ONLY.match(path):
            return HTMLResponse(access_denied_html(user, "Ta funkcja jest dostępna tylko dla administratorów."), status_code=403)

        # /admin panel — admin only
        if path.startswith("/admin") and role != "admin":
            return HTMLResponse(access_denied_html(user, "Panel administratora jest dostępny tylko dla adminów."), status_code=403)

        return await call_next(request)

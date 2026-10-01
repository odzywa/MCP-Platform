"""MCP Platform control plane — FastAPI application wiring.

Routes live in app/routers/, shared domain logic in app/services.py, UI helpers in app/web.py,
authentication in app/auth.py + app/middleware.py, templates in app/templates/.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import store
from .auth import ensure_admin
from .catalog.seed import seed_all
from .middleware import AuthMiddleware
from .rendering import STATIC_DIR
from .routers import approvals, auth, external, general, images, packages, platform, quickstart, runtimes, security, webhooks


app = FastAPI(title="MCP Platform", version="0.1.0", docs_url="/api-swagger", redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.add_middleware(AuthMiddleware)


@app.on_event("startup")
def startup() -> None:
    store.init_db()
    ensure_admin()
    seed_all()


# Order matters: FastAPI matches routes in registration order, and routers/runtimes.py contains the
# catch-all POST /api/runtimes/{runtime_id}/{action}.
for module in (quickstart, general, external, auth, runtimes, platform, images, packages, security, webhooks, approvals):
    app.include_router(module.router)

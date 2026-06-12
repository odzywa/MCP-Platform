"""Static configuration: cookies, auth path patterns, on-disk file locations."""
import re

from . import store

# ── Auth / RBAC ────────────────────────────────────────────────────────────────
AUTH_COOKIE = "mcp_session"
SESSION_TTL_H = 24

# Public paths that never require login
_PUBLIC = re.compile(r"^/(login|register)(/?|\?.*)$|^/api/runtimes/[^/]+/openwebui-tool\.py$|^/api/tool-call$|^/api/runtime-callback")
# Paths that are read-only (any logged-in user can GET them)
_READONLY_GET = re.compile(
    r"^/(|runtimes.*|audit.*|logs.*|security.*|docs.*|external-mcp.*"
    r"|api/runtimes/[^/]+/status|api/user/.*)$"
)
# Paths blocked for read_write (admin only)
_ADMIN_ONLY = re.compile(
    r"^/(tool-packages/generate|runtime-classes.*|tool-types.*|adapters.*|admin.*"
    r"|api/(tool-packages.*|runtime-images.*|runtime-classes.*|adapters.*))"
)

_FAVICON_TAG = '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 64 64\'%3E%3Crect width=\'64\' height=\'64\' rx=\'12\' fill=\'%230f1722\'/%3E%3Ctext x=\'32\' y=\'36\' font-family=\'Arial Black,Arial,sans-serif\' font-size=\'24\' font-weight=\'900\' fill=\'%231f9bd1\' text-anchor=\'middle\'%3EMCP%3C/text%3E%3Ctext x=\'32\' y=\'52\' font-family=\'Arial,sans-serif\' font-size=\'9\' font-weight=\'600\' fill=\'%234a7a9b\' text-anchor=\'middle\' letter-spacing=\'2\'%3EPLATFORM%3C/text%3E%3C/svg%3E">'

CUSTOM_TEMPLATES_FILE = store.CONFIG_ROOT / "custom_policy_templates.json"

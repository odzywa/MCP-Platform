"""UI layer: page layout context (sidebar, topbar), render_page() and helpers exposed to templates."""
import json
import shlex
from typing import Any

from markupsafe import Markup

from . import store
from .auth import current_user
from .config import _FAVICON_TAG
from .rendering import env as templates_env
from .rendering import render, render_markup, static_text
from .services import adapter_contract, enabled_adapters, schema_defaults


def schema_form(schema: dict[str, Any], prefix: str, values: dict[str, Any] | None = None) -> Markup:
    values = {**schema_defaults(schema), **(values or {})}
    required = set(schema.get("required") or [])
    fields = []
    for name, spec in (schema.get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        value = values.get(name, "")
        field_type = spec.get("type", "string")
        if field_type in {"array", "object"} and (value == "" or value is None):
            value = [] if field_type == "array" else {}
        fields.append({
            "name": f"{prefix}.{name}",
            "label": str(spec.get("title") or name.replace("_", " ").title()),
            "required": name in required,
            "enum": [str(item) for item in spec.get("enum") or []],
            "type": field_type,
            "value": value,
        })
    return render_markup("partials/schema_form.html", fields=fields)


def action_forms(runtime_id: str) -> Markup:
    """Deploy/stop/restart/... buttons with inline feedback for the runtime detail page."""
    return render_markup("partials/action_forms.html", msg_id=f"act-msg-{runtime_id}", rid=runtime_id)


def _validation_ui(tool: dict[str, Any]) -> Markup:
    schema = json.loads(tool["input_schema_json"] or "{}")
    params = []
    for pname, pdef in (schema.get("properties") or {}).items():
        val = pdef.get("validation") or {}
        params.append({
            "name": pname,
            "allowed": ", ".join(val.get("allowed_values") or []),
            "blocked": ", ".join(val.get("blocked_words") or []),
            "pattern": val.get("pattern") or "",
            "max_len": val.get("max_length") or "",
        })
    return render_markup("partials/validation_ui.html", params=params)


def tool_edit_form(runtime_id: str, tool: dict[str, Any]) -> Markup:
    config = json.loads(tool["config_json"] or "{}")
    is_shell = tool["execution_type"] in ("shell", "ssh")
    input_schema_json = json.dumps(json.loads(tool["input_schema_json"] or "{}"), indent=2, ensure_ascii=False)
    output_schema_json = json.dumps(json.loads(tool["output_schema_json"] or "{}"), indent=2, ensure_ascii=False)
    if is_shell:
        cmd_parts = config.get("command") or []
        exec_ctx = {
            "cmd_str": " ".join(shlex.quote(p) if " " in str(p) else str(p) for p in cmd_parts),
            "timeout_val": config.get("timeout_seconds", 30),
        }
    else:
        exec_ctx = {
            "body_json": json.dumps(config.get("body", {}), indent=2, ensure_ascii=False),
            "headers_json": json.dumps(config.get("headers", {}), indent=2, ensure_ascii=False),
        }
    return render_markup(
        "partials/tool_edit_form.html",
        config=config,
        is_shell=is_shell,
        input_schema_json=input_schema_json,
        output_schema_json=output_schema_json,
        adapter_names=[a["name"] for a in enabled_adapters()],
        runtime_id=runtime_id,
        tool=tool,
        **exec_ctx,
    )


def masked_secret(value: str) -> str:
    if not value:
        return ""
    return "***" + value[-4:] if len(value) > 4 else "***"


_PAGE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "dashboard":  ("🏠 Dashboard", "Przegląd całej platformy — działające serwery, ostatnie operacje i logi błędów. Tu widzisz od razu co wymaga uwagi."),
    "quickstart": ("⚡ Szybki start", "Utwórz gotowy serwer MCP w kilku krokach bez pisania kodu. Wybierz gotowy zestaw z katalogu lub zaimportuj konfigurację."),
    "create":     ("🛠️ Kreator zaawansowany", "5-krokowy kreator z pełną kontrolą — wybierz źródło tools, środowisko Docker, zdefiniuj narzędzie, ustaw politykę bezpieczeństwa i uruchom serwer."),
    "runtimes":   ("🖥️ Moje serwery MCP", "Lista wszystkich serwerów MCP na platformie — statusy, endpointy do podłączenia w AI oraz zarządzanie (deploy, stop, restart, logi)."),
    "external":   ("🔗 Zewnętrzne MCP", "Rejestruj i monitoruj serwery MCP działające poza platformą — np. pobrane z GitHuba lub uruchomione ręcznie. Platforma sprawdza ich dostępność i wylistowuje tools."),
    "webhooks":   ("🔔 Webhooki", "Powiadomienia HTTP gdy serwer MCP padnie, health check się nie powiedzie lub tool zwróci błąd. Integracja ze Slackiem, Teams, Discordem lub własnym systemem."),
    "packages":   ("🏗️ Build", "Wbudowane szablony + serwery z Kreatora zaawansowanego. Wdróż jednym kliknięciem; własne obrazy z dodatkowymi narzędziami zbudujesz w zakładce Budowanie obrazów."),
    "adapters":   ("⚙️ Silniki wykonania", "Globalne typy egzekucji dostępne na platformie (http_request, shell, ssh…). Określają jak runtime wywołuje narzędzia. Możesz dodawać własne silniki z własnym obrazem Docker."),
    "classes":    ("🏗️ Typy środowisk", "Typy środowisk określają jaki obraz Docker jest uruchamiany dla danego serwera i jakie silniki są dozwolone. Nowe typy tworzy Runtime Image Builder automatycznie."),
    "images":     ("🐳 Budowanie obrazów", "Zbuduj własny obraz kontenera: wybierz obraz bazowy i doinstaluj do niego narzędzia (pakiety systemowe, pip). Niżej lista obrazów ze statusem budowania."),
    "security":   ("🔒 Bezpieczeństwo", "Przegląd polityk bezpieczeństwa wszystkich serwerów i globalny hardening kontenerów. Każdy kontener działa jako user 1000, bez uprawnień root, z read-only filesystem."),
    "audit":      ("🔍 Audit log", "Historia wszystkich operacji na platformie — kto i kiedy uruchomił deploy, zmienił konfigurację, otworzył stronę serwera lub wywołał akcję. Przydatne do audytu dostępu."),
    "logs":       ("📋 Logi", "Logi diagnostyczne kontenerów runtime — błędy startowania, komunikaty aplikacji, wyniki health checków. Pomocne przy debugowaniu problemów z serwerem."),
    "admin":      ("👥 Użytkownicy", "Zarządzanie kontami — zatwierdzanie rejestracji, zmiana ról (read_only / read_write / admin), włączanie i wyłączanie kont."),
    "docs":       ("📖 Jak to działa?", "Przewodnik po platformie — architektura, przepływ danych, różnice między kreatorami, bezpieczeństwo kontenerów i FAQ dla użytkowników technicznych i nietech."),
}


_NAV_TABS: list[tuple[str, str, str, str, str]] = [
    # (key, label, href, description, minimal role)
    ("dashboard",  "🏠  Dashboard",          "/",                "Przegląd stanu platformy — działające serwery, ostatnie operacje i logi", "read_only"),
    ("quickstart", "⚡  Szybki start",         "/quick-start",     "Utwórz gotowy serwer MCP w 2 krokach — bez pisania kodu",                "read_write"),
    ("create",     "🛠️  Kreator zaawansowany", "/create",          "Kreator krok po kroku z pełną kontrolą — wybór paczki, silnika, polityki","read_write"),
    ("runtimes",   "🖥️  Moje serwery",         "/runtimes",        "Lista wszystkich serwerów MCP — status, endpointy, zarządzanie",          "read_only"),
    ("external",   "🔗  Zewnętrzne MCP",       "/external-mcp",    "Rejestruj i monitoruj serwery MCP uruchomione poza platformą",            "read_only"),
    ("webhooks",   "🔔  Webhooki",              "/webhooks",        "Powiadomienia gdy serwer padnie lub tool zwróci błąd",                     "admin"),
    ("packages",   "🏗️  Build",                "/tool-packages",   "Wdrażaj serwery MCP z gotowych paczek, importuj własne paczki",           "read_only"),
    ("adapters",   "⚙️  Silniki wykonania",    "/tool-types",      "Globalne typy egzekucji (http_request, shell…)",                          "admin"),
    ("classes",    "🏗️  Typy środowisk",       "/runtime-classes", "Docker images i klasy runtime — definiują jakie binarki są dostępne",     "admin"),
    ("images",     "🐳  Budowanie obrazów",    "/runtime-images",  "Własne obrazy: obraz bazowy + doinstalowane narzędzia",                    "admin"),
    ("security",   "🔒  Bezpieczeństwo",       "/security",        "Przegląd polityk i hardening kontenerów",                                 "read_only"),
    ("approvals",  "🛡️  Zatwierdzenia",        "/approvals",       "Wywołania narzędzi czekające na decyzję człowieka",                        "read_only"),
    ("audit",      "🔍  Audit",                "/audit",           "Historia wszystkich operacji — deploy, stop, reload, błędy",               "read_only"),
    ("logs",       "📋  Logi",                 "/logs",            "Logi runtimeów — informacje diagnostyczne i błędy kontenerów",            "read_only"),
    ("admin",      "👥  Użytkownicy",           "/admin/users",     "Zarządzanie użytkownikami — role, rejestracje, hasła",                    "admin"),
    ("docs",       "📖  Jak to działa?",       "/docs",            "Przewodnik po platformie dla użytkowników technicznych i nietech",         "read_only"),
]


_ROLE_ORDER = {"read_only": 0, "read_write": 1, "admin": 2}


_ROLE_COLORS = {"admin": ("#c084fc", "#2a1040"), "read_write": ("#5ce89a", "#0e2e1e"), "read_only": ("#7a92a8", "#1e252e")}


_lang_js_cache: str = ""


def _cached_lang_js() -> str:
    """Standalone translator for pages outside base.html; dictionary shared with static/js/i18n.js."""
    global _lang_js_cache
    if _lang_js_cache:
        return _lang_js_cache
    src = static_text("js/i18n.js")
    start = src.find("var TRANS_RAW = [")
    end = src.find("];", start) + 2
    raw_block = src[start:end]
    _lang_js_cache = render("lang.js", trans_raw=raw_block)
    return _lang_js_cache


def _pending_approvals_badge() -> str:
    try:
        row = store.one("SELECT COUNT(*) AS n FROM approval_requests WHERE status='pending'")
        return f" ({row['n']})" if row and row["n"] else ""
    except Exception:
        return ""


def _shell_context(active: str) -> dict[str, Any]:
    user = current_user.get()
    role = (user or {}).get("role", "admin")
    user_level = _ROLE_ORDER.get(role, 2)
    tabs = []
    for key, label, href, desc, min_role in _NAV_TABS:
        if _ROLE_ORDER.get(min_role, 0) > user_level:
            continue
        if key == "approvals":
            label += _pending_approvals_badge()
        tabs.append({"key": key, "label": label, "href": href, "desc": desc})
    page_title, page_sub = next(
        ((t["label"].split("  ", 1)[-1].strip(), t["desc"]) for t in tabs if t["key"] == active), ("MCP Platform", "")
    )
    role_color, role_bg = _ROLE_COLORS.get(role, ("#7a92a8", "#1e252e"))
    return {
        "active": active,
        "tabs": tabs,
        "page_title": page_title,
        "page_sub": page_sub,
        "description": _PAGE_DESCRIPTIONS.get(active),
        "username": (user or {}).get("username", ""),
        "role": role,
        "role_color": role_color,
        "role_bg": role_bg,
    }


def render_page(active: str, template: str, /, **ctx: Any) -> str:
    """Render a page template that extends base.html (sidebar, topbar, i18n)."""
    return render(template, shell=_shell_context(active), **ctx)


# Helpers callable from templates (all return Markup or plain values).
templates_env.globals.update(
    _FAVICON_TAG=Markup(_FAVICON_TAG),
    _validation_ui=_validation_ui,
    action_forms=action_forms,
    adapter_contract=adapter_contract,
    masked_secret=masked_secret,
    schema_form=schema_form,
    tool_edit_form=tool_edit_form,
)

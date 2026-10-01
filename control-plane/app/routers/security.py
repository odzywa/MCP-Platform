"""Security overview, per-runtime policy editing and policy templates."""
import json
import re
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..auth import current_user
from ..config import CUSTOM_TEMPLATES_FILE
from ..strings import slug
from ..web import render_page


router = APIRouter()


def _load_custom_templates() -> list[dict]:
    try:
        return json.loads(CUSTOM_TEMPLATES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_custom_templates(templates: list[dict]) -> None:
    store.CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    CUSTOM_TEMPLATES_FILE.write_text(json.dumps(templates, indent=2, ensure_ascii=False), encoding="utf-8")


@router.get("/security", response_class=HTMLResponse)
def security_page(ok: str = "") -> str:
    runtimes = store.rows("SELECT r.id, r.name, r.status, r.runtime_class, r.risk_level, p.policy_json FROM runtimes r LEFT JOIN policies p ON r.id = p.runtime_id WHERE r.status != 'deleted' ORDER BY r.name")
    credentials = store.rows("SELECT runtime_id, COUNT(*) as cnt FROM runtime_credentials GROUP BY runtime_id")
    cred_by_rid = {c["runtime_id"]: c["cnt"] for c in credentials}

    # Parse each policy and compute a risk score
    def parse_policy(pol_json: str | None) -> dict:
        if not pol_json:
            return {}
        try:
            return json.loads(pol_json)
        except Exception:
            return {}

    def policy_level(p: dict) -> tuple[str, str]:
        """Returns (css_class, label) based on how strict the policy is."""
        if not p:
            return ("failed", "⚠️ brak")
        ro = p.get("require_read_only", False)
        bw = p.get("block_write_tools", False)
        bd = p.get("block_destructive_tools", False)
        if ro and bw and bd:
            return ("running", "🔒 ścisła")
        if ro or bw:
            return ("deploying", "🔶 częściowa")
        return ("failed", "🔓 luźna")

    levels = [policy_level(parse_policy(r.get("policy_json")))[0] for r in runtimes]
    strict_count = levels.count("running")
    moderate_count = levels.count("deploying")
    loose_count = len(levels) - strict_count - moderate_count

    total = len(runtimes)

    templates = [
        {
            "name": "🔒 Ścisła (produkcja)",
            "desc": "Maksymalna ochrona — tylko odczyt, blokada zapisu i destruktywnych operacji. Zalecana dla wszystkich serwerów produkcyjnych.",
            "color": "var(--success-bg)", "border": "var(--success-border)",
            "policy": {"require_read_only": True, "block_write_tools": True, "block_destructive_tools": True, "timeout_seconds": 30, "max_payload_bytes": 262144, "max_response_bytes": 5242880},
        },
        {
            "name": "🔶 Standardowa",
            "desc": "Blokuje operacje destruktywne, ale pozwala na zapis. Przydatna dla serwerów zarządzających danymi (np. tworzenie ticketów).",
            "color": "var(--warning-bg)", "border": "var(--warning-border)",
            "policy": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": True, "timeout_seconds": 60, "max_payload_bytes": 524288, "max_response_bytes": 10485760},
        },
        {
            "name": "🧪 Deweloperska",
            "desc": "Brak ograniczeń policy — tylko dla testów lokalnych. NIGDY nie używaj na produkcji.",
            "color": "var(--danger-bg)", "border": "var(--danger-border)",
            "policy": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": False, "timeout_seconds": 120, "max_payload_bytes": 1048576, "max_response_bytes": 20971520},
        },
    ]
    custom_templates = _load_custom_templates()

    return render_page('security', 'pages/security.html', cred_by_rid=cred_by_rid, custom_templates=custom_templates, loose_count=loose_count, moderate_count=moderate_count, ok=ok, parse_policy=parse_policy, policy_level=policy_level, runtimes=runtimes, strict_count=strict_count, templates=templates, total=total)


@router.post("/api/security/templates")
async def create_policy_template(request: Request):
    user = current_user.get()
    if not user or user["role"] not in ("admin", "read_write"):
        raise HTTPException(status_code=403)
    payload = await request.json()
    name = str(payload.get("name") or "").strip()
    if not name:
        return JSONResponse({"ok": False, "error": "Brak nazwy szablonu"})
    templates = _load_custom_templates()
    slug_val = slug(name) + "-" + uuid.uuid4().hex[:4]
    templates.append({
        "slug": slug_val,
        "name": name,
        "desc": str(payload.get("desc") or ""),
        "policy": payload.get("policy") or {},
    })
    _save_custom_templates(templates)
    store.audit(user["username"], "create_policy_template", "policy_template", slug_val)
    return JSONResponse({"ok": True, "slug": slug_val})


@router.delete("/api/security/templates/{tpl_slug}")
async def delete_policy_template(tpl_slug: str, request: Request):
    user = current_user.get()
    if not user or user["role"] not in ("admin", "read_write"):
        raise HTTPException(status_code=403)
    templates = _load_custom_templates()
    before = len(templates)
    templates = [t for t in templates if t.get("slug") != tpl_slug]
    if len(templates) == before:
        return JSONResponse({"ok": False, "error": "Nie znaleziono szablonu"})
    _save_custom_templates(templates)
    store.audit(user["username"], "delete_policy_template", "policy_template", tpl_slug)
    return JSONResponse({"ok": True})


@router.post("/api/security/policy/{runtime_id}")
async def security_update_policy(runtime_id: str, request: Request):
    """Update policy from the Security page — form fields instead of raw JSON."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    current = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    try:
        policy: dict[str, Any] = json.loads(current["policy_json"] if current else "{}")
    except Exception:
        policy = {}
    policy["require_read_only"] = form.get("require_read_only") == "1"
    policy["block_write_tools"] = form.get("block_write_tools") == "1"
    policy["block_destructive_tools"] = form.get("block_destructive_tools") == "1"
    try:
        policy["timeout_seconds"] = max(5, min(300, int(form.get("timeout_seconds") or 30)))
    except (ValueError, TypeError):
        policy["timeout_seconds"] = 30
    try:
        max_kb = max(64, min(51200, int(form.get("max_response_kb") or 5120)))
        policy["max_response_bytes"] = max_kb * 1024
    except (ValueError, TypeError):
        pass
    bins_raw = str(form.get("allowed_binaries") or "").strip()
    policy["allowed_binaries"] = [b.strip() for b in re.split(r"[\s,]+", bins_raw) if b.strip()] if bins_raw else []
    store.execute(
        sql.UPSERT_POLICY_COMPACT,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "update_policy", "runtime", runtime_id, {"source": "security_page"})
    store.log(runtime_id, "Policy updated from Security page")
    return RedirectResponse("/security?ok=1", status_code=303)


@router.post("/api/security/policy/{runtime_id}/apply-template")
async def security_apply_template(runtime_id: str, request: Request):
    """Apply a named policy template to a runtime."""
    if not store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
        raise HTTPException(status_code=404, detail="Runtime not found")
    form = await request.form()
    tpl = str(form.get("template") or "strict")
    templates: dict[str, dict[str, Any]] = {
        "strict":   {"require_read_only": True,  "block_write_tools": True,  "block_destructive_tools": True,  "timeout_seconds": 30,  "max_payload_bytes": 262144,  "max_response_bytes": 5242880},
        "standard": {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": True,  "timeout_seconds": 60,  "max_payload_bytes": 524288,  "max_response_bytes": 10485760},
        "dev":      {"require_read_only": False, "block_write_tools": False, "block_destructive_tools": False, "timeout_seconds": 120, "max_payload_bytes": 1048576, "max_response_bytes": 20971520},
    }
    policy = templates.get(tpl, templates["strict"])
    # Preserve allowed_binaries from current policy
    current = store.one(sql.SELECT_POLICY_JSON_BY_RUNTIME, (runtime_id,))
    if current:
        try:
            existing = json.loads(current["policy_json"])
            if existing.get("allowed_binaries"):
                policy["allowed_binaries"] = existing["allowed_binaries"]
        except Exception:
            pass
    store.execute(
        sql.UPSERT_POLICY_COMPACT,
        (runtime_id, json.dumps(policy), store.now_iso()),
    )
    store.audit("admin", "apply_policy_template", "runtime", runtime_id, {"template": tpl})
    store.log(runtime_id, f"Policy template '{tpl}' applied")
    return RedirectResponse("/security?ok=1", status_code=303)

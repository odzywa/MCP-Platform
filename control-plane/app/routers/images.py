"""Image builder: custom runtime images = a base runtime image plus extra tools (built by the operator)."""
import json
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import queries as sql
from .. import store
from ..adapters_config import adapter_contracts
from ..auth import current_user
from ..build_images import build_runtime_dockerfile
from ..build_images.presets import (
    PIP_TOOL_PRESETS,
    PLATFORM_BASE_IMAGES,
    PLATFORM_IMAGE_BASE,
    SYSTEM_TOOL_PRESETS,
    guess_family,
)
from ..services import enqueue_runtime_image_build
from ..strings import clean_words, slug, validate_image_ref
from ..web import render_page


router = APIRouter()

_PLATFORM_BY_IMAGE = {item["image"]: item for item in PLATFORM_BASE_IMAGES}
CUSTOM_BASE = "__custom__"


def _class_execution_types(image: str) -> list[str]:
    """Execution types of the runtime class that runs `image` (empty if no class uses it)."""
    row = store.one(
        "SELECT allowed_execution_types_json FROM runtime_classes WHERE runtime_image = ? ORDER BY name LIMIT 1", (image,)
    )
    if not row:
        return []
    try:
        return list(json.loads(row["allowed_execution_types_json"] or "[]"))
    except json.JSONDecodeError:
        return []


def _inherited_execution_types(base_image: str) -> list[str]:
    """A custom image can do what its base can: platform preset first, then the base's runtime class."""
    if base_image in _PLATFORM_BY_IMAGE:
        return list(_PLATFORM_BY_IMAGE[base_image]["execution_types"])
    return _class_execution_types(base_image)


def _base_image_groups(builds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Base images offered by the builder: platform runtimes and successfully built custom images."""
    base_of = {b["image"]: b["base_image"] for b in builds}

    def family(image: str) -> str:
        seen = set()
        while image in base_of and image not in seen:  # follow custom image -> its base
            seen.add(image)
            image = base_of[image]
        return _PLATFORM_BY_IMAGE[image]["family"] if image in _PLATFORM_BY_IMAGE else guess_family(image)

    built = []
    for build in builds:
        image = build["image"]
        if build["status"] != "done" or image in _PLATFORM_BY_IMAGE or any(o["image"] == image for o in built):
            continue
        built.append({
            "image": image,
            "label": image,
            "contains": f"zbudowany z {build['base_image']}",
            "execution_types": _inherited_execution_types(image) or _inherited_execution_types(build["base_image"]) or ["shell"],
            "family": family(image),
        })
    groups = [{"label": "Obrazy platformy", "options": PLATFORM_BASE_IMAGES}]
    if built:
        groups.append({"label": "Twoje zbudowane obrazy", "options": built})
    return groups


def _parse_build_form(form: Any) -> dict[str, Any]:
    """Validate the builder form; raises HTTPException(400) with a readable message."""
    image = validate_image_ref(str(form.get("image") or ""), "image tag")
    base_image = str(form.get("base_image") or "")
    if base_image == CUSTOM_BASE:  # "other image" option — the reference comes from a separate field
        base_image = str(form.get("base_image_custom") or "")
    base_image = validate_image_ref(base_image, "base image")
    runtime_class = slug(str(form.get("runtime_class") or image.rsplit("/", 1)[-1].split(":", 1)[0]))
    # "apt_packages" is the historical field name — these are system packages for any package manager.
    system_packages = clean_words(str(form.get("apt_packages") or ""), r"[a-zA-Z0-9][a-zA-Z0-9+._:-]*", "system package")
    pip_packages = clean_words(str(form.get("pip_packages") or ""), r"[a-zA-Z0-9][a-zA-Z0-9+._:/<>=!~-]*", "pip package")
    allowed_execution_types = clean_words(
        str(form.get("allowed_execution_types") or ""),
        r"[a-zA-Z0-9_][a-zA-Z0-9_-]*",
        "execution type",
    ) or _inherited_execution_types(base_image) or ["http_request"]
    risk_level = str(form.get("risk_level") or "low")
    if risk_level not in {"low", "medium", "high"}:
        raise HTTPException(status_code=400, detail="Invalid risk level")
    return {
        "image": image,
        "base_image": base_image,
        "runtime_class": runtime_class,
        "system_packages": system_packages,
        "pip_packages": pip_packages,
        "allowed_execution_types": allowed_execution_types,
        "risk_level": risk_level,
        "security_profile": str(form.get("security_profile") or "restricted").strip() or "restricted",
        "extra_dockerfile": str(form.get("extra_dockerfile") or ""),
    }


@router.get("/runtime-images", response_class=HTMLResponse)
def runtime_images_page(ok: str = "", error: str = "") -> str:
    builds = store.rows("SELECT * FROM runtime_image_builds ORDER BY created_at DESC")
    is_admin = (current_user.get() or {}).get("role") == "admin"
    builtin_rows = [
        {"image": item["image"], "base_image": PLATFORM_IMAGE_BASE, "runtime_class": item["runtime_class"],
         "status": "builtin", "error": None, "created_at": "—", "id": "builtin", "dockerfile": ""}
        for item in PLATFORM_BASE_IMAGES
    ]
    return render_page(
        "images",
        "pages/runtime_images.html",
        ok=ok,
        error=error,
        is_admin=is_admin,
        base_image_groups=_base_image_groups(builds),
        custom_base=CUSTOM_BASE,
        system_presets=SYSTEM_TOOL_PRESETS,
        pip_presets=PIP_TOOL_PRESETS,
        builds=builds,
        builtin_rows=builtin_rows,
        stats_done=sum(1 for b in builds if b["status"] == "done"),
        stats_running=sum(1 for b in builds if b["status"] in ("pending", "running")),
        stats_failed=sum(1 for b in builds if b["status"] == "failed"),
    )


@router.get("/api/runtime-image-builds")
def list_image_builds() -> list[dict[str, Any]]:
    """Build statuses — polled by the builder page while builds are in progress."""
    return store.rows("SELECT id, image, status, error, updated_at FROM runtime_image_builds ORDER BY created_at DESC")


@router.get("/api/runtime-image-builds/latest")
def get_latest_build_status(rc: str = "") -> dict[str, Any]:
    """Poll latest build status for a given runtime class name."""
    if rc:
        row = store.one(
            "SELECT id, status, error, updated_at FROM runtime_image_builds WHERE runtime_class = ? ORDER BY created_at DESC LIMIT 1",
            (rc,),
        )
    else:
        row = store.one("SELECT id, status, error, updated_at FROM runtime_image_builds ORDER BY created_at DESC LIMIT 1")
    if not row:
        return {"status": "not_found"}
    return dict(row)


@router.delete("/api/runtime-image-builds/{build_id}")
async def delete_image_build(build_id: str, request: Request):
    user = current_user.get()
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Tylko admin może usuwać obrazy")
    row = store.one("SELECT * FROM runtime_image_builds WHERE id = ?", (build_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono buildu")
    # Try to remove Docker image
    image = row["image"]
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        client.images.remove(image, force=True)
    except Exception:
        pass  # Image may not exist locally or Docker unavailable — still remove from DB
    store.execute("DELETE FROM runtime_image_builds WHERE id = ?", (build_id,))
    store.execute("DELETE FROM runtime_classes WHERE runtime_image = ?", (image,))
    store.audit(user["username"], "delete_image_build", "runtime_image_build", build_id, {"image": image})
    return JSONResponse({"ok": True})


@router.post("/api/runtime-images/preview")
async def preview_runtime_image(request: Request) -> JSONResponse:
    """Dockerfile that a build with this form would use (nothing is queued)."""
    try:
        spec = _parse_build_form(await request.form())
    except HTTPException as exc:
        return JSONResponse({"ok": False, "detail": str(exc.detail)}, status_code=400)
    dockerfile = build_runtime_dockerfile(
        spec["base_image"], spec["system_packages"], spec["pip_packages"], spec["extra_dockerfile"]
    )
    return JSONResponse({
        "ok": True,
        "dockerfile": dockerfile,
        "runtime_class": spec["runtime_class"],
        "allowed_execution_types": spec["allowed_execution_types"],
    })


@router.post("/api/runtime-images/build")
async def build_runtime_image(request: Request):
    try:
        spec = _parse_build_form(await request.form())
        image, runtime_class = spec["image"], spec["runtime_class"]
        build_id = enqueue_runtime_image_build(
            image, spec["base_image"], spec["system_packages"], spec["pip_packages"], spec["extra_dockerfile"], runtime_class
        )
        now = store.now_iso()
        store.execute(
            sql.UPSERT_RUNTIME_CLASS,
            (
                runtime_class,
                f"Custom runtime image built by MCP Platform: {image}",
                image,
                json.dumps(spec["allowed_execution_types"]),
                1,
                spec["risk_level"],
                spec["security_profile"],
                now,
                now,
            ),
        )
        for execution_type in spec["allowed_execution_types"]:
            contract = adapter_contracts().get(execution_type, {"name": execution_type, "config_schema": {}})
            store.execute(
                """
                INSERT INTO execution_adapters(name, description, adapter_type, runtime_image, config_schema_json,
                                               adapter_contract_json, enabled, implemented, risk_level, mode, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  runtime_image = excluded.runtime_image,
                  adapter_contract_json = excluded.adapter_contract_json,
                  enabled = excluded.enabled,
                  implemented = excluded.implemented,
                  risk_level = excluded.risk_level,
                  updated_at = excluded.updated_at
                """,
                (
                    execution_type,
                    f"{execution_type} execution adapter for custom runtime image {image}",
                    execution_type,
                    image,
                    json.dumps(contract.get("config_schema") or {}),
                    json.dumps(contract),
                    1,
                    1,
                    spec["risk_level"],
                    "read-only",
                    now,
                    now,
                ),
            )
        store.audit("admin", "upsert_runtime_class_from_image_build", "runtime_class", runtime_class, {"image": image, "build": build_id})
    except HTTPException as exc:
        return RedirectResponse(f"/runtime-images?error={quote(str(exc.detail))}", status_code=303)
    ok = f"Budowanie obrazu {image} zlecone — status zobaczysz na liście poniżej."
    return RedirectResponse(f"/runtime-images?ok={quote(ok)}#builds", status_code=303)

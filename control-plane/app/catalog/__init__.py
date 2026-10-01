"""Catalog of example MCP servers shipped with the platform.

packages/*.json  — built-in Tool Packages (same format as the repo-level templates/ presets),
                   seeded in filename order.
runtimes/*.json  — example runtimes created on first start (runtime row + tools + policy).

Extra presets are loaded from MCP_PLATFORM_TEMPLATES_DIR (default: <repo>/templates). That
directory is not part of the image — compose bind-mounts it, K8s uses a ConfigMap.
"""
import json
import os
from pathlib import Path
from typing import Any

CATALOG_DIR = Path(__file__).parent
PACKAGES_DIR = CATALOG_DIR / "packages"
RUNTIMES_DIR = CATALOG_DIR / "runtimes"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _templates_dir() -> Path:
    return Path(
        os.getenv("MCP_PLATFORM_TEMPLATES_DIR")
        or Path(__file__).resolve().parent.parent.parent.parent / "templates"
    )


def builtin_packages() -> list[dict[str, Any]]:
    return [_read_json(p) for p in sorted(PACKAGES_DIR.glob("*.json"))]


def builtin_package(package_id: str) -> dict[str, Any]:
    return next(p for p in builtin_packages() if p["id"] == package_id)


def extra_packages(exclude_ids: set[str]) -> list[dict[str, Any]]:
    """Presets from the templates directory; ids of built-in packages are skipped."""
    templates_dir = _templates_dir()
    packages = []
    if templates_dir.exists():
        for path in templates_dir.rglob("*.json"):
            try:
                package = _read_json(path)
            except Exception:
                continue
            if not isinstance(package, dict):
                continue
            if package.get("id") and package.get("tools") and package["id"] not in exclude_ids:
                packages.append(package)
    return packages


def builtin_tool_packages() -> list[dict[str, Any]]:
    """Built-in packages followed by presets from the templates directory."""
    builtin = builtin_packages()
    return builtin + extra_packages({p["id"] for p in builtin})


def example_runtimes() -> list[dict[str, Any]]:
    runtimes = [_read_json(p) for p in sorted(RUNTIMES_DIR.glob("*.json"))]
    for runtime in runtimes:
        if "tools_from_package" in runtime:
            runtime["tools"] = builtin_package(runtime["tools_from_package"])["tools"]
    return runtimes

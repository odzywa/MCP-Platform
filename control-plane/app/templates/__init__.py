"""Loader for standalone HTML view templates (string.Template, $placeholder syntax)."""
from pathlib import Path
from string import Template

_DIR = Path(__file__).parent


def render_template(name: str, **values: str) -> str:
    path = _DIR / f"{name}.html"
    return Template(path.read_text(encoding="utf-8")).safe_substitute(**values)

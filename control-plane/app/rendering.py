"""Jinja2 environment for the HTML views.

Templates live in app/templates (pages/, partials/, auth/), static assets in app/static.
Autoescaping is on: values are escaped unless they are Markup (helpers returning HTML
wrap their output in Markup, partial templates are rendered with render_markup()).
"""
import json
from pathlib import Path
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup, escape

APP_DIR = Path(__file__).parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"

env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)
env.globals.update(
    abs=abs, all=all, any=any, bool=bool, chr=chr, dict=dict, enumerate=enumerate, float=float,
    format=format, getattr=getattr, hasattr=hasattr, int=int, isinstance=isinstance, len=len,
    list=list, max=max, min=min, repr=repr, reversed=reversed, round=round, set=set, sorted=sorted,
    str=str, sum=sum, tuple=tuple, zip=zip,
    escape=escape, json=json, quote=quote,
)


def render(name: str, /, **ctx) -> str:
    return env.get_template(name).render(**ctx)


def render_markup(name: str, /, **ctx) -> Markup:
    """Render a partial template for embedding in another template."""
    return Markup(render(name, **ctx))


def static_text(path: str) -> str:
    return (STATIC_DIR / path).read_text(encoding="utf-8")

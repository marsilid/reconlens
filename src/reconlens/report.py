"""HTML and JSON report writers."""

from __future__ import annotations

import json
import re
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup, escape

from reconlens import __version__
from reconlens.models import LookupReport, ScanReport

_ACRONYMS = frozenset(
    {
        "a",
        "aaaa",
        "caa",
        "cn",
        "dkim",
        "dmarc",
        "dns",
        "dnssec",
        "http",
        "https",
        "ip",
        "ips",
        "mx",
        "ns",
        "ptr",
        "san",
        "soa",
        "spf",
        "tls",
        "txt",
        "url",
    }
)
_CODE_SPAN = re.compile(r"`([^`]+)`")


def _humanize(key: object) -> str:
    words = str(key).replace("_", " ").replace("-", " ").split()
    words = [w.upper() if w.lower() in _ACRONYMS else w for w in words]
    text = " ".join(words)
    return text[:1].upper() + text[1:]


def _codespans(text: str) -> Markup:
    """Escape text, then turn `backticked` fragments into <code> elements."""
    return Markup(_CODE_SPAN.sub(r"<code>\1</code>", str(escape(text))))


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("reconlens", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["humanize"] = _humanize
    env.filters["codespans"] = _codespans
    return env


def render_html(report: ScanReport) -> str:
    template = _environment().get_template("report.html.j2")
    return template.render(report=report, version=__version__)


def write_html(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path


def render_lookup_html(result: LookupReport) -> str:
    template = _environment().get_template("lookup.html.j2")
    return template.render(version=__version__, **result.to_context())


def write_lookup_html(result: LookupReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_lookup_html(result), encoding="utf-8")
    return path


def write_lookup_json(result: LookupReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path


def write_json(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return path

"""Standalone HTML report for one image (no external assets, safe against injected content)."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from podshield import __version__
from podshield.api_models import SEVERITIES, FindingOut, ImageDetail

# Report content comes from untrusted images (labels, env names, file paths), so autoescape
# is forced on, not left to the template extension.
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)

CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"


def _size_h(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024 or unit == "TiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TiB"  # pragma: no cover


def _dt(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "unknown"


def render_report(image: ImageDetail) -> str:
    grouped: dict[str, list[FindingOut]] = defaultdict(list)
    for f in image.findings:
        grouped[f.severity.value].append(f)
    return _env.get_template("report.html.j2").render(
        image=image,
        severities=SEVERITIES,
        grouped=grouped,
        unavailable=[s for s in image.scanners if s.status != "ok"],
        max_layer=max((layer.size for layer in image.layers), default=0),
        size_h=_size_h,
        dt=_dt,
        version=__version__,
        generated=_dt(datetime.now(UTC)),
    )

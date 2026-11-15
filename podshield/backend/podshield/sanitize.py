"""Turn an ``ImageInfo`` into a JSON-safe snapshot with secrets masked.

The snapshot is what gets stored in the database and shown in the UI/reports (config tab,
layers tab). Raw ENV values, command lines, labels and layer history never leave this module
unredacted, because they commonly contain baked-in credentials.
"""

from __future__ import annotations

from typing import Any

from podshield.scanners.secrets import mask, redact, scan_env
from podshield.schemas import ImageInfo

BASE_NAME_KEY = "org.opencontainers.image.base.name"


def base_image_of(image: ImageInfo) -> str | None:
    """Best-effort base image name from labels/annotations (Podman does not record it)."""
    meta = {**image.labels, **image.annotations}
    if base := meta.get(BASE_NAME_KEY, "").strip():
        return base
    if meta.get("vendor", "").lower().startswith("red hat") and (name := meta.get("name")):
        return f"{name} (inherited Red Hat labels)"
    return None


def _redact_list(items: list[str]) -> list[str]:
    return [redact(i) for i in items]


def sanitize_image(image: ImageInfo) -> dict[str, Any]:
    flagged = {m.location.removeprefix("ENV ") for m in scan_env(image.env_pairs)}
    env = [
        f"{name}={mask(value)}" if name in flagged else redact(f"{name}={value}")
        for name, value in image.env_pairs
    ]
    healthcheck = image.healthcheck
    if healthcheck is not None:
        healthcheck = {
            k: _redact_list([str(x) for x in v]) if isinstance(v, list) else v
            for k, v in healthcheck.items()
        }
    return {
        "architecture": image.architecture,
        "os": image.os,
        "user": image.user,
        "env": env,
        "entrypoint": _redact_list(image.entrypoint),
        "cmd": _redact_list(image.cmd),
        "exposed_ports": image.exposed_ports,
        "labels": {k: redact(v) for k, v in image.labels.items()},
        "healthcheck": healthcheck,
        "layer_count": image.layer_count,
        "base_image": base_image_of(image),
        "layers": [
            {
                "created_by": redact(layer.created_by),
                "created": layer.created.isoformat() if layer.created else None,
                "size": layer.size,
                "empty": layer.empty,
                "comment": redact(layer.comment),
            }
            for layer in image.layers
        ],
    }

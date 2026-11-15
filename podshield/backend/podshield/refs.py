"""Image reference validation shared by the Podman client and scanners."""

from __future__ import annotations

import re

_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]*$")


def validate_reference(reference: str) -> str:
    """Reject image references that could be mistaken for options or contain odd characters.

    Returns the cleaned reference (a leading ``docker://`` is stripped).
    """
    ref = reference.strip().removeprefix("docker://")
    if not ref or len(ref) > 512 or not _REFERENCE_RE.match(ref):
        raise ValueError(f"invalid image reference: {reference!r}")
    return ref

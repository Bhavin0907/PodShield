"""Secret detection helpers. Detected values are never returned unmasked.

Phase 1 covers image ENV. Filesystem layer scanning (PS-004) is added in Phase 2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Env var names that suggest a secret. Matches whole underscore-delimited words so that
# PWD or TOKENIZERS_PARALLELISM do not trigger.
_NAME_RE = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIALS?|API_?KEY|PRIVATE_?KEY|"
    r"ACCESS_?KEY|SECRET_?KEY|AUTH_?KEY|ENCRYPTION_?KEY|SIGNING_?KEY|CLIENT_?SECRET)"
    r"(?:$|_)",
    re.IGNORECASE,
)
# Names ending in these usually reference a location, not the secret itself.
_REFERENCE_SUFFIXES = (
    "_FILE",
    "_PATH",
    "_DIR",
    "_NAME",
    "_ID",
    "_URL",
    "_URI",
    "_ENABLED",
    # settings *about* a secret (policy, lifetime, size), not the secret itself
    "_LENGTH",
    "_POLICY",
    "_TTL",
    "_EXPIRY",
    "_EXPIRES",
    "_EXPIRATION",
    "_TIMEOUT",
    "_LIFETIME",
    "_DAYS",
    "_SECONDS",
    "_MINUTES",
    "_HOURS",
    "_TYPE",
    "_ALGORITHM",
    "_HEADER",
    "_REQUIRED",
    "_FORMAT",
    "_COUNT",
    "_MODE",
)

# (label, regex) for values that look like secrets regardless of the variable name.
VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")),
    ("Credentials in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@")),
)

_PLACEHOLDER_RE = re.compile(r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|<.*>|\{\{.*\}\})$")
_NON_SECRET_VALUES = {"", "true", "false", "yes", "no", "none", "null", "0", "1", "required"}


@dataclass(frozen=True)
class SecretMatch:
    location: str  # e.g. "ENV DB_PASSWORD"
    reason: str
    masked_value: str


def mask(value: str) -> str:
    """Show only the first 4 characters followed by ****.

    Never more than half of the value, so a short secret (``abc``) is not echoed back whole.
    """
    return f"{value[: min(4, len(value) // 2)]}****"


def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in _NON_SECRET_VALUES or bool(_PLACEHOLDER_RE.match(value.strip()))


# File contents are noisier than ENV (docs, test fixtures), so only high-confidence patterns.
_FILE_PATTERNS = tuple(
    (label, pat)
    for label, pat in VALUE_PATTERNS
    if label not in {"Credentials in URL", "JSON Web Token"}
)


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return (line_number, reason, masked_value) for high-confidence secrets in text."""
    hits: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in _FILE_PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append((number, f"{label} pattern", mask(match.group(0))))
                break
    return hits


_ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_.-]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIALS?|API_?KEY|"
    r"PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY)[A-Za-z0-9_.-]*)=(?P<value>[^\s&;|\"']+)",
    re.IGNORECASE,
)
_ENV_SPACE_RE = re.compile(
    r"(?P<prefix>\bENV\s+)(?P<name>[A-Za-z0-9_.-]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|"
    r"CREDENTIALS?|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY)[A-Za-z0-9_.-]*)\s+"
    r"(?P<value>[^\s=]\S*)",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Best-effort masking of secret-looking values in free text (e.g. image history).

    Used before anything derived from an image is stored or shown. Known token formats are
    masked wherever they appear; ``NAME=value`` and ``ENV NAME value`` are masked when NAME
    looks like a secret. This is a safety net, not a guarantee.
    """
    for _label, pattern in VALUE_PATTERNS:
        text = pattern.sub(lambda m: mask(m.group(0)), text)

    def assign(m: re.Match[str]) -> str:
        name, value = m.group("name"), m.group("value")
        if name.upper().endswith(_REFERENCE_SUFFIXES) or _is_placeholder(value):
            return m.group(0)
        return f"{name}={mask(value)}"

    def env_space(m: re.Match[str]) -> str:
        name, value = m.group("name"), m.group("value")
        if name.upper().endswith(_REFERENCE_SUFFIXES) or _is_placeholder(value):
            return m.group(0)
        return f"{m.group('prefix')}{name} {mask(value)}"

    return _ENV_SPACE_RE.sub(env_space, _ASSIGN_RE.sub(assign, text))


def scan_env(pairs: list[tuple[str, str]]) -> list[SecretMatch]:
    """Inspect (name, value) env pairs; return masked matches."""
    matches: list[SecretMatch] = []
    for name, value in pairs:
        if _is_placeholder(value):
            continue
        reason: str | None = None
        for label, pattern in VALUE_PATTERNS:
            if pattern.search(value):
                reason = f"value matches {label} pattern"
                break
        if (
            reason is None
            and _NAME_RE.search(name)
            and not name.upper().endswith(_REFERENCE_SUFFIXES)
        ):
            reason = "variable name suggests a secret"
        if reason:
            matches.append(SecretMatch(f"ENV {name}", reason, mask(value)))
    return matches

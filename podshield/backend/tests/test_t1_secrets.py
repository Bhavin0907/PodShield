"""T1: secret detection (true positives, false positives) and the masking guarantee.

Every credential below is fake: AWS's documented example keys, `ghp_` plus filler, and
passwords such as "hunter2".
"""

from __future__ import annotations

import pytest

from podshield.config import Settings
from podshield.scanners import secrets
from podshield.scanners.hygiene import build_rules
from podshield.schemas import ImageInfo

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_TEMP_KEY = "ASIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GH_CLASSIC = "ghp_" + "x" * 36
GH_OAUTH = "gho_" + "y" * 36
GH_SERVER = "ghs_" + "z" * 36
GH_FINE_GRAINED = "github_pat_" + "A1b2C3d4E5" * 8
SLACK = "xoxb-123456789012-abcdefghijkl"
GOOGLE = "AIza" + "S" * 35
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJl"
URL_CREDS = "postgres://admin:hunter2@db.internal:5432/app"
KEY_HEADERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
]


def hit(name: str, value: str) -> bool:
    return bool(secrets.scan_env([(name, value)]))


# ------------------------------------------------------------------- true positives


@pytest.mark.parametrize(
    "name",
    [
        "PASSWORD",
        "DB_PASSWORD",
        "MYSQL_ROOT_PASSWORD",
        "POSTGRES_PASSWORD",
        "password",
        "API_KEY",
        "APIKEY",
        "api_key",
        "GITHUB_TOKEN",
        "AUTH_TOKEN",
        "TOKEN",
        "SECRET",
        "SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "CLIENT_SECRET",
        "PRIVATE_KEY",
        "JWT_SECRET",
        "REDIS_PASSWD",
        "GPG_PASSPHRASE",
        "SERVICE_CREDENTIALS",
        "ENCRYPTION_KEY",
        "SIGNING_KEY",
    ],
)
def test_secret_looking_names_with_real_looking_values_are_flagged(name: str) -> None:
    assert hit(name, "hunter2-not-a-real-password")


@pytest.mark.parametrize(
    "value",
    [
        AWS_KEY,
        AWS_TEMP_KEY,
        GH_CLASSIC,
        GH_OAUTH,
        GH_SERVER,
        GH_FINE_GRAINED,
        SLACK,
        GOOGLE,
        JWT,
        URL_CREDS,
        *KEY_HEADERS,
    ],
)
def test_known_token_formats_are_flagged_under_any_variable_name(value: str) -> None:
    (match,) = secrets.scan_env([("MYAPP_SETTING", value)])
    assert "pattern" in match.reason


def test_value_pattern_in_the_middle_of_a_longer_string() -> None:
    assert hit("CONFIG", f"aws_access_key_id={AWS_KEY};region=us-east-1")


@pytest.mark.parametrize("header", KEY_HEADERS)
def test_private_key_headers_found_in_file_content(header: str) -> None:
    text = f"line one\n{header}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
    ((number, reason, masked),) = secrets.scan_text(text)
    assert number == 2 and "Private key" in reason and masked == "----****"


@pytest.mark.parametrize(
    "value", [AWS_KEY, AWS_TEMP_KEY, GH_CLASSIC, GH_FINE_GRAINED, SLACK, GOOGLE]
)
def test_file_scanner_finds_high_confidence_tokens(value: str) -> None:
    assert len(secrets.scan_text(f"token = {value}\n")) == 1


def test_file_scanner_reports_the_right_lines() -> None:
    text = f"a\nb\nkey={AWS_KEY}\nc\n{GH_CLASSIC}\n"
    assert [n for n, _r, _m in secrets.scan_text(text)] == [3, 5]


# ------------------------------------------------------------------ false positives


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PASSWORD_FILE", "/run/secrets/db_password"),  # a path to the secret, not the secret
        ("DB_PASSWORD_FILE", "/run/secrets/x"),
        ("SECRET_KEY_FILE", "/run/secrets/key"),
        ("TOKEN_PATH", "/var/run/token"),
        ("API_KEY_URL", "https://vault.internal/keys"),
        ("TOKEN_NAME", "build-token"),
        ("PASSWORD_MIN_LENGTH", "12"),
        ("PASSWORD_POLICY", "strict"),
        ("TOKEN_EXPIRY", "3600"),
        ("TOKEN_TTL", "300"),
        ("SECRET_ROTATION_DAYS", "30"),
        ("TOKENIZERS_PARALLELISM", "false"),
        ("PWD", "/app"),
        ("KEYBOARD_LAYOUT", "us"),
        ("MONKEY", "banana"),
        ("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock"),
        ("PATH", "/usr/local/bin:/usr/bin"),
        ("LANG", "C.UTF-8"),
        ("JAVA_TOOL_OPTIONS", "-Xmx512m"),
        ("DB_PASSWORD", "${DB_PASSWORD}"),
        ("DB_PASSWORD", "$DB_PASSWORD"),
        ("DB_PASSWORD", "<your-password-here>"),
        ("DB_PASSWORD", "{{ .Values.password }}"),
        ("DB_PASSWORD", ""),
        ("AUTH_ENABLED", "true"),
        ("SECRET_REQUIRED", "required"),
        ("HOME_URL", "https://example.com/path"),
        ("REPO", "https://user@github.com/org/repo.git"),  # a user name, no password
    ],
)
def test_not_flagged(name: str, value: str) -> None:
    assert not hit(name, value)


def test_password_file_reference_produces_no_ps003_finding(settings: Settings) -> None:
    rule = next(r for r in build_rules(settings) if r.id == "PS-003")
    img = ImageInfo(id="x", env=["PASSWORD_FILE=/run/secrets/x", "DB_PASSWORD_FILE=/run/secrets/y"])
    assert rule.evaluate(img) == []


def test_file_scanner_ignores_ordinary_text() -> None:
    text = "password policy: use a long passphrase\nexample: AKIA-prefix keys start with AKIA\n"
    assert secrets.scan_text(text) == []


# --------------------------------------------------------------------------- masking

ALL_SECRET_VALUES = [
    AWS_KEY,
    AWS_TEMP_KEY,
    GH_CLASSIC,
    GH_OAUTH,
    GH_SERVER,
    GH_FINE_GRAINED,
    SLACK,
    GOOGLE,
    JWT,
    URL_CREDS,
    "hunter2-not-a-real-password",
]


def leaks(text: str, secret: str) -> bool:
    """True if more than the 4-character prefix of ``secret`` appears in ``text``."""
    return secret[:5] in text or secret[4:] in text


@pytest.mark.parametrize("value", ALL_SECRET_VALUES)
def test_scan_env_never_returns_more_than_a_four_character_prefix(value: str) -> None:
    (match,) = secrets.scan_env([("DB_PASSWORD", value)])
    assert match.masked_value == value[:4] + "****"
    assert not leaks(repr(match), value)


@pytest.mark.parametrize("value", ALL_SECRET_VALUES)
def test_ps003_evidence_is_masked(value: str, settings: Settings) -> None:
    rule = next(r for r in build_rules(settings) if r.id == "PS-003")
    (finding,) = rule.evaluate(ImageInfo(id="x", env=[f"API_TOKEN={value}"]))
    assert not leaks(finding.model_dump_json(), value)
    assert value[:4] + "****" in " ".join(finding.evidence)


@pytest.mark.parametrize("value", [AWS_KEY, GH_CLASSIC, SLACK, GOOGLE])
def test_scan_text_output_is_masked(value: str) -> None:
    ((_n, _reason, masked),) = secrets.scan_text(f"x = {value}")
    assert masked == value[:4] + "****"


@pytest.mark.parametrize(
    "line",
    [
        f"RUN echo {AWS_KEY} > /root/key",
        f"RUN git clone https://{GH_CLASSIC}@github.com/org/repo.git",
        "ENV DB_PASSWORD hunter2-not-a-real-password",
        f"ENV API_TOKEN={GH_CLASSIC}",
        "RUN curl -u admin:hunter2 https://x && export DB_PASSWORD=hunter2-not-a-real-password",
        f"RUN psql {URL_CREDS}",
    ],
)
def test_redact_masks_history_lines(line: str) -> None:
    out = secrets.redact(line)
    for secret in (AWS_KEY, GH_CLASSIC, "hunter2-not-a-real-password", "hunter2@"):
        assert secret not in out or secret == "hunter2@" and "hunter2@" not in out


def test_redact_keeps_references_and_ordinary_text_unchanged() -> None:
    for line in [
        "RUN dnf install -y python3",
        "ENV PASSWORD_FILE=/run/secrets/x",
        "ENV DB_PASSWORD=${DB_PASSWORD}",
        "ENV TOKEN_TTL=300",
    ]:
        assert secrets.redact(line) == line


@pytest.mark.parametrize("short", ["a", "ab", "abc", "abcd", "abcde"])
def test_short_secrets_are_never_revealed_in_full(short: str) -> None:
    masked = secrets.mask(short)
    assert masked.endswith("****")
    assert short not in masked, "a short secret must not be echoed back in full"


def test_mask_of_empty_value_is_just_stars() -> None:
    assert secrets.mask("") == "****"

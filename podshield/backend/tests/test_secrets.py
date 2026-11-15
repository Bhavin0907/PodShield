from __future__ import annotations

import pytest

from podshield.scanners.secrets import mask, scan_env


def test_mask_shows_four_chars() -> None:
    assert mask("supersecret") == "supe****"
    # A value of 4 characters or fewer used to be echoed back whole ("ab" -> "ab****"),
    # which defeats masking; at most half of the value is shown now.
    assert mask("ab") == "a****"
    assert mask("abcdefgh") == "abcd****"


@pytest.mark.parametrize(
    "name,value",
    [
        ("DB_PASSWORD", "hunter2"),
        ("API_KEY", "abc123"),
        ("GITHUB_TOKEN", "x"),
        ("STRIPE_SECRET_KEY", "sk_live_abc"),
        ("MY_PRIVATE_KEY", "xyz"),
        ("FOO", "ghp_" + "a" * 36),
        ("FOO", "xoxb-1234567890-abcdef"),
        ("FOO", "-----BEGIN RSA PRIVATE KEY-----"),
        ("FOO", "AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_detects(name: str, value: str) -> None:
    matches = scan_env([(name, value)])
    assert len(matches) == 1
    assert value not in matches[0].masked_value or len(value) <= 4


@pytest.mark.parametrize(
    "name,value",
    [
        ("PATH", "/usr/bin"),
        ("PWD", "/"),
        ("TOKENIZERS_PARALLELISM", "false"),
        ("DB_PASSWORD", ""),
        ("DB_PASSWORD", "${DB_PASSWORD}"),
        ("DB_PASSWORD", "<your-password>"),
        ("DB_PASSWORD_FILE", "/run/secrets/db"),
        ("SECRET_PATH", "/run/secrets"),
        ("USE_TOKEN", "true"),
        ("KEYBOARD", "us"),
    ],
)
def test_ignores(name: str, value: str) -> None:
    assert scan_env([(name, value)]) == []

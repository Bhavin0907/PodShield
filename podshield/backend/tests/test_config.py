from __future__ import annotations

from pathlib import Path

import pytest

from podshield.config import ConfigError, load_settings
from podshield.schemas import Severity


def test_defaults_when_file_missing(tmp_path: Path) -> None:
    s = load_settings(tmp_path / "nope.toml", env={})
    assert s.podman.socket == "unix:///run/podman/podman.sock"
    assert s.database.path == "/var/lib/podshield/podshield.db"
    assert s.thresholds.max_image_age_days == 90


def test_file_values_and_rule_overrides(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        """
[podman]
socket = "unix:///run/user/1000/podman/podman.sock"
mode = "rootless"

[thresholds]
max_image_age_days = 30

[rules.PS-005]
enabled = false

[rules.PS-011]
severity = "medium"
""",
        encoding="utf-8",
    )
    s = load_settings(cfg, env={})
    assert s.podman.socket.endswith("/1000/podman/podman.sock")
    assert s.podman.mode == "rootless"
    assert s.thresholds.max_image_age_days == 30
    assert s.rule_override("PS-005").enabled is False
    assert s.rule_override("PS-011").severity is Severity.MEDIUM
    assert s.rule_override("PS-001").enabled is None


def test_env_overrides_file(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[database]\npath = "/from/file.db"\n', encoding="utf-8")
    s = load_settings(
        cfg,
        env={
            "PODSHIELD_DB_PATH": "/from/env.db",
            "PODSHIELD_PODMAN_SOCKET": "unix:///x.sock",
            "PODSHIELD_MAX_IMAGE_AGE_DAYS": "7",
            "PODSHIELD_LOG_LEVEL": "debug",
        },
    )
    assert s.database.path == "/from/env.db"
    assert s.podman.socket == "unix:///x.sock"
    assert s.thresholds.max_image_age_days == 7
    assert s.logging.level == "DEBUG"


def test_config_path_from_env(tmp_path: Path) -> None:
    cfg = tmp_path / "alt.toml"
    cfg.write_text("[thresholds]\nmax_layers = 5\n", encoding="utf-8")
    assert load_settings(env={"PODSHIELD_CONFIG": str(cfg)}).thresholds.max_layers == 5


def test_invalid_toml_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[podman\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, env={})


def test_unknown_key_and_bad_value_raise(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.toml"
    cfg.write_text("[thresholds]\nmax_image_age_days = 0\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, env={})
    cfg.write_text("[podmann]\nsocket = 'x'\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, env={})


def test_bad_severity_override_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.toml"
    cfg.write_text('[rules.PS-001]\nseverity = "urgent"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(cfg, env={})

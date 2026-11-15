"""T1: configuration loading (defaults, file, environment) and validation errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from podshield.config import ConfigError, Settings, load_settings


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def load(tmp_path: Path, text: str, env: dict[str, str] | None = None) -> Settings:
    return load_settings(write(tmp_path, text), env=env or {})


# ---------------------------------------------------------------------------- defaults


def test_defaults_for_every_section(tmp_path: Path) -> None:
    s = load_settings(tmp_path / "missing.toml", env={})
    assert s == Settings()
    assert (s.podman.socket, s.podman.mode, s.podman.timeout_seconds) == (
        "unix:///run/podman/podman.sock",
        "rootful",
        30,
    )
    assert s.database.path == "/var/lib/podshield/podshield.db"
    assert s.logging.level == "INFO"
    assert (
        s.thresholds.max_image_age_days,
        s.thresholds.max_image_size_mb,
        s.thresholds.max_layers,
    ) == (90, 1024, 30)
    assert s.filesystem.enabled and s.oscap.enabled and s.trivy.enabled
    assert s.oscap.binary == "oscap-podman" and s.trivy.binary == "trivy"
    assert s.registry.binary == "skopeo" and s.registry.tls_verify is True
    assert "registry.access.redhat.com" in s.trust.trusted_registries
    assert s.scoring.cve_cap == 40 and s.rules == {}
    assert s.watcher.debounce_seconds == 5.0 and not s.watcher.scan_on_start


def test_empty_file_means_defaults(tmp_path: Path) -> None:
    assert load(tmp_path, "") == Settings()
    assert load(tmp_path, "# only a comment\n") == Settings()


def test_defaults_are_not_shared_between_instances() -> None:
    a, b = Settings(), Settings()
    a.trust.trusted_registries.append("example.com")
    a.watcher.actions.append("push")
    assert "example.com" not in b.trust.trusted_registries and "push" not in b.watcher.actions


# --------------------------------------------------------------------------- TOML file


def test_partial_section_keeps_other_defaults(tmp_path: Path) -> None:
    s = load(tmp_path, "[thresholds]\nmax_layers = 5\n")
    assert s.thresholds.max_layers == 5
    assert s.thresholds.max_image_age_days == 90 and s.thresholds.max_image_size_mb == 1024


def test_every_section_can_be_overridden(tmp_path: Path) -> None:
    s = load(
        tmp_path,
        """
[podman]
socket = "unix:///run/user/1000/podman/podman.sock"
timeout_seconds = 5
mode = "rootless"
[database]
path = "/tmp/x.db"
[logging]
level = "debug"
[server]
static_dir = "/srv/ui"
[watcher]
actions = ["pull"]
debounce_seconds = 0
scan_on_start = true
[thresholds]
max_image_age_days = 30
max_image_size_mb = 200
max_layers = 10
[trust]
trusted_registries = ["quay.io/acme"]
[filesystem]
enabled = false
max_files = 1000
[oscap]
enabled = false
oval_path = "/data/rhel-9.oval.xml.bz2"
[trivy]
skip_db_update = true
[registry]
tls_verify = false
authfile = "/run/auth.json"
[scoring]
critical = 30
cve_cap = 20
[rules.PS-001]
enabled = false
[rules.PS-002]
severity = "critical"
""",
    )
    assert s.podman.mode == "rootless" and s.podman.timeout_seconds == 5
    assert s.logging.level == "DEBUG"  # normalised
    assert s.server.static_dir == "/srv/ui"
    assert s.watcher.actions == ["pull"] and s.watcher.scan_on_start
    assert s.thresholds.max_image_size_mb == 200
    assert s.trust.trusted_registries == ["quay.io/acme"]
    assert not s.filesystem.enabled and s.filesystem.max_files == 1000
    assert not s.oscap.enabled and s.oscap.oval_path.endswith(".bz2")
    assert s.trivy.skip_db_update and not s.registry.tls_verify
    assert s.scoring.critical == 30 and s.scoring.cve_cap == 20
    assert s.rule_override("PS-001").enabled is False
    assert s.rule_override("PS-002").severity == "critical"


# ----------------------------------------------------------------------- environment


@pytest.mark.parametrize(
    ("var", "value", "read"),
    [
        ("PODSHIELD_PODMAN_SOCKET", "unix:///x.sock", lambda s: s.podman.socket),
        ("PODSHIELD_DB_PATH", "/e.db", lambda s: s.database.path),
        ("PODSHIELD_LOG_LEVEL", "warning", lambda s: s.logging.level),
        ("PODSHIELD_STATIC_DIR", "/ui", lambda s: s.server.static_dir),
        ("PODSHIELD_MAX_IMAGE_AGE_DAYS", "7", lambda s: s.thresholds.max_image_age_days),
    ],
)
def test_each_environment_variable_overrides_the_file(
    tmp_path: Path, var: str, value: str, read: object
) -> None:
    text = (
        '[podman]\nsocket = "unix:///file.sock"\n[database]\npath = "/file.db"\n'
        '[logging]\nlevel = "ERROR"\n[server]\nstatic_dir = "/file-ui"\n'
        "[thresholds]\nmax_image_age_days = 60\n"
    )
    s = load(tmp_path, text, env={var: value})
    got = read(s)  # type: ignore[operator]
    assert str(got).lower() == value.lower() or got == int(value)


def test_environment_without_a_file_and_empty_values_ignored(tmp_path: Path) -> None:
    s = load_settings(
        tmp_path / "none.toml", env={"PODSHIELD_DB_PATH": "/e.db", "PODSHIELD_LOG_LEVEL": ""}
    )
    assert s.database.path == "/e.db" and s.logging.level == "INFO"


def test_config_path_comes_from_environment(tmp_path: Path) -> None:
    path = write(tmp_path, "[thresholds]\nmax_layers = 3\n")
    assert load_settings(env={"PODSHIELD_CONFIG": str(path)}).thresholds.max_layers == 3


def test_explicit_path_beats_the_environment_path(tmp_path: Path) -> None:
    a = tmp_path / "a.toml"
    a.write_text("[thresholds]\nmax_layers = 1\n", encoding="utf-8")
    b = tmp_path / "b.toml"
    b.write_text("[thresholds]\nmax_layers = 2\n", encoding="utf-8")
    assert load_settings(a, env={"PODSHIELD_CONFIG": str(b)}).thresholds.max_layers == 1


# ----------------------------------------------------------------------- invalid input


@pytest.mark.parametrize(
    ("toml", "mentions"),
    [
        ("[thresholds]\nmax_image_age_days = 0\n", "max_image_age_days"),
        ("[thresholds]\nmax_image_age_days = -5\n", "max_image_age_days"),
        ('[thresholds]\nmax_layers = "many"\n', "max_layers"),
        ("[thresholds]\nmax_image_size_mb = 1.5\n", "max_image_size_mb"),
        ("[podman]\ntimeout_seconds = 0\n", "timeout_seconds"),
        ('[podman]\nmode = "sudo"\n', "mode"),
        ('[logging]\nlevel = "LOUD"\n', "level"),
        ("[scoring]\ncritical = -1\n", "critical"),
        ("[scoring]\ngrade_a = 50\ngrade_b = 80\n", "grade"),
        ("[scoring]\ngrade_a = 101\n", "grade"),
        ("[filesystem]\nmax_files = 0\n", "max_files"),
        ("[oscap]\ntimeout_seconds = 1\n", "timeout_seconds"),
        ("[watcher]\ndebounce_seconds = -1\n", "debounce_seconds"),
        ("[podmann]\nsocket = 'x'\n", "podmann"),
        ("[podman]\nsockett = 'x'\n", "sockett"),
        ("[rules.PS-001]\nenabled = 'maybe'\n", "enabled"),
        ('[rules.PS-001]\nseverity = "urgent"\n', "severity"),
        ("[rules.PS-001]\ncolour = 'red'\n", "colour"),
        ("top_level_junk = 1\n", "top_level_junk"),
    ],
)
def test_invalid_values_are_rejected_with_a_clear_message(
    tmp_path: Path, toml: str, mentions: str
) -> None:
    path = write(tmp_path, toml)
    with pytest.raises(ConfigError) as err:
        load_settings(path, env={})
    message = str(err.value)
    assert mentions in message, message
    assert str(path) in message  # tells the user which file to fix


def test_invalid_toml_syntax_names_the_file(tmp_path: Path) -> None:
    path = write(tmp_path, "[podman\nsocket = \n")
    with pytest.raises(ConfigError, match="cannot read"):
        load_settings(path, env={})


def test_config_path_that_is_a_directory(tmp_path: Path) -> None:
    # is_file() is False, so this behaves like a missing file rather than crashing
    assert load_settings(tmp_path, env={}) == Settings()


def test_unreadable_binary_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"\xff\xfe\x00garbage\x00")
    with pytest.raises(ConfigError):
        load_settings(path, env={})


@pytest.mark.parametrize(
    ("env", "mentions"),
    [
        ({"PODSHIELD_MAX_IMAGE_AGE_DAYS": "abc"}, "max_image_age_days"),
        ({"PODSHIELD_MAX_IMAGE_AGE_DAYS": "0"}, "max_image_age_days"),
        ({"PODSHIELD_LOG_LEVEL": "LOUD"}, "level"),
    ],
)
def test_invalid_environment_values_are_rejected(
    tmp_path: Path, env: dict[str, str], mentions: str
) -> None:
    with pytest.raises(ConfigError) as err:
        load_settings(tmp_path / "none.toml", env=env)
    assert mentions in str(err.value)


def test_environment_value_overrides_an_invalid_file_value_only_if_valid(tmp_path: Path) -> None:
    path = write(tmp_path, "[thresholds]\nmax_image_age_days = 0\n")
    ok = load_settings(path, env={"PODSHIELD_MAX_IMAGE_AGE_DAYS": "5"})
    assert ok.thresholds.max_image_age_days == 5

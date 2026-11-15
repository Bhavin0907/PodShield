"""Static checks on the files in deploy/ and demo/ (they cannot be run on a CI box without RHEL)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from podshield.config import Settings

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
UNITS = DEPLOY / "systemd"


class Unit:
    """Minimal systemd unit parser: repeated keys (Environment=) are all kept, in order."""

    def __init__(self, text: str) -> None:
        self.sections: dict[str, dict[str, list[str]]] = {}
        section = ""
        pending = ""
        for raw in text.replace("\r\n", "\n").split("\n"):
            line = pending + raw.strip()
            pending = ""
            if line.endswith("\\"):
                pending = line[:-1].rstrip() + " "
                continue
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                self.sections.setdefault(section, {})
                continue
            key, _, value = line.partition("=")
            self.sections[section].setdefault(key.strip(), []).append(value.strip())

    def __contains__(self, section: str) -> bool:
        return section in self.sections

    def values(self, section: str, key: str) -> list[str]:
        return self.sections[section].get(key, [])

    def get(self, section: str, key: str) -> str:
        values = self.values(section, key)
        assert values, f"[{section}] {key} is missing"
        return values[-1]


def read_unit(name: str) -> Unit:
    return Unit((UNITS / name).read_text(encoding="utf-8"))


def test_config_example_matches_builtin_defaults() -> None:
    """The example documents the defaults, so it must not drift from them."""
    with (DEPLOY / "config.toml.example").open("rb") as fh:
        example = Settings.model_validate(tomllib.load(fh))
    assert example == Settings()


def test_config_example_has_every_top_level_section() -> None:
    with (DEPLOY / "config.toml.example").open("rb") as fh:
        sections = set(tomllib.load(fh))
    assert sections == set(Settings.model_fields) - {"rules"}


UNIT_NAMES = [
    "podshield-api.service",
    "podshield-watch.service",
    "podshield-scan.service",
    "podshield-scan.timer",
]
SERVICES = UNIT_NAMES[:3]


@pytest.mark.parametrize("name", UNIT_NAMES)
def test_units_parse_and_have_required_sections(name: str) -> None:
    unit = read_unit(name)
    assert unit.get("Unit", "Description")
    if name != "podshield-scan.service":  # the oneshot is started by its timer
        assert unit.get("Install", "WantedBy")


@pytest.mark.parametrize("name", SERVICES)
def test_services_run_installed_binaries_without_a_shell(name: str) -> None:
    unit = read_unit(name)
    exec_start = unit.get("Service", "ExecStart").split()
    assert exec_start[0].startswith("/opt/podshield/venv/bin/")
    assert exec_start[0].rsplit("/", 1)[-1] not in {"sh", "bash"}
    assert unit.get("Service", "User") == "root"  # rootful socket and image mounts
    assert "podman.socket" in unit.get("Unit", "After")
    assert "podman.socket" in unit.get("Unit", "Requires")  # starts with, stops with the socket


def test_api_unit_is_single_worker_and_local_by_default() -> None:
    unit = read_unit("podshield-api.service")
    exec_start = unit.get("Service", "ExecStart")
    assert "--factory podshield.main:create_default_app" in exec_start
    assert "--workers 1" in exec_start
    assert "${PODSHIELD_HOST}" in exec_start and "${PODSHIELD_PORT}" in exec_start
    env = unit.values("Service", "Environment")
    assert "PODSHIELD_HOST=127.0.0.1" in env  # there is no login: stay on loopback
    assert "PODSHIELD_STATIC_DIR=/opt/podshield/frontend/dist" in env
    assert unit.get("Service", "EnvironmentFile").startswith("-")  # optional file


@pytest.mark.parametrize("name", SERVICES)
def test_services_log_to_journald(name: str) -> None:
    unit = read_unit(name)
    assert unit.get("Service", "StandardOutput") == "journal"
    assert unit.get("Service", "StandardError") == "journal"
    assert unit.get("Service", "SyslogIdentifier") == name.removesuffix(".service")


@pytest.mark.parametrize("name", ["podshield-api.service", "podshield-watch.service"])
def test_long_running_services_restart_on_failure(name: str) -> None:
    assert read_unit(name).get("Service", "Restart") == "on-failure"


def test_scan_runs_the_cli_for_all_images_daily() -> None:
    service = read_unit("podshield-scan.service")
    assert service.get("Service", "ExecStart").endswith("podshield scan --all")
    assert read_unit("podshield-scan.timer").get("Timer", "OnCalendar").startswith("*-*-* ")


def test_scan_service_is_oneshot_and_timer_is_persistent() -> None:
    assert read_unit("podshield-scan.service").get("Service", "Type") == "oneshot"
    timer = read_unit("podshield-scan.timer")
    assert timer.get("Timer", "Persistent") == "true"
    assert timer.get("Timer", "Unit") == "podshield-scan.service"
    assert timer.get("Timer", "OnCalendar")
    assert timer.get("Install", "WantedBy") == "timers.target"


def test_watch_unit_lets_running_scans_finish_on_stop() -> None:
    unit = read_unit("podshield-watch.service")
    assert unit.get("Service", "KillMode") == "mixed"
    assert int(unit.get("Service", "TimeoutStopSec")) >= 120
    assert unit.get("Service", "Restart") == "on-failure"
    assert unit.get("Service", "ExecStart").endswith("podshield watch")


# ------------------------------------------------------------------------------ install.sh


def install_script() -> str:
    return (DEPLOY / "install.sh").read_text(encoding="utf-8")


def test_install_script_has_lf_endings_and_strict_mode() -> None:
    raw = (DEPLOY / "install.sh").read_bytes()
    assert b"\r\n" not in raw
    assert raw.startswith(b"#!/usr/bin/env bash\n")
    assert "set -Eeuo pipefail" in install_script()


def install_code() -> str:
    return "\n".join(
        line for line in install_script().splitlines() if not line.lstrip().startswith("#")
    )


def test_install_script_never_weakens_selinux() -> None:
    code = install_code()
    for forbidden in (
        "setenforce",
        "SELINUX=",
        "semanage permissive",
        "setsebool",
        "--disable",
        "chmod 777",
        "chcon",
    ):
        assert forbidden not in code, forbidden


def test_install_script_only_opens_the_firewall_for_a_non_loopback_bind() -> None:
    """The dashboard has no login: firewall-cmd may only run behind the loopback check."""
    code = install_code()
    assert code.count("firewall-cmd --permanent") == 1  # one place, no other rules
    start = code.index("open_firewall() {")
    guard = code.index("if is_loopback", start)
    rule = code.index("firewall-cmd --permanent", start)
    assert guard < rule
    assert "return" in code[guard:rule]


def test_install_script_never_overwrites_existing_config() -> None:
    script = install_script()
    assert 'if [[ -e "$CONF_DIR/config.toml" ]]' in script


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_script_syntax_and_dry_run() -> None:
    script = str(DEPLOY / "install.sh")
    subprocess.run(["bash", "-n", script], check=True)
    proc = subprocess.run(
        ["bash", script, "--dry-run", "--skip-packages", "--force"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "nothing was changed" in proc.stdout
    assert "systemctl enable --now podshield-api.service" in proc.stdout
    assert "[dry-run] install -m 0644" in proc.stdout
    assert "firewall-cmd" not in proc.stdout  # default bind is 127.0.0.1


def dry_run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(DEPLOY / "install.sh"), "--dry-run", "--skip-packages", "--force", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_dry_run_default_layout_and_oval_download() -> None:
    proc = dry_run()
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "PODSHIELD_HOST=127.0.0.1 PODSHIELD_PORT=8080" in out
    assert "https://security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2" in out
    assert "bzip2 -df /var/lib/podshield/oval/rhel-9.oval.xml.tmp.bz2" in out
    assert "restorecon -Rv /opt/podshield /etc/podshield /var/lib/podshield" in out
    assert "ln -sfn /opt/podshield/venv/bin/podshield /usr/local/bin/podshield" in out
    assert "systemctl enable --now podman.socket" in out


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_dry_run_non_loopback_bind_opens_only_that_port() -> None:
    proc = dry_run("--bind", "0.0.0.0", "--port", "9090")
    assert proc.returncode == 0, proc.stderr
    assert "firewall-cmd --permanent --add-port=9090/tcp" in proc.stdout
    assert proc.stdout.count("firewall-cmd --permanent") == 1
    assert "PODSHIELD_HOST=0.0.0.0 PODSHIELD_PORT=9090" in proc.stdout


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_oval_file_is_used_instead_of_downloading(tmp_path: Path) -> None:
    feed = tmp_path / "feed.xml"
    feed.write_text("<oval_definitions/>")
    proc = dry_run("--oval-file", str(feed))
    assert proc.returncode == 0, proc.stderr
    assert "curl" not in proc.stdout
    assert f"cp -f {feed} /var/lib/podshield/oval/rhel-9.oval.xml.tmp" in proc.stdout


def fake_checkout(tmp_path: Path) -> Path:
    """A minimal checkout without frontend/dist, so the dashboard has to be built."""
    root = tmp_path / "checkout"
    shutil.copytree(DEPLOY, root / "deploy")
    (root / "backend").mkdir()
    (root / "backend" / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (root / "frontend").mkdir()
    return root


def env_with_node(tmp_path: Path, version: str) -> dict[str, str]:
    """An environment whose `node --version` prints the given version."""
    bin_dir = tmp_path / f"bin-{version}"
    bin_dir.mkdir()
    node = bin_dir / "node"
    node.write_text(f"#!/bin/sh\necho {version}\n")
    node.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}


def run_dry(root: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / "deploy" / "install.sh"), "--dry-run", "--force", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_builds_the_dashboard_with_node_20_when_dist_is_missing(tmp_path: Path) -> None:
    root = fake_checkout(tmp_path)
    proc = run_dry(root, env_with_node(tmp_path, "v16.20.2"))  # RHEL 9's default Node is too old
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "dnf module install -y nodejs:20" in out
    assert out.index("nodejs:20") < out.index("npm ci && npm run build")
    assert f"cp -a --no-preserve=ownership {root}/frontend/dist /opt/podshield/frontend/dist" in out
    assert "chown -R root:root /opt/podshield/frontend" in out


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_does_not_reinstall_a_recent_node(tmp_path: Path) -> None:
    root = fake_checkout(tmp_path)
    proc = run_dry(root, env_with_node(tmp_path, "v20.19.4"))
    assert proc.returncode == 0, proc.stderr
    assert "nodejs:20" not in proc.stdout
    assert "npm ci && npm run build" in proc.stdout


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_skips_the_build_when_dist_exists(tmp_path: Path) -> None:
    root = fake_checkout(tmp_path)
    (root / "frontend" / "dist").mkdir()
    (root / "frontend" / "dist" / "index.html").write_text("<html></html>")
    proc = run_dry(root, env_with_node(tmp_path, "v16.0.0"))
    assert proc.returncode == 0, proc.stderr
    assert "npm ci" not in proc.stdout and "nodejs:20" not in proc.stdout
    assert "cp -a --no-preserve=ownership" in proc.stdout


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(
    "args",
    [
        ["--port", "0"],
        ["--port", "70000"],
        ["--port", "80; reboot"],
        ["--bind", "1.2.3.4; reboot"],
        ["--bind", "$(id)"],
        ["--oval-file", "/nonexistent/feed.xml"],
        ["--port"],
    ],
)
def test_install_rejects_bad_option_values(args: list[str]) -> None:
    proc = dry_run(*args)
    assert proc.returncode != 0
    assert "[ FAIL ]" in proc.stderr
    assert "firewall-cmd" not in proc.stdout


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash")
def test_install_script_requires_root_without_dry_run() -> None:
    import os

    if os.geteuid() == 0:
        pytest.skip("running as root")
    proc = subprocess.run(
        ["bash", str(DEPLOY / "install.sh"), "--skip-packages"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode != 0
    assert "run as root" in proc.stderr


# ------------------------------------------------------------------------------ demo images


def test_demo_containerfiles_show_the_expected_contrast() -> None:
    bad = (ROOT / "demo" / "Containerfile.bad").read_text(encoding="utf-8")
    good = (ROOT / "demo" / "Containerfile.good").read_text(encoding="utf-8")

    def instructions(text: str) -> list[str]:
        return [
            line.split()[0].upper()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#") and not line.startswith(" ")
        ]

    assert "USER" not in instructions(bad) and "HEALTHCHECK" not in instructions(bad)
    assert "AKIAIOSFODNN7EXAMPLE" in bad  # the documented fake AWS key
    assert "USER" in instructions(good) and "HEALTHCHECK" in instructions(good)
    assert "ubi9" in good and "PASSWORD" not in good and "SECRET" not in good

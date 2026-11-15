from __future__ import annotations

import json
from pathlib import Path

import pytest

from podshield import cli
from podshield.config import Settings
from podshield.scanners.mount import FilesystemScanUnavailable
from podshield.schemas import FilesystemReport, ImageInfo
from tests.conftest import FakeSource, trust_toml


@pytest.fixture
def cli_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_image: ImageInfo, good_image: ImageInfo
) -> list[str]:
    cfg = tmp_path / "config.toml"
    db = (tmp_path / "cli.db").as_posix()
    cfg.write_text(f'[database]\npath = "{db}"\n' + trust_toml(tmp_path), encoding="utf-8")
    source = FakeSource([bad_image, good_image])
    monkeypatch.setattr(cli, "_make_source", lambda _s: source)
    # Never mount real images in CLI tests.
    monkeypatch.setattr(cli, "FilesystemScanner", lambda _s: lambda _id: FilesystemReport())
    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {})  # no real oscap/trivy
    return ["--config", str(cfg)]


def test_filesystem_scanner_failure_prints_warning(
    cli_env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(_id: str) -> FilesystemReport:
        raise FilesystemScanUnavailable("podman not found in PATH")

    monkeypatch.setattr(cli, "FilesystemScanner", lambda _s: broken)
    assert cli.main([*cli_env, "scan", "--all"]) == 0
    err = capsys.readouterr().err
    assert "warning:" in err and "filesystem scan unavailable" in err


def test_skip_filesystem_flag(cli_env: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_s: object) -> None:
        raise AssertionError("scanner must not be built")

    monkeypatch.setattr(cli, "FilesystemScanner", boom)
    assert cli.main([*cli_env, "scan", "--all", "--skip-filesystem"]) == 0


def test_scan_all_text_output(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*cli_env, "scan", "--all"]) == 0
    out = capsys.readouterr().out
    assert "localhost/demo-bad:latest" in out
    assert "PS-001" in out and "PS-003" in out
    assert "hunt****" in out
    assert "hunter2-super-secret" not in out
    assert "grade A" in out


def test_scan_single_json(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*cli_env, "scan", "localhost/demo-bad:latest", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "completed"
    assert data["images"][0]["grade"] in {"D", "F"}
    assert {f["rule_id"] for f in data["images"][0]["findings"]} >= {"PS-001", "PS-003"}
    assert "hunter2-super-secret" not in json.dumps(data)


def test_verbose_shows_remediation(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    cli.main([*cli_env, "scan", "localhost/demo-bad:latest", "-v"])
    assert "USER 1001" in capsys.readouterr().out


def test_fail_on(cli_env: list[str]) -> None:
    assert cli.main([*cli_env, "scan", "localhost/demo-bad:latest", "--fail-on", "critical"]) == 1
    good = "registry.access.redhat.com/ubi9/ubi-minimal:9.4"
    assert cli.main([*cli_env, "scan", good, "--fail-on", "info"]) == 0


def test_scan_requires_target(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*cli_env, "scan"]) == 2
    assert cli.main([*cli_env, "scan", "x", "--all"]) == 2


def test_scan_missing_image(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([*cli_env, "scan", "does-not-exist"]) == 2
    assert "not found" in capsys.readouterr().err


def test_report_after_scan(cli_env: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    cli.main([*cli_env, "report"])
    assert "No stored results" in capsys.readouterr().out
    cli.main([*cli_env, "scan", "--all"])
    capsys.readouterr()
    assert cli.main([*cli_env, "report", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2
    assert cli.main([*cli_env, "report", "localhost/demo-bad"]) == 0
    assert "demo-bad" in capsys.readouterr().out


def test_bad_config_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[podman\n", encoding="utf-8")
    assert cli.main(["--config", str(bad), "scan", "--all"]) == 2
    assert "error" in capsys.readouterr().err


def test_podman_down_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from podshield.podman_client import PodmanClient

    cfg = tmp_path / "c.toml"
    cfg.write_text(
        f'[database]\npath = "{(tmp_path / "d.db").as_posix()}"\n'
        '[podman]\nsocket = "unix:///nonexistent/podman.sock"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_make_source", lambda s: PodmanClient(s.podman.socket, 2))
    assert cli.main(["--config", str(cfg), "scan", "--all"]) == 2
    assert "cannot reach Podman" in capsys.readouterr().err


def test_settings_type() -> None:
    assert isinstance(Settings(), Settings)

from __future__ import annotations

import json
from pathlib import Path

import pytest

from podshield import cli
from podshield.podman_client import PodmanError
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.registry import RegistryAuditor
from podshield.schemas import FilesystemReport, ImageInfo, Severity, Vulnerability
from tests.conftest import FakeSource, load_json, trust_toml


@pytest.fixture
def env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_image: ImageInfo, good_image: ImageInfo
) -> list[str]:
    cfg = tmp_path / "config.toml"
    db = (tmp_path / "cli.db").as_posix()
    cfg.write_text(f'[database]\npath = "{db}"\n' + trust_toml(tmp_path), encoding="utf-8")
    monkeypatch.setattr(cli, "_make_source", lambda _s: FakeSource([bad_image, good_image]))
    monkeypatch.setattr(cli, "FilesystemScanner", lambda _s: lambda _id: FilesystemReport())
    return ["--config", str(cfg)]


def fake_cves(img: ImageInfo) -> list[Vulnerability]:
    return [
        Vulnerability(
            cve_id="CVE-2024-0001",
            package="openssl",
            severity=Severity.CRITICAL,
            fixed_version="1:3.0.7-27.el9",
            source="oscap",
        ),
        Vulnerability(
            cve_id="CVE-2024-0002", package="curl", severity=Severity.LOW, source="trivy"
        ),
    ]


def test_scan_prints_cve_summary_and_list(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {"oscap": fake_cves})
    assert cli.main([*env, "scan", "registry.access.redhat.com/ubi9/ubi-minimal:9.4"]) == 0
    out = capsys.readouterr().out
    assert "CVEs: 2 (1 critical, 1 low)" in out
    assert "CVE-2024-0001" not in out  # list only with -v
    cli.main([*env, "scan", "registry.access.redhat.com/ubi9/ubi-minimal:9.4", "-v"])
    out = capsys.readouterr().out
    assert "CVE-2024-0001" in out and "1:3.0.7-27.el9" in out and "[oscap]" in out


def test_scan_json_includes_cves_and_scanner_status(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(_img: ImageInfo) -> list[Vulnerability]:
        raise ScannerUnavailable("trivy not installed (optional scanner)")

    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {"oscap": fake_cves, "trivy": broken})
    assert cli.main([*env, "scan", "--all", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scanners"]["oscap"]["status"] == "ok"
    assert data["scanners"]["trivy"]["status"] == "unavailable"
    assert any("trivy scan unavailable" in w for w in data["warnings"])
    assert {v["cve_id"] for v in data["images"][0]["vulnerabilities"]} == {
        "CVE-2024-0001",
        "CVE-2024-0002",
    }


def test_fail_on_considers_cves(env: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    good = "registry.access.redhat.com/ubi9/ubi-minimal:9.4"
    assert cli.main([*env, "scan", good, "--fail-on", "critical"]) == 0
    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {"oscap": fake_cves})
    assert cli.main([*env, "scan", good, "--fail-on", "critical"]) == 1
    assert cli.main([*env, "scan", good, "--skip-cve", "--fail-on", "critical"]) == 0


def test_skip_cve_does_not_build_scanners(env: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_s: object) -> None:
        raise AssertionError("must not be built")

    monkeypatch.setattr(cli, "_make_cve_scanners", boom)
    assert cli.main([*env, "scan", "--all", "--skip-cve"]) == 0


def test_cve_scanners_follow_config(tmp_path: Path) -> None:
    from podshield.config import Settings

    s = Settings()
    assert set(cli._make_cve_scanners(s)) == {"oscap", "trivy"}
    s.trivy.enabled = False
    assert set(cli._make_cve_scanners(s)) == {"oscap"}
    s.oscap.enabled = False
    assert cli._make_cve_scanners(s) == {}


def test_report_shows_stored_cves(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_make_cve_scanners", lambda _s: {"oscap": fake_cves})
    cli.main([*env, "scan", "--all"])
    capsys.readouterr()
    cli.main([*env, "report", "-v"])
    assert "CVE-2024-0001" in capsys.readouterr().out
    cli.main([*env, "report", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["vulnerabilities"][0]["cve_id"].startswith("CVE-2024")


# ---- containers


class FakeContainers:
    def __init__(self, raw: list[dict[str, object]] | Exception) -> None:
        self.raw = raw
        self.closed = False

    def list_containers(self) -> list[dict[str, object]]:
        if isinstance(self.raw, Exception):
            raise self.raw
        return self.raw

    def close(self) -> None:
        self.closed = True


def test_containers_command(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeContainers(load_json("containers.json"))
    monkeypatch.setattr(cli, "_make_container_source", lambda _s: fake)
    assert cli.main([*env, "containers", "-v"]) == 0
    out = capsys.readouterr().out
    assert "evil" in out and "PS-R01" in out and "PS-R04" in out
    assert "no-new-privileges" not in out
    assert "--cap-drop=ALL" in out  # remediation shown with -v
    assert "web" in out and "grade A" in out
    assert fake.closed

    cli.main([*env, "containers", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [c["name"] for c in data] == ["evil", "web"]
    assert data[0]["grade"] == "F" and len(data[0]["findings"]) == 5


def test_containers_none_and_error(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_make_container_source", lambda _s: FakeContainers([]))
    assert cli.main([*env, "containers"]) == 0
    assert "No running containers" in capsys.readouterr().out
    monkeypatch.setattr(
        cli, "_make_container_source", lambda _s: FakeContainers(PodmanError("cannot reach Podman"))
    )
    assert cli.main([*env, "containers"]) == 2
    assert "cannot reach Podman" in capsys.readouterr().err


# ---- registry


class FakeAuditor(RegistryAuditor):
    def fetch(self, reference: str) -> ImageInfo:
        from podshield.scanners.registry import normalize_reference, parse_skopeo

        return parse_skopeo(
            load_json("skopeo_summary.json"),
            load_json("skopeo_config.json"),
            normalize_reference(reference),
        )


def test_registry_command(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "RegistryAuditor", FakeAuditor)
    assert cli.main([*env, "registry", "nginx"]) == 0
    out = capsys.readouterr().out
    assert "nginx:latest" in out and "[pre-pull audit]" in out
    assert "PS-001" in out and "PS-014" in out
    assert "Not evaluated before pulling" in out
    assert "remote-secret-value" not in out

    assert cli.main([*env, "registry", "nginx", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["skipped_rules"] == ["PS-004", "PS-009", "PS-010", "PS-015"]
    assert "remote-secret-value" not in json.dumps(data)


def test_registry_errors(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main([*env, "registry", "--", "--evil"]) == 2
    assert "invalid image reference" in capsys.readouterr().err

    class Down(FakeAuditor):
        def fetch(self, reference: str) -> ImageInfo:
            raise ScannerUnavailable("skopeo not installed (dnf install skopeo)")

    monkeypatch.setattr(cli, "RegistryAuditor", Down)
    assert cli.main([*env, "registry", "nginx"]) == 2
    assert "unavailable" in capsys.readouterr().err

    class Fails(FakeAuditor):
        def fetch(self, reference: str) -> ImageInfo:
            raise ScannerError("manifest unknown")

    monkeypatch.setattr(cli, "RegistryAuditor", Fails)
    assert cli.main([*env, "registry", "nginx"]) == 2
    assert "manifest unknown" in capsys.readouterr().err


# ---- doctor / scan input validation


def test_doctor(
    env: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/skopeo" if b == "skopeo" else None)
    assert cli.main([*env, "doctor"]) == 0
    out = capsys.readouterr().out
    assert "oscap" in out and "UNAVAILABLE" in out
    skopeo_line = next(ln for ln in out.splitlines() if ln.startswith("skopeo"))
    assert "ok" in skopeo_line
    trust_line = next(ln for ln in out.splitlines() if ln.startswith("trust"))
    assert "ok" in trust_line  # hermetic policy.json exists


def test_scan_rejects_option_like_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from podshield.podman_client import PodmanClient

    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[database]\npath = "{(tmp_path / "d.db").as_posix()}"\n', encoding="utf-8")
    monkeypatch.setattr(cli, "_make_source", lambda s: PodmanClient(s.podman.socket, 2))
    assert (
        cli.main(["--config", str(cfg), "scan", "--skip-filesystem", "--skip-cve", "--", "--rm"])
        == 2
    )
    assert "invalid image reference" in capsys.readouterr().err

"""T1: oscap / trivy / skopeo wrappers with a mocked subprocess.

For each tool: success, non-zero exit, timeout, tool missing and garbage output. The contract:
a missing tool raises ScannerUnavailable (the scan carries on, status "unavailable"); anything
else that goes wrong raises ScannerError (status "failed"); nothing ever escapes as another
exception type, and no command is run through a shell.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from podshield.config import Settings
from podshield.orchestrator import Orchestrator
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.oscap import OscapScanner
from podshield.scanners.registry import RegistryAuditor
from podshield.scanners.trivy import TrivyScanner
from podshield.schemas import ImageInfo
from tests.conftest import DATA, FakeSource, load_json

Cmd = list[str]
Behaviour = Callable[[Cmd], subprocess.CompletedProcess[str]]


class Env:
    """A fake host: records every command and answers with the configured behaviour."""

    def __init__(self) -> None:
        self.calls: list[Cmd] = []
        self.behaviour: Behaviour = lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")

    def run(self, cmd: Cmd, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert isinstance(cmd, list), "commands must be argument lists"
        assert not kwargs.get("shell"), "shell=True is forbidden"
        assert kwargs.get("timeout"), "every call needs a timeout"
        self.calls.append(cmd)
        return self.behaviour(cmd)


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Env:
    env = Env()
    monkeypatch.setattr(shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(subprocess, "run", env.run)
    return env


@pytest.fixture
def cfg(tmp_path: Path, settings: Settings) -> Settings:
    s = settings  # hermetic trust paths, so PS-014 never reads the real /etc/containers
    feed = tmp_path / "rhel-9.oval.xml"
    feed.write_text("<oval_definitions/>", encoding="utf-8")
    s.oscap.oval_path = str(feed)
    return s


def done(cmd: Cmd, out: str = "", err: str = "", code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, code, out, err)


def timeout(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    raise subprocess.TimeoutExpired(cmd, 1)


def not_found(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    raise FileNotFoundError(cmd[0])


def permission_denied(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    raise PermissionError(13, "Permission denied", cmd[0])


# --------------------------------------------------------------------------- the three


def oscap_run(settings: Settings, results: str | None) -> Callable[[ImageInfo], object]:
    return OscapScanner(settings)


def oscap_ok(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    if "--results" in cmd:
        Path(cmd[cmd.index("--results") + 1]).write_bytes((DATA / "oval_results.xml").read_bytes())
    return done(cmd, code=2)  # exit status 2 means "some definitions are true"


def oscap_garbage(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    Path(cmd[cmd.index("--results") + 1]).write_text("this is <not xml", encoding="utf-8")
    return done(cmd)


def oscap_empty(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    Path(cmd[cmd.index("--results") + 1]).write_text("", encoding="utf-8")
    return done(cmd)


def trivy_behaviour(report: str, save_ok: bool = True) -> Behaviour:
    def run(cmd: Cmd) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["podman", "save"]:
            if not save_ok:
                return done(cmd, err="Error: image not known", code=125)
            Path(cmd[cmd.index("-o") + 1]).write_bytes(b"tar")
            return done(cmd)
        return done(cmd, report)

    return run


def skopeo_ok(cmd: Cmd) -> subprocess.CompletedProcess[str]:
    name = "skopeo_config.json" if "--config" in cmd else "skopeo_summary.json"
    return done(cmd, json.dumps(load_json(name)))


def scan_oscap(s: Settings) -> object:
    return OscapScanner(s)(ImageInfo(id="img"))


def scan_trivy(s: Settings) -> object:
    return TrivyScanner(s)(ImageInfo(id="img"))


def scan_skopeo(s: Settings) -> object:
    return RegistryAuditor(s).fetch("quay.io/podman/hello:latest")


# ---------------------------------------------------------------------------- success


def test_oscap_success(host: Env, cfg: Settings) -> None:
    host.behaviour = oscap_ok
    vulns = scan_oscap(cfg)
    assert vulns and {v.source for v in vulns} == {"oscap"}  # type: ignore[attr-defined]


def test_trivy_success(host: Env, cfg: Settings) -> None:
    host.behaviour = trivy_behaviour(json.dumps(load_json("trivy_report.json")))
    assert len(scan_trivy(cfg)) == 3  # type: ignore[arg-type]


def test_skopeo_success(host: Env, cfg: Settings) -> None:
    host.behaviour = skopeo_ok
    image = scan_skopeo(cfg)
    assert image.id.startswith("sha256:")  # type: ignore[attr-defined]


# ---------------------------------------------------------- failure modes, per scanner

SCANNERS: dict[str, Callable[[Settings], object]] = {
    "oscap": scan_oscap,
    "trivy": scan_trivy,
    "skopeo": scan_skopeo,
}


@pytest.mark.parametrize("name", sorted(SCANNERS))
def test_nonzero_exit_is_a_scanner_error_with_the_stderr(
    name: str, host: Env, cfg: Settings
) -> None:
    host.behaviour = lambda cmd: done(cmd, err="FATAL: something broke badly", code=1)
    with pytest.raises(ScannerError, match="something broke badly"):
        SCANNERS[name](cfg)


@pytest.mark.parametrize("name", sorted(SCANNERS))
def test_timeout_is_a_scanner_error(name: str, host: Env, cfg: Settings) -> None:
    host.behaviour = timeout
    with pytest.raises(ScannerError, match="timed out"):
        SCANNERS[name](cfg)


@pytest.mark.parametrize("name", sorted(SCANNERS))
def test_binary_missing_at_exec_time_is_unavailable(name: str, host: Env, cfg: Settings) -> None:
    host.behaviour = not_found  # which() said yes, exec says no (race, broken PATH, ...)
    with pytest.raises(ScannerUnavailable):
        SCANNERS[name](cfg)


@pytest.mark.parametrize("name", sorted(SCANNERS))
def test_binary_not_executable_is_unavailable(name: str, host: Env, cfg: Settings) -> None:
    host.behaviour = permission_denied
    with pytest.raises(ScannerUnavailable, match="cannot execute"):
        SCANNERS[name](cfg)


@pytest.mark.parametrize("name", sorted(SCANNERS))
def test_tool_not_installed_is_unavailable_without_running_anything(
    name: str, host: Env, cfg: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(ScannerUnavailable):
        SCANNERS[name](cfg)
    assert host.calls == []


def test_oscap_without_the_oval_feed_is_unavailable(host: Env, cfg: Settings) -> None:
    cfg.oscap.oval_path = "/nonexistent/rhel-9.oval.xml.bz2"
    with pytest.raises(ScannerUnavailable, match="OVAL"):
        scan_oscap(cfg)
    assert host.calls == []


def test_trivy_needs_podman_to_export_the_image(
    host: Env, cfg: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda b: None if b == "podman" else f"/usr/bin/{b}")
    with pytest.raises(ScannerUnavailable, match="podman"):
        scan_trivy(cfg)


def test_trivy_podman_save_failure_is_a_scanner_error(host: Env, cfg: Settings) -> None:
    host.behaviour = trivy_behaviour("{}", save_ok=False)
    with pytest.raises(ScannerError, match="image not known"):
        scan_trivy(cfg)
    assert [c[0] for c in host.calls] == ["podman"]  # trivy never ran


# ------------------------------------------------------------------------- garbage


@pytest.mark.parametrize("garbage", ["", "not json", "{", "[1, 2, 3]", '"a string"', "null", "42"])
def test_trivy_garbage_output(garbage: str, host: Env, cfg: Settings) -> None:
    host.behaviour = trivy_behaviour(garbage)
    with pytest.raises(ScannerError):
        scan_trivy(cfg)


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"Results": None},
        {"Results": []},
        {"Results": [{}]},
        {"Results": [{"Vulnerabilities": None}]},
        {"Results": [{"Vulnerabilities": [{"PkgName": "x"}]}]},
    ],  # entry without an ID is skipped
)
def test_trivy_valid_but_empty_reports_mean_no_cves(
    report: dict[str, Any], host: Env, cfg: Settings
) -> None:
    host.behaviour = trivy_behaviour(json.dumps(report))
    assert scan_trivy(cfg) == []


def test_trivy_unknown_severity_does_not_crash(host: Env, cfg: Settings) -> None:
    doc = {
        "Results": [
            {"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "WEIRD"}]}
        ]
    }
    host.behaviour = trivy_behaviour(json.dumps(doc))
    (vuln,) = scan_trivy(cfg)  # type: ignore[misc]
    assert vuln.severity.value == "info"


def test_oscap_garbage_results_file(host: Env, cfg: Settings) -> None:
    host.behaviour = oscap_garbage
    with pytest.raises(ScannerError, match="cannot parse"):
        scan_oscap(cfg)


def test_oscap_empty_results_file(host: Env, cfg: Settings) -> None:
    host.behaviour = oscap_empty
    with pytest.raises(ScannerError, match="no results"):
        scan_oscap(cfg)


def test_oscap_exit_code_1_is_an_error_but_2_is_not(host: Env, cfg: Settings) -> None:
    def code(n: int) -> Behaviour:
        def run(cmd: Cmd) -> subprocess.CompletedProcess[str]:
            oscap_ok(cmd)
            return done(cmd, err="oscap: evaluation error", code=n)

        return run

    host.behaviour = code(2)
    assert scan_oscap(cfg)
    host.behaviour = code(1)
    with pytest.raises(ScannerError, match="evaluation error"):
        scan_oscap(cfg)


@pytest.mark.parametrize("garbage", ["", "not json", "{", "[]", "null", "42", '"s"'])
def test_skopeo_garbage_output(garbage: str, host: Env, cfg: Settings) -> None:
    host.behaviour = lambda cmd: done(cmd, garbage)
    with pytest.raises(ScannerError):
        scan_skopeo(cfg)


def test_skopeo_document_without_a_digest(host: Env, cfg: Settings) -> None:
    host.behaviour = lambda cmd: done(cmd, "{}")
    with pytest.raises(ScannerError, match="Digest"):
        scan_skopeo(cfg)


@pytest.mark.parametrize(
    "stderr",
    [
        "FATA[0001] Error parsing image name: manifest unknown",
        "FATA[0000] no image found in image index for architecture amd64, variant, OS linux",
        "FATA[0002] unauthorized: authentication required",
        "FATA[0003] pinging container registry quay.io: dial tcp: lookup quay.io: no such host",
        "FATA[0003] tls: failed to verify certificate: x509: certificate signed by unknown authority",
    ],
)
def test_registry_failures_surface_the_reason_to_the_user(
    stderr: str, host: Env, cfg: Settings
) -> None:
    host.behaviour = lambda cmd: done(cmd, err=stderr, code=1)
    with pytest.raises(ScannerError) as err:
        scan_skopeo(cfg)
    assert stderr.split("] ", 1)[1][:40] in str(err.value)


def test_multi_arch_summary_for_another_architecture_still_parses(host: Env, cfg: Settings) -> None:
    summary = load_json("skopeo_summary.json")
    summary["Architecture"] = "arm64"
    config = load_json("skopeo_config.json")
    config["architecture"] = "arm64"
    config["variant"] = "v8"

    def run(cmd: Cmd) -> subprocess.CompletedProcess[str]:
        return done(cmd, json.dumps(config if "--config" in cmd else summary))

    host.behaviour = run
    assert scan_skopeo(cfg).architecture == "arm64"  # type: ignore[attr-defined]


# ------------------------------------------------------------- end to end, via the engine


@pytest.mark.parametrize(
    ("behaviour", "expected"),
    [
        (not_found, "unavailable"),
        (permission_denied, "unavailable"),
        (timeout, "failed"),
        (lambda cmd: done(cmd, err="boom", code=1), "failed"),
    ],
    ids=["missing", "not-executable", "timeout", "nonzero"],
)
def test_a_broken_scanner_never_breaks_the_scan(
    behaviour: Behaviour,
    expected: str,
    host: Env,
    cfg: Settings,
    engine: Engine,
    good_image: ImageInfo,
) -> None:
    host.behaviour = behaviour
    summary = Orchestrator(
        FakeSource([good_image]),
        engine,
        cfg,
        cve_scanners={"oscap": OscapScanner(cfg), "trivy": TrivyScanner(cfg)},
    ).scan(scan_all=True)
    assert summary.status == "completed"
    assert len(summary.results) == 1 and summary.results[0].findings == []
    assert {o.status for o in summary.scanners.values()} == {expected}
    assert summary.warnings  # the user is told which scanner could not run


def test_no_scanner_command_ever_uses_a_shell(host: Env, cfg: Settings) -> None:
    host.behaviour = oscap_ok
    scan_oscap(cfg)
    host.behaviour = trivy_behaviour("{}")
    scan_trivy(cfg)
    host.behaviour = skopeo_ok
    scan_skopeo(cfg)
    assert host.calls and all(isinstance(c, list) for c in host.calls)

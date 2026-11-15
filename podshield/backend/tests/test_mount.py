from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from podshield.config import Settings
from podshield.scanners import mount
from podshield.scanners.mount import FilesystemScanner, FilesystemScanUnavailable, mounted_image
from podshield.schemas import FilesystemReport


class FakeRun:
    """Records subprocess calls and returns canned results keyed by the podman verb."""

    def __init__(self, mount_dir: Path | None, mount_rc: int = 0, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.mount_dir = mount_dir
        self.mount_rc = mount_rc
        self.stderr = stderr

    def __call__(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        assert kwargs.get("timeout"), "every subprocess call needs a timeout"
        assert "shell" not in kwargs
        if cmd[:3] == ["podman", "image", "mount"]:
            return subprocess.CompletedProcess(
                cmd, self.mount_rc, f"{self.mount_dir}\n", self.stderr
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")


def test_mount_then_unmount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake)
    with mounted_image("abc123") as root:
        assert root == tmp_path
    assert fake.calls == [
        ["podman", "image", "mount", "abc123"],
        ["podman", "image", "unmount", "abc123"],
    ]


def test_unmount_runs_even_if_scan_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(RuntimeError), mounted_image("abc123"):
        raise RuntimeError("scan blew up")
    assert fake.calls[-1] == ["podman", "image", "unmount", "abc123"]


def test_mount_failure_is_unavailable_and_does_not_unmount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRun(None, mount_rc=125, stderr="Error: permission denied")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(FilesystemScanUnavailable, match="permission denied"), mounted_image("x"):
        pass
    assert len(fake.calls) == 1


def test_bad_mount_output_still_unmounts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun(tmp_path / "does-not-exist")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(FilesystemScanUnavailable), mounted_image("x"):
        pass
    assert fake.calls[-1][:3] == ["podman", "image", "unmount"]


def test_missing_podman_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise FileNotFoundError("podman")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(FilesystemScanUnavailable, match="not found"), mounted_image("x"):
        pass


def test_timeout_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(cmd: list[str], **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(FilesystemScanUnavailable, match="timed out"), mounted_image("x"):
        pass


def test_rootful_scan_uses_mount(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "usr/bin").mkdir(parents=True)
    (tmp_path / "usr/bin/bash").write_text("x")
    fake = FakeRun(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(mount.os, "geteuid", lambda: 0, raising=False)
    report = FilesystemScanner(Settings())("img1")
    assert report.shells == ["/usr/bin/bash"]
    assert fake.calls[-1][:3] == ["podman", "image", "unmount"]


def test_rootful_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mount.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(FilesystemScanUnavailable, match="not running as root"):
        FilesystemScanner(Settings())("img1")


def test_rootless_runs_helper_under_unshare(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.podman.mode = "rootless"
    expected = FilesystemReport(files_scanned=7, shells=["/bin/sh"])
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_k: object) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, expected.model_dump_json(), "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert FilesystemScanner(settings)("img1") == expected
    cmd = seen[0]
    assert cmd[:3] == ["podman", "unshare", sys.executable]
    assert cmd[3:6] == ["-m", "podshield.scanners.mount", "img1"]


def test_rootless_failure_and_garbage_output(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.podman.mode = "rootless"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **_k: subprocess.CompletedProcess(cmd, 1, "", "no such image"),
    )
    with pytest.raises(FilesystemScanUnavailable, match="no such image"):
        FilesystemScanner(settings)("img1")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **_k: subprocess.CompletedProcess(cmd, 0, "not json", "")
    )
    with pytest.raises(FilesystemScanUnavailable, match="invalid output"):
        FilesystemScanner(settings)("img1")


def test_helper_main_prints_report_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "usr/bin").mkdir(parents=True)
    (tmp_path / "usr/bin/sh").write_text("x")
    monkeypatch.setattr(subprocess, "run", FakeRun(tmp_path))
    assert mount._helper_main(["img1"]) == 0
    report = FilesystemReport.model_validate_json(capsys.readouterr().out)
    assert report.shells == ["/usr/bin/sh"]


def test_helper_main_failure_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", FakeRun(None, mount_rc=1, stderr="boom"))
    assert mount._helper_main(["img1"]) == 1
    assert "boom" in capsys.readouterr().err

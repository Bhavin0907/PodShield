from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from podshield.scanners.filesystem import MIN_CACHE_BYTES, scan_tree

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX modes/symlinks")

PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def put(root: Path, rel: str, content: str | bytes = "x", mode: int | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)
    return path


def test_empty_tree(tmp_path: Path) -> None:
    report = scan_tree(tmp_path)
    assert report.files_scanned == 0
    assert report.secrets == [] and report.setuid_files == [] and not report.truncated


def test_detects_private_key_and_masks(tmp_path: Path) -> None:
    put(tmp_path, "root/.ssh/id_rsa", PRIVATE_KEY)
    (hit,) = scan_tree(tmp_path).secrets
    assert hit.path == "/root/.ssh/id_rsa:1"
    assert "Private key" in hit.reason
    assert hit.masked_value == "----****"
    assert "OPENSSH" not in hit.masked_value


def test_detects_cloud_and_token_patterns_with_line_numbers(tmp_path: Path) -> None:
    put(
        tmp_path,
        "app/config.py",
        "x = 1\nKEY = 'AKIAIOSFODNN7EXAMPLE'\ntok = 'ghp_" + "a" * 36 + "'\n",
    )
    secrets_found = scan_tree(tmp_path).secrets
    assert [s.path for s in secrets_found] == ["/app/config.py:2", "/app/config.py:3"]
    assert all("AKIAIOSFODNN7EXAMPLE" not in s.masked_value for s in secrets_found)
    assert secrets_found[0].masked_value == "AKIA****"


def test_env_file_credentials(tmp_path: Path) -> None:
    put(
        tmp_path,
        "app/.env",
        "# comment\nDEBUG=true\nexport DB_PASSWORD='hunter2-secret'\nPATH=/bin\n",
    )
    (hit,) = scan_tree(tmp_path).secrets
    assert hit.path == "/app/.env"
    assert "DB_PASSWORD" in hit.reason
    assert hit.masked_value == "hunt****"


def test_sensitive_filenames_and_npmrc(tmp_path: Path) -> None:
    put(tmp_path, "home/u/.aws/credentials", "[default]\naws_secret_access_key = abc\n")
    put(tmp_path, "home/u/.netrc", "machine x login y password z\n")
    put(tmp_path, "home/u/.npmrc", "//registry.npmjs.org/:_authToken=npm_abcdef123456\n")
    put(tmp_path, "etc/ssl/cert.p12", b"\x30\x82\x00")
    paths = {s.path for s in scan_tree(tmp_path).secrets}
    assert paths == {
        "/home/u/.aws/credentials",
        "/home/u/.netrc",
        "/home/u/.npmrc",
        "/etc/ssl/cert.p12",
    }
    npm = next(s for s in scan_tree(tmp_path).secrets if s.path.endswith(".npmrc"))
    assert npm.masked_value == "npm_****"


def test_empty_sensitive_file_is_ignored(tmp_path: Path) -> None:
    put(tmp_path, "home/u/.netrc", "")
    assert scan_tree(tmp_path).secrets == []


def test_ignores_binary_big_skipped_and_doc_paths(tmp_path: Path) -> None:
    put(tmp_path, "usr/bin/tool", b"\x00\x01AKIAIOSFODNN7EXAMPLE")  # binary
    put(tmp_path, "usr/lib/libx.so", "AKIAIOSFODNN7EXAMPLE")  # skipped extension
    put(tmp_path, "usr/share/doc/pkg/README", "AKIAIOSFODNN7EXAMPLE")  # skipped dir
    put(tmp_path, "data/big.txt", "AKIAIOSFODNN7EXAMPLE" + " " * 5000)
    assert scan_tree(tmp_path, max_file_size=1000).secrets == []
    assert len(scan_tree(tmp_path, max_file_size=10_000).secrets) == 1


def test_max_reported_caps_secrets(tmp_path: Path) -> None:
    for i in range(10):
        put(tmp_path, f"k/{i}.txt", PRIVATE_KEY)
    assert len(scan_tree(tmp_path, max_reported=3).secrets) == 3


def test_package_caches_threshold(tmp_path: Path) -> None:
    put(tmp_path, "var/cache/dnf/repo/pkg.rpm", b"\x00" * (MIN_CACHE_BYTES + 1))
    put(tmp_path, "var/cache/yum/tiny", "x")  # below threshold
    put(tmp_path, "var/lib/apt/lists/big", b"\x00" * MIN_CACHE_BYTES)
    report = scan_tree(tmp_path)
    assert {c.path for c in report.cache_dirs} == {"/var/cache/dnf", "/var/lib/apt/lists"}
    dnf = next(c for c in report.cache_dirs if c.path == "/var/cache/dnf")
    assert dnf.files == 1 and dnf.size == MIN_CACHE_BYTES + 1


def test_shells_and_package_managers(tmp_path: Path) -> None:
    put(tmp_path, "usr/bin/bash")
    put(tmp_path, "usr/bin/microdnf")
    put(tmp_path, "usr/sbin/apk")
    put(tmp_path, "opt/app/bash")  # not in a bin dir
    put(tmp_path, "usr/bin/python3")
    report = scan_tree(tmp_path)
    assert report.shells == ["/usr/bin/bash"]
    assert report.package_managers == ["/usr/bin/microdnf", "/usr/sbin/apk"]


def test_minimal_image_has_no_shell(tmp_path: Path) -> None:
    put(tmp_path, "app/server", b"\x7fELF")
    report = scan_tree(tmp_path)
    assert report.shells == [] and report.package_managers == []


@posix_only
def test_setuid_and_setgid_detected(tmp_path: Path) -> None:
    put(tmp_path, "usr/bin/su", "x", mode=0o4755)
    put(tmp_path, "usr/bin/wall", "x", mode=0o2755)
    put(tmp_path, "usr/bin/ls", "x", mode=0o755)
    report = scan_tree(tmp_path)
    assert [(s.path, s.mode) for s in report.setuid_files] == [
        ("/usr/bin/su", "4755"),
        ("/usr/bin/wall", "2755"),
    ]


@posix_only
def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "host"
    outside.mkdir()
    put(outside, "id_rsa", PRIVATE_KEY)
    root = tmp_path / "root"
    root.mkdir()
    (root / "leak").symlink_to(outside)  # absolute symlink to a host directory
    (root / "link_file").symlink_to(outside / "id_rsa")
    (root / "bin").symlink_to("usr/bin")
    put(root, "usr/bin/sh")
    report = scan_tree(root)
    assert report.secrets == []
    assert report.shells == ["/usr/bin/sh"]


@posix_only
def test_symlinked_shell_counts(tmp_path: Path) -> None:
    put(tmp_path, "usr/bin/bash")
    (tmp_path / "usr/bin/sh").symlink_to("bash")
    assert scan_tree(tmp_path).shells == ["/usr/bin/bash", "/usr/bin/sh"]


def test_file_limit_truncates(tmp_path: Path) -> None:
    for i in range(20):
        put(tmp_path, f"d/{i}.txt")
    report = scan_tree(tmp_path, max_files=5)
    assert report.truncated and report.files_scanned == 5


def test_deadline_truncates(tmp_path: Path) -> None:
    put(tmp_path, "a.txt")
    report = scan_tree(tmp_path, deadline_seconds=-1)
    assert report.truncated and report.files_scanned == 0


def test_special_top_level_dirs_skipped(tmp_path: Path) -> None:
    put(tmp_path, "proc/1/environ", PRIVATE_KEY)
    put(tmp_path, "sys/x", PRIVATE_KEY)
    assert scan_tree(tmp_path).files_scanned == 0

"""Walk an extracted/mounted image root and collect filesystem facts.

Pure with respect to Podman: it only needs a directory, so it is tested with ``tmp_path``.

Safety: the tree comes from an untrusted image. Symlinks are never followed (an absolute
symlink would otherwise resolve against the *host* filesystem), only regular files are
read, and file size, file count and wall-clock time are all bounded.
"""

from __future__ import annotations

import os
import re
import stat
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath

from podshield.scanners import secrets
from podshield.schemas import CacheDir, FilesystemReport, FsSecret, SetuidFile

SKIP_TOP_LEVEL = {"proc", "sys", "dev"}
# Directories whose contents are huge and never hold deployable secrets.
SKIP_CONTENT_DIRS = (
    "usr/share/doc",
    "usr/share/man",
    "usr/share/locale",
    "usr/share/zoneinfo",
    "usr/share/info",
    "usr/lib/.build-id",
    "usr/lib/locale",
    "usr/lib/modules",
    "etc/pki/ca-trust",
    "usr/share/pki",
    "usr/share/licenses",
)
SKIP_EXTENSIONS = {
    ".so",
    ".a",
    ".o",
    ".pyc",
    ".pyo",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".gz",
    ".xz",
    ".bz2",
    ".zst",
    ".zip",
    ".jar",
    ".whl",
    ".rpm",
    ".deb",
    ".mo",
    ".ttf",
    ".woff",
    ".woff2",
}

# Files whose mere presence (non-empty) is a leak.
SENSITIVE_BASENAMES = {
    ".git-credentials": "git credential store",
    ".netrc": "netrc credentials",
    ".pgpass": "PostgreSQL password file",
    ".htpasswd": "htpasswd credentials",
}
SENSITIVE_SUFFIXES = {".pfx": "PKCS#12 keystore", ".p12": "PKCS#12 keystore"}
AWS_CREDENTIALS_SUFFIX = ".aws/credentials"
ENV_FILE_RE = re.compile(r"(^|\.)env(\.[\w-]+)?$|^\.env", re.IGNORECASE)
_NPM_TOKEN_RE = re.compile(r"_authToken\s*=\s*\S{4,}")

# Cache dirs left behind by package managers, and the smallest size worth reporting.
CACHE_DIRS = (
    "var/cache/dnf",
    "var/cache/yum",
    "var/cache/microdnf",
    "var/cache/apt",
    "var/lib/apt/lists",
    "var/cache/apk",
    "etc/apk/cache",
)
MIN_CACHE_BYTES = 64 * 1024

SHELL_NAMES = {"sh", "bash", "ash", "dash", "zsh", "ksh", "csh", "tcsh", "fish"}
PACKAGE_MANAGER_NAMES = {
    "dnf",
    "yum",
    "microdnf",
    "rpm",
    "apt",
    "apt-get",
    "dpkg",
    "apk",
    "zypper",
    "pip",
    "pip3",
}
BIN_DIRS = {"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin"}


def _is_text(sample: bytes) -> bool:
    return b"\x00" not in sample


def _under(rel: str, prefixes: tuple[str, ...]) -> bool:
    return any(rel == p or rel.startswith(p + "/") for p in prefixes)


def _sensitive_name_reason(rel: str) -> str | None:
    base = PurePosixPath(rel).name
    if base in SENSITIVE_BASENAMES:
        return SENSITIVE_BASENAMES[base]
    if rel.endswith("/" + AWS_CREDENTIALS_SUFFIX) or rel == AWS_CREDENTIALS_SUFFIX:
        return "AWS credentials file"
    return SENSITIVE_SUFFIXES.get(PurePosixPath(base.lower()).suffix)


def _scan_file_content(path: Path, rel: str, size: int, max_size: int, out: list[FsSecret]) -> None:
    try:
        with path.open("rb") as fh:
            sample = fh.read(8192)
            if not _is_text(sample):
                return
            data = sample + fh.read(max_size - len(sample)) if size > len(sample) else sample
    except OSError:
        return
    text = data.decode("utf-8", errors="replace")
    base = PurePosixPath(rel).name

    for line_no, reason, masked in secrets.scan_text(text):
        out.append(FsSecret(path=f"/{rel}:{line_no}", reason=reason, masked_value=masked))

    if ENV_FILE_RE.search(base):
        pairs = [
            (k.strip().removeprefix("export ").strip(), v.strip().strip("'\""))
            for k, _, v in (
                ln.partition("=")
                for ln in text.splitlines()
                if "=" in ln and not ln.lstrip().startswith("#")
            )
        ]
        for match in secrets.scan_env(pairs):
            out.append(
                FsSecret(
                    path=f"/{rel}",
                    reason=f"{match.location}: {match.reason}",
                    masked_value=match.masked_value,
                )
            )
    elif base == ".npmrc" and (m := _NPM_TOKEN_RE.search(text)):
        out.append(
            FsSecret(
                path=f"/{rel}",
                reason="npm auth token",
                masked_value=secrets.mask(m.group(0).split("=", 1)[1].strip()),
            )
        )


OS_RELEASE_FILES = ("usr/lib/os-release", "etc/os-release")
OS_RELEASE_KEYS = ("ID", "ID_LIKE", "VERSION_ID", "NAME", "PRETTY_NAME", "CPE_NAME")
_OS_RELEASE_MAX = 16 * 1024


def read_os_release(root: Path) -> dict[str, str]:
    """Parse the image's os-release without ever following a symlink out of the image.

    ``/etc/os-release`` is normally a symlink to ``../usr/lib/os-release``, so the real file
    is tried first; a symlink is never opened (it could point at the host's file).
    """
    for rel in OS_RELEASE_FILES:
        path = root / rel
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                continue
            with path.open("rb") as fh:
                text = fh.read(_OS_RELEASE_MAX).decode("utf-8", errors="replace")
        except OSError:
            continue
        values: dict[str, str] = {}
        for line in text.splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and key in OS_RELEASE_KEYS:
                values[key] = value.strip().strip("'\"")
        if values:
            return values
    return {}


def scan_tree(
    root: Path,
    *,
    max_file_size: int = 1024 * 1024,
    max_files: int = 300_000,
    deadline_seconds: float = 300.0,
    max_reported: int = 50,
) -> FilesystemReport:
    """Walk ``root`` (an image's root filesystem) and return a ``FilesystemReport``."""
    report = FilesystemReport(os_release=read_os_release(root))
    started = time.monotonic()
    cache_files: dict[str, int] = defaultdict(int)
    cache_bytes: dict[str, int] = defaultdict(int)
    shells: set[str] = set()
    managers: set[str] = set()
    setuid: list[SetuidFile] = []
    found: list[FsSecret] = []

    stop = False
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        if stop:
            break
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        if rel_dir == "":
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP_LEVEL]

        for name in filenames:
            if report.files_scanned >= max_files or time.monotonic() - started > deadline_seconds:
                report.truncated = True
                stop = True
                break
            report.files_scanned += 1
            rel = f"{rel_dir}/{name}" if rel_dir else name
            path = Path(dirpath) / name
            try:
                st = os.lstat(path)
            except OSError:
                continue

            if rel_dir in BIN_DIRS:
                if name in SHELL_NAMES:
                    shells.add(f"/{rel}")
                elif name in PACKAGE_MANAGER_NAMES:
                    managers.add(f"/{rel}")

            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue

            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                setuid.append(SetuidFile(path=f"/{rel}", mode=format(st.st_mode & 0o7777, "04o")))

            for cache in CACHE_DIRS:
                if rel == cache or rel.startswith(cache + "/"):
                    cache_files[cache] += 1
                    cache_bytes[cache] += st.st_size
                    break

            if _under(rel, SKIP_CONTENT_DIRS) or st.st_size == 0:
                continue

            if (reason := _sensitive_name_reason(rel)) and len(found) < max_reported:
                found.append(FsSecret(path=f"/{rel}", reason=reason))
                continue
            if (
                Path(name).suffix.lower() not in SKIP_EXTENSIONS
                and st.st_size <= max_file_size
                and len(found) < max_reported
            ):
                _scan_file_content(path, rel, st.st_size, max_file_size, found)

    report.secrets = found[:max_reported]
    report.setuid_files = sorted(setuid, key=lambda s: s.path)
    report.cache_dirs = [
        CacheDir(path=f"/{c}", files=cache_files[c], size=cache_bytes[c])
        for c in CACHE_DIRS
        if cache_bytes.get(c, 0) >= MIN_CACHE_BYTES
    ]
    report.shells = sorted(shells)
    report.package_managers = sorted(managers)
    return report

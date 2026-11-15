"""Mount an image with Podman and scan its filesystem.

Rootful: ``podman image mount`` runs in-process, always followed by ``podman image unmount``
in a ``finally`` block.

Rootless: mounting needs the user namespace, so we re-run this module under
``podman unshare`` (``python -m podshield.scanners.mount IMAGE``). The helper mounts, scans,
unmounts, and prints the ``FilesystemReport`` as JSON on stdout.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from podshield.config import Settings
from podshield.scanners.base import ScannerImageGone, ScannerUnavailable
from podshield.scanners.filesystem import scan_tree
from podshield.schemas import FilesystemReport

log = logging.getLogger(__name__)

MOUNT_TIMEOUT = 60
# Exit status of the rootless helper when its image vanished (distinct from a generic failure).
HELPER_IMAGE_GONE = 3
# What podman prints when an image is deleted between listing and mounting it.
_IMAGE_GONE_RE = re.compile(
    r"no such image|image not known|unable to find image|image .* not found", re.IGNORECASE
)


class FilesystemScanUnavailable(ScannerUnavailable):
    """The image filesystem could not be mounted or scanned; the scanner is 'unavailable'."""


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise FilesystemScanUnavailable(f"{cmd[0]} not found in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise FilesystemScanUnavailable(
            f"`{' '.join(cmd[:3])}` timed out after {timeout}s"
        ) from exc


@contextmanager
def mounted_image(image_id: str, timeout: int = MOUNT_TIMEOUT) -> Iterator[Path]:
    """Mount an image with ``podman image mount``; always unmount on exit."""
    proc = _run(["podman", "image", "mount", image_id], timeout)
    if proc.returncode != 0:
        if _IMAGE_GONE_RE.search(proc.stderr):
            raise ScannerImageGone(f"image {image_id[:12]} was removed while it was being scanned")
        hint = ""
        if "cannot run command" in proc.stderr or "rootless" in proc.stderr.lower():
            hint = ' (rootless Podman cannot mount directly; set podman.mode = "rootless")'
        raise FilesystemScanUnavailable(f"podman image mount failed: {proc.stderr.strip()}{hint}")
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    root = Path(lines[-1]) if lines else None
    try:
        if root is None or not root.is_dir():
            raise FilesystemScanUnavailable(f"unexpected mount output: {proc.stdout.strip()!r}")
        yield root
    finally:
        try:
            out = _run(["podman", "image", "unmount", image_id], timeout)
            if out.returncode != 0:
                log.warning(
                    "image unmount failed",
                    extra={"image": image_id[:12], "stderr": out.stderr.strip()},
                )
        except FilesystemScanUnavailable as exc:
            log.warning("image unmount failed", extra={"image": image_id[:12], "error": str(exc)})


class FilesystemScanner:
    """Callable used by the orchestrator: ``scanner(image_id) -> FilesystemReport``."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def __call__(self, image_id: str) -> FilesystemReport:
        cfg = self.settings.filesystem
        if self.settings.podman.mode == "rootless":
            return self._scan_rootless(image_id)
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and geteuid() != 0:
            raise FilesystemScanUnavailable(
                "podman.mode is 'rootful' but PodShield is not running as root; "
                'run as root or set podman.mode = "rootless"'
            )
        with mounted_image(image_id) as root:
            return scan_tree(
                root,
                max_file_size=cfg.max_file_size_kb * 1024,
                max_files=cfg.max_files,
                deadline_seconds=cfg.timeout_seconds,
                max_reported=cfg.max_reported,
            )

    def _scan_rootless(self, image_id: str) -> FilesystemReport:
        cfg = self.settings.filesystem
        cmd = [
            "podman",
            "unshare",
            sys.executable,
            "-m",
            "podshield.scanners.mount",
            image_id,
            "--max-file-size-kb",
            str(cfg.max_file_size_kb),
            "--max-files",
            str(cfg.max_files),
            "--deadline",
            str(cfg.timeout_seconds),
            "--max-reported",
            str(cfg.max_reported),
        ]
        proc = _run(cmd, cfg.timeout_seconds + MOUNT_TIMEOUT)
        if proc.returncode == HELPER_IMAGE_GONE:
            raise ScannerImageGone(
                proc.stderr.strip() or "image was removed while it was being scanned"
            )
        if proc.returncode != 0:
            raise FilesystemScanUnavailable(
                f"rootless filesystem scan failed: {proc.stderr.strip()[-300:]}"
            )
        try:
            return FilesystemReport.model_validate_json(proc.stdout)
        except ValidationError as exc:
            raise FilesystemScanUnavailable(f"helper returned invalid output: {exc}") from exc


def _helper_main(argv: list[str] | None = None) -> int:
    """Entry point executed inside ``podman unshare``."""
    parser = argparse.ArgumentParser(prog="podshield.scanners.mount")
    parser.add_argument("image")
    parser.add_argument("--max-file-size-kb", type=int, default=1024)
    parser.add_argument("--max-files", type=int, default=300_000)
    parser.add_argument("--deadline", type=float, default=300.0)
    parser.add_argument("--max-reported", type=int, default=50)
    args = parser.parse_args(argv)
    try:
        with mounted_image(args.image) as root:
            report = scan_tree(
                root,
                max_file_size=args.max_file_size_kb * 1024,
                max_files=args.max_files,
                deadline_seconds=args.deadline,
                max_reported=args.max_reported,
            )
    except ScannerImageGone as exc:
        print(str(exc), file=sys.stderr)
        return HELPER_IMAGE_GONE
    except FilesystemScanUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    sys.stdout.write(report.model_dump_json())
    return 0


if __name__ == "__main__":
    sys.exit(_helper_main())

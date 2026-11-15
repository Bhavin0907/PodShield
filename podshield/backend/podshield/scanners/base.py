"""Shared plumbing for external-tool scanners (oscap-podman, trivy, skopeo, podman)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence


class ScannerUnavailable(Exception):
    """The scanner cannot run at all here (tool or data missing, wrong privileges)."""


class ScannerError(Exception):
    """The scanner ran but failed for this target (timeout, bad output, non-zero exit)."""


class ScannerImageGone(ScannerError):
    """The image was removed from Podman while the scan was running.

    Not a scanner problem: the orchestrator skips the image instead of recording a
    half-scanned result for something that no longer exists, and keeps scanning the rest.
    """


class ScannerUnsupported(Exception):
    """The scanner ran but cannot assess this image (e.g. the OVAL feed has no data for its OS).

    Different from "no vulnerabilities found": the image gets no result from this scanner.
    """


def run_tool(
    cmd: Sequence[str], timeout: int, ok_codes: Sequence[int] = (0,)
) -> subprocess.CompletedProcess[str]:
    """Run an argument-list command (never a shell) with a timeout.

    Raises ``ScannerUnavailable`` if the binary is missing and ``ScannerError`` on timeout
    or an exit code outside ``ok_codes``.
    """
    try:
        proc = subprocess.run(
            list(cmd), capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise ScannerUnavailable(f"{cmd[0]} not found in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{cmd[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise ScannerUnavailable(f"cannot execute {cmd[0]}: {exc}") from exc
    if proc.returncode not in ok_codes:
        detail = (proc.stderr or proc.stdout).strip()[-400:]
        raise ScannerError(f"{cmd[0]} exited with {proc.returncode}: {detail}")
    return proc

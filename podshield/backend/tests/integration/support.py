"""Helpers shared by the integration tests (real Podman, no mocks).

Mode follows the user running pytest: root drives rootful Podman, anyone else rootless. Run the
suite once as each (`sudo make test-integration`, then `make test-integration`) to cover both.

Resource policy: every image, container and mount a test creates is named ``pstest-*`` and is
removed by the session cleanup in conftest.py, even after a failed or interrupted run.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from podshield.config import Settings
from podshield.db import init_db, make_engine
from podshield.orchestrator import CveScan, ImageResult, Orchestrator, ScanSummary
from podshield.podman_client import PodmanClient
from podshield.scanners.mount import FilesystemScanner

HERE = Path(__file__).parent
IMAGES_DIR = HERE / "images"
PREFIX = "pstest-"
BASE_REF = os.environ.get("PSTEST_BASE_IMAGE", "registry.access.redhat.com/ubi9/ubi-minimal:latest")
OVAL_PATH = os.environ.get("PODSHIELD_OVAL_PATH", "/var/lib/podshield/oval/rhel-9.oval.xml")
REGISTRY_PORT = int(os.environ.get("PSTEST_REGISTRY_PORT", "5000"))
REGISTRY_IMAGE = os.environ.get("PSTEST_REGISTRY_IMAGE", "docker.io/library/registry:2")

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
MODE = "rootful" if IS_ROOT else "rootless"
# Rules that need the image filesystem mounted.
MOUNT_RULES = {"PS-004", "PS-009", "PS-010", "PS-015"}

OLD_TIMESTAMP = "1609459200"  # 2021-01-01
INHERITED_LABELS = (
    "maintainer",
    "version",
    "vcs-url",
    "org.opencontainers.image.authors",
    "org.opencontainers.image.version",
    "org.opencontainers.image.source",
)


@dataclass(frozen=True)
class ImageCase:
    """One Containerfile and the single rule it must trigger (``rule=None``: none at all)."""

    rule: str | None
    name: str  # also the Containerfile name: images/<name>.Containerfile
    tag: str = "1.0.0"
    registry: str = "localhost"
    build_args: tuple[str, ...] = ()
    needs: tuple[str, ...] = ()  # podman build options this case relies on

    @property
    def containerfile(self) -> Path:
        return IMAGES_DIR / f"{self.name}.Containerfile"

    @property
    def ref(self) -> str:
        return f"{self.registry}/{self.name}:{self.tag}"


def _unset_labels() -> tuple[str, ...]:
    return tuple(arg for label in INHERITED_LABELS for arg in ("--unsetlabel", label))


GOLDEN = ImageCase(None, "pstest-golden")
RULE_CASES: tuple[ImageCase, ...] = (
    ImageCase("PS-001", "pstest-root"),
    ImageCase("PS-002", "pstest-latest", tag="latest"),
    ImageCase("PS-003", "pstest-env-secret"),
    ImageCase("PS-004", "pstest-layer-secret"),
    ImageCase(
        "PS-005",
        "pstest-old",
        # --no-cache: a fully cached build reuses the cached image and ignores --timestamp.
        build_args=("--timestamp", OLD_TIMESTAMP, "--no-cache"),
        needs=("--timestamp",),
    ),
    ImageCase("PS-006", "pstest-untrusted"),
    ImageCase("PS-007", "pstest-bloat"),
    ImageCase("PS-008", "pstest-layers"),
    ImageCase("PS-009", "pstest-cache"),
    ImageCase("PS-010", "pstest-setuid"),
    ImageCase("PS-011", "pstest-nohealth"),
    ImageCase("PS-012", "pstest-nolabels", build_args=_unset_labels(), needs=("--unsetlabel",)),
    ImageCase("PS-013", "pstest-ports"),
    ImageCase("PS-014", "pstest-unsigned", registry="localhost.invalid"),
    ImageCase("PS-015", "pstest-shell"),
)
ALL_CASES = (GOLDEN, *RULE_CASES)


# ------------------------------------------------------------------------------ podman


def podman(*args: str, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``podman`` with an argument list (never a shell) and a timeout."""
    proc = subprocess.run(
        ["podman", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"`podman {' '.join(args[:3])} ...` exited {proc.returncode}:\n"
            f"{(proc.stderr or proc.stdout).strip()[-1500:]}"
        )
    return proc


def build_supports(option: str) -> bool:
    out = podman("build", "--help", check=False)
    return option in (out.stdout + out.stderr)


def image_exists(ref: str) -> bool:
    return podman("image", "exists", ref, check=False).returncode == 0


def image_id(ref: str) -> str:
    return podman("image", "inspect", "--format", "{{.Id}}", ref).stdout.strip()


def build_image(case: ImageCase) -> str:
    """Build a case image (docker format: OCI drops HEALTHCHECK); returns its ID."""
    podman(
        "build",
        "--format",
        "docker",
        "-t",
        case.ref,
        "-f",
        str(case.containerfile),
        "--build-arg",
        f"BASE={BASE_REF}",
        *case.build_args,
        str(IMAGES_DIR),
    )
    return image_id(case.ref)


def pstest_container_ids() -> list[str]:
    out = podman("ps", "-a", "--filter", f"name={PREFIX}", "--format", "{{.ID}}", check=False)
    return out.stdout.split()


def pstest_image_ids() -> list[str]:
    out = podman(
        "image", "ls", "--filter", f"reference=*/{PREFIX}*", "--format", "{{.ID}}", check=False
    )
    return sorted(set(out.stdout.split()))


def mounted_images() -> str:
    """What ``podman image mount`` (no arguments) lists as currently mounted."""
    cmd = (
        ["podman", "image", "mount"]
        if IS_ROOT
        else ["podman", "unshare", "podman", "image", "mount"]
    )
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    return proc.stdout


def is_mounted(ref: str) -> bool:
    """True if ``podman image mount`` still lists the image (by name, ID or short ID)."""
    listing = mounted_images()
    iid = image_id(ref)
    return any(token in listing for token in (iid, iid[:12], ref))


def purge() -> None:
    """Remove every pstest container, mount and image. Safe to call repeatedly."""
    for cid in pstest_container_ids():
        podman("rm", "-f", "-t", "0", "-v", cid, check=False)
    for iid in pstest_image_ids():
        podman("image", "unmount", iid, check=False)
        podman("rmi", "-f", iid, check=False)
    vols = podman(
        "volume", "ls", "--filter", f"name={PREFIX}", "--format", "{{.Name}}", check=False
    )
    for volume in vols.stdout.split():
        podman("volume", "rm", "-f", volume, check=False)


# --------------------------------------------------------------------- settings/config


def write_policy(directory: Path) -> dict[str, str]:
    """A signature policy that covers the local test registries, so the golden image is clean.

    The host's real policy.json is never read or changed. ``localhost.invalid`` is deliberately
    left uncovered; that is how PS-014 is triggered.
    """
    key = {"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/dev/null"}
    policy = directory / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "default": [{"type": "reject"}],
                "transports": {
                    "docker": {
                        "localhost": [key],
                        f"localhost:{REGISTRY_PORT}": [key],
                        "registry.access.redhat.com": [key],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return {
        "policy_path": policy.as_posix(),
        "registries_conf": (directory / "registries.conf").as_posix(),
        "registries_conf_d": (directory / "registries.conf.d").as_posix(),
        "registries_d": (directory / "registries.d").as_posix(),
    }


def make_settings(directory: Path, socket: str) -> Settings:
    directory.mkdir(parents=True, exist_ok=True)
    s = Settings()
    s.podman.socket = socket
    s.podman.mode = MODE
    s.database.path = (directory / "podshield.db").as_posix()
    for key, value in write_policy(directory).items():
        setattr(s.trust, key, value)
    # Sized for the fixtures: a ~100 MiB ubi-minimal passes, the 150 MiB ballast image does not.
    s.thresholds.max_image_size_mb = 200
    s.thresholds.max_layers = 12
    s.oscap.oval_path = OVAL_PATH
    return s


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def write_config(settings: Settings, path: Path) -> Path:
    """The handful of settings the CLI/subprocess tests need, as TOML."""
    sections: dict[str, dict[str, Any]] = {
        "podman": {"socket": settings.podman.socket, "mode": settings.podman.mode},
        "database": {"path": settings.database.path},
        "thresholds": {
            "max_image_size_mb": settings.thresholds.max_image_size_mb,
            "max_layers": settings.thresholds.max_layers,
        },
        "trust": settings.trust.model_dump(
            include={"policy_path", "registries_conf", "registries_conf_d", "registries_d"}
        ),
        "oscap": {"oval_path": settings.oscap.oval_path},
        "registry": {"tls_verify": settings.registry.tls_verify},
        "watcher": {"debounce_seconds": settings.watcher.debounce_seconds},
        "logging": {"level": "INFO"},
    }
    lines: list[str] = []
    for name, values in sections.items():
        lines.append(f"[{name}]")
        lines += [f"{k} = {_toml_value(v)}" for k, v in values.items()]
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ------------------------------------------------------------------------------ scanning


def open_engine(settings: Settings) -> Engine:
    engine = make_engine(settings.database.path)
    init_db(engine)
    return engine


def scan(
    settings: Settings,
    ref: str | None = None,
    *,
    all_images: bool = False,
    cve_scanners: Mapping[str, CveScan] | None = None,
) -> ScanSummary:
    """Scan with the real Podman API and the real filesystem scanner (CVE scanners opt-in)."""
    client = PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)
    try:
        return Orchestrator(
            client,
            open_engine(settings),
            settings,
            fs_scanner=FilesystemScanner(settings),
            cve_scanners=cve_scanners,
        ).scan(image=ref, scan_all=all_images)
    finally:
        client.close()


def scan_one(
    settings: Settings, ref: str, cve_scanners: Mapping[str, CveScan] | None = None
) -> ImageResult:
    summary = scan(settings, ref, cve_scanners=cve_scanners)
    assert summary.results, f"scan of {ref} produced no result: {summary.errors}"
    return summary.results[0]


def rule_ids(result: ImageResult) -> set[str]:
    return {f.rule_id for f in result.findings}


CLI_SNIPPET = "import sys; from podshield.cli import main; sys.exit(main())"


def cli_command(config: Path, *args: str) -> list[str]:
    """argv for ``podshield -c CONFIG ARGS...`` (the console script may not be on PATH)."""
    return [sys.executable, "-c", CLI_SNIPPET, "-c", str(config), *args]


def run_cli(config: Path, *args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cli_command(config, *args), capture_output=True, text=True, timeout=timeout, check=False
    )


def have(binary: str) -> bool:
    return shutil.which(binary) is not None

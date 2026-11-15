"""Scan-performance harness. Not a pytest module: run it by hand.

    # Anywhere (no Podman): real filesystem walker, rules, scoring and SQLite on synthetic images.
    python -m tests.perf.perf_scan --images 20 --concurrency 4

    # On the RHEL VM: the real thing (Podman, image mounts, oscap/trivy) over every local image.
    python -m tests.perf.perf_scan --real --limit 20 --concurrency 4

It reports total wall time, time per image (start to finish, as seen by the progress events),
and peak memory of the whole process tree. Any image slower than --slow-seconds (default 60)
is flagged. Exit status is 1 when something was flagged, so it can gate a pipeline.

Synthetic mode exercises PodShield's own code. It does not include Podman mounts or the oscap
and trivy subprocesses: pass --simulate-tool-seconds to model those as a sleep (the output is
labelled "simulated" so the number is never mistaken for a measurement of the real tools).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Self

from podshield.config import Settings
from podshield.db import init_db, make_engine
from podshield.orchestrator import Orchestrator, ProgressEvent
from podshield.podman_client import ImageInfo, parse_inspect
from podshield.scanners.filesystem import scan_tree
from podshield.schemas import FilesystemReport, Severity, Vulnerability

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key, never a real credential


# ---------------------------------------------------------------------------------- memory


class MemorySampler:
    """Peak resident memory of this process plus every child (oscap, trivy, podman, ...)."""

    def __init__(self, interval: float = 0.05) -> None:
        self.interval, self.peak, self._stop = interval, 0, threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        try:
            import psutil  # type: ignore[import-untyped]

            self._psutil: Any = psutil
        except ImportError:
            self._psutil = None

    def _rss(self) -> int:
        proc = self._psutil.Process()
        total = proc.memory_info().rss
        for child in proc.children(recursive=True):
            try:
                total += child.memory_info().rss
            except self._psutil.Error:
                continue
        return int(total)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.peak = max(self.peak, self._rss())
            self._stop.wait(self.interval)

    def __enter__(self) -> Self:
        if self._psutil is not None:
            self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._psutil is not None:
            self._thread.join(timeout=2)
        self.peak = max(self.peak, self._fallback_peak())

    @staticmethod
    def _fallback_peak() -> int:
        """Peak RSS of this process from the OS, used when psutil is missing (and as a floor)."""
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
            ctypes.windll.psapi.GetProcessMemoryInfo(  # type: ignore[attr-defined]
                handle, ctypes.byref(counters), counters.cb
            )
            return int(counters.PeakWorkingSetSize)
        import resource

        scale = 1 if sys.platform == "darwin" else 1024  # ru_maxrss: bytes on macOS, KiB on Linux
        own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale
        child = (
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * scale
        )  # largest single child
        return own + child


# ----------------------------------------------------------------------- synthetic images


def build_tree(root: Path, files: int, kb: int, seed: int) -> None:
    """A plausible image filesystem: nested dirs, mixed file sizes, a few planted secrets."""
    line = "# generated by podshield perf harness " + "lorem ipsum dolor sit amet " * 3 + "\n"
    body = (line * (kb * 1024 // len(line) + 1))[: kb * 1024]
    for i in range(files):
        d = root / f"usr/lib/pkg{(i + seed) % 40}/sub{i % 7}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"file{i}.txt").write_text(body, encoding="utf-8")
    (root / "app").mkdir(exist_ok=True)
    (root / "app/.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_SECRET}\n", encoding="utf-8")
    (root / "var/cache/dnf").mkdir(parents=True, exist_ok=True)
    (root / "var/cache/dnf/metadata.xml").write_text(body, encoding="utf-8")
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc/os-release").write_text('ID="rhel"\nVERSION_ID="9.4"\n', encoding="utf-8")


def images(count: int) -> list[ImageInfo]:
    import json as _json

    base = [
        parse_inspect(
            _json.loads((FIXTURES / "inspect_bad.json").read_text("utf-8")),
            _json.loads((FIXTURES / "history_bad.json").read_text("utf-8")),
        ),
        parse_inspect(_json.loads((FIXTURES / "inspect_good.json").read_text("utf-8"))),
    ]
    out = []
    for i in range(count):
        tag = f"{i:02d}"
        out.append(
            base[i % 2].model_copy(
                deep=True,
                update={
                    "id": "sha256:" + f"{i:02x}".ljust(64, "a"),
                    "repo_tags": [f"localhost/pstest-perf{tag}:1.0"],
                },
            )
        )
    return out


class Source:
    def __init__(self, imgs: list[ImageInfo]) -> None:
        self.imgs = imgs

    def list_images(self) -> list[ImageInfo]:
        return [i.model_copy(deep=True) for i in self.imgs]

    def get_image(self, reference: str) -> ImageInfo:  # pragma: no cover - unused here
        raise NotImplementedError


# --------------------------------------------------------------------------------- running


def run(args: argparse.Namespace) -> dict[str, Any]:
    settings = Settings()
    settings.scan.max_concurrent_images = args.concurrency
    work = Path(tempfile.mkdtemp(prefix="pstest-perf-"))
    events: list[tuple[float, ProgressEvent]] = []

    def on_progress(ev: ProgressEvent) -> None:
        events.append((time.monotonic(), ev))

    try:
        engine = make_engine((work / "perf.db").as_posix())
        init_db(engine)
        if args.real:
            from podshield.factory import make_cve_scanners, make_fs_scanner
            from podshield.podman_client import PodmanClient

            real_source = PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)
            all_images = real_source.list_images()
            chosen = all_images[: args.limit] if args.limit else all_images
            source: Any = Source(chosen)
            fs_scan: Any = make_fs_scanner(settings)
            cve_scans: Any = make_cve_scanners(settings)
            mode = "real"
        else:
            chosen = images(args.images)
            trees = []
            for t in range(args.trees):
                tree = work / f"tree{t}"
                build_tree(tree, args.files, args.file_kb, seed=t)
                trees.append(tree)
            by_id = {img.id: trees[i % len(trees)] for i, img in enumerate(chosen)}
            source = Source(chosen)

            def fs_scan(image_id: str) -> FilesystemReport:
                return scan_tree(
                    by_id[image_id],
                    max_file_size=settings.filesystem.max_file_size_kb * 1024,
                    max_files=settings.filesystem.max_files,
                    deadline_seconds=settings.filesystem.timeout_seconds,
                    max_reported=settings.filesystem.max_reported,
                )

            def fake_cve(_image: ImageInfo) -> list[Vulnerability]:
                time.sleep(args.simulate_tool_seconds)  # SIMULATED external tool latency
                return [
                    Vulnerability(
                        cve_id="CVE-2024-0001",
                        package="openssl",
                        severity=Severity.HIGH,
                        source="simulated",
                    )
                ]

            cve_scans = {"simulated-oscap": fake_cve} if args.simulate_tool_seconds else {}
            mode = "synthetic"

        orch = Orchestrator(
            source, engine, settings, on_progress, fs_scanner=fs_scan, cve_scanners=cve_scans
        )
        with MemorySampler() as memory:
            started = time.monotonic()
            summary = orch.scan(scan_all=True)
            total = time.monotonic() - started
        engine.dispose()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    begin: dict[str, float] = {}
    per_image: dict[str, float] = {}
    for at, ev in events:
        if ev.stage == "image_started":
            begin[ev.image] = at
        elif ev.stage in {"image_done", "image_failed"} and ev.image in begin:
            per_image[ev.image] = at - begin[ev.image]
    durations = list(per_image.values())
    slow = {name: round(sec, 2) for name, sec in per_image.items() if sec > args.slow_seconds}
    return {
        "mode": mode,
        "host": f"{platform.system()} {platform.release()}, Python {platform.python_version()}, "
        f"{os.cpu_count()} CPUs",
        "images": len(chosen),
        "concurrency": args.concurrency,
        "scan_status": summary.status,
        "errors": summary.errors,
        "simulated_tool_seconds": args.simulate_tool_seconds if mode == "synthetic" else None,
        "total_seconds": round(total, 2),
        "seconds_per_image_avg": round(sum(durations) / len(durations), 3) if durations else None,
        "seconds_per_image_max": round(max(durations), 3) if durations else None,
        "throughput_images_per_second": round(len(chosen) / total, 2) if total else None,
        "peak_memory_mb": round(memory.peak / 1024 / 1024, 1),
        "psutil": memory._psutil is not None,
        "slow_threshold_seconds": args.slow_seconds,
        "slow_images": slow,
        "synthetic_tree": None
        if args.real
        else f"{args.trees} trees x {args.files} files x {args.file_kb} KiB (+ secrets, cache, os-release)",
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--images", type=int, default=20, help="synthetic images to scan")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--real", action="store_true", help="use real Podman and scanners (RHEL VM)")
    p.add_argument("--limit", type=int, default=20, help="with --real: at most this many images")
    p.add_argument("--files", type=int, default=3000, help="files per synthetic image tree")
    p.add_argument("--file-kb", type=int, default=4)
    p.add_argument("--trees", type=int, default=5, help="distinct trees, reused round-robin")
    p.add_argument(
        "--simulate-tool-seconds",
        type=float,
        default=0.0,
        help="SIMULATED oscap/trivy latency per image (synthetic mode only)",
    )
    p.add_argument("--slow-seconds", type=float, default=60.0)
    p.add_argument("--out", type=Path, help="write the result as JSON")
    args = p.parse_args()

    result = run(args)
    print(json.dumps(result, indent=2))
    if args.out:
        args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if result["slow_images"]:
        print(
            f"\nSLOW: {len(result['slow_images'])} image(s) over {args.slow_seconds:.0f}s",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Command line interface.

``podshield scan``, ``report``, ``containers``, ``registry``, ``doctor`` and ``watch``.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sqlite3
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any

from sqlalchemy.exc import DatabaseError as SaDatabaseError

from podshield import __version__
from podshield.config import ConfigError, Settings, load_settings
from podshield.db import DatabaseProblem, explain_db_error, init_db, make_engine
from podshield.factory import make_cve_scanners
from podshield.logging_setup import configure_logging
from podshield.orchestrator import (
    CveScan,
    ImageResult,
    Orchestrator,
    StoredReport,
    latest_reports,
    unique_cve_severities,
)
from podshield.overrides import apply_rule_overrides
from podshield.podman_client import ImageSource, PodmanClient, PodmanError
from podshield.scanners.base import ScannerError, ScannerUnavailable
from podshield.scanners.mount import FilesystemScanner
from podshield.scanners.registry import RegistryAudit, RegistryAuditor
from podshield.scanners.runtime import ContainerAudit, audit_containers
from podshield.scanners.status import scanner_statuses
from podshield.schemas import Severity, Vulnerability
from podshield.watcher import Watcher

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

# (severity, rule_id, title, evidence, remediation)
FindingRow = tuple[str, str, str, list[str], str]
# (cve_id, package, severity, fixed_version, source)
CveRow = tuple[str, str, str, str, str]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="podshield", description="Container image security and hygiene auditor for Podman."
    )
    parser.add_argument("--version", action="version", version=f"podshield {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        help="path to config.toml (default: $PODSHIELD_CONFIG or /etc/podshield/config.toml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one image or all images")
    scan.add_argument("image", nargs="?", help="image name, tag, or ID")
    scan.add_argument("--all", action="store_true", help="scan every local image")
    scan.add_argument(
        "--skip-filesystem",
        action="store_true",
        help="do not mount images (skips PS-004, PS-009, PS-010, PS-015)",
    )
    scan.add_argument(
        "--skip-cve", action="store_true", help="do not run the oscap and trivy CVE scanners"
    )
    scan.add_argument("--json", action="store_true", help="machine-readable output")
    scan.add_argument(
        "-v", "--verbose", action="store_true", help="show remediation snippets and the CVE list"
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit with status 1 if any finding or CVE is at or above this severity",
    )

    report = sub.add_parser("report", help="show stored results from the latest scans")
    report.add_argument("image", nargs="?", help="limit to one image name or ID prefix")
    report.add_argument("--json", action="store_true", help="machine-readable output")
    report.add_argument(
        "-v", "--verbose", action="store_true", help="show remediation snippets and the CVE list"
    )

    containers = sub.add_parser("containers", help="audit running containers (PS-R01..R05)")
    containers.add_argument("--json", action="store_true", help="machine-readable output")
    containers.add_argument(
        "-v", "--verbose", action="store_true", help="show remediation snippets"
    )

    registry = sub.add_parser("registry", help="audit a remote image before pulling it (skopeo)")
    registry.add_argument("reference", help="e.g. registry.access.redhat.com/ubi9/ubi-minimal:9.4")
    registry.add_argument("--json", action="store_true", help="machine-readable output")
    registry.add_argument("-v", "--verbose", action="store_true", help="show remediation snippets")

    sub.add_parser("doctor", help="show which scanners are available on this host")
    watch = sub.add_parser("watch", help="scan automatically on Podman pull/build/tag events")
    watch.add_argument(
        "--scan-on-start",
        action="store_true",
        help="scan every image once before waiting for events",
    )
    watch.add_argument(
        "--debounce",
        type=float,
        metavar="SECONDS",
        help="wait this long after the last event for an image before scanning",
    )
    watch.add_argument(
        "--skip-filesystem",
        action="store_true",
        help="do not mount images (skips PS-004, PS-009, PS-010, PS-015)",
    )
    watch.add_argument(
        "--skip-cve", action="store_true", help="do not run the oscap and trivy CVE scanners"
    )
    return parser


def _make_source(settings: Settings) -> ImageSource:
    return PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)


def _make_container_source(settings: Settings) -> Any:
    return PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)


def _make_cve_scanners(settings: Settings) -> dict[str, CveScan]:
    return make_cve_scanners(settings)


# ------------------------------------------------------------------------- rendering


def _render_findings(items: Sequence[FindingRow], verbose: bool) -> list[str]:
    lines: list[str] = []
    for severity, rule_id, title, evidence, remediation in items:
        lines.append(f"  [{severity.upper():8}] {rule_id}  {title}")
        lines.extend(f"      - {e}" for e in evidence)
        if verbose and remediation:
            lines.append("      fix:")
            lines.extend(f"        {line}" for line in remediation.splitlines())
    return lines


def _render_cves(rows: Sequence[CveRow], verbose: bool, limit: int = 25) -> list[str]:
    if not rows:
        return []
    worst: dict[str, str] = {}
    order = [s.value for s in Severity]
    for cve_id, _pkg, severity, _fixed, _src in rows:
        if cve_id not in worst or order.index(severity) < order.index(worst[cve_id]):
            worst[cve_id] = severity
    counts = Counter(worst.values())
    summary = ", ".join(f"{counts[s]} {s}" for s in order if counts[s])
    lines = [f"  CVEs: {len(worst)} ({summary})"]
    if verbose:
        ranked = sorted(rows, key=lambda r: (order.index(r[2]), r[0], r[1]))
        for cve_id, pkg, severity, fixed, src in ranked[:limit]:
            lines.append(
                f"      {severity.upper():8} {cve_id:18} {pkg or '-':24} "
                f"fixed: {fixed or 'n/a':16} [{src}]"
            )
        if len(ranked) > limit:
            lines.append(f"      ... and {len(ranked) - limit} more (use --json for all)")
    return lines


def _vuln_rows(vulns: Sequence[Vulnerability]) -> list[CveRow]:
    return [(v.cve_id, v.package, v.severity.value, v.fixed_version, v.source) for v in vulns]


def _finding_rows(findings: Sequence[Any]) -> list[FindingRow]:
    return [
        (
            getattr(f.severity, "value", f.severity),
            f.rule_id,
            f.title,
            list(f.evidence),
            f.remediation,
        )
        for f in findings
    ]


def _print_block(
    header: str, findings: list[FindingRow], cves: list[CveRow], verbose: bool
) -> None:
    print(header)
    if not findings and not cves:
        print("  no findings")
    for line in _render_findings(findings, verbose):
        print(line)
    for line in _render_cves(cves, verbose):
        print(line)
    print()


def _print_result(result: ImageResult, verbose: bool) -> None:
    img = result.image
    header = (
        f"{img.display_name}  ({img.short_id})  grade {result.score.grade}  "
        f"score {result.score.score}/100"
    )
    _print_block(
        header, _finding_rows(result.findings), _vuln_rows(result.vulnerabilities), verbose
    )
    for scanner, note in sorted(result.cve_notes.items()):
        print(f"  CVE data: {scanner} {note}")


def _print_stored(report: StoredReport, verbose: bool) -> None:
    img = report.image
    name = img.repo_tags[0] if img.repo_tags else img.id[:12]
    when = img.last_scanned_at.isoformat(timespec="seconds") if img.last_scanned_at else "never"
    header = f"{name}  ({img.id[:12]})  grade {img.grade}  score {img.score}/100  scanned {when}"
    cves = [
        (v.cve_id, v.package, v.severity, v.fixed_version, v.source) for v in report.vulnerabilities
    ]
    _print_block(header, _finding_rows(report.findings), cves, verbose)


def _result_json(result: ImageResult) -> dict[str, Any]:
    return {
        "id": result.image.id,
        "name": result.image.display_name,
        "tags": result.image.repo_tags,
        "score": result.score.score,
        "grade": result.score.grade,
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "vulnerabilities": [v.model_dump(mode="json") for v in result.vulnerabilities],
        "cve_notes": result.cve_notes,
    }


def _stored_json(report: StoredReport) -> dict[str, Any]:
    img = report.image
    return {
        "id": img.id,
        "tags": img.repo_tags,
        "score": img.score,
        "grade": img.grade,
        "last_scanned_at": img.last_scanned_at.isoformat() if img.last_scanned_at else None,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "package": v.package,
                "severity": v.severity,
                "installed_version": v.installed_version,
                "fixed_version": v.fixed_version,
                "title": v.title,
                "url": v.url,
                "source": v.source,
            }
            for v in report.vulnerabilities
        ],
    }


# ------------------------------------------------------------------------- commands


def cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    if bool(args.image) == bool(args.all):
        print("error: specify either IMAGE or --all", file=sys.stderr)
        return EXIT_ERROR

    engine = make_engine(settings.database.path)
    init_db(engine)
    apply_rule_overrides(settings, engine)
    source = _make_source(settings)
    use_fs = settings.filesystem.enabled and not args.skip_filesystem
    orchestrator = Orchestrator(
        source,
        engine,
        settings,
        fs_scanner=FilesystemScanner(settings) if use_fs else None,
        cve_scanners={} if args.skip_cve else _make_cve_scanners(settings),
    )
    try:
        summary = orchestrator.scan(image=args.image, scan_all=args.all)
    except PodmanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()

    if args.json:
        print(
            json.dumps(
                {
                    "scan_id": summary.scan_id,
                    "status": summary.status,
                    "errors": summary.errors,
                    "warnings": summary.warnings,
                    "scanners": {
                        n: dict(zip(("status", "detail"), o.final(), strict=True))
                        for n, o in summary.scanners.items()
                    },
                    "images": [_result_json(r) for r in summary.results],
                },
                indent=2,
            )
        )
    else:
        if not summary.results and not summary.errors:
            print("No images found. Pull or build one, then rerun.")
        for result in summary.results:
            _print_result(result, args.verbose)
        for err in summary.errors:
            print(f"error: {err}", file=sys.stderr)
        for warning in summary.warnings:
            print(f"warning: {warning}", file=sys.stderr)

    if summary.status == "failed":
        return EXIT_ERROR
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        for r in summary.results:
            if any(f.severity.rank >= threshold for f in r.findings) or any(
                s.rank >= threshold for s in unique_cve_severities(r.vulnerabilities)
            ):
                return EXIT_FINDINGS
    return EXIT_OK


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database.path)
    init_db(engine)
    reports = latest_reports(engine, args.image)
    if args.json:
        print(json.dumps([_stored_json(r) for r in reports], indent=2))
    elif not reports:
        print("No stored results. Run `podshield scan --all` first.")
    else:
        for report in reports:
            _print_stored(report, args.verbose)
    return EXIT_OK


def _audit_json(audit: ContainerAudit) -> dict[str, Any]:
    c = audit.container
    return {
        "id": c.id,
        "name": c.name,
        "image": c.image,
        "status": c.status,
        "score": audit.score.score,
        "grade": audit.score.grade,
        "findings": [f.model_dump(mode="json") for f in audit.findings],
    }


def cmd_containers(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database.path)
    init_db(engine)
    apply_rule_overrides(settings, engine)
    client = _make_container_source(settings)
    try:
        raw = client.list_containers()
    except PodmanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()
    audits = audit_containers(raw, settings)
    if args.json:
        print(json.dumps([_audit_json(a) for a in audits], indent=2))
    elif not audits:
        print("No running containers.")
    for audit in audits:
        if args.json:
            break
        c = audit.container
        header = (
            f"{c.name or c.short_id}  ({c.short_id})  image {c.image or '?'}  "
            f"grade {audit.score.grade}  score {audit.score.score}/100"
        )
        _print_block(header, _finding_rows(audit.findings), [], args.verbose)
    return EXIT_OK


def _print_registry(audit: RegistryAudit, verbose: bool) -> None:
    header = (
        f"{audit.reference}  ({audit.image.short_id})  grade {audit.score.grade}  "
        f"score {audit.score.score}/100  [pre-pull audit]"
    )
    _print_block(header, _finding_rows(audit.findings), [], verbose)
    for note in audit.notes:
        print(f"note: {note}")


def cmd_registry(args: argparse.Namespace, settings: Settings) -> int:
    engine = make_engine(settings.database.path)
    init_db(engine)
    apply_rule_overrides(settings, engine)
    auditor = RegistryAuditor(settings)
    try:
        audit = auditor.audit(args.reference)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ScannerUnavailable as exc:
        print(f"error: registry scanner unavailable: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(
            json.dumps(
                {
                    "reference": audit.reference,
                    "id": audit.image.id,
                    "score": audit.score.score,
                    "grade": audit.score.grade,
                    "findings": [f.model_dump(mode="json") for f in audit.findings],
                    "skipped_rules": audit.skipped_rules,
                    "notes": audit.notes,
                },
                indent=2,
            )
        )
    else:
        _print_registry(audit, args.verbose)
    return EXIT_OK


def cmd_doctor(_args: argparse.Namespace, settings: Settings) -> int:
    for status in scanner_statuses(settings):
        state = "ok" if status.available else "UNAVAILABLE"
        note = "" if status.enabled else " (disabled in config)"
        detail = f" - {status.detail}" if status.detail else ""
        print(f"{status.name:12} {state}{note}{detail}")
    return EXIT_OK


def cmd_watch(args: argparse.Namespace, settings: Settings) -> int:
    if args.debounce is not None:
        settings.watcher.debounce_seconds = args.debounce
    if args.scan_on_start:
        settings.watcher.scan_on_start = True

    engine = make_engine(settings.database.path)
    init_db(engine)
    rules = apply_rule_overrides(settings, engine)
    events_client = PodmanClient(settings.podman.socket, settings.podman.timeout_seconds)
    use_fs = settings.filesystem.enabled and not args.skip_filesystem

    def scan(target: str | None) -> None:
        source = _make_source(settings)  # fresh connection per scan; the daemon is long-lived
        try:
            orchestrator = Orchestrator(
                source,
                engine,
                settings,
                fs_scanner=FilesystemScanner(settings) if use_fs else None,
                cve_scanners={} if args.skip_cve else _make_cve_scanners(settings),
            )
            summary = orchestrator.scan(image=target, scan_all=target is None)
        finally:
            close = getattr(source, "close", None)
            if callable(close):
                close()
        log.info(
            "watcher scan finished",
            extra={
                "scan_id": summary.scan_id,
                "status": summary.status,
                "images": len(summary.results),
                "errors": len(summary.errors),
            },
        )

    watcher = Watcher(settings.watcher, events_client.events, scan, before_scan=rules.reload)

    def request_stop(signum: int, _frame: object) -> None:
        log.info("stop requested", extra={"signal": signal.Signals(signum).name})
        watcher.stop.set()

    previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        watcher.run()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        events_client.close()
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    configure_logging(settings.logging.level)

    handlers = {
        "scan": cmd_scan,
        "report": cmd_report,
        "containers": cmd_containers,
        "registry": cmd_registry,
        "doctor": cmd_doctor,
        "watch": cmd_watch,
    }
    try:
        return handlers[args.command](args, settings)
    except KeyboardInterrupt:
        return 130
    except DatabaseProblem as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (SaDatabaseError, sqlite3.Error) as exc:
        print(f"error: {explain_db_error(exc, settings.database.path) or exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:  # e.g. database path not writable
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

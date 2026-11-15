"""CVE detection with ``oscap-podman <image> oval eval`` and the Red Hat OVAL feed.

``oscap-podman`` mounts the image and evaluates the OVAL definitions against its RPM
database. We parse the results XML: definitions with ``result="true"`` are vulnerabilities.
Their metadata (title, severity, CVE ids, fixed package versions) comes from the
``oval_definitions`` section embedded in the results, or from the feed itself if absent.
"""

from __future__ import annotations

import bz2
import gzip
import logging
import re
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import IO, cast
from xml.etree.ElementTree import Element, ParseError  # nosec B405

from defusedxml.ElementTree import iterparse

from podshield.config import Settings
from podshield.scanners.base import ScannerError, ScannerUnavailable, ScannerUnsupported, run_tool
from podshield.schemas import ImageInfo, Severity, Vulnerability

log = logging.getLogger(__name__)

NS_DEF = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
NS_RES = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
SOURCE = "oscap"

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "important": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}
_EARLIER_RE = re.compile(r"^(?P<pkg>[A-Za-z0-9_.+-]+) is earlier than (?P<evr>\S+)$")
_TITLE_SEVERITY_RE = re.compile(r"\((Critical|Important|Moderate|Low)\)\s*$", re.IGNORECASE)


def _open(path: Path) -> IO[bytes]:
    suffix = path.suffix.lower()
    if suffix == ".bz2":
        return bz2.open(path, "rb")
    if suffix == ".gz":
        return cast(IO[bytes], gzip.open(path, "rb"))
    return path.open("rb")


def parse_true_definitions(source: IO[bytes]) -> set[str]:
    """IDs of OVAL definitions that evaluated to true (i.e. the image is affected)."""
    ids: set[str] = set()
    for _event, elem in iterparse(source, events=("end",)):
        if elem.tag == NS_RES + "definition":
            if elem.get("result") == "true" and (def_id := elem.get("definition_id")):
                ids.add(def_id)
            elem.clear()
    return ids


def _definition_to_vulns(elem: Element) -> list[Vulnerability]:
    meta = elem.find(NS_DEF + "metadata")
    if meta is None:
        return []
    title = (meta.findtext(NS_DEF + "title") or "").strip()

    severity_text = (meta.findtext(f"{NS_DEF}advisory/{NS_DEF}severity") or "").strip().lower()
    if severity_text not in _SEVERITY and (m := _TITLE_SEVERITY_RE.search(title)):
        severity_text = m.group(1).lower()
    severity = _SEVERITY.get(severity_text, Severity.MEDIUM)

    cves: list[tuple[str, str]] = []
    advisory: tuple[str, str] | None = None
    for ref in meta.findall(NS_DEF + "reference"):
        ref_id, url = ref.get("ref_id") or "", ref.get("ref_url") or ""
        if ref.get("source") == "CVE" and ref_id:
            cves.append((ref_id, url))
        elif ref.get("source") == "RHSA" and ref_id:
            advisory = (ref_id, url)
    if not cves and advisory:
        cves = [advisory]  # no CVE ids: report the advisory itself
    if not cves:
        return []

    packages: dict[str, str] = {}
    for crit in elem.iter(NS_DEF + "criterion"):
        m = _EARLIER_RE.match(crit.get("comment") or "")
        if m:
            packages.setdefault(m.group("pkg"), m.group("evr"))
    if not packages:
        packages = {"": ""}

    return [
        Vulnerability(
            cve_id=cve_id,
            package=pkg,
            severity=severity,
            fixed_version=evr,
            title=title,
            url=url,
            source=SOURCE,
        )
        for cve_id, url in cves
        for pkg, evr in packages.items()
    ]


def parse_definitions(source: IO[bytes], wanted: set[str]) -> dict[str, list[Vulnerability]]:
    """Extract vulnerabilities for the wanted definition IDs from an oval_definitions stream."""
    found: dict[str, list[Vulnerability]] = {}
    for _event, elem in iterparse(source, events=("end",)):
        if elem.tag == NS_DEF + "definition":
            def_id = elem.get("id")
            if def_id in wanted:
                found[def_id] = _definition_to_vulns(elem)
            elem.clear()
            if len(found) == len(wanted):
                break
    return found


def parse_results(results_path: Path, feed_path: Path | None = None) -> list[Vulnerability]:
    """Parse an oscap results file (falling back to the feed for definition metadata)."""
    try:
        with _open(results_path) as fh:
            true_ids = parse_true_definitions(fh)
        if not true_ids:
            return []
        with _open(results_path) as fh:
            meta = parse_definitions(fh, true_ids)
        missing = true_ids - set(meta)
        if missing and feed_path is not None:
            with _open(feed_path) as fh:
                meta.update(parse_definitions(fh, missing))
    except (ParseError, OSError, EOFError) as exc:
        raise ScannerError(f"cannot parse oscap results: {exc}") from exc
    return [v for vulns in meta.values() for v in vulns]


def merge_vulnerabilities(vulns: Iterable[Vulnerability]) -> list[Vulnerability]:
    """Dedupe by (CVE, package); keep the highest severity and a fixed version if any know it."""
    merged: dict[tuple[str, str], Vulnerability] = {}
    for v in vulns:
        key = (v.cve_id, v.package)
        cur = merged.get(key)
        if cur is None:
            merged[key] = v.model_copy()
            continue
        if v.severity.rank > cur.severity.rank:
            cur.severity = v.severity
        cur.fixed_version = cur.fixed_version or v.fixed_version
        cur.installed_version = cur.installed_version or v.installed_version
        cur.title = cur.title or v.title
        cur.url = cur.url or v.url
        sources = dict.fromkeys([*cur.source.split(","), *v.source.split(",")])
        cur.source = ",".join(s for s in sources if s)
    return sorted(merged.values(), key=lambda v: (-v.severity.rank, v.cve_id, v.package))


def unsupported_reason(image: ImageInfo, supported_ids: Iterable[str]) -> str | None:
    """Why the Red Hat OVAL feed cannot assess this image, or None if it can (or we can't tell).

    The evidence is the image's own os-release, read from the mounted filesystem by the
    filesystem scanner. Without it (scanner disabled or unavailable) the scan proceeds
    rather than guessing from labels.
    """
    release = image.filesystem.os_release if image.filesystem else {}
    if not release:
        return None
    if release.get("ID", "").lower() in {s.lower() for s in supported_ids}:
        return None
    name = release.get("PRETTY_NAME") or release.get("NAME") or release.get("ID") or "unknown OS"
    return f"{name} is not covered by the Red Hat OVAL feed"


class OscapScanner:
    name = "oscap"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def check(self) -> None:
        """Raise ``ScannerUnavailable`` unless the binary and OVAL feed are present."""
        cfg = self.settings.oscap
        if shutil.which(cfg.binary) is None:
            raise ScannerUnavailable(f"{cfg.binary} not installed (dnf install openscap-utils)")
        if not Path(cfg.oval_path).is_file():
            raise ScannerUnavailable(
                f"OVAL feed not found at {cfg.oval_path}; download it from "
                "https://www.redhat.com/security/data/oval/v2/ and set [oscap].oval_path"
            )

    def __call__(self, image: ImageInfo) -> list[Vulnerability]:
        self.check()
        cfg = self.settings.oscap
        if reason := unsupported_reason(image, cfg.supported_os_ids):
            raise ScannerUnsupported(reason)
        with tempfile.TemporaryDirectory(prefix="podshield-oscap-") as tmp:
            results = Path(tmp) / "results.xml"
            cmd: list[str] = [
                cfg.binary,
                image.id,
                "oval",
                "eval",
                "--results",
                str(results),
                cfg.oval_path,
            ]
            if self.settings.podman.mode == "rootless":
                cmd = ["podman", "unshare", *cmd]
            # oscap exits 0 when nothing is vulnerable and 2 when some definitions are true.
            run_tool(cmd, cfg.timeout_seconds, ok_codes=(0, 2))
            if not results.is_file() or results.stat().st_size == 0:
                raise ScannerError("oscap-podman produced no results file")
            vulns = parse_results(results, Path(cfg.oval_path))
        log.info("oscap finished", extra={"image": image.short_id, "vulnerabilities": len(vulns)})
        return merge_vulnerabilities(vulns)

"""Pre-pull audit of a remote image using ``skopeo inspect docker://...``.

Only metadata is fetched (config blob and manifest), so rules that need the filesystem
(PS-004, PS-009, PS-010, PS-015) are skipped and reported as such.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from typing import Any

from podshield.config import Settings
from podshield.podman_client import get_ci, parse_time
from podshield.refs import validate_reference
from podshield.scanners.base import ScannerError, ScannerUnavailable, run_tool
from podshield.scanners.hygiene import build_rules, run_rules
from podshield.schemas import Finding, ImageInfo, LayerInfo
from podshield.scoring import Score, compute_score

log = logging.getLogger(__name__)


def normalize_reference(reference: str) -> str:
    """Validate and add the implicit ``:latest`` so PS-002 sees what a pull would fetch."""
    ref = validate_reference(reference)
    if "@" in ref:
        return ref
    last = ref.rsplit("/", 1)[-1]
    return ref if ":" in last else f"{ref}:latest"


def parse_skopeo(summary: dict[str, Any], config: dict[str, Any], reference: str) -> ImageInfo:
    """Build an ``ImageInfo`` from ``skopeo inspect`` and ``skopeo inspect --config`` output."""
    cfg: dict[str, Any] = get_ci(config, "config") or {}
    digest = str(get_ci(summary, "Digest") or "")
    if not digest:
        raise ScannerError("skopeo output has no Digest")

    layers_data = get_ci(summary, "LayersData") or []
    sizes = [int(get_ci(layer, "Size") or 0) for layer in layers_data]
    history = get_ci(config, "history") or []
    layers: list[LayerInfo] = []
    size_iter = iter(sizes)
    for entry in history:
        empty = bool(entry.get("empty_layer"))
        layers.append(
            LayerInfo(
                created_by=str(entry.get("created_by") or ""),
                created=parse_time(entry.get("created")),
                size=0 if empty else next(size_iter, 0),
                comment=str(entry.get("comment") or ""),
                empty=empty,
            )
        )
    diff_ids = (get_ci(config, "rootfs") or {}).get("diff_ids") or []
    labels = get_ci(cfg, "Labels") or get_ci(summary, "Labels") or {}
    by_digest = "@" in reference

    return ImageInfo(
        id=digest,
        repo_tags=[] if by_digest else [reference],
        repo_digests=[reference] if by_digest else [],
        created=parse_time(get_ci(config, "created") or get_ci(summary, "Created")),
        size=sum(sizes),  # compressed layer sizes; smaller than the on-disk size
        architecture=str(get_ci(config, "architecture") or get_ci(summary, "Architecture") or ""),
        os=str(get_ci(config, "os") or get_ci(summary, "Os") or ""),
        user=str(get_ci(cfg, "User") or ""),
        env=[str(e) for e in (get_ci(cfg, "Env") or [])],
        entrypoint=[str(e) for e in (get_ci(cfg, "Entrypoint") or [])],
        cmd=[str(e) for e in (get_ci(cfg, "Cmd") or [])],
        exposed_ports=sorted((get_ci(cfg, "ExposedPorts") or {}).keys()),
        labels={str(k): str(v) for k, v in labels.items()},
        healthcheck=get_ci(cfg, "Healthcheck")
        if isinstance(get_ci(cfg, "Healthcheck"), dict)
        else None,
        layers=layers,
        layer_count=len(diff_ids) or len(layers_data),
    )


@dataclass
class RegistryAudit:
    reference: str
    image: ImageInfo
    findings: list[Finding]
    score: Score
    skipped_rules: list[str] = field(default_factory=list)  # need a pulled image
    notes: list[str] = field(default_factory=list)


class RegistryAuditor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def check(self) -> None:
        if shutil.which(self.settings.registry.binary) is None:
            raise ScannerUnavailable(
                f"{self.settings.registry.binary} not installed (dnf install skopeo)"
            )

    def _skopeo(self, *args: str, reference: str) -> dict[str, Any]:
        cfg = self.settings.registry
        cmd = [cfg.binary, "inspect", *args]
        if not cfg.tls_verify:
            cmd.append("--tls-verify=false")
        if cfg.authfile:
            cmd += ["--authfile", cfg.authfile]
        cmd.append(f"docker://{reference}")
        proc = run_tool(cmd, cfg.timeout_seconds)
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"skopeo returned invalid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise ScannerError("skopeo returned an unexpected JSON document")
        return doc

    def fetch(self, reference: str) -> ImageInfo:
        ref = normalize_reference(reference)
        self.check()
        summary = self._skopeo("--no-tags", reference=ref)
        # --raw: plain --config converts to the OCI config, which has no Healthcheck field,
        # so every Docker-format image would be flagged PS-011. Schema-1 images have no
        # config blob; fall back to the converted config for those.
        try:
            config = self._skopeo("--config", "--raw", reference=ref)
        except ScannerError:
            config = self._skopeo("--config", reference=ref)
        return parse_skopeo(summary, config, ref)

    def audit(self, reference: str) -> RegistryAudit:
        """Audit a remote image. Raises ValueError for malformed references."""
        image = self.fetch(reference)
        rules = build_rules(self.settings)
        findings = run_rules(image, rules)
        skipped = [r.id for r in rules if r.needs_filesystem]
        notes = ["Size is the compressed layer size; the pulled image will be larger."]
        if skipped:
            notes.append(f"Not evaluated before pulling: {', '.join(skipped)}")
        return RegistryAudit(
            reference=image.display_name,
            image=image,
            findings=findings,
            score=compute_score(findings, self.settings.scoring),
            skipped_rules=skipped,
            notes=notes,
        )

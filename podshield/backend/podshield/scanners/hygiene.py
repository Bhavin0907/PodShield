"""Hygiene rule engine and the built-in image rules.

Each rule is a class registered with ``@register``. Rules are pure functions of an
``ImageInfo`` plus settings, which keeps them trivial to unit test. Enable/disable and
severity overrides come from ``[rules.<ID>]`` in the config file.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, TypeVar

from podshield.config import Settings
from podshield.scanners import secrets, trust
from podshield.schemas import Finding, ImageInfo, Severity

if TYPE_CHECKING:
    from podshield.scanners.runtime import RuntimeRule

log = logging.getLogger(__name__)

RULE_REGISTRY: dict[str, type[Rule]] = {}


class Rule(ABC):
    """Base class for image hygiene rules."""

    id: ClassVar[str]
    title: ClassVar[str]
    default_severity: ClassVar[Severity]
    description: ClassVar[str]
    # True for rules that read ``image.filesystem`` (the orchestrator mounts the image only
    # when at least one enabled rule needs it).
    needs_filesystem: ClassVar[bool] = False

    def __init__(self, settings: Settings, severity: Severity | None = None) -> None:
        self.settings = settings
        self.severity = severity or self.default_severity

    @abstractmethod
    def evaluate(self, image: ImageInfo) -> list[Finding]:
        """Return zero or more findings for the image."""

    def finding(self, evidence: list[str], remediation: str, title: str | None = None) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title or self.title,
            severity=self.severity,
            description=self.description,
            evidence=evidence,
            remediation=remediation,
        )


R = TypeVar("R", bound=type[Rule])


def register(cls: R) -> R:
    if cls.id in RULE_REGISTRY:
        raise ValueError(f"duplicate rule id {cls.id}")
    RULE_REGISTRY[cls.id] = cls
    return cls


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    description: str
    default_severity: Severity
    severity: Severity
    enabled: bool
    kind: str = "image"  # "image" or "runtime"


def rule_catalog(settings: Settings) -> list[RuleInfo]:
    """Describe every registered image and runtime rule with config overrides applied."""
    from podshield.scanners.runtime import RUNTIME_REGISTRY  # avoids an import cycle

    entries: list[tuple[str, str, type[Rule | RuntimeRule]]] = [
        ("image", rid, cls) for rid, cls in RULE_REGISTRY.items()
    ] + [("runtime", rid, rcls) for rid, rcls in RUNTIME_REGISTRY.items()]
    out: list[RuleInfo] = []
    for kind, rule_id, cls in sorted(entries, key=lambda e: e[1]):
        override = settings.rule_override(rule_id)
        out.append(
            RuleInfo(
                id=rule_id,
                title=cls.title,
                description=cls.description,
                default_severity=cls.default_severity,
                severity=override.severity or cls.default_severity,
                enabled=True if override.enabled is None else override.enabled,
                kind=kind,
            )
        )
    return out


def build_rules(settings: Settings) -> list[Rule]:
    """Instantiate enabled rules with severity overrides applied."""
    rules: list[Rule] = []
    for rule_id in sorted(RULE_REGISTRY):
        override = settings.rule_override(rule_id)
        if override.enabled is False:
            log.debug("rule disabled by config", extra={"rule_id": rule_id})
            continue
        rules.append(RULE_REGISTRY[rule_id](settings, override.severity))
    return rules


def run_rules(image: ImageInfo, rules: list[Rule]) -> list[Finding]:
    """Run rules; one misbehaving rule never aborts the scan."""
    findings: list[Finding] = []
    for rule in rules:
        try:
            findings.extend(rule.evaluate(image))
        except Exception:
            log.exception("rule crashed", extra={"rule_id": rule.id, "image": image.short_id})
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return findings


# --------------------------------------------------------------------------- rules


@register
class RunsAsRoot(Rule):
    id = "PS-001"
    title = "Container runs as root"
    default_severity = Severity.HIGH
    description = (
        "The image does not set a non-root USER, so processes run as UID 0. A container "
        "escape or a vulnerable application then has root privileges inside the container."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        user = image.user.strip()
        account = user.split(":", 1)[0].strip()
        # Podman parses numeric users as integers, so "00" is uid 0 too. User names are
        # case-sensitive: "ROOT" is a different (probably nonexistent) account.
        is_root = account in ("", "root") or (account.isdigit() and int(account) == 0)
        if not is_root:
            return []
        shown = repr(user) if user else "no USER instruction (defaults to root)"
        return [
            self.finding(
                [f"Configured user: {shown}"],
                "Create an unprivileged user and switch to it at the end of the Containerfile:\n"
                "RUN useradd --system --uid 1001 --no-create-home appuser\n"
                "USER 1001",
            )
        ]


@register
class MutableOrMissingTag(Rule):
    id = "PS-002"
    title = "Uses :latest tag or is untagged/dangling"
    default_severity = Severity.MEDIUM
    description = (
        "Images referenced by :latest (or with no tag at all) are not reproducible: the "
        "content behind the tag can change without notice, defeating audits and rollbacks."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        remediation = (
            "Pin an explicit version tag, ideally with a digest:\n"
            "FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4@sha256:<digest>\n"
            "and tag your own builds, e.g. podman tag <image> myapp:1.4.2"
        )
        if image.is_dangling:
            return [self.finding(["Image has no tag and no digest (dangling)"], remediation)]
        # Pulled by digest only: pinned, therefore fine.
        if not image.repo_tags:
            return []
        if any(_tag_of(t) != "latest" for t in image.repo_tags):
            return []
        return [self.finding([f"Only mutable tags: {', '.join(image.repo_tags)}"], remediation)]


def _tag_of(reference: str) -> str:
    """Return the tag of a repo:tag string ('' if none, e.g. host:5000/name)."""
    name = reference.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else ""


@register
class SecretsInEnv(Rule):
    id = "PS-003"
    title = "Secrets baked into ENV"
    default_severity = Severity.CRITICAL
    description = (
        "Environment variables set in the image are visible to anyone who can pull or "
        "inspect it, and persist in every layer's metadata. Secrets must be injected at "
        "runtime instead."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        matches = secrets.scan_env(image.env_pairs)
        if not matches:
            return []
        evidence = [f"{m.location} = {m.masked_value} ({m.reason})" for m in matches]
        return [
            self.finding(
                evidence,
                "Remove the ENV/ARG from the Containerfile and rotate the exposed values. "
                "Provide secrets at runtime instead:\n"
                "podman secret create db_password -\n"
                "podman run --secret db_password,type=env,target=DB_PASSWORD <image>",
            )
        ]


@register
class ImageTooOld(Rule):
    id = "PS-005"
    title = "Image is older than the age threshold"
    default_severity = Severity.MEDIUM
    description = (
        "Old images accumulate unpatched vulnerabilities. Rebuild regularly on a fresh base."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        if image.created is None or image.created.year <= 1:
            return []  # unknown or reproducible-build epoch timestamp
        threshold = self.settings.thresholds.max_image_age_days
        created = image.created if image.created.tzinfo else image.created.replace(tzinfo=UTC)
        age_days = (datetime.now(UTC) - created).days
        if age_days <= threshold:
            return []
        return [
            self.finding(
                [
                    f"Created {created.date().isoformat()} ({age_days} days ago)",
                    f"Threshold: {threshold} days",
                ],
                "Pull the latest base image and rebuild without cache:\n"
                "podman build --pull=always --no-cache -t <name>:<new-version> .",
            )
        ]


@register
class NoHealthcheck(Rule):
    id = "PS-011"
    title = "No HEALTHCHECK defined"
    default_severity = Severity.LOW
    description = (
        "Without a HEALTHCHECK, Podman and systemd cannot tell a hung process from a "
        "healthy one, so failed containers are not detected or restarted."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        hc = image.healthcheck
        test = hc.get("Test") if hc else None
        if isinstance(test, list) and test and test[0] != "NONE":
            return []
        return [
            self.finding(
                ["No healthcheck in image config"],
                "Add a HEALTHCHECK and build with the docker format (the default OCI format "
                "drops HEALTHCHECK):\n"
                "HEALTHCHECK --interval=30s --timeout=3s --retries=3 \\\n"
                "  CMD curl -fsS http://localhost:8080/health || exit 1\n"
                "podman build --format docker -t <name> .",
            )
        ]


_LABEL_ALIASES: dict[str, tuple[str, ...]] = {
    "maintainer": ("org.opencontainers.image.authors", "maintainer"),
    "version": ("org.opencontainers.image.version", "version"),
    "source": ("org.opencontainers.image.source", "vcs-url"),
}


@register
class MissingOciLabels(Rule):
    id = "PS-012"
    title = "Missing OCI labels (maintainer, version, source)"
    default_severity = Severity.INFO
    description = (
        "Standard OCI labels let operators trace an image to its owner and source "
        "repository, which speeds up incident response."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        missing = [
            kind
            for kind, aliases in _LABEL_ALIASES.items()
            if not any(image.labels.get(a, "").strip() for a in aliases)
        ]
        if not missing:
            return []
        return [
            self.finding(
                [f"Missing: {', '.join(missing)}"],
                'LABEL org.opencontainers.image.authors="team@example.com" \\\n'
                '      org.opencontainers.image.version="1.0.0" \\\n'
                '      org.opencontainers.image.source="https://git.example.com/org/repo"',
            )
        ]


# --------------------------------------------------------------------- phase 2 rules


def _human_size(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if num < 1024 or unit == "GiB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} GiB"  # pragma: no cover


def _limited(items: list[str], cap: int = 20) -> list[str]:
    if len(items) <= cap:
        return items
    return [*items[:cap], f"... and {len(items) - cap} more"]


@register
class SecretsInFilesystem(Rule):
    id = "PS-004"
    title = "Secrets found inside image filesystem layers"
    default_severity = Severity.CRITICAL
    description = (
        "Private keys, cloud credentials or token files are present in the image "
        "filesystem. Anyone who can pull the image can extract them, even if a later "
        "layer deleted the file."
    )
    needs_filesystem = True

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        fs = image.filesystem
        if fs is None or not fs.secrets:
            return []
        evidence = [
            f"{s.path} - {s.reason}" + (f" ({s.masked_value})" if s.masked_value else "")
            for s in fs.secrets
        ]
        return [
            self.finding(
                _limited(evidence),
                "Never COPY credentials into the image; rotate anything listed above. Use "
                "build secrets so they never land in a layer:\n"
                "RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci\n"
                "podman build --secret id=npmrc,src=$HOME/.npmrc -t <name> .",
            )
        ]


@register
class UntrustedBaseImage(Rule):
    id = "PS-006"
    title = "Base image not from a trusted source"
    default_severity = Severity.MEDIUM
    description = (
        "The image is not based on Red Hat UBI or a registry on the trusted list, so its "
        "patching cadence and provenance are unknown."
    )

    @staticmethod
    def _matches(reference: str, prefixes: list[str]) -> bool:
        ref = reference.lower()
        return any(
            ref == p.lower().rstrip("/") or ref.startswith(p.lower().rstrip("/") + "/")
            for p in prefixes
        )

    @staticmethod
    def _looks_like_ubi(reference: str) -> bool:
        name = reference.lower().split("@", 1)[0]
        return bool(re.search(r"(^|/)(ubi\d*(-|/|:|$)|ubi\d*/)", name))

    @staticmethod
    def _red_hat_labels(labels: dict[str, str]) -> bool:
        return (
            labels.get("vendor", "").lower().startswith("red hat")
            or labels.get("com.redhat.component", "").lower().startswith(("ubi", "rhel"))
            or labels.get("name", "").lower().startswith(("ubi", "rhel"))
        )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        trusted = self.settings.trust.trusted_registries
        meta = {**image.labels, **image.annotations}
        base = meta.get("org.opencontainers.image.base.name", "").strip()

        if base:
            if self._matches(base, trusted) or self._looks_like_ubi(base):
                return []
            evidence = [f"Declared base image: {base}"]
        else:
            if self._red_hat_labels(meta):
                return []  # UBI/RHEL labels are inherited from the base image
            if any(self._matches(t, trusted) for t in image.repo_tags):
                return []  # the image itself comes from a trusted registry
            evidence = [
                (
                    "Base image could not be identified as UBI or a trusted registry "
                    "(no base-image label, no Red Hat vendor labels)"
                ),
                f"Image: {image.display_name}",
            ]
        evidence.append(f"Trusted registries: {', '.join(trusted)}")
        return [
            self.finding(
                evidence,
                "Build on UBI and record the base image:\n"
                "FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4\n"
                "or add your registry to [trust].trusted_registries in config.toml.",
            )
        ]


@register
class ImageTooLarge(Rule):
    id = "PS-007"
    title = "Excessive image size"
    default_severity = Severity.LOW
    description = (
        "Large images have more packages (a bigger attack surface) and are slower to pull and scan."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        limit = self.settings.thresholds.max_image_size_mb * 1024 * 1024
        if image.size <= limit:
            return []
        return [
            self.finding(
                [f"Size: {_human_size(image.size)}", f"Limit: {_human_size(limit)}"],
                "Use a minimal base and a multi-stage build:\n"
                "FROM registry.access.redhat.com/ubi9/ubi AS build\n"
                "RUN dnf install -y gcc make && make install DESTDIR=/out\n"
                "FROM registry.access.redhat.com/ubi9/ubi-minimal\n"
                "COPY --from=build /out/ /",
            )
        ]


@register
class TooManyLayers(Rule):
    id = "PS-008"
    title = "Excessive layer count"
    default_severity = Severity.LOW
    description = "Many layers slow pulls, bloat storage, and make an image harder to audit."

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        limit = self.settings.thresholds.max_layers
        if image.layer_count <= limit:
            return []
        return [
            self.finding(
                [f"Layers: {image.layer_count}", f"Limit: {limit}"],
                "Combine related RUN steps and use multi-stage builds, or squash:\n"
                "RUN dnf install -y pkg1 pkg2 && dnf clean all\n"
                "podman build --squash -t <name> .",
            )
        ]


@register
class PackageCachesLeft(Rule):
    id = "PS-009"
    title = "Package manager caches left in image"
    default_severity = Severity.LOW
    description = (
        "Package caches (dnf, yum, apt, apk) add size and stale metadata without any runtime value."
    )
    needs_filesystem = True

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        fs = image.filesystem
        if fs is None or not fs.cache_dirs:
            return []
        evidence = [f"{c.path}: {c.files} files, {_human_size(c.size)}" for c in fs.cache_dirs]
        return [
            self.finding(
                evidence,
                "Clean the cache in the same RUN step that installs packages:\n"
                "RUN microdnf install -y <pkg> && microdnf clean all\n"
                "# Debian/Ubuntu: apt-get install -y --no-install-recommends <pkg> "
                "&& rm -rf /var/lib/apt/lists/*\n"
                "# Alpine: apk add --no-cache <pkg>",
            )
        ]


@register
class SetuidBinaries(Rule):
    id = "PS-010"
    title = "Setuid/setgid binaries present"
    default_severity = Severity.MEDIUM
    description = (
        "Setuid and setgid files run with the owner's privileges and are a classic "
        "privilege-escalation route inside a container."
    )
    needs_filesystem = True

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        fs = image.filesystem
        if fs is None or not fs.setuid_files:
            return []
        evidence = [f"{f.path} (mode {f.mode})" for f in fs.setuid_files]
        return [
            self.finding(
                _limited(evidence),
                "Strip the bits in the final image and block new privileges at runtime:\n"
                "RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true\n"
                "podman run --security-opt no-new-privileges <image>",
            )
        ]


SENSITIVE_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    2375: "Docker API (unencrypted)",
}


@register
class SensitivePortsExposed(Rule):
    id = "PS-013"
    title = "Sensitive ports exposed"
    default_severity = Severity.MEDIUM
    description = (
        "The image declares remote-administration or database ports. Services like these "
        "should not be reachable from outside the container by default."
    )

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        hits: list[str] = []
        for spec in image.exposed_ports:
            port_text, _, _proto = spec.partition("/")
            if port_text.isdigit() and int(port_text) in SENSITIVE_PORTS:
                hits.append(f"{spec} ({SENSITIVE_PORTS[int(port_text)]})")
        if not hits:
            return []
        return [
            self.finding(
                hits,
                "Remove the EXPOSE line for these ports and do not run SSH in containers "
                "(use `podman exec`). Databases belong in their own container reachable "
                "only over a private network:\n"
                "podman network create backend\n"
                "podman run --network backend --name db <db-image>",
            )
        ]


@register
class UnsignedImage(Rule):
    id = "PS-014"
    title = "Image unsigned or registry not covered by a signature policy"
    default_severity = Severity.MEDIUM
    description = (
        "Podman only verifies signatures for registries where policy.json requires "
        "signedBy or sigstoreSigned. Elsewhere any image, including a tampered or "
        "typosquatted one, is accepted, and registries marked insecure also skip TLS checks."
    )

    def __init__(self, settings: Settings, severity: Severity | None = None) -> None:
        super().__init__(settings, severity)
        self._policy: trust.TrustPolicy | None = None

    def _load(self) -> trust.TrustPolicy:
        if self._policy is None:  # parse host config once per scan, not once per image
            self._policy = trust.load_trust_policy(self.settings.trust)
        return self._policy

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        policy = self._load()
        refs = [*image.repo_tags, *image.repo_digests]
        insecure = [
            f"{ref}: registry '{e.location}' is configured insecure (TLS verification disabled)"
            for ref in refs
            if (e := policy.registry_entry(ref)) and e.insecure
        ]
        verified = bool(refs) and any(policy.is_signature_verified(r) for r in refs)
        if verified and not insecure:
            return []

        evidence: list[str] = []
        if policy.policy_error:
            evidence.append(f"Trust policy unavailable: {policy.policy_error}")
        if not refs:
            evidence.append("Image has no registry reference, so no policy can apply")
        elif not verified:
            evidence.extend(policy.describe(r) for r in refs)
        evidence.extend(insecure)
        return [
            self.finding(
                evidence,
                "Require signatures for the registries you rely on in "
                "/etc/containers/policy.json:\n"
                '{"default": [{"type": "reject"}], "transports": {"docker": {\n'
                '  "registry.access.redhat.com": [{"type": "signedBy", "keyType": "GPGKeys",\n'
                '    "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"}]}}}\n'
                "and sign your own images: skopeo copy --sign-by <key-id> ...",
            )
        ]


@register
class ShellOrPackageManager(Rule):
    id = "PS-015"
    title = "Shell or package manager present in final image"
    default_severity = Severity.INFO
    description = (
        "A shell or package manager lets an attacker who gains code execution install "
        "tools and move around. Informational for minimal or distroless-style images."
    )
    needs_filesystem = True

    def evaluate(self, image: ImageInfo) -> list[Finding]:
        fs = image.filesystem
        if fs is None or not (fs.shells or fs.package_managers):
            return []
        evidence: list[str] = []
        if fs.shells:
            evidence.append(f"Shells: {', '.join(fs.shells)}")
        if fs.package_managers:
            evidence.append(f"Package managers: {', '.join(fs.package_managers)}")
        return [
            self.finding(
                evidence,
                "Copy only the application into a minimal runtime stage:\n"
                "FROM registry.access.redhat.com/ubi9/ubi-micro\n"
                "COPY --from=build /app /app",
            )
        ]

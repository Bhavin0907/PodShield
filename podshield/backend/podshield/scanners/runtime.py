"""Runtime audit of running containers (rules PS-R01 .. PS-R05).

Works on ``podman inspect`` documents, so the rules are plain functions of a ``ContainerInfo``.
Rules use their own registry but share config overrides (``[rules.PS-R01]``) and scoring with
the image hygiene rules.
"""

from __future__ import annotations

import logging
import posixpath
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, Field

from podshield.config import Settings
from podshield.podman_client import get_ci
from podshield.schemas import Finding, Severity
from podshield.scoring import Score, compute_score

log = logging.getLogger(__name__)

RUNTIME_REGISTRY: dict[str, type[RuntimeRule]] = {}


class MountInfo(BaseModel):
    type: str = ""
    source: str = ""
    destination: str = ""
    rw: bool = True


class ContainerInfo(BaseModel):
    id: str
    name: str = ""
    image: str = ""
    image_id: str = ""
    status: str = ""
    user: str = ""
    privileged: bool = False
    network_mode: str = ""
    pid_mode: str = ""
    ipc_mode: str = ""
    security_opt: list[str] = Field(default_factory=list)
    cap_add: list[str] = Field(default_factory=list)
    mounts: list[MountInfo] = Field(default_factory=list)

    @property
    def short_id(self) -> str:
        return self.id[:12]


def _str_list(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def parse_container(inspect: dict[str, Any]) -> ContainerInfo:
    host: dict[str, Any] = get_ci(inspect, "HostConfig") or {}
    config: dict[str, Any] = get_ci(inspect, "Config") or {}
    state: dict[str, Any] = get_ci(inspect, "State") or {}
    mounts = [
        MountInfo(
            type=str(get_ci(m, "Type") or ""),
            source=str(get_ci(m, "Source") or ""),
            destination=str(get_ci(m, "Destination") or ""),
            rw=bool(get_ci(m, "RW") if get_ci(m, "RW") is not None else True),
        )
        for m in (get_ci(inspect, "Mounts") or [])
    ]
    return ContainerInfo(
        id=str(get_ci(inspect, "Id") or ""),
        name=str(get_ci(inspect, "Name") or "").lstrip("/"),
        image=str(get_ci(inspect, "ImageName") or ""),
        image_id=str(get_ci(inspect, "Image") or ""),
        status=str(get_ci(state, "Status") or ""),
        user=str(get_ci(config, "User") or ""),
        privileged=bool(get_ci(host, "Privileged")),
        network_mode=str(get_ci(host, "NetworkMode") or ""),
        pid_mode=str(get_ci(host, "PidMode") or ""),
        ipc_mode=str(get_ci(host, "IpcMode") or ""),
        security_opt=_str_list(get_ci(host, "SecurityOpt")),
        cap_add=_str_list(get_ci(host, "CapAdd")),
        mounts=mounts,
    )


class RuntimeRule(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    default_severity: ClassVar[Severity]
    description: ClassVar[str]

    def __init__(self, settings: Settings, severity: Severity | None = None) -> None:
        self.settings = settings
        self.severity = severity or self.default_severity

    @abstractmethod
    def evaluate(self, container: ContainerInfo) -> list[Finding]: ...

    def finding(self, evidence: list[str], remediation: str) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            evidence=evidence,
            remediation=remediation,
        )


R = TypeVar("R", bound=type[RuntimeRule])


def register_runtime(cls: R) -> R:
    if cls.id in RUNTIME_REGISTRY:
        raise ValueError(f"duplicate rule id {cls.id}")
    RUNTIME_REGISTRY[cls.id] = cls
    return cls


# ----------------------------------------------------------------------------- rules


@register_runtime
class Privileged(RuntimeRule):
    id = "PS-R01"
    title = "Container runs with --privileged"
    default_severity = Severity.CRITICAL
    description = (
        "A privileged container has all capabilities, access to host devices, and no "
        "seccomp or SELinux confinement. It is effectively root on the host."
    )

    def evaluate(self, container: ContainerInfo) -> list[Finding]:
        if not container.privileged:
            return []
        return [
            self.finding(
                ["HostConfig.Privileged = true"],
                "Drop --privileged and grant only what is needed:\n"
                "podman run --cap-add=NET_BIND_SERVICE --device /dev/<needed> <image>",
            )
        ]


@register_runtime
class SelinuxDisabled(RuntimeRule):
    id = "PS-R02"
    title = "SELinux labeling disabled for container"
    default_severity = Severity.HIGH
    description = (
        "With label=disable the container process runs unconfined (spc_t), so SELinux no "
        "longer isolates it from the host or other containers."
    )

    def evaluate(self, container: ContainerInfo) -> list[Finding]:
        hits = [o for o in container.security_opt if re.fullmatch(r"label[=:]disable", o.strip())]
        if not hits:
            return []
        return [
            self.finding(
                [f"SecurityOpt: {o}" for o in hits],
                "Remove --security-opt label=disable. If a bind mount is denied, relabel it "
                "instead:\npodman run -v /data:/data:Z <image>   # private label\n"
                "podman run -v /shared:/shared:z <image>  # shared label",
            )
        ]


@register_runtime
class HostNamespaces(RuntimeRule):
    id = "PS-R03"
    title = "Container shares host network, PID or IPC namespace"
    default_severity = Severity.HIGH
    description = (
        "Sharing a host namespace removes isolation: the container can see host processes "
        "or IPC objects, or bind directly on host network interfaces."
    )

    def evaluate(self, container: ContainerInfo) -> list[Finding]:
        evidence = []
        if container.network_mode == "host":
            evidence.append("Network namespace: host (--network host)")
        if container.pid_mode == "host":
            evidence.append("PID namespace: host (--pid host)")
        if container.ipc_mode == "host":
            evidence.append("IPC namespace: host (--ipc host)")
        if not evidence:
            return []
        return [
            self.finding(
                evidence,
                "Use private namespaces and publish only needed ports:\n"
                "podman run --network bridge -p 8080:8080 <image>",
            )
        ]


SENSITIVE_EXACT = {
    "/",
    "/etc",
    "/var",
    "/var/run",
    "/run",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/var/lib",
    "/var/lib/containers",
    "/home",
}
SENSITIVE_PREFIXES = (
    "/etc/ssh",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/var/lib/containers/",
    "/etc/pki/private",
)
_SOCKET_RE = re.compile(r"/(podman|docker|containerd|crio)\.sock$")


def sensitive_mount_reason(source: str) -> str | None:
    if not source.startswith("/"):
        return None
    # normpath keeps a leading "//" as-is (POSIX allows it to differ from "/"), but for a
    # bind mount source it is the same directory, so collapse it before comparing.
    path = "/" + posixpath.normpath(source).lstrip("/")
    if path in SENSITIVE_EXACT:
        return "sensitive host directory"
    if _SOCKET_RE.search(path):
        return "container runtime socket (full control of the host's containers)"
    if path.startswith(SENSITIVE_PREFIXES):
        return "sensitive host path"
    return None


@register_runtime
class SensitiveMounts(RuntimeRule):
    id = "PS-R04"
    title = "Sensitive host paths mounted into container"
    default_severity = Severity.CRITICAL
    description = (
        "Mounting the host root, /etc, runtime directories or the Podman socket lets the "
        "container read or modify the host and escape confinement."
    )

    def evaluate(self, container: ContainerInfo) -> list[Finding]:
        evidence = []
        for m in container.mounts:
            if m.type == "volume":
                continue  # named volumes live under /var/lib/containers by design
            reason = sensitive_mount_reason(m.source)
            if reason:
                evidence.append(
                    f"{m.source} -> {m.destination} ({'rw' if m.rw else 'ro'}): {reason}"
                )
        if not evidence:
            return []
        return [
            self.finding(
                evidence,
                "Mount only the specific files or directories the workload needs, "
                "read-only where possible:\n"
                "podman run -v /srv/app/config:/config:ro,Z <image>\n"
                "Never mount the Podman socket; use the Podman API from a dedicated, "
                "restricted service instead.",
            )
        ]


DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_TIME",
    "DAC_READ_SEARCH",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "BPF",
    "PERFMON",
    "ALL",
}


@register_runtime
class DangerousCapabilities(RuntimeRule):
    id = "PS-R05"
    title = "Dangerous capabilities added"
    default_severity = Severity.HIGH
    description = (
        "Capabilities such as SYS_ADMIN, NET_ADMIN or SYS_PTRACE greatly widen what a "
        "compromised process can do to the host kernel and other containers."
    )

    def evaluate(self, container: ContainerInfo) -> list[Finding]:
        hits = []
        for cap in container.cap_add:
            name = cap.upper().removeprefix("CAP_")
            if name in DANGEROUS_CAPS:
                hits.append(f"--cap-add {name}")
        if not hits:
            return []
        return [
            self.finding(
                hits,
                "Drop everything and add back only what the workload needs:\n"
                "podman run --cap-drop=ALL --cap-add=NET_BIND_SERVICE <image>",
            )
        ]


# ------------------------------------------------------------------------- engine


def build_runtime_rules(settings: Settings) -> list[RuntimeRule]:
    rules: list[RuntimeRule] = []
    for rule_id in sorted(RUNTIME_REGISTRY):
        override = settings.rule_override(rule_id)
        if override.enabled is False:
            continue
        rules.append(RUNTIME_REGISTRY[rule_id](settings, override.severity))
    return rules


@dataclass
class ContainerAudit:
    container: ContainerInfo
    findings: list[Finding]
    score: Score


def audit_container(
    container: ContainerInfo, rules: list[RuntimeRule], settings: Settings
) -> ContainerAudit:
    findings: list[Finding] = []
    for rule in rules:
        try:
            findings.extend(rule.evaluate(container))
        except Exception:
            log.exception(
                "runtime rule crashed", extra={"rule_id": rule.id, "container": container.short_id}
            )
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return ContainerAudit(container, findings, compute_score(findings, settings.scoring))


def audit_containers(raw: list[dict[str, Any]], settings: Settings) -> list[ContainerAudit]:
    rules = build_runtime_rules(settings)
    audits = []
    for doc in raw:
        try:
            container = parse_container(doc)
        except Exception:
            log.exception("cannot parse container inspect document")
            continue
        audits.append(audit_container(container, rules, settings))
    return sorted(audits, key=lambda a: (a.score.score, a.container.name))

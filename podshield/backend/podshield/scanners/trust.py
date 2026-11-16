"""Read the host's container trust configuration (read-only).

Parses ``policy.json`` (signature requirements), ``registries.conf`` (insecure/blocked
registries) and ``registries.d`` (where signatures are stored), and answers: is a given image
reference covered by a policy that actually verifies signatures?
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from podshield.config import TrustSettings, path_is_file

log = logging.getLogger(__name__)

VERIFYING_TYPES = {"signedBy", "sigstoreSigned"}


def split_reference(reference: str) -> tuple[str, str]:
    """Split a reference into (registry host[:port], 'host/path' without tag or digest)."""
    name = reference.split("@", 1)[0]
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = "docker.io", name  # unqualified references resolve via search registries
    last = path.rsplit("/", 1)[-1]
    if ":" in last:  # strip tag
        path = path[: len(path) - len(last)] + last.split(":", 1)[0]
    return host, f"{host}/{path}"


@dataclass
class RegistryEntry:
    location: str
    insecure: bool = False
    blocked: bool = False


@dataclass
class TrustPolicy:
    policy_found: bool = False
    policy_error: str | None = None
    default: list[dict[str, Any]] = field(default_factory=list)
    docker: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    registries: list[RegistryEntry] = field(default_factory=list)
    unqualified_search: list[str] = field(default_factory=list)
    # registries that have a signature store (lookaside / sigstore) configured
    signature_stores: set[str] = field(default_factory=set)

    # ---- queries

    def requirements_for(self, reference: str) -> tuple[str, list[dict[str, Any]]]:
        """Most specific policy scope for a reference and its requirements."""
        host, full = split_reference(reference)
        candidates: list[str] = []
        parts = full.split("/")
        for i in range(len(parts), 0, -1):  # host/ns/repo, host/ns, host
            candidates.append("/".join(parts[:i]))
        labels = host.split(":")[0].split(".")
        for i in range(1, len(labels)):  # *.example.com wildcards
            candidates.append("*." + ".".join(labels[i:]))
        for scope in candidates:
            if scope in self.docker:
                return scope, self.docker[scope]
        if "" in self.docker:
            return "docker (transport default)", self.docker[""]
        return "default", self.default

    def is_signature_verified(self, reference: str) -> bool:
        _scope, reqs = self.requirements_for(reference)
        return any(r.get("type") in VERIFYING_TYPES for r in reqs)

    def describe(self, reference: str) -> str:
        scope, reqs = self.requirements_for(reference)
        types = ", ".join(str(r.get("type", "?")) for r in reqs) or "none"
        return f"{reference}: policy scope '{scope}' requires {types}"

    def insecure_registries(self) -> list[str]:
        return [r.location for r in self.registries if r.insecure]

    def registry_entry(self, reference: str) -> RegistryEntry | None:
        host, _ = split_reference(reference)
        for entry in self.registries:
            if entry.location == host or reference.startswith(entry.location + "/"):
                return entry
        return None


def _load_registries(paths: list[Path], policy: TrustPolicy) -> None:
    for path in paths:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            log.warning(
                "cannot read registries config", extra={"path": str(path), "error": str(exc)}
            )
            continue
        policy.unqualified_search += list(data.get("unqualified-search-registries", []))
        for item in data.get("registry", []):
            if loc := item.get("location") or item.get("prefix"):
                policy.registries.append(
                    RegistryEntry(str(loc), bool(item.get("insecure")), bool(item.get("blocked")))
                )


_KEY_RE = re.compile(r"^(\s*)([^\s#:][^:#]*):\s*(\S.*)?$")


def _parse_registries_d(text: str) -> set[str]:
    """Tiny parser for registries.d YAML: find ``docker:`` scopes that define a signature store.

    Handles the documented shape only::

        docker:
          registry.example.com:
            lookaside: https://...
    """
    stores: set[str] = set()
    in_docker = False
    scope: str | None = None
    scope_indent = -1
    for line in text.splitlines():
        m = _KEY_RE.match(line)
        if not m:
            continue
        indent, key, value = len(m.group(1)), m.group(2).strip(), (m.group(3) or "").strip()
        if indent == 0:
            in_docker = key == "docker"
            scope = None
        elif in_docker and (scope is None or indent <= scope_indent) and not value:
            scope, scope_indent = key, indent
        elif (
            in_docker
            and scope
            and indent > scope_indent
            and (
                key in {"lookaside", "lookaside-staging", "sigstore", "sigstore-staging"}
                and value
                or key == "use-sigstore-attachments"
                and value.lower() == "true"
            )
        ):
            stores.add(scope)
    return stores


def load_trust_policy(cfg: TrustSettings) -> TrustPolicy:
    """Load policy; never raises (problems are recorded on the returned object)."""
    policy = TrustPolicy()

    path = Path(cfg.policy_path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        policy.policy_found = True
        policy.default = list(doc.get("default", []))
        policy.docker = {
            k: list(v) for k, v in (doc.get("transports", {}).get("docker") or {}).items()
        }
    except FileNotFoundError:
        policy.policy_error = f"{path} not found"
    except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        policy.policy_error = f"cannot parse {path}: {exc}"

    conf_paths = [Path(cfg.registries_conf)]
    conf_d = Path(cfg.registries_conf_d)
    if conf_d.is_dir():
        conf_paths += sorted(conf_d.glob("*.conf"))
    _load_registries([p for p in conf_paths if path_is_file(p)], policy)

    reg_d = Path(cfg.registries_d)
    if reg_d.is_dir():
        for yaml_file in sorted([*reg_d.glob("*.yaml"), *reg_d.glob("*.yml")]):
            try:
                policy.signature_stores |= _parse_registries_d(
                    yaml_file.read_text(encoding="utf-8")
                )
            except OSError as exc:
                log.warning(
                    "cannot read registries.d file",
                    extra={"path": str(yaml_file), "error": str(exc)},
                )
    return policy

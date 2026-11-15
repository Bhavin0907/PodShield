"""Thin wrapper over podman-py with a ``podman ... --format json`` subprocess fallback.

The rest of PodShield only sees ``ImageInfo``; all parsing of Podman's JSON shapes lives in
``parse_inspect`` so it can be tested with sample files and no Podman installed.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, Protocol

from podshield.refs import validate_reference
from podshield.schemas import ImageInfo, LayerInfo

log = logging.getLogger(__name__)


class PodmanError(Exception):
    """Any failure talking to Podman."""


class PodmanUnavailable(PodmanError):
    """The Podman socket cannot be reached (not running, wrong path, or permissions)."""


class ImageNotFoundError(PodmanError):
    pass


class ImageSource(Protocol):
    """What the orchestrator needs; implemented by PodmanClient and by test fakes."""

    def list_images(self) -> list[ImageInfo]: ...

    def get_image(self, reference: str) -> ImageInfo: ...


# ----------------------------------------------------------------------------- parsing

_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def parse_time(value: Any) -> datetime | None:
    """Parse RFC3339 (with nanoseconds) or unix seconds into an aware datetime."""
    if value in (None, "", 0):
        return None
    try:
        if isinstance(value, int | float):
            return datetime.fromtimestamp(value, tz=UTC)
        text = _FRACTION_RE.sub(r"\1", str(value))
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (ValueError, OSError, OverflowError):
        return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [str(v) for v in value]
    return []


def _mapping(value: Any) -> dict[str, Any]:
    """``value`` if it is a dict, else {} (Podman versions differ in what they emit)."""
    return value if isinstance(value, dict) else {}


def _to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def get_ci(d: dict[str, Any], *keys: str) -> Any:
    """Case-insensitive lookup of the first present key."""
    lowered = {k.lower(): v for k, v in d.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def parse_history(entries: list[dict[str, Any]] | None) -> list[LayerInfo]:
    layers: list[LayerInfo] = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        size = _to_int(get_ci(entry, "Size", "size"))
        layers.append(
            LayerInfo(
                created_by=str(get_ci(entry, "CreatedBy", "created_by") or ""),
                created=parse_time(get_ci(entry, "Created", "created")),
                size=size,
                comment=str(get_ci(entry, "Comment", "comment") or ""),
                empty=size == 0,
            )
        )
    return layers


def _exposed_ports(value: Any) -> list[str]:
    """ExposedPorts is a mapping like {"8080/tcp": {}}; tolerate a plain list too."""
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    return sorted(_as_list(value))


def parse_inspect(
    inspect: dict[str, Any], history: list[dict[str, Any]] | None = None
) -> ImageInfo:
    """Normalize a libpod image inspect document (and optional history) to ``ImageInfo``."""
    if not isinstance(inspect, dict):
        raise PodmanError(f"unexpected inspect document of type {type(inspect).__name__}")
    config = _mapping(get_ci(inspect, "Config"))
    healthcheck = get_ci(config, "Healthcheck") or get_ci(inspect, "HealthCheck", "Healthcheck")
    labels = _mapping(get_ci(config, "Labels") or get_ci(inspect, "Labels"))
    user = get_ci(config, "User") or get_ci(inspect, "User") or ""
    rootfs = _mapping(get_ci(inspect, "RootFS"))
    rootfs_layers = get_ci(rootfs, "Layers")
    rootfs_layers = rootfs_layers if isinstance(rootfs_layers, list) else []
    layers = parse_history(history)
    image_id = get_ci(inspect, "Id")
    if not image_id:
        raise PodmanError("inspect document has no Id")

    return ImageInfo(
        id=str(image_id),
        repo_tags=[t for t in _as_list(get_ci(inspect, "RepoTags")) if t != "<none>:<none>"],
        repo_digests=_as_list(get_ci(inspect, "RepoDigests")),
        created=parse_time(get_ci(inspect, "Created")),
        size=_to_int(get_ci(inspect, "Size")),
        architecture=str(get_ci(inspect, "Architecture") or ""),
        os=str(get_ci(inspect, "Os") or ""),
        user=str(user),
        env=_as_list(get_ci(config, "Env")),
        entrypoint=_as_list(get_ci(config, "Entrypoint")),
        cmd=_as_list(get_ci(config, "Cmd")),
        exposed_ports=_exposed_ports(get_ci(config, "ExposedPorts")),
        labels={str(k): str(v) for k, v in labels.items()},
        annotations={str(k): str(v) for k, v in _mapping(get_ci(inspect, "Annotations")).items()},
        healthcheck=healthcheck if isinstance(healthcheck, dict) else None,
        layers=layers,
        layer_count=len(rootfs_layers) or sum(1 for layer in layers if not layer.empty),
    )


# ----------------------------------------------------------------------------- client


class PodmanClient:
    def __init__(self, socket: str, timeout: int = 30) -> None:
        self.socket = socket
        self.timeout = timeout
        self._client: Any = None
        self._events_client: Any = None

    # -- connection

    def _api(self) -> Any:
        if self._client is None:
            try:
                from podman import PodmanClient as PodmanPy
            except ImportError as exc:  # pragma: no cover - dependency is declared
                raise PodmanError("podman-py is not installed") from exc
            try:
                client = PodmanPy(base_url=self.socket, timeout=self.timeout)
                client.ping()
            except Exception as exc:
                raise PodmanUnavailable(self._unavailable_message(exc)) from exc
            self._client = client
        return self._client

    def _unavailable_message(self, exc: Exception) -> str:
        msg = f"cannot reach Podman at {self.socket}: {exc}"
        if "ermission" in str(exc):
            msg += (
                " (permission denied: run as root, or use the rootless socket and check "
                "socket permissions / SELinux AVCs with `ausearch -m avc -ts recent`)"
            )
        else:
            msg += " (is podman.socket enabled? `systemctl enable --now podman.socket`)"
        return msg

    def ping(self) -> bool:
        try:
            self._api()
            return True
        except PodmanError:
            return False

    def close(self) -> None:
        for client in (self._client, self._events_client):
            if client is not None:
                try:
                    client.close()
                except Exception:
                    log.debug("error while closing the Podman connection", exc_info=True)
        self._client = None
        self._events_client = None

    # -- events

    def events(
        self, since: int | None = None, types: tuple[str, ...] = ("image",)
    ) -> Iterator[dict[str, Any]]:
        """Yield decoded Podman events (dicts) until the stream ends.

        Uses its own connection without a read timeout: the shared one has a request timeout
        that would abort a stream that is idle for longer than that. Raises ``PodmanError``
        when the socket is unreachable or the stream breaks.
        """
        try:
            from podman import PodmanClient as PodmanPy
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise PodmanError("podman-py is not installed") from exc
        if self._events_client is None:
            try:
                client = PodmanPy(base_url=self.socket, timeout=None)
                client.ping()
            except Exception as exc:
                raise PodmanUnavailable(self._unavailable_message(exc)) from exc
            self._events_client = client
        try:
            yield from self._events_client.events(
                since=since, filters={"type": list(types)}, decode=True
            )
        except Exception as exc:
            self._events_client = None  # force a fresh connection on the next attempt
            raise PodmanError(f"event stream failed: {exc}") from exc

    # -- images

    def list_images(self) -> list[ImageInfo]:
        api = self._api()
        try:
            refs = [str(img.attrs.get("Id") or img.id) for img in api.images.list()]
        except Exception as exc:
            raise PodmanError(f"failed to list images: {exc}") from exc
        images: list[ImageInfo] = []
        for ref in refs:
            try:
                images.append(self.get_image(ref))
            except PodmanError as exc:
                log.warning(
                    "skipping image that cannot be inspected",
                    extra={"image": ref[:12], "error": str(exc)},
                )
        return images

    def get_image(self, reference: str) -> ImageInfo:
        try:
            reference = validate_reference(reference)
        except ValueError as exc:
            raise PodmanError(str(exc)) from exc
        api = self._api()
        try:
            image = api.images.get(reference)
            inspect: dict[str, Any] = dict(image.attrs)
            try:
                history: list[dict[str, Any]] | None = image.history()
            except Exception as exc:  # noqa: BLE001 - fall back to the CLI on any API error
                log.debug("history via API failed, using CLI", extra={"error": str(exc)})
                try:
                    history = self._cli_json(["history", reference])
                except PodmanError:
                    history = None
            return parse_inspect(inspect, history)
        except PodmanError:
            raise
        except Exception as exc:
            if type(exc).__name__ == "ImageNotFound":
                raise ImageNotFoundError(f"image not found: {reference}") from exc
            log.warning(
                "API inspect failed, falling back to CLI",
                extra={"image": reference, "error": str(exc)},
            )
            return self._get_image_cli(reference)

    # -- containers (used by runtime rules in a later phase)

    def list_containers(self) -> list[dict[str, Any]]:
        api = self._api()
        try:
            return [dict(c.inspect()) for c in api.containers.list()]
        except Exception as exc:
            raise PodmanError(f"failed to list containers: {exc}") from exc

    # -- CLI fallback

    def _cli_json(self, args: list[str]) -> Any:
        cmd = ["podman", "--url", self.socket, *args, "--format", "json"]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except FileNotFoundError as exc:
            raise PodmanError("podman binary not found in PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise PodmanError(f"`podman {' '.join(args)}` timed out") from exc
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            if "no such image" in stderr.lower():
                raise ImageNotFoundError(stderr)
            raise PodmanError(f"`podman {' '.join(args)}` failed: {stderr}")
        try:
            return json.loads(proc.stdout or "null")
        except json.JSONDecodeError as exc:
            raise PodmanError(f"podman returned invalid JSON: {exc}") from exc

    def _get_image_cli(self, reference: str) -> ImageInfo:
        data = self._cli_json(["image", "inspect", reference])
        if not isinstance(data, list) or not data:
            raise ImageNotFoundError(f"image not found: {reference}")
        if not isinstance(data[0], dict):
            raise PodmanError("podman image inspect returned an unexpected document")
        try:
            history = self._cli_json(["history", reference])
        except PodmanError:
            history = None
        return parse_inspect(data[0], history)

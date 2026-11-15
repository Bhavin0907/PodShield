"""T1: PodmanClient against a fake podman-py (no Podman needed).

Covers the socket-connection errors, the API path, and the fallbacks to the `podman` CLI.
"""

from __future__ import annotations

import json
import subprocess
import sys
import types
from typing import Any, ClassVar

import pytest

from podshield.podman_client import (
    ImageNotFoundError,
    PodmanClient,
    PodmanError,
    PodmanUnavailable,
)
from tests.conftest import load_json


class ImageNotFound(Exception):  # name matters: the client matches on the class name
    pass


class FakeImage:
    def __init__(self, attrs: dict[str, Any], history: Any = None) -> None:
        self.attrs = attrs
        self.id = attrs.get("Id", "")
        self._history = history

    def history(self) -> Any:
        if isinstance(self._history, Exception):
            raise self._history
        return self._history


class FakeContainer:
    def __init__(self, doc: dict[str, Any]) -> None:
        self._doc = doc

    def inspect(self) -> dict[str, Any]:
        return self._doc


class FakeApi:
    """Stands in for podman.PodmanClient."""

    instances: ClassVar[list[FakeApi]] = []
    ping_error: Exception | None = None
    images: ClassVar[dict[str, FakeImage]] = {}
    list_error: Exception | None = None
    get_error: Exception | None = None
    containers: ClassVar[list[FakeContainer]] = []
    event_docs: ClassVar[list[Any]] = []

    def __init__(self, base_url: str, timeout: Any = None) -> None:
        self.base_url, self.timeout = base_url, timeout
        self.closed = False
        FakeApi.instances.append(self)
        outer = self

        class Images:
            def list(self) -> list[FakeImage]:
                if FakeApi.list_error:
                    raise FakeApi.list_error
                return list(FakeApi.images.values())

            def get(self, ref: str) -> FakeImage:
                if FakeApi.get_error:
                    raise FakeApi.get_error
                if ref not in FakeApi.images:
                    raise ImageNotFound(ref)
                return FakeApi.images[ref]

        class Containers:
            def list(self) -> list[FakeContainer]:
                return FakeApi.containers

        self.images = Images()
        self.containers = Containers()
        self.outer = outer

    def ping(self) -> bool:
        if FakeApi.ping_error:
            raise FakeApi.ping_error
        return True

    def events(self, since: Any = None, filters: Any = None, decode: bool = False) -> Any:
        self.last_events_args = (since, filters, decode)
        for doc in FakeApi.event_docs:
            if isinstance(doc, Exception):
                raise doc
            yield doc

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def fake_podman(monkeypatch: pytest.MonkeyPatch) -> type[FakeApi]:
    FakeApi.instances = []
    FakeApi.ping_error = FakeApi.list_error = FakeApi.get_error = None
    FakeApi.images = {}
    FakeApi.containers = []
    FakeApi.event_docs = []
    module = types.ModuleType("podman")
    module.PodmanClient = FakeApi  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "podman", module)
    return FakeApi


def client() -> PodmanClient:
    return PodmanClient("unix:///run/podman/podman.sock", timeout=7)


# ------------------------------------------------------------------------ connection


def test_connects_with_socket_and_timeout_and_reuses_the_connection() -> None:
    c = client()
    assert c.ping() and c.ping()
    assert len(FakeApi.instances) == 1
    assert FakeApi.instances[0].base_url == "unix:///run/podman/podman.sock"
    assert FakeApi.instances[0].timeout == 7


def test_permission_denied_message_explains_the_fix() -> None:
    FakeApi.ping_error = PermissionError("[Errno 13] Permission denied")
    with pytest.raises(PodmanUnavailable) as err:
        client()._api()
    text = str(err.value)
    assert "permission denied" in text.lower() and "ausearch" in text and "root" in text


def test_socket_not_running_message_mentions_systemctl() -> None:
    FakeApi.ping_error = FileNotFoundError("No such file or directory")
    with pytest.raises(PodmanUnavailable, match="systemctl enable --now podman.socket"):
        client()._api()


def test_ping_is_false_instead_of_raising_when_unavailable() -> None:
    FakeApi.ping_error = ConnectionRefusedError("refused")
    assert client().ping() is False


def test_close_closes_every_connection_and_tolerates_errors() -> None:
    c = client()
    c.ping()
    assert c._client is not None
    api = FakeApi.instances[0]
    c.close()
    assert api.closed and c._client is None
    c.close()  # idempotent

    c2 = client()
    c2.ping()
    FakeApi.instances[-1].close = lambda: (_ for _ in ()).throw(OSError("boom"))  # type: ignore[method-assign]
    c2.close()  # must not raise


# ------------------------------------------------------------------------------ images


def image_doc(n: int) -> dict[str, Any]:
    doc = load_json("inspect_good.json")
    doc["Id"] = f"{n}" * 64
    doc["RepoTags"] = [f"localhost/pstest-{n}:1"]
    return doc  # type: ignore[no-any-return]


def test_list_images_inspects_each_image() -> None:
    FakeApi.images = {f"{n}" * 64: FakeImage(image_doc(n), history=[]) for n in (1, 2)}
    images = client().list_images()
    assert [i.repo_tags for i in images] == [["localhost/pstest-1:1"], ["localhost/pstest-2:1"]]


def test_list_images_skips_one_broken_image_but_keeps_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = image_doc(1)
    FakeApi.images = {
        "bad": FakeImage({"Id": "bad"}, history=[]),
        good["Id"]: FakeImage(good, history=[]),
    }
    c = client()
    real = c.get_image

    def flaky(ref: str) -> Any:
        if ref == "bad":
            raise PodmanError("cannot inspect")
        return real(ref)

    monkeypatch.setattr(c, "get_image", flaky)
    assert [i.repo_tags for i in c.list_images()] == [["localhost/pstest-1:1"]]


def test_list_images_api_failure_is_a_podman_error() -> None:
    FakeApi.list_error = RuntimeError("storage locked")
    with pytest.raises(PodmanError, match="failed to list images"):
        client().list_images()


def test_get_image_uses_api_history() -> None:
    history = load_json("history_bad.json")
    FakeApi.images = {"localhost/pstest-1:1": FakeImage(image_doc(1), history=history)}
    img = client().get_image("localhost/pstest-1:1")
    assert len(img.layers) == len(history)


def test_get_image_falls_back_to_cli_history_when_the_api_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.images = {"x": FakeImage(image_doc(1), history=RuntimeError("no history endpoint"))}
    seen: list[list[str]] = []

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, json.dumps(load_json("history_bad.json")), "")

    monkeypatch.setattr(subprocess, "run", run)
    img = client().get_image("x")
    assert seen and seen[0][:4] == ["podman", "--url", "unix:///run/podman/podman.sock", "history"]
    assert img.layers


def test_get_image_survives_history_failing_everywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.images = {"x": FakeImage(image_doc(1), history=RuntimeError("nope"))}

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("podman")

    monkeypatch.setattr(subprocess, "run", run)
    assert client().get_image("x").layers == []


def test_unknown_image_is_image_not_found() -> None:
    with pytest.raises(ImageNotFoundError, match="image not found: nope"):
        client().get_image("nope")


def test_api_failure_falls_back_to_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.get_error = RuntimeError("api exploded")
    calls: list[list[str]] = []

    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if "inspect" in cmd:
            return subprocess.CompletedProcess(cmd, 0, json.dumps([image_doc(3)]), "")
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr(subprocess, "run", run)
    img = client().get_image("localhost/pstest-3:1")
    assert img.repo_tags == ["localhost/pstest-3:1"]
    assert any("inspect" in c for c in calls)


def test_cli_fallback_with_empty_result_means_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.get_error = RuntimeError("api exploded")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **_: subprocess.CompletedProcess(cmd, 0, "[]", "")
    )
    with pytest.raises(ImageNotFoundError):
        client().get_image("ghost")


# ------------------------------------------------------------------------- containers


def test_list_containers_returns_inspect_documents() -> None:
    FakeApi.containers = [FakeContainer(load_json("containers.json")[0])]
    (doc,) = client().list_containers()
    assert doc["Name"].lstrip("/") == "evil"


def test_list_containers_failure_is_a_podman_error() -> None:
    class Boom:
        def inspect(self) -> None:
            raise RuntimeError("gone")

    FakeApi.containers = [Boom()]  # type: ignore[list-item]
    with pytest.raises(PodmanError, match="failed to list containers"):
        client().list_containers()


# ---------------------------------------------------------------------------- events


def test_events_uses_a_dedicated_connection_without_a_read_timeout() -> None:
    FakeApi.event_docs = [{"Type": "image", "Action": "pull"}]
    c = client()
    assert list(c.events(since=5)) == [{"Type": "image", "Action": "pull"}]
    events_api = FakeApi.instances[-1]
    assert events_api.timeout is None  # idle streams must not time out
    assert events_api.last_events_args == (5, {"type": ["image"]}, True)
    c.close()
    assert events_api.closed


def test_events_unreachable_socket() -> None:
    FakeApi.ping_error = FileNotFoundError("no socket")
    with pytest.raises(PodmanUnavailable):
        list(client().events())


def test_events_stream_error_forces_a_fresh_connection() -> None:
    FakeApi.event_docs = [{"Type": "image"}, ConnectionResetError("stream dropped")]
    c = client()
    it = c.events()
    assert next(it) == {"Type": "image"}
    with pytest.raises(PodmanError, match="event stream failed"):
        next(it)
    assert c._events_client is None
    FakeApi.event_docs = []
    list(c.events())
    assert len([i for i in FakeApi.instances if i.timeout is None]) == 2


# --------------------------------------------------------------------- input safety


@pytest.mark.parametrize(
    "ref", ["", " ", "; rm -rf /", "$(id)", "`id`", "a\nb", "--privileged", "-v /:/host", "a" * 600]
)
def test_hostile_references_never_reach_podman(ref: str) -> None:
    with pytest.raises(PodmanError):
        client().get_image(ref)
    assert FakeApi.instances == []  # not even a connection was opened

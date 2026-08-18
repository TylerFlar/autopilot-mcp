"""The `bw serve` transport — the path that makes writes work at all.

Background: on Bitwarden CLI 2026.3.0 a session from `bw unlock --raw` is
rejected by every later process with "Vault is locked." Reads limped on via
LocalBitwardenVault; writes had no fallback and always failed. These tests
pin the daemon-backed replacement: one unlocked process, HTTP over loopback.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
from typing import Any

import pytest

import credentials


class FakeProc:
    """Stand-in for the `bw serve` child process."""

    def __init__(self, port: int = 45999) -> None:
        self.port = port
        self.terminated = False
        self.killed = False
        self._rc: int | None = None
        self.returncode = None

    def poll(self) -> int | None:
        return self._rc

    def terminate(self) -> None:
        self.terminated = True
        self._rc = 0

    def wait(self, timeout: float | None = None) -> int:
        self._rc = 0
        return 0

    def kill(self) -> None:
        self.killed = True
        self._rc = -9

    def die(self) -> None:
        """Simulate the daemon exiting under us."""
        self._rc = 1


class FakeServeApi:
    """Minimal in-memory stand-in for the Vault Management API."""

    def __init__(self, items: list[dict[str, Any]] | None = None) -> None:
        self.items = items or []
        self.requests: list[tuple[str, str, Any]] = []
        self.unlocked = False
        self.syncs = 0
        self.last_sync = "2026-08-18T04:45:48.737Z"
        self.unreachable = False

    def handle(self, method: str, path: str, payload: Any) -> tuple[int, dict[str, Any]]:
        self.requests.append((method, path, payload))
        if path == "/status":
            return 200, _ok({
                "object": "template",
                "template": {
                    "status": "unlocked" if self.unlocked else "locked",
                    "userEmail": "u@example.com",
                    "lastSync": self.last_sync,
                },
            })
        if path == "/unlock":
            self.unlocked = True
            return 200, _ok({"object": "message", "title": "Your vault is now unlocked!"})
        if path == "/lock":
            self.unlocked = False
            return 200, _ok({"object": "message"})
        if path == "/sync":
            self.syncs += 1
            return 200, _ok({"object": "message"})
        if not self.unlocked:
            return 400, {"success": False, "message": "Vault is locked."}
        if path.startswith("/list/object/items"):
            query = path.partition("?")[2]
            found = self.items
            if "search=" in query:
                needle = query.split("search=")[1].split("&")[0].lower()
                found = [i for i in found if needle in i["name"].lower()]
            if "url=" in query:
                found = [i for i in found if (i.get("login") or {}).get("uris")]
            return 200, _ok({"object": "list", "data": found})
        if path.startswith("/object/item/"):
            item_id = path.rsplit("/", 1)[-1]
            existing = next((i for i in self.items if i["id"] == item_id), None)
            if method == "GET":
                if existing is None:
                    return 404, {"success": False, "message": "Not found."}
                return 200, _ok(existing)
            if method == "PUT":
                self.items = [payload if i["id"] == item_id else i for i in self.items]
                return 200, _ok(payload)
            if method == "DELETE":
                self.items = [i for i in self.items if i["id"] != item_id]
                return 200, _ok(None)
        if path == "/object/item" and method == "POST":
            created = {**payload, "id": "NEW-ID"}
            self.items.append(created)
            return 200, _ok(created)
        return 404, {"success": False, "message": f"no route {method} {path}"}


def _ok(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data}


@pytest.fixture
def serve_api(monkeypatch: pytest.MonkeyPatch, mock_keyring) -> FakeServeApi:
    """Wire a BitwardenServe to an in-memory API instead of a real daemon."""
    api = FakeServeApi()
    procs: list[FakeProc] = []

    def spawn(*_a: object, **_k: object) -> FakeProc:
        procs.append(FakeProc())
        return procs[-1]

    monkeypatch.setenv("AUTOPILOT_BW_TRANSPORT", "serve")
    monkeypatch.setattr("credentials.subprocess.Popen", spawn)
    monkeypatch.setattr("credentials._free_port", lambda host: 45999)

    def fake_urlopen(req, timeout=None):
        parts = urllib.parse.urlsplit(req.full_url)
        # Only the port a daemon was actually spawned on answers; anything
        # else behaves like a dead process (stale state file, killed owner).
        if api.unreachable or parts.port not in {p.port for p in procs}:
            raise urllib.error.URLError("connection refused")
        payload = json.loads(req.data.decode()) if req.data else None
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        status, body = api.handle(req.get_method(), path, payload)
        if status >= 400:
            raise urllib.error.HTTPError(
                req.full_url, status, "err", {}, io.BytesIO(json.dumps(body).encode())
            )
        return _FakeResponse(json.dumps(body).encode())

    monkeypatch.setattr("credentials.urllib.request.urlopen", fake_urlopen)
    api.procs = procs  # type: ignore[attr-defined]
    return api


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _client() -> credentials.BitwardenClient:
    return credentials.BitwardenClient(idle_minutes=15)


# --- the core regression ----------------------------------------------------


def test_writes_work_over_serve(serve_api: FakeServeApi) -> None:
    client = _client()
    created = client.create_item({"type": 1, "name": "example.com", "login": {}})
    assert created["id"] == "NEW-ID"
    assert ("POST", "/object/item", {"type": 1, "name": "example.com", "login": {}}) in [
        (m, p, d) for m, p, d in serve_api.requests
    ]


def test_edit_merges_login_and_saves_the_whole_item(serve_api: FakeServeApi) -> None:
    serve_api.items = [
        {"id": "ITEM1", "name": "example.com", "login": {"username": "u", "password": "old"}}
    ]
    client = _client()

    client.edit_item("ITEM1", {"login": {"password": "new"}})

    saved = next(i for i in serve_api.items if i["id"] == "ITEM1")
    assert saved["login"] == {"username": "u", "password": "new"}


def test_delete_removes_the_item(serve_api: FakeServeApi) -> None:
    serve_api.items = [{"id": "ITEM1", "name": "example.com", "login": {}}]

    _client().delete_item("ITEM1")

    assert serve_api.items == []


# --- lifecycle --------------------------------------------------------------


def test_daemon_is_unlocked_once_and_reused(serve_api: FakeServeApi) -> None:
    client = _client()
    client.list_items(None)
    client.invalidate_cache()
    client.list_items(None)

    unlocks = [r for r in serve_api.requests if r[1] == "/unlock"]
    assert len(unlocks) == 1


def test_unreachable_daemon_is_restarted_once(serve_api: FakeServeApi) -> None:
    client = _client()
    client.list_items(None)
    serve_api.requests.clear()

    # daemon dies; the next call must bring it back rather than surface
    # a connection error to the caller mid-login
    serve_api.unlocked = False
    calls = {"n": 0}
    original = serve_api.handle

    def flaky(method, path, payload):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError("connection refused")
        return original(method, path, payload)

    serve_api.handle = flaky  # type: ignore[assignment]
    client.invalidate_cache()
    client.list_items(None)

    assert [r[1] for r in serve_api.requests if r[1] == "/unlock"]


def test_idle_expiry_locks_the_daemon(
    serve_api: FakeServeApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both clocks move: the local idle check is monotonic, the cross-process
    # one is wall-clock (monotonic isn't comparable between processes).
    now = [1000.0]
    wall = [1_786_000_000.0]
    monkeypatch.setattr("credentials.time.monotonic", lambda: now[0])
    monkeypatch.setattr("credentials.time.time", lambda: wall[0])
    client = credentials.BitwardenClient(idle_minutes=15)
    client.list_items(None)
    serve_api.requests.clear()

    now[0] += 16 * 60
    wall[0] += 16 * 60
    client.invalidate_cache()
    client.list_items(None)

    paths = [r[1] for r in serve_api.requests]
    assert "/lock" in paths, "an idle vault must not stay unlocked and listening"
    assert "/unlock" in paths


def test_a_sibling_process_keeps_the_daemon_alive(
    serve_api: FakeServeApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This process being idle is not enough — another MCP may be mid-login
    on the same daemon, and killing it under them would fail their run."""
    now = [1000.0]
    wall = [1_786_000_000.0]
    monkeypatch.setattr("credentials.time.monotonic", lambda: now[0])
    monkeypatch.setattr("credentials.time.time", lambda: wall[0])
    client = credentials.BitwardenClient(idle_minutes=15)
    client.list_items(None)
    serve_api.requests.clear()

    # 16 minutes pass for us, but a sibling touched the daemon 1 minute ago.
    now[0] += 16 * 60
    wall[0] += 16 * 60
    credentials._write_shared_state(45999, owner_pid=None)
    wall[0] += 60
    client.invalidate_cache()
    client.list_items(None)

    assert "/lock" not in [r[1] for r in serve_api.requests]


# --- one daemon per box, not one per MCP process ----------------------------


def test_second_process_adopts_the_running_daemon(serve_api: FakeServeApi) -> None:
    """Several autopilot MCP processes can run at once. They must share one
    unlocked `bw serve`, not stand up N of them."""
    first = _client()
    first.list_items(None)
    assert len(serve_api.procs) == 1  # type: ignore[attr-defined]

    second = _client()
    second.invalidate_cache()
    second.list_items(None)

    assert len(serve_api.procs) == 1, "the sibling should have adopted, not spawned"  # type: ignore[attr-defined]
    assert second.transport == "serve"


def test_an_adopter_never_kills_the_daemon(serve_api: FakeServeApi) -> None:
    owner = _client()
    owner.list_items(None)
    adopter = _client()
    adopter.invalidate_cache()
    adopter.list_items(None)
    serve_api.requests.clear()

    adopter.lock()

    assert "/lock" not in [r[1] for r in serve_api.requests]
    assert not serve_api.procs[0].terminated  # type: ignore[attr-defined]

    owner.lock()
    assert serve_api.procs[0].terminated  # type: ignore[attr-defined]


def test_a_dead_recorded_daemon_is_replaced(serve_api: FakeServeApi) -> None:
    """A state file left by a process that died must not wedge the next one."""
    credentials._write_shared_state(45998, owner_pid=999999)

    client = _client()
    client.list_items(None)

    assert len(serve_api.procs) == 1, "should have spawned past the dead port"  # type: ignore[attr-defined]
    assert credentials._read_shared_state()["port"] == 45999


def test_lock_shuts_the_daemon_down(serve_api: FakeServeApi) -> None:
    client = _client()
    client.list_items(None)

    client.lock()

    assert serve_api.procs[-1].terminated  # type: ignore[attr-defined]
    assert "/lock" in [r[1] for r in serve_api.requests]


# --- staleness --------------------------------------------------------------


def test_stale_snapshot_syncs_before_the_first_read(
    serve_api: FakeServeApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A months-old lastSync is exactly the state this MCP was found in —
    reads came off a snapshot that predated recently added logins."""
    serve_api.last_sync = "2026-07-07T05:55:51.748Z"
    monkeypatch.setattr("credentials.time.time", lambda: 1786000000.0)

    _client().list_items(None)

    assert serve_api.syncs >= 1


def test_fresh_snapshot_does_not_resync_every_call(serve_api: FakeServeApi) -> None:
    import time as real_time

    serve_api.last_sync = (
        __import__("datetime")
        .datetime.fromtimestamp(real_time.time(), __import__("datetime").UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    client = _client()
    client.list_items(None)
    before = serve_api.syncs
    client.invalidate_cache()
    client.list_items(None)

    assert serve_api.syncs == before


def test_write_syncs_so_the_server_sees_it(serve_api: FakeServeApi) -> None:
    client = _client()
    before = serve_api.syncs

    client.create_item({"type": 1, "name": "example.com", "login": {}})

    assert serve_api.syncs > before


def test_vault_status_reports_transport_and_staleness(serve_api: FakeServeApi) -> None:
    serve_api.items = [
        {"id": "A", "name": "a.com", "login": {"totp": "SEED"}},
        {"id": "B", "name": "b.com", "login": {}},
    ]

    status = _client().vault_status()

    assert status["transport"] == "serve"
    assert status["item_count"] == 2
    assert status["items_with_totp"] == 1
    assert status["sync_age_minutes"] is not None


# --- transport selection ----------------------------------------------------


def test_auto_falls_back_to_cli_when_serve_cannot_start(
    monkeypatch: pytest.MonkeyPatch, mock_keyring, mock_subprocess, prime_unlock
) -> None:
    monkeypatch.setenv("AUTOPILOT_BW_TRANSPORT", "auto")

    def refuse(*_a: object, **_k: object) -> None:
        raise OSError("bw not found")

    monkeypatch.setattr("credentials.subprocess.Popen", refuse)
    prime_unlock()
    mock_subprocess.responses[("list", "items")] = {"stdout": "[]"}

    client = credentials.BitwardenClient()
    assert client.list_items(None) == []
    assert client.transport == "cli"


def test_serve_mode_surfaces_startup_failure(
    monkeypatch: pytest.MonkeyPatch, mock_keyring
) -> None:
    monkeypatch.setenv("AUTOPILOT_BW_TRANSPORT", "serve")
    monkeypatch.setattr(
        "credentials.subprocess.Popen",
        lambda *a, **k: (_ for _ in ()).throw(OSError("bw not found")),
    )

    with pytest.raises(credentials.BitwardenError, match="could not start"):
        credentials.BitwardenClient().list_items(None)


def test_cli_write_failure_explains_the_session_bug(
    monkeypatch: pytest.MonkeyPatch, mock_keyring, mock_subprocess, prime_unlock
) -> None:
    monkeypatch.setenv("AUTOPILOT_BW_TRANSPORT", "cli")
    prime_unlock()
    mock_subprocess.responses[("create", "item")] = {
        "rc": 1,
        "stderr": "Vault is locked.",
    }

    with pytest.raises(credentials.BitwardenVaultLocked) as excinfo:
        credentials.BitwardenClient().create_item({"type": 1, "name": "x"})

    assert "bw serve" in str(excinfo.value)

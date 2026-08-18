"""BitwardenClient read-side behaviour: unlock, list, get, totp, caching,
idle expiry, startup check. All bw calls and keyring lookups are mocked."""

from __future__ import annotations

import json
import logging
import subprocess
import time

import pytest

import credentials


def _bw_args(call: dict) -> list[str]:
    return [arg for arg in call["cmd"][1:] if arg != "--nointeraction"]


def test_startup_check_missing_bw(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("credentials.shutil.which", lambda _: None)
    with pytest.raises(credentials.BitwardenError, match="not found on PATH"):
        credentials.startup_check()


def test_startup_check_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("credentials.shutil.which", lambda _: "/usr/local/bin/bw")
    credentials.startup_check()  # no raise


def test_unlock_uses_keyring_and_passwordenv(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock(session="S1")
    bw_client.unlock()

    assert bw_client._session == "S1"
    unlock_call = mock_subprocess.calls[0]
    cmd = unlock_call["cmd"]
    assert cmd[0] == "bw"
    assert "--nointeraction" in cmd
    assert _bw_args(unlock_call)[0] == "unlock"
    assert "--raw" in cmd and "--passwordenv" in cmd and "BW_PW" in cmd
    # Master password must travel via env, never argv.
    for arg in cmd:
        assert "test-master-password" not in arg
    assert unlock_call["env"]["BW_PW"] == "test-master-password"


def test_bw_command_timeout_raises_clear_error(monkeypatch, bw_client) -> None:
    bw_client._session = "S1"

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout"))

    monkeypatch.setattr("credentials.subprocess.run", fake_run)

    with pytest.raises(credentials.BitwardenError, match="timed out after"):
        bw_client._run(["get", "item", "example.com"], with_session=True)


def test_get_item_timeout_does_not_attempt_url_fallback(monkeypatch, bw_client) -> None:
    calls: list[list[str]] = []
    bw_client._session = "S1"
    bw_client._last_touch = time.monotonic()

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout"))

    monkeypatch.setattr("credentials.subprocess.run", fake_run)

    with pytest.raises(credentials.BitwardenTimeout, match="timed out after"):
        bw_client.get_item("example.com")

    assert [
        [arg for arg in call[1:] if arg != "--nointeraction"] for call in calls
    ] == [["get", "item", "example.com"]]


def test_unlock_fails_without_keyring_entry(mock_subprocess, bw_client, monkeypatch) -> None:
    monkeypatch.setattr("credentials.keyring.get_password", lambda *_: None)
    with pytest.raises(credentials.BitwardenError, match="no master password"):
        bw_client.unlock()


def test_unlock_bubbles_bw_failure(mock_subprocess, mock_keyring, bw_client) -> None:
    mock_subprocess.responses[("unlock", "--raw", "--passwordenv", "BW_PW")] = {
        "rc": 1,
        "stderr": "Invalid master password.",
    }
    with pytest.raises(credentials.BitwardenError, match="Invalid master password"):
        bw_client.unlock()


def test_list_items_sends_search_and_session(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    payload = [{"id": "1", "name": "example-store", "login": {"username": "u"}}]
    mock_subprocess.responses[("list", "items", "--search", "example-store")] = {
        "stdout": json.dumps(payload),
    }
    items = bw_client.list_items("example-store")
    assert items == payload

    list_call = next(c for c in mock_subprocess.calls if _bw_args(c)[:2] == ["list", "items"])
    assert list_call["env"]["BW_SESSION"] == "TESTSESSION"


def test_list_items_caches_within_session(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "q")] = {
        "stdout": json.dumps([{"id": "1"}])
    }
    bw_client.list_items("q")
    bw_client.list_items("q")

    list_calls = [c for c in mock_subprocess.calls if _bw_args(c)[:2] == ["list", "items"]]
    assert len(list_calls) == 1


def test_get_item_by_url_skips_get_item_call(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://example-store.test")] = {
        "stdout": json.dumps([
            {"id": "X", "name": "example-store", "login": {"username": "me"}}
        ])
    }
    item = bw_client.get_item("https://example-store.test")
    assert item["id"] == "X"

    for c in mock_subprocess.calls:
        assert _bw_args(c)[:2] != ["get", "item"]


def test_get_item_by_name_falls_back_to_url_search(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "example-store")] = {
        "rc": 1, "stderr": "Not found."
    }
    mock_subprocess.responses[("list", "items", "--url", "example-store")] = {
        "stdout": json.dumps([{"id": "X", "name": "example-store", "login": {}}])
    }
    item = bw_client.get_item("example-store")
    assert item["id"] == "X"


def test_list_items_falls_back_to_local_vault_when_cli_session_is_locked(
    mock_subprocess, bw_client, prime_unlock, monkeypatch
) -> None:
    class FakeLocalVault:
        def list_items(self, query):
            assert query == "example"
            return [{"id": "LOCAL", "name": "example.com", "login": {"username": "u"}}]

    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "example")] = {
        "rc": 1,
        "stderr": "Vault is locked.",
    }
    monkeypatch.setattr(
        "credentials.LocalBitwardenVault.from_disk",
        lambda: FakeLocalVault(),
    )

    items = bw_client.list_items("example")

    assert items == [{"id": "LOCAL", "name": "example.com", "login": {"username": "u"}}]


def test_get_item_falls_back_to_local_vault_when_cli_session_is_locked(
    mock_subprocess, bw_client, prime_unlock, monkeypatch
) -> None:
    class FakeLocalVault:
        def get_item(self, id_or_url, username=None):
            assert id_or_url == "example.com"
            return {
                "id": "LOCAL",
                "name": "example.com",
                "login": {"username": "u", "password": "p"},
            }

    prime_unlock()
    mock_subprocess.responses[("get", "item", "example.com")] = {
        "rc": 1,
        "stderr": "Vault is locked.",
    }
    monkeypatch.setattr(
        "credentials.LocalBitwardenVault.from_disk",
        lambda: FakeLocalVault(),
    )

    item = bw_client.get_item("example.com")

    assert item["id"] == "LOCAL"
    assert item["login"]["password"] == "p"


def test_get_item_ambiguous_url_match_raises(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://shared.co")] = {
        "stdout": json.dumps([
            {"id": "A", "name": "acct-1"},
            {"id": "B", "name": "acct-2"},
        ])
    }
    with pytest.raises(credentials.BitwardenError, match="2 items match"):
        bw_client.get_item("https://shared.co")


def test_get_totp_computes_locally_from_the_stored_seed(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    """Bitwarden gates `get totp` / /object/totp behind Premium, so the code
    is derived from the seed we already hold rather than asked for."""
    import pyotp

    secret = pyotp.random_base32()
    prime_unlock()
    mock_subprocess.responses[("get", "item", "example-store")] = {
        "stdout": json.dumps(
            {"id": "ITEM42", "name": "example-store", "login": {"totp": secret}}
        ),
    }

    code = bw_client.get_totp("example-store")

    assert code == pyotp.TOTP(secret).now()
    assert not [c for c in mock_subprocess.calls if _bw_args(c)[:2] == ("get", "totp")]


def test_get_totp_accepts_an_otpauth_uri_seed(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    import pyotp

    secret = pyotp.random_base32()
    uri = f"otpauth://totp/site:user?secret={secret}&issuer=site"
    prime_unlock()
    mock_subprocess.responses[("get", "item", "example-store")] = {
        "stdout": json.dumps({"id": "ITEM42", "name": "example-store", "login": {"totp": uri}}),
    }

    assert bw_client.get_totp("example-store") == pyotp.TOTP(secret).now()


def test_get_totp_without_a_seed_says_what_to_do_instead(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "shared.example")] = {
        "stdout": json.dumps({"id": "ITEM42", "name": "shared.example", "login": {}}),
    }

    with pytest.raises(credentials.BitwardenError) as excinfo:
        bw_client.get_totp("shared.example")

    message = str(excinfo.value)
    assert "has no TOTP secret stored" in message
    assert "has_totp" in message


def test_get_item_disambiguates_by_username(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://shared.example")] = {
        "stdout": json.dumps([
            {"id": "A", "name": "shared.example", "login": {"username": "one@example.com"}},
            {"id": "B", "name": "shared.example", "login": {"username": "two@example.com"}},
        ])
    }

    assert bw_client.get_item("https://shared.example", "two@example.com")["id"] == "B"


def test_ambiguous_match_error_names_the_candidates(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    """Two accounts on one site are commonly stored under the same name, so an
    error that only lists names tells the caller nothing actionable."""
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://shared.example")] = {
        "stdout": json.dumps([
            {"id": "A", "name": "shared.example", "login": {"username": "one@example.com"}},
            {"id": "B", "name": "shared.example", "login": {"username": "two@example.com"}},
        ])
    }

    with pytest.raises(credentials.BitwardenError) as excinfo:
        bw_client.get_item("https://shared.example")

    message = str(excinfo.value)
    assert "one@example.com" in message and "two@example.com" in message
    assert "id=A" in message and "id=B" in message
    assert "username" in message


def test_session_idle_expires_and_reunlocks(
    mock_subprocess, bw_client, prime_unlock, monkeypatch
) -> None:
    prime_unlock()
    now = [0.0]
    monkeypatch.setattr("credentials.time.monotonic", lambda: now[0])
    mock_subprocess.responses[("list", "items")] = {"stdout": "[]"}

    bw_client.list_items(None)
    unlocks = [c for c in mock_subprocess.calls if _bw_args(c)[0] == "unlock"]
    assert len(unlocks) == 1

    now[0] = 15 * 60 + 1
    bw_client.list_items(None)
    unlocks = [c for c in mock_subprocess.calls if _bw_args(c)[0] == "unlock"]
    assert len(unlocks) == 2


def test_lock_clears_session_and_cache(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items")] = {"stdout": "[]"}
    bw_client.list_items(None)
    assert bw_client._session is not None
    assert bw_client._item_cache

    bw_client.lock()
    assert bw_client._session is None
    assert not bw_client._item_cache


def test_audit_log_for_list_omits_values(
    mock_subprocess, bw_client, prime_unlock, caplog: pytest.LogCaptureFixture
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "q")] = {
        "stdout": json.dumps([
            {"id": "1", "name": "secret-login", "login": {"password": "p@ssw0rd!"}}
        ]),
    }
    caplog.set_level(logging.DEBUG, logger="autopilot.credentials")

    bw_client.list_items("q")

    for record in caplog.records:
        text = record.getMessage() + " " + json.dumps(record.__dict__, default=str)
        assert "p@ssw0rd!" not in text

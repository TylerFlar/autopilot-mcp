"""Write-op helpers: create_login, update_login, upsert_login, delete_login.

Key invariants under test:
  - create_login fails on name collision (doesn't silently overwrite)
  - update_login fails on not-found (won't silently create)
  - upsert_login picks create vs update correctly; errors on ambiguous match
  - delete_login requires confirm=True
  - every successful write triggers a `bw sync`
  - every successful write invalidates the read cache
  - the payload sent to bw matches the fields the caller asked for
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import pytest

import credentials


def _bw_cmd(cmd: list[str]) -> list[str]:
    return [cmd[0], *(arg for arg in cmd[1:] if arg != "--nointeraction")]


def _bw_args(call: dict[str, Any]) -> list[str]:
    return _bw_cmd(call["cmd"])[1:]


def _decode_payload(cmd: list[str], position: int) -> dict[str, Any]:
    """bw create/edit takes a base64-encoded JSON payload; decode it."""
    encoded = _bw_cmd(cmd)[position]
    return json.loads(base64.b64decode(encoded))


def _bw_subcmd(call: dict[str, Any]) -> list[str]:
    return _bw_args(call)[:2]


# --- client-level create_item / edit_item / delete_item -------------------


def test_create_item_base64_encodes_payload_and_syncs(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("create", "item")] = {
        "stdout": json.dumps({"id": "NEW", "name": "example", "login": {}}),
    }
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    result = bw_client.create_item({"type": 1, "name": "example", "login": {}})
    assert result["id"] == "NEW"

    create_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["create", "item"])
    payload = _decode_payload(create_call["cmd"], position=3)
    assert payload["name"] == "example"
    assert payload["type"] == 1

    # Sync ran after create.
    assert any(_bw_args(c)[0] == "sync" for c in mock_subprocess.calls)


def test_edit_item_merges_login_patch_onto_existing(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    existing = {
        "id": "EX",
        "name": "existing",
        "notes": "keep me",
        "login": {"username": "u", "password": "old", "totp": "OLDSEED"},
    }
    mock_subprocess.responses[("get", "item", "EX")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("edit", "item")] = {
        "stdout": json.dumps(existing),  # content value doesn't matter for assertions
    }
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    bw_client.edit_item("EX", {"login": {"password": "NEWPW"}})

    edit_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["edit", "item"])
    assert _bw_cmd(edit_call["cmd"])[3] == "EX"
    payload = _decode_payload(edit_call["cmd"], position=4)
    # Unrelated fields preserved:
    assert payload["notes"] == "keep me"
    assert payload["login"]["username"] == "u"
    assert payload["login"]["totp"] == "OLDSEED"
    # Patch applied:
    assert payload["login"]["password"] == "NEWPW"


def test_delete_item_calls_bw_and_syncs(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("delete", "item", "EX")] = {"stdout": ""}
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    bw_client.delete_item("EX")

    assert any(_bw_args(c)[:2] == ["delete", "item"] for c in mock_subprocess.calls)
    assert any(_bw_args(c)[0] == "sync" for c in mock_subprocess.calls)


def test_write_invalidates_read_cache(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "q")] = {
        "stdout": json.dumps([{"id": "1", "name": "q"}]),
    }
    mock_subprocess.responses[("create", "item")] = {
        "stdout": json.dumps({"id": "NEW", "name": "new"}),
    }
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    bw_client.list_items("q")
    assert bw_client._item_cache  # got cached

    bw_client.create_item({"type": 1, "name": "new", "login": {}})
    assert not bw_client._item_cache  # cleared by write


# --- create_login helper ---------------------------------------------------


def test_create_login_builds_login_payload(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "new")] = {"stdout": "[]"}
    mock_subprocess.responses[("create", "item")] = {
        "stdout": json.dumps({"id": "NEW", "name": "new"}),
    }
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    credentials.create_login(
        bw_client,
        name="new",
        url="https://example.com",
        username="me@example.com",
        password="hunter2",
        totp_secret="JBSWY3DPEHPK3PXP",
    )

    create_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["create", "item"])
    payload = _decode_payload(create_call["cmd"], position=3)
    assert payload["type"] == 1
    assert payload["name"] == "new"
    assert payload["login"]["username"] == "me@example.com"
    assert payload["login"]["password"] == "hunter2"
    assert payload["login"]["totp"] == "JBSWY3DPEHPK3PXP"
    assert payload["login"]["uris"] == [{"uri": "https://example.com", "match": None}]


def test_create_login_collision_raises(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "taken")] = {
        "stdout": json.dumps([{"id": "X", "name": "taken"}]),
    }
    with pytest.raises(credentials.BitwardenError, match="already exists"):
        credentials.create_login(
            bw_client, name="taken", url="x", username="u", password="p"
        )
    # No create_item call was issued.
    assert not any(_bw_args(c)[:2] == ["create", "item"] for c in mock_subprocess.calls)


# --- update_login helper ---------------------------------------------------


def test_update_login_builds_partial_patch(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    existing = {
        "id": "EX",
        "name": "existing",
        "login": {"username": "u", "password": "old", "uris": [{"uri": "https://x"}]},
    }
    mock_subprocess.responses[("get", "item", "existing")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("get", "item", "EX")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("edit", "item")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    credentials.update_login(bw_client, "existing", password="newpw")

    edit_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["edit", "item"])
    payload = _decode_payload(edit_call["cmd"], position=4)
    assert payload["login"]["password"] == "newpw"
    # Didn't blow away the username:
    assert payload["login"]["username"] == "u"
    # Name untouched (we didn't pass it):
    assert payload["name"] == "existing"


def test_update_login_rejects_empty_patch(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "existing")] = {
        "stdout": json.dumps({"id": "EX", "name": "existing", "login": {}}),
    }
    with pytest.raises(ValueError, match="no fields"):
        credentials.update_login(bw_client, "existing")


def test_update_login_not_found_raises(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "ghost")] = {
        "rc": 1, "stderr": "Not found."
    }
    mock_subprocess.responses[("list", "items", "--url", "ghost")] = {"stdout": "[]"}
    with pytest.raises(credentials.BitwardenError, match="no unique vault item"):
        credentials.update_login(bw_client, "ghost", password="x")


# --- upsert_login helper ---------------------------------------------------


def test_upsert_login_creates_when_no_match(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://x")] = {"stdout": "[]"}
    mock_subprocess.responses[("list", "items", "--search", "https://x")] = {"stdout": "[]"}
    mock_subprocess.responses[("create", "item")] = {
        "stdout": json.dumps({"id": "NEW", "name": "https://x"}),
    }
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    credentials.upsert_login(bw_client, url="https://x", username="u", password="p")
    create_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["create", "item"])
    payload = _decode_payload(create_call["cmd"], position=3)
    assert payload["login"]["username"] == "u"
    assert payload["login"]["password"] == "p"


def test_upsert_login_updates_single_match(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    existing = {
        "id": "EX",
        "name": "existing",
        "login": {"username": "u", "password": "old", "uris": [{"uri": "https://x"}]},
    }
    mock_subprocess.responses[("list", "items", "--url", "https://x")] = {
        "stdout": json.dumps([existing]),
    }
    mock_subprocess.responses[("get", "item", "EX")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("edit", "item")] = {"stdout": json.dumps(existing)}
    mock_subprocess.responses[("sync",)] = {"stdout": "Syncing complete."}

    credentials.upsert_login(bw_client, url="https://x", username="u", password="newpw")
    edit_call = next(c for c in mock_subprocess.calls if _bw_subcmd(c) == ["edit", "item"])
    payload = _decode_payload(edit_call["cmd"], position=4)
    assert payload["login"]["password"] == "newpw"


def test_upsert_login_ambiguous_match_raises(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--url", "https://x")] = {
        "stdout": json.dumps([
            {"id": "A", "name": "a", "login": {"username": "u"}},
            {"id": "B", "name": "b", "login": {"username": "u"}},
        ]),
    }
    with pytest.raises(credentials.BitwardenError, match="2 vault items"):
        credentials.upsert_login(bw_client, url="https://x", username="u", password="p")
    # Nothing written.
    assert not any(
        _bw_args(c)[:2] in (["create", "item"], ["edit", "item"])
        for c in mock_subprocess.calls
    )


def test_upsert_login_skips_unrelated_username_matches(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    # URL matches two items but only one shares the target username.
    prime_unlock()
    items = [
        {"id": "A", "name": "personal", "login": {"username": "me"}},
        {"id": "B", "name": "work", "login": {"username": "other"}},
    ]
    mock_subprocess.responses[("list", "items", "--url", "https://x")] = {
        "stdout": json.dumps(items),
    }
    mock_subprocess.responses[("get", "item", "A")] = {"stdout": json.dumps(items[0])}
    mock_subprocess.responses[("edit", "item")] = {"stdout": json.dumps(items[0])}
    mock_subprocess.responses[("sync",)] = {"stdout": ""}

    credentials.upsert_login(bw_client, url="https://x", username="me", password="newpw")
    # Should have edited A, not erred.
    assert any(_bw_args(c)[:2] == ["edit", "item"] for c in mock_subprocess.calls)


# --- delete_login helper ---------------------------------------------------


def test_delete_login_requires_confirm(bw_client) -> None:
    with pytest.raises(ValueError, match="confirm=True"):
        credentials.delete_login(bw_client, "anything")
    with pytest.raises(ValueError, match="confirm=True"):
        credentials.delete_login(bw_client, "anything", confirm=False)


def test_delete_login_happy_path(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "Legacy")] = {
        "stdout": json.dumps({"id": "LEG", "name": "Legacy", "login": {}}),
    }
    mock_subprocess.responses[("delete", "item", "LEG")] = {"stdout": ""}
    mock_subprocess.responses[("sync",)] = {"stdout": ""}

    result = credentials.delete_login(bw_client, "Legacy", confirm=True)
    assert result["deleted"] is True
    assert result["item_id"] == "LEG"
    assert any(_bw_args(c)[:3] == ["delete", "item", "LEG"] for c in mock_subprocess.calls)
    assert any(_bw_args(c)[0] == "sync" for c in mock_subprocess.calls)


# --- audit log doesn't leak values ----------------------------------------


def test_write_audit_log_omits_values(
    mock_subprocess, bw_client, prime_unlock, caplog: pytest.LogCaptureFixture
) -> None:
    prime_unlock()
    mock_subprocess.responses[("list", "items", "--search", "new")] = {"stdout": "[]"}
    mock_subprocess.responses[("create", "item")] = {
        "stdout": json.dumps({"id": "NEW", "name": "new", "login": {}}),
    }
    mock_subprocess.responses[("sync",)] = {"stdout": ""}
    caplog.set_level(logging.DEBUG, logger="autopilot.credentials")

    credentials.create_login(
        bw_client, name="new", url="https://x",
        username="me@example", password="DO-NOT-LOG-ME",
    )
    for record in caplog.records:
        text = record.getMessage() + " " + json.dumps(record.__dict__, default=str)
        assert "DO-NOT-LOG-ME" not in text

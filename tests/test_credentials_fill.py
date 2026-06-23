"""fill_login + reveal_credentials behaviour. The central invariant: the
password value never crosses back to the caller via return value or log."""

from __future__ import annotations

import json
import logging

import pytest

import credentials


class FakeKeyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []
        self.pressed: list[str] = []

    async def type(self, text: str) -> None:
        self.typed.append(text)

    async def press(self, key: str) -> None:
        self.pressed.append(key)


class FakePage:
    """Minimal Playwright Page stand-in. Records (selector, value) pairs."""

    def __init__(self) -> None:
        self.fills: list[tuple[str, str]] = []
        self.clicks: list[str] = []
        self.keyboard = FakeKeyboard()

    async def fill(self, selector: str, value: str) -> None:
        self.fills.append((selector, value))

    async def click(self, selector: str) -> None:
        self.clicks.append(selector)


async def test_fill_login_autodetects_selectors_and_never_returns_password(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    item = {
        "id": "VID",
        "name": "cubebrush",
        "login": {
            "username": "me@example.com",
            "password": "s3cr3t-p@ss",
            "uris": [{"uri": "https://cubebrush.co/"}],
        },
    }
    mock_subprocess.responses[("list", "items", "--url", "https://cubebrush.co/")] = {
        "stdout": json.dumps([item]),
    }

    page = FakePage()
    result = await credentials.fill_login(bw_client, page, "https://cubebrush.co/")

    assert result["filled"] is True
    assert result["item_id"] == "VID"
    assert result["fields_filled"] == ["username", "password"]

    # Password value must not appear anywhere in the response.
    serialized = json.dumps(result)
    assert "s3cr3t-p@ss" not in serialized

    # But it MUST have been injected into the form.
    values = [v for _, v in page.fills]
    assert "me@example.com" in values
    assert "s3cr3t-p@ss" in values

    # Selectors: first fill was the username heuristic, second was pw.
    assert "password" in page.fills[1][0].lower()


async def test_fill_login_honors_explicit_selectors(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "MyLogin")] = {
        "stdout": json.dumps({
            "id": "V",
            "name": "MyLogin",
            "login": {"username": "u", "password": "p", "uris": []},
        }),
    }

    page = FakePage()
    await credentials.fill_login(
        bw_client,
        page,
        "https://any",
        username_selector="#custom-user",
        password_selector="#custom-pw",
        vault_item="MyLogin",
    )
    assert page.fills == [("#custom-user", "u"), ("#custom-pw", "p")]


async def test_fill_login_keystroke_mode_clears_and_types_password(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "Fidelity")] = {
        "stdout": json.dumps({
            "id": "F",
            "name": "Fidelity",
            "login": {"username": "me", "password": "k3y-str0ke-pw", "uris": []},
        }),
    }

    page = FakePage()
    result = await credentials.fill_login(
        bw_client,
        page,
        "https://digital.fidelity.com/prgw/digital/login/full-page",
        vault_item="Fidelity",
        password_mode="keystroke",
    )

    assert result["password_mode"] == "keystroke"
    assert result["fields_filled"] == ["username", "password"]

    # Username still goes through page.fill.
    assert ("me" in [v for _, v in page.fills])

    # Password went through keystrokes, not page.fill.
    assert "k3y-str0ke-pw" not in [v for _, v in page.fills]
    assert page.keyboard.typed == ["k3y-str0ke-pw"]

    # Password field was focused and cleared before typing.
    assert page.clicks == ["input[type=password]"]
    assert ("input[type=password]", "") in page.fills

    # Password value must not appear in the returned dict.
    assert "k3y-str0ke-pw" not in json.dumps(result)


async def test_fill_login_value_mode_does_not_use_keystrokes(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "Plain")] = {
        "stdout": json.dumps({
            "id": "P",
            "name": "Plain",
            "login": {"username": "u", "password": "pw-value", "uris": []},
        }),
    }

    page = FakePage()
    result = await credentials.fill_login(
        bw_client, page, "https://x", vault_item="Plain"
    )

    assert result["password_mode"] == "value"
    assert "pw-value" in [v for _, v in page.fills]
    assert page.keyboard.typed == []
    assert page.clicks == []


async def test_fill_login_rejects_unknown_password_mode(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    page = FakePage()
    with pytest.raises(ValueError, match="password_mode"):
        await credentials.fill_login(
            bw_client, page, "https://x", vault_item="x", password_mode="bogus"
        )
    assert page.fills == []
    assert page.keyboard.typed == []


async def test_fill_login_raises_when_vault_missing_password(
    mock_subprocess, bw_client, prime_unlock
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "nocreds")] = {
        "stdout": json.dumps({
            "id": "N",
            "name": "nocreds",
            "login": {"username": "only-name", "password": None, "uris": []},
        }),
    }
    page = FakePage()
    with pytest.raises(credentials.BitwardenError, match="no username or password"):
        await credentials.fill_login(bw_client, page, "n/a", vault_item="nocreds")
    assert page.fills == []  # nothing touched


async def test_fill_login_audit_log_omits_password(
    mock_subprocess, bw_client, prime_unlock, caplog: pytest.LogCaptureFixture
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "Login")] = {
        "stdout": json.dumps({
            "id": "V",
            "name": "Login",
            "login": {"username": "u", "password": "NOT-IN-LOGS", "uris": []},
        }),
    }
    caplog.set_level(logging.DEBUG, logger="autopilot.credentials")

    page = FakePage()
    await credentials.fill_login(bw_client, page, "https://x", vault_item="Login")

    for record in caplog.records:
        text = record.getMessage() + " " + json.dumps(record.__dict__, default=str)
        assert "NOT-IN-LOGS" not in text


def test_reveal_credentials_requires_reason(
    mock_subprocess, mock_keyring, bw_client
) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        credentials.reveal_credentials(bw_client, "x", "")
    with pytest.raises(ValueError, match="non-empty"):
        credentials.reveal_credentials(bw_client, "x", "   ")


def test_reveal_credentials_returns_plaintext_and_audits_reason(
    mock_subprocess, bw_client, prime_unlock, caplog: pytest.LogCaptureFixture
) -> None:
    prime_unlock()
    mock_subprocess.responses[("get", "item", "Legacy")] = {
        "stdout": json.dumps({
            "id": "V",
            "name": "Legacy",
            "login": {"username": "u", "password": "p", "uris": []},
        }),
    }
    caplog.set_level(logging.DEBUG, logger="autopilot.credentials")

    result = credentials.reveal_credentials(
        bw_client, "Legacy", "iframe login form, fill_login can't target"
    )
    assert result["username"] == "u"
    assert result["password"] == "p"

    # Reason is audited, password value is not.
    reveal_records = [r for r in caplog.records if "reveal" in r.getMessage()]
    assert reveal_records, "expected a credentials.reveal log record"
    for record in reveal_records:
        text = record.getMessage() + " " + json.dumps(record.__dict__, default=str)
        assert "iframe login form" in text

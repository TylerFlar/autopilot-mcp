"""Shared fixtures: mock bw subprocess + mock keyring so no real CLI runs."""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

# Make the MCP root importable from tests without installing the package.
_MCP_ROOT = Path(__file__).resolve().parents[1]
if str(_MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_ROOT))

# Route structlog through stdlib logging so pytest's caplog captures records.
# Without this, structlog's default PrintLoggerFactory prints to stdout but
# produces no stdlib records, which silently turns `assert "secret" not in caplog`
# into a vacuous pass.
import logging_setup  # noqa: E402

logging_setup.configure()


@pytest.fixture
def mock_subprocess(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """Intercept credentials.subprocess.run. Tests set canned responses keyed
    by the tuple of bw args (everything after the "bw" executable name)."""
    calls: list[dict[str, Any]] = []
    responses: dict[tuple[str, ...], dict[str, Any]] = {}

    def normalized_bw_args(cmd: list[str]) -> tuple[str, ...]:
        return tuple(arg for arg in cmd[1:] if arg != "--nointeraction")

    def fake_run(
        cmd: list[str],
        env: dict[str, str] | None = None,
        capture_output: bool = True,
        text: bool = True,
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        calls.append({"cmd": list(cmd), "env": dict(env) if env else {}})
        args = normalized_bw_args(cmd)
        spec: dict[str, Any] | None = None
        # Exact match wins; otherwise fall back to the longest registered
        # prefix. This lets write-op tests match `bw create item <base64>`
        # without predicting the exact base64 payload.
        if args in responses:
            spec = responses[args]
        else:
            for prefix_len in range(len(args), 0, -1):
                if args[:prefix_len] in responses:
                    spec = responses[args[:prefix_len]]
                    break
        if spec is None:
            raise AssertionError(f"no canned response for bw args {args!r}; cmd={cmd}")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=spec.get("rc", 0),
            stdout=spec.get("stdout", ""),
            stderr=spec.get("stderr", ""),
        )

    monkeypatch.setattr("credentials.subprocess.run", fake_run)
    return types.SimpleNamespace(calls=calls, responses=responses)


@pytest.fixture
def mock_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    """Replace keyring.get_password with a dict-backed stub. Pre-seeded with
    the master password the real MCP would look up."""
    import credentials

    store: dict[tuple[str, str], str] = {
        (credentials.KEYRING_SERVICE, credentials.KEYRING_USERNAME): "test-master-password",
    }
    monkeypatch.setattr(
        "credentials.keyring.get_password",
        lambda svc, user: store.get((svc, user)),
    )
    return store


@pytest.fixture
def bw_client(mock_subprocess, mock_keyring):
    """A BitwardenClient with both subprocess and keyring mocked."""
    import credentials

    return credentials.BitwardenClient(idle_minutes=15)


@pytest.fixture
def prime_unlock(mock_subprocess):
    """Preload canned responses for unlock + lock. Returns a callable so
    tests can override the session token."""

    def _prime(session: str = "TESTSESSION") -> None:
        mock_subprocess.responses[("unlock", "--raw", "--passwordenv", "BW_PW")] = {
            "stdout": session,
        }
        mock_subprocess.responses[("lock",)] = {"stdout": "Your vault is locked."}

    return _prime

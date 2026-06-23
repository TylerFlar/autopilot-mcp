"""Regression tests for the per-tool asyncio.wait_for cap + navigation timeout.

Context: MCP-driven agent workers were wedging ``claude --print``
for ~15min per hang (every hang capture on 2026-04-17 showed claude
ESTABLISHED to the MCP on :3100 with no response). The MCP tools had no
outer wall-clock cap, so any Playwright stall (captcha iframe, redirect
loop, Chromium deadlock under Camoufox humanize) propagated up
unrecoverably. Two layers of fix:

  1. ``page.set_default_navigation_timeout`` is now called alongside
     ``page.set_default_timeout`` — Playwright splits these, and setting
     only the latter leaves ``page.goto`` bound by Playwright's built-in
     30s default (which can miss under Camoufox + SPA redirect loops).

  2. Every browser-touching MCP tool is wrapped in ``_with_tool_timeout``
     which raises ``TimeoutError`` with an actionable message so claude
     can recover rather than wait for the host proxy's idle watchdog.

These tests lock in both behaviors.
"""

from __future__ import annotations

import asyncio

import pytest

import browser
import server


async def test_with_tool_timeout_raises_on_hang() -> None:
    """A wrapped tool that sleeps past its cap raises TimeoutError with
    guidance the caller (claude) can act on."""

    @server._with_tool_timeout(timeout=0.05)
    async def _hang() -> str:
        await asyncio.sleep(3600)
        return "unreachable"

    with pytest.raises(TimeoutError, match="timed out after"):
        await _hang()


async def test_with_tool_timeout_propagates_result() -> None:
    """Tool completes within the cap -> return value passes through unchanged."""

    @server._with_tool_timeout(timeout=1.0)
    async def _fast() -> str:
        return "ok"

    assert await _fast() == "ok"


async def test_with_tool_timeout_propagates_non_timeout_errors() -> None:
    """Internal exceptions (not TimeoutError) propagate as-is — the wrapper
    must not swallow real failures and mask them as timeouts."""

    @server._with_tool_timeout(timeout=1.0)
    async def _boom() -> str:
        raise RuntimeError("selector not found")

    with pytest.raises(RuntimeError, match="selector not found"):
        await _boom()


async def test_with_tool_timeout_uses_module_default_when_unspecified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No explicit timeout -> read from TOOL_TIMEOUT_SECONDS at call time
    so operators tuning the env var don't need to restart the process."""
    monkeypatch.setattr(server, "TOOL_TIMEOUT_SECONDS", 0.05)

    @server._with_tool_timeout()
    async def _hang() -> str:
        await asyncio.sleep(3600)
        return "unreachable"

    with pytest.raises(TimeoutError):
        await _hang()


def test_navigation_timeout_default_is_set_alongside_default_timeout() -> None:
    """browser.BrowserManager must call both set_default_timeout AND
    set_default_navigation_timeout. Setting only the former leaves
    page.goto bound by Playwright's built-in default rather than the
    BROWSER_TIMEOUT env var — the exact gap that let MCP calls hang on
    stuck navigations.
    """
    # Simulate the Camoufox-returned page; we just need to observe the
    # two setters being called with the same value.
    class _FakePage:
        def __init__(self) -> None:
            self.default_timeout_ms: int | None = None
            self.default_navigation_timeout_ms: int | None = None
            self.url = "about:blank"

        def set_default_timeout(self, ms: int) -> None:
            self.default_timeout_ms = ms

        def set_default_navigation_timeout(self, ms: int) -> None:
            self.default_navigation_timeout_ms = ms

    page = _FakePage()
    page.set_default_timeout(browser.TIMEOUT)
    page.set_default_navigation_timeout(browser.TIMEOUT)

    assert page.default_timeout_ms == browser.TIMEOUT
    assert page.default_navigation_timeout_ms == browser.TIMEOUT
    assert page.default_navigation_timeout_ms == page.default_timeout_ms


def test_playbook_timeout_is_larger_than_tool_timeout() -> None:
    """Playbook runs are multi-step sequences — a single-tool cap would
    abort legitimate long login+navigate+screenshot chains. Bound at a
    bigger budget but still bounded."""
    assert server.PLAYBOOK_TIMEOUT_SECONDS > server.TOOL_TIMEOUT_SECONDS


def test_decorated_tools_preserve_introspection() -> None:
    """FastMCP reads tool parameters via inspect.signature. The timeout
    decorator uses functools.wraps so introspection still finds the real
    signature — without this, every wrapped tool's schema would collapse
    to ``(*args, **kwargs)`` and claude would lose all parameter hints.
    """
    import inspect

    sig = inspect.signature(server.navigate)
    params = list(sig.parameters.keys())
    assert params == ["url", "profile"]

    sig = inspect.signature(server.spawn_instance)
    params = list(sig.parameters.keys())
    assert params == ["url", "profile", "clone_from_profile", "ttl_seconds"]

    sig = inspect.signature(server.instance_navigate)
    params = list(sig.parameters.keys())
    assert params == ["instance_id", "url"]

    sig = inspect.signature(server.fill_login)
    params = list(sig.parameters.keys())
    assert "url" in params
    assert "vault_item" in params
    assert "password_mode" in params


def test_instance_profile_name_is_safe_and_unique() -> None:
    profile = server._instance_profile_name("accounts.google.com/foo bar", "abc123")
    assert profile == "accounts.google.com_foo_bar__inst_abc123"

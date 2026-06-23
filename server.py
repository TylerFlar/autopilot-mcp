"""Autopilot MCP — free-roam browser automation with Bitwarden-backed creds."""

from __future__ import annotations

import asyncio
import atexit
import base64
import functools
import json
import os
import re
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar
from uuid import uuid4

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.types import Image

import credentials as _credentials
import logging_setup
from browser import DATA_DIR, BrowserManager, resolve_profile
from file_server import FileServer
from playbooks import PlaybookManager

# Per-tool wall-clock cap. Every browser-touching MCP tool is wrapped so
# no single Playwright call can hang indefinitely — a Chromium deadlock,
# captcha iframe that never resolves, auth redirect loop, or Camoufox
# humanize-mode stall gets bounded here rather than propagating up to
# claude (which has no way to recover a stuck MCP tool call on its own).
#
# 2026-04-17 baseline: ~15-min hangs on autopilot-MCP-driven workers,
# every hang capture showing an ESTABLISHED TCP to :3100 with claude
# blocked waiting on an MCP response. The host proxy and tasque job
# runner have their own safety nets (nudge ladder, asyncio.wait_for on
# call_llm); this cap is the fix at the root.
TOOL_TIMEOUT_SECONDS: float = float(
    os.environ.get("AUTOPILOT_TOOL_TIMEOUT_SECONDS", "60")
)
# Playbook runs are multi-step; one cap for the whole sequence rather
# than per-step so a long legitimate login + navigate + screenshot
# sequence isn't cut short.
PLAYBOOK_TIMEOUT_SECONDS: float = float(
    os.environ.get("AUTOPILOT_PLAYBOOK_TIMEOUT_SECONDS", "300")
)

_T = TypeVar("_T")


def _with_tool_timeout(
    timeout: float | None = None,
) -> Callable[[Callable[..., Awaitable[_T]]], Callable[..., Awaitable[_T]]]:
    """Wrap an async MCP tool in asyncio.wait_for with a bounded cap.

    On timeout, raises ``TimeoutError`` with a message pointing the caller
    at the likely failure modes (captcha, redirect loop, Playwright hang)
    so claude can adapt rather than retry the same stuck call. Preserves
    the wrapped function's signature so FastMCP's schema introspection
    still sees the original parameters.
    """

    def _decorator(inner: Callable[..., Awaitable[_T]]) -> Callable[..., Awaitable[_T]]:
        cap = timeout if timeout is not None else TOOL_TIMEOUT_SECONDS

        @functools.wraps(inner)
        async def _wrapped(*args: Any, **kwargs: Any) -> _T:
            try:
                return await asyncio.wait_for(inner(*args, **kwargs), timeout=cap)
            except asyncio.TimeoutError as exc:
                raise TimeoutError(
                    f"{inner.__name__} timed out after {cap:.0f}s — "
                    f"browser likely stuck (captcha wall, auth redirect, "
                    f"2FA prompt, or Playwright/Chromium hang). "
                    f"Try a different URL, re-navigate, or call "
                    f"screenshot/get_text to see the current state."
                ) from exc

        return _wrapped

    return _decorator

logging_setup.configure()
_credentials.startup_check()

INSTRUCTIONS = """Free-roam browser automation with Bitwarden-backed credentials.

Typical workflow:
  1. For parallel work, spawn_instance(url) first. It returns instance_id.
     Use instance_navigate / instance_screenshot / instance_run_js /
     instance_click / instance_type_text with that id, then close_instance.
  2. For legacy single-profile work, list_playbooks(url_match) first.
  3. run_playbook(name)         if yes, replay in 1 call; done
  4. navigate(url)              otherwise, start navigating anywhere
  5. screenshot(profile)        see what's on screen
  6. run_js / click / type      interact with the page
  7. save_playbook(...)         once you succeed, save the sequence
  8. playbook_run_list/get      inspect durable playbook run ledgers

Profile model:
  Each registrable domain (eTLD+1) — e.g. "fidelity.com", "news.ycombinator.com" —
  gets its own persistent browser profile under data/profiles/<profile>/.
  `navigate(url)` auto-derives the profile from the URL. Subsequent tools
  (screenshot, click, run_js, etc.) take `profile` explicitly — pass the
  same eTLD+1 to act on the page you just opened.

Instance model:
  Persistent profiles are shared browser contexts. Multiple workers touching
  the same profile at the same time should use spawn_instance(url), which
  clones the base profile into a temporary isolated profile and returns an
  opaque instance_id. All follow-up calls must use instance_* tools with that
  id. Always call close_instance(instance_id) in cleanup.

Handling login pages:
  fill_login(url, ...)          inject creds from Bitwarden directly;
                                password never enters your context
  get_totp(vault_item)          current 6-digit 2FA code (short-lived)
  list_logins(query)            search vault (no passwords ever returned)
  reveal_credentials(item, reason)  escape hatch when fill_login can't target

Signing up and want to remember the creds? Use upsert_login(url, user, pw).

SMS 2FA? navigate("https://messages.google.com/web/") and read the code —
the Messages profile is auth-persisted via its own browser profile.

Uploading a file the site asks for? Two paths:
  attach_file(profile, selector, path)   standard <input type="file">
                                          (works even if hidden inside a
                                          dropzone widget — target the input,
                                          not the visible drop area)
  serve_local_file(path)                  pure-JS uploader with no real
                                          input element — publishes a local
                                          CORS URL the page can fetch() and
                                          wrap in a File. Then drive the
                                          drop event yourself via run_js.

Every run_playbook call writes a JSON run ledger under data/playbook-runs/;
use playbook_run_get(run_id) after drift or failure to inspect the step trace.

Prefer run_js over coordinate clicks — selectors work across viewport sizes.
"""

mcp = FastMCP("autopilot", instructions=INSTRUCTIONS)
browser_mgr = BrowserManager()
playbook_mgr = PlaybookManager()
bw = _credentials.BitwardenClient()
file_server = FileServer(
    host=os.environ.get("AUTOPILOT_FILE_SERVER_HOST", "127.0.0.1"),
    port=int(os.environ.get("AUTOPILOT_FILE_SERVER_PORT", "0")),
)
atexit.register(bw.lock)
atexit.register(file_server.shutdown)


@dataclass
class BrowserInstance:
    instance_id: str
    profile: str
    source_profile: str
    created_at: float
    expires_at: float
    last_used_at: float


_instances: dict[str, BrowserInstance] = {}
_instances_lock = asyncio.Lock()


def _safe_profile_fragment(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return (safe or "profile")[:80]


def _instance_profile_name(source_profile: str, instance_id: str) -> str:
    return f"{_safe_profile_fragment(source_profile)}__inst_{instance_id}"


def _copy_profile_tree(source_dir: Path, dest_dir: Path) -> list[str]:
    """Clone a browser profile, skipping cache/lock files."""
    if not source_dir.exists():
        dest_dir.mkdir(parents=True, exist_ok=True)
        return []

    ignored_names = {
        "cache2",
        "startupCache",
        "shader-cache",
        "jumpListCache",
        "crashes",
        "minidumps",
        "thumbnails",
        "datareporting",
        "lock",
        ".parentlock",
        "parent.lock",
    }
    skipped: list[str] = []
    dest_dir.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(source_dir):
        rel_root = Path(root).relative_to(source_dir)
        dirs[:] = [d for d in dirs if d not in ignored_names]
        target_root = dest_dir / rel_root
        target_root.mkdir(parents=True, exist_ok=True)
        for filename in files:
            if filename in ignored_names or filename.startswith("Singleton"):
                continue
            src = Path(root) / filename
            dst = target_root / filename
            try:
                shutil.copy2(src, dst)
            except OSError:
                skipped.append(str(src.relative_to(source_dir)))
    return skipped


async def _close_instance_record(instance: BrowserInstance) -> None:
    await browser_mgr.close_profile(instance.profile)
    shutil.rmtree(DATA_DIR / instance.profile, ignore_errors=True)


async def _sweep_expired_instances() -> None:
    now = time.monotonic()
    expired: list[BrowserInstance] = []
    async with _instances_lock:
        for instance_id, instance in list(_instances.items()):
            if instance.expires_at <= now:
                expired.append(instance)
                _instances.pop(instance_id, None)
    for instance in expired:
        await _close_instance_record(instance)


async def _profile_for_instance(instance_id: str) -> str:
    await _sweep_expired_instances()
    async with _instances_lock:
        instance = _instances.get(instance_id)
        if instance is None:
            raise KeyError(
                f"unknown browser instance_id {instance_id!r}; "
                "call spawn_instance first or list_instances to inspect live ids"
            )
        instance.last_used_at = time.monotonic()
        return instance.profile


def _atexit_close_instances() -> None:
    instances = list(_instances.values())
    _instances.clear()
    for instance in instances:
        try:
            asyncio.run(browser_mgr.close_profile(instance.profile))
        except Exception:
            pass
        shutil.rmtree(DATA_DIR / instance.profile, ignore_errors=True)


atexit.register(_atexit_close_instances)


# ---------------------------------------------------------------------------
# Browser tools
# ---------------------------------------------------------------------------


@mcp.tool()
@_with_tool_timeout()
async def spawn_instance(
    url: str,
    profile: str = "",
    clone_from_profile: str = "",
    ttl_seconds: float = 1800.0,
) -> str:
    """Create an isolated temporary browser instance for parallel work.

    Use this when multiple workers might touch the same site/profile at the
    same time. The instance is seeded by cloning the base profile directory,
    so a logged-in ``google.com`` profile can be used by several workers
    without them sharing one live page. Follow-up calls must use the returned
    ``instance_id`` with ``instance_*`` tools. Call ``close_instance`` when done.

    Args:
        url: Initial URL to open.
        profile: Optional base profile override. Defaults to resolve_profile(url).
        clone_from_profile: Optional source profile to clone. Defaults to profile.
        ttl_seconds: Auto-cleanup TTL for this instance.
    """
    await _sweep_expired_instances()
    if ttl_seconds <= 0:
        return "Error: ttl_seconds must be positive"

    resolved_profile = profile or resolve_profile(url)
    source_profile = clone_from_profile or resolved_profile
    instance_id = uuid4().hex[:12]
    instance_profile = _instance_profile_name(source_profile, instance_id)
    source_dir = DATA_DIR / source_profile
    dest_dir = DATA_DIR / instance_profile

    try:
        skipped = await asyncio.to_thread(_copy_profile_tree, source_dir, dest_dir)
    except OSError as exc:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return f"Error: failed to clone profile {source_profile!r}: {exc}"

    now = time.monotonic()
    instance = BrowserInstance(
        instance_id=instance_id,
        profile=instance_profile,
        source_profile=source_profile,
        created_at=now,
        expires_at=now + ttl_seconds,
        last_used_at=now,
    )
    async with _instances_lock:
        _instances[instance_id] = instance

    try:
        page = await browser_mgr.get_page(instance_profile)
        await page.goto(url, wait_until="domcontentloaded")
        await asyncio.sleep(2)
        text = await page.inner_text("body")
    except Exception:
        async with _instances_lock:
            _instances.pop(instance_id, None)
        await _close_instance_record(instance)
        raise

    payload = {
        "instance_id": instance_id,
        "profile": instance_profile,
        "source_profile": source_profile,
        "current_url": page.url,
        "ttl_seconds": ttl_seconds,
        "skipped_clone_files": skipped[:20],
        "instruction": (
            "Use this instance_id with instance_* tools and call "
            "close_instance when finished."
        ),
        "page_text": text[:5000],
    }
    return json.dumps(payload, indent=2)


@mcp.tool()
async def list_instances() -> str:
    """List live spawned browser instances."""
    await _sweep_expired_instances()
    now = time.monotonic()
    async with _instances_lock:
        rows = [
            {
                "instance_id": instance.instance_id,
                "profile": instance.profile,
                "source_profile": instance.source_profile,
                "ttl_remaining_seconds": max(0, round(instance.expires_at - now, 1)),
                "idle_seconds": round(now - instance.last_used_at, 1),
            }
            for instance in _instances.values()
        ]
    return json.dumps(rows, indent=2)


@mcp.tool()
async def close_instance(instance_id: str) -> str:
    """Close a spawned browser instance and delete its temporary profile."""
    async with _instances_lock:
        instance = _instances.pop(instance_id, None)
    if instance is None:
        return f"no such instance_id: {instance_id}"
    await _close_instance_record(instance)
    return f"closed instance_id={instance_id}"


@mcp.tool()
@_with_tool_timeout()
async def instance_navigate(instance_id: str, url: str) -> str:
    """Navigate a spawned instance to a URL.

    Args:
        instance_id: ID returned by spawn_instance.
        url: URL to navigate to.
    """
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    await page.goto(url, wait_until="domcontentloaded")
    await asyncio.sleep(2)
    text = await page.inner_text("body")
    return (
        f"Current URL: {page.url}\n"
        f"Instance: {instance_id}\n\n"
        f"Page text:\n{text[:5000]}"
    )


@mcp.tool()
@_with_tool_timeout()
async def instance_screenshot(instance_id: str) -> Image:
    """PNG screenshot of the page open in a spawned instance."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    data = await page.screenshot()
    return Image(data=data, format="png")


@mcp.tool()
@_with_tool_timeout()
async def instance_get_text(instance_id: str) -> str:
    """Visible text from the current page in a spawned instance."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    text = await page.inner_text("body")
    return f"Current URL: {page.url}\nInstance: {instance_id}\n\nPage text:\n{text[:10000]}"


@mcp.tool()
@_with_tool_timeout()
async def instance_get_url(instance_id: str) -> str:
    """Current URL for a spawned instance."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    return page.url


@mcp.tool()
@_with_tool_timeout()
async def instance_run_js(instance_id: str, script: str) -> str:
    """Run JavaScript in a spawned instance and return the stringified result."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    result = await page.evaluate(script)
    if result is None:
        return "OK (no return value)"
    return str(result)


@mcp.tool()
@_with_tool_timeout()
async def instance_click(instance_id: str, x: int, y: int) -> str:
    """Click viewport coordinates in a spawned instance."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    await page.mouse.click(x, y)
    await asyncio.sleep(1)
    text = await page.inner_text("body")
    return f"Clicked ({x}, {y}). Current URL: {page.url}\n\nPage text:\n{text[:5000]}"


@mcp.tool()
@_with_tool_timeout()
async def instance_type_text(instance_id: str, text: str) -> str:
    """Type text into the focused element in a spawned instance."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    await page.keyboard.type(text)
    return f"Typed {len(text)} characters"


@mcp.tool()
@_with_tool_timeout()
async def instance_attach_file(instance_id: str, selector: str, path: str) -> str:
    """Attach a local file to an input in a spawned instance."""
    p = os.path.expanduser(path)
    if not os.path.isfile(p):
        return f"Error: file not found at {p!r}"
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    await page.set_input_files(selector, p)
    return f"Attached {p!r} to {selector!r}"


@mcp.tool()
@_with_tool_timeout()
async def instance_scroll(instance_id: str, direction: str = "down") -> str:
    """Scroll a spawned instance by roughly one viewport."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    delta = -500 if direction == "up" else 500
    await page.mouse.wheel(0, delta)
    await asyncio.sleep(0.5)
    return f"Scrolled {direction}. Current URL: {page.url}"


@mcp.tool()
@_with_tool_timeout()
async def instance_fill_login(
    instance_id: str,
    url: str,
    username_selector: str = "",
    password_selector: str = "",
    vault_item: str = "",
    password_mode: str = "",
) -> str:
    """Fill a login form in a spawned instance with a Bitwarden entry."""
    profile = await _profile_for_instance(instance_id)
    page = await browser_mgr.get_page(profile)
    result = await _credentials.fill_login(
        bw,
        page,
        url,
        username_selector=username_selector or None,
        password_selector=password_selector or None,
        vault_item=vault_item or None,
        password_mode=password_mode or "value",
    )
    return json.dumps(result)


@mcp.tool()
@_with_tool_timeout()
async def navigate(url: str, profile: str = "") -> str:
    """Open `url` in a persistent browser profile and return the page text.

    The profile is derived from the URL's eTLD+1 (e.g. "fidelity.com") unless
    you pass `profile` explicitly. A fresh profile is created on first use
    and kept forever under data/profiles/<profile>/.

    Args:
        url: URL to navigate to.
        profile: Optional profile override (eTLD+1 string).
    """
    resolved = profile or resolve_profile(url)
    page = await browser_mgr.get_page(resolved)
    await page.goto(url, wait_until="domcontentloaded")
    await asyncio.sleep(2)

    text = await page.inner_text("body")
    return (
        f"Current URL: {page.url}\n"
        f"Profile: {resolved}\n\n"
        f"Page text:\n{text[:5000]}"
    )


@mcp.tool()
@_with_tool_timeout()
async def screenshot(profile: str) -> Image:
    """PNG screenshot of the page open in `profile`.

    Args:
        profile: eTLD+1 string (same key you passed to navigate).
    """
    page = await browser_mgr.get_page(profile)
    data = await page.screenshot()
    return Image(data=data, format="png")


@mcp.tool()
@_with_tool_timeout()
async def get_text(profile: str) -> str:
    """Visible text from the current page — cheaper than a screenshot.

    Args:
        profile: eTLD+1 string.
    """
    page = await browser_mgr.get_page(profile)
    text = await page.inner_text("body")
    return f"Current URL: {page.url}\n\nPage text:\n{text[:10000]}"


@mcp.tool()
@_with_tool_timeout()
async def get_url(profile: str) -> str:
    """Current URL for the profile's page.

    Args:
        profile: eTLD+1 string.
    """
    page = await browser_mgr.get_page(profile)
    return page.url


@mcp.tool()
@_with_tool_timeout()
async def run_js(profile: str, script: str) -> str:
    """Run JavaScript in the page and return the stringified result. PREFERRED
    over click() for form filling and button activation — CSS/DOM selectors
    are robust to viewport size.

    Args:
        profile: eTLD+1 string.
        script: JavaScript expression or statement to evaluate.
    """
    page = await browser_mgr.get_page(profile)
    result = await page.evaluate(script)
    if result is None:
        return "OK (no return value)"
    return str(result)


@mcp.tool()
@_with_tool_timeout()
async def click(profile: str, x: int, y: int) -> str:
    """Click at viewport coordinates. Use only when you can't target by
    selector — prefer run_js for robustness.

    Args:
        profile: eTLD+1 string.
        x: X pixel in the viewport.
        y: Y pixel in the viewport.
    """
    page = await browser_mgr.get_page(profile)
    await page.mouse.click(x, y)
    await asyncio.sleep(1)
    text = await page.inner_text("body")
    return f"Clicked ({x}, {y}). Current URL: {page.url}\n\nPage text:\n{text[:5000]}"


@mcp.tool()
@_with_tool_timeout()
async def type_text(profile: str, text: str) -> str:
    """Type text into the currently-focused element. Click or focus first.

    Args:
        profile: eTLD+1 string.
        text: Text to type.
    """
    page = await browser_mgr.get_page(profile)
    await page.keyboard.type(text)
    return f"Typed {len(text)} characters"


@mcp.tool()
@_with_tool_timeout()
async def attach_file(profile: str, selector: str, path: str) -> str:
    """Attach a local file to a ``<input type="file">`` element on the page.

    PREFERRED upload path. Uses Playwright's ``set_input_files`` — works
    for standard file inputs, including hidden ones nested inside custom
    dropzone widgets (Playwright will populate the input even if it's
    ``display:none``). Pass a CSS selector for the ``<input type="file">``,
    not for the visible drop zone.

    For sites with NO ``<input type="file">`` at all (pure-JS uploaders
    that build a ``FormData`` from a ``File`` constructed in JS), fall
    back to ``serve_local_file`` + ``run_js`` instead.

    Args:
        profile: eTLD+1 string (the same key passed to navigate).
        selector: CSS selector for the ``<input type="file">``.
        path: Absolute or ``~``-relative path to the local file.
    """
    p = os.path.expanduser(path)
    if not os.path.isfile(p):
        return f"Error: file not found at {p!r}"
    page = await browser_mgr.get_page(profile)
    await page.set_input_files(selector, p)
    return f"Attached {p!r} to {selector!r}"


@mcp.tool()
@_with_tool_timeout()
async def scroll(profile: str, direction: str = "down") -> str:
    """Scroll the page by roughly one viewport.

    Args:
        profile: eTLD+1 string.
        direction: 'up' or 'down'.
    """
    page = await browser_mgr.get_page(profile)
    delta = -500 if direction == "up" else 500
    await page.mouse.wheel(0, delta)
    await asyncio.sleep(0.5)
    return f"Scrolled {direction}. Current URL: {page.url}"


# ---------------------------------------------------------------------------
# Credential tools (Bitwarden-backed, fill-don't-reveal)
# ---------------------------------------------------------------------------


@mcp.tool()
@_with_tool_timeout()
async def list_logins(query: str = "") -> str:
    """Search Bitwarden for saved logins. Returns id, name, urls, username
    for each match — NEVER the password. `query=""` lists everything.

    Args:
        query: Free-text search across name/url/username.
    """
    items = await asyncio.to_thread(bw.list_items, query or None)
    safe = [
        {
            "id": it.get("id"),
            "name": it.get("name"),
            "username": (it.get("login") or {}).get("username"),
            "urls": [
                u.get("uri") for u in (it.get("login") or {}).get("uris") or []
            ],
        }
        for it in items
    ]
    return json.dumps(safe, indent=2)


@mcp.tool()
@_with_tool_timeout()
async def fill_login(
    url: str,
    username_selector: str = "",
    password_selector: str = "",
    vault_item: str = "",
    password_mode: str = "",
) -> str:
    """Fill a login form with a Bitwarden entry. Preferred over typing the
    password yourself — the password is injected into the DOM and never
    returns to you.

    Matching: `vault_item` (name or id) takes precedence; else match by url.

    Selectors are auto-detected if omitted: password goes to the first
    input[type=password]; username tries input[autocomplete=username], then
    type=email, then common name/id hints. Pass explicit CSS for weird forms.

    Args:
        url: Current page URL — picks the matching vault entry AND the
             browser profile (its eTLD+1).
        username_selector: Optional CSS selector for the username field.
        password_selector: Optional CSS selector for the password field.
        vault_item: Optional vault item name/id; overrides URL matching.
        password_mode: 'value' (default) fills via DOM. 'keystroke' focuses
             the password field, clears it, and types via real key events —
             needed for frameworks (e.g. Fidelity) that ignore .value fills.
    """
    profile = resolve_profile(url)
    page = await browser_mgr.get_page(profile)
    result = await _credentials.fill_login(
        bw,
        page,
        url,
        username_selector=username_selector or None,
        password_selector=password_selector or None,
        vault_item=vault_item or None,
        password_mode=password_mode or "value",
    )
    return json.dumps(result)


@mcp.tool()
@_with_tool_timeout()
async def get_totp(vault_item: str) -> str:
    """Current 6-digit TOTP for a Bitwarden item. Bitwarden is the single
    source of truth for TOTP secrets. Codes are ~30s; call right before you
    need to paste.

    Args:
        vault_item: Vault item name or id.
    """
    return await asyncio.to_thread(bw.get_totp, vault_item)


@mcp.tool()
@_with_tool_timeout()
async def reveal_credentials(vault_item: str, reason: str) -> str:
    """ESCAPE HATCH — returns plaintext username + password. Only use when
    fill_login can't target the form. `reason` is mandatory and audited.

    Args:
        vault_item: Vault item name or id.
        reason: 1+ sentence explanation of why plaintext is needed.
    """
    if not reason or not reason.strip():
        return "Error: reason must be a non-empty explanation"
    result = await asyncio.to_thread(_credentials.reveal_credentials, bw, vault_item, reason)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Credential write tools
# ---------------------------------------------------------------------------


def _result_summary(item: dict) -> str:
    return json.dumps({"id": item.get("id"), "name": item.get("name")})


@mcp.tool()
async def create_login(
    name: str,
    url: str,
    username: str,
    password: str,
    totp_secret: str = "",
    folder_id: str = "",
) -> str:
    """Create a new Bitwarden Login item. Errors if `name` already exists —
    use update_login or upsert_login to modify an existing entry.

    Args:
        name: Display name (unique per vault).
        url: Login URL.
        username: Username or email.
        password: Password to store.
        totp_secret: Optional TOTP seed (base32).
        folder_id: Optional Bitwarden folder id.
    """
    item = await asyncio.to_thread(
        _credentials.create_login,
        bw,
        name=name,
        url=url,
        username=username,
        password=password,
        totp_secret=totp_secret or None,
        folder_id=folder_id or None,
    )
    return _result_summary(item)


@mcp.tool()
async def update_login(
    id_or_url: str,
    name: str = "",
    url: str = "",
    username: str = "",
    password: str = "",
    totp_secret: str = "",
) -> str:
    """Patch fields on an existing Bitwarden Login. Errors if `id_or_url`
    doesn't resolve to a unique item. Leave fields empty to skip — only
    the fields you pass get written.

    Args:
        id_or_url: Item id, exact name, or URL.
        name: New display name (optional).
        url: Replace the primary URI (optional).
        username: New username (optional).
        password: New password (optional).
        totp_secret: New TOTP seed (optional).
    """
    fields: dict[str, str] = {}
    if name:
        fields["name"] = name
    if url:
        fields["url"] = url
    if username:
        fields["username"] = username
    if password:
        fields["password"] = password
    if totp_secret:
        fields["totp_secret"] = totp_secret
    if not fields:
        return "Error: no fields provided to update"
    item = await asyncio.to_thread(_credentials.update_login, bw, id_or_url, **fields)
    return _result_summary(item)


@mcp.tool()
async def upsert_login(
    url: str,
    username: str,
    password: str,
    name: str = "",
    totp_secret: str = "",
) -> str:
    """Create a new login, or update the existing one matching (url, username).
    The "I just signed up, remember these" path. Errors if more than one
    existing item matches both url and username.

    Args:
        url: Login URL.
        username: Username or email.
        password: Password to store.
        name: Display name when creating (ignored if updating; defaults to url).
        totp_secret: Optional TOTP seed.
    """
    item = await asyncio.to_thread(
        _credentials.upsert_login,
        bw,
        url=url,
        username=username,
        password=password,
        name=name or None,
        totp_secret=totp_secret or None,
    )
    return _result_summary(item)


@mcp.tool()
async def delete_login(id_or_url: str, confirm: bool = False) -> str:
    """DESTRUCTIVE — sends a Bitwarden Login item to trash. Requires
    `confirm=True`. Recoverable from Bitwarden's trash until purged.

    Args:
        id_or_url: Item id, exact name, or URL.
        confirm: Must be True for the deletion to proceed.
    """
    if not confirm:
        return "Error: delete_login requires confirm=True. This is destructive."
    result = await asyncio.to_thread(_credentials.delete_login, bw, id_or_url, confirm=True)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Local file server (CORS) — for sites whose uploader is pure JS
# ---------------------------------------------------------------------------


@mcp.tool()
async def serve_local_file(
    path: str,
    ttl_seconds: float = 1800.0,
    download_filename: str = "",
) -> str:
    """Publish a local file at an unguessable URL on 127.0.0.1 with CORS so
    the browser can ``fetch()`` it. Use when the site's upload widget is
    pure JS (drag-drop, fetch+FormData) and there's NO ``<input type="file">``
    you can target with ``attach_file``.

    Server binds to 127.0.0.1 only; the URL token is uuid4 hex (122 bits
    of entropy); CORS is open so the controlled browser can fetch from
    any origin. Entries auto-expire after ``ttl_seconds`` (default 30 min).

    Returns JSON with ``url``, ``token``, ``content_type``, ``size``, and
    ``expires_at``. The LLM should then use ``run_js`` to:
      1. ``fetch(url)`` from inside the page,
      2. wrap the response Blob in a ``new File([blob], filename, {type})``,
      3. either set it on a hidden file input via ``DataTransfer`` +
         ``input.files`` + dispatching ``change``, or dispatch a synthetic
         ``drop`` event on the dropzone with ``DataTransfer.items.add``.

    Example run_js for a dropzone:
      ```
      const r = await fetch("<URL>");
      const blob = await r.blob();
      const file = new File([blob], "<FILENAME>", {type: blob.type});
      const dt = new DataTransfer();
      dt.items.add(file);
      const dz = document.querySelector("<DROPZONE_SELECTOR>");
      dz.dispatchEvent(new DragEvent("drop", {dataTransfer: dt, bubbles: true}));
      ```

    Call ``unserve_local_file(token)`` when the upload completes to
    revoke the URL early.

    Args:
        path: Absolute or ``~``-relative path to the local file.
        ttl_seconds: How long the URL stays valid (default 1800).
        download_filename: Optional override for the Content-Disposition
            filename — set this when the on-disk name differs from what
            the site should see.
    """
    try:
        info = await asyncio.to_thread(
            file_server.publish,
            path,
            ttl_seconds=ttl_seconds,
            download_filename=download_filename or None,
        )
    except FileNotFoundError as exc:
        return f"Error: {exc}"
    except ValueError as exc:
        return f"Error: {exc}"
    return json.dumps(info, indent=2)


@mcp.tool()
async def list_served_files() -> str:
    """List files currently published by ``serve_local_file`` (token, url,
    path, size, expires_at). Useful when an earlier upload session left a
    URL active and you want to find or revoke it."""
    items = await asyncio.to_thread(file_server.list_entries)
    if not items:
        return "No files currently served"
    return json.dumps(items, indent=2)


@mcp.tool()
async def unserve_local_file(token: str) -> str:
    """Revoke a URL published by ``serve_local_file`` (frees the token
    immediately rather than waiting for TTL).

    Args:
        token: The ``token`` value returned from ``serve_local_file``.
    """
    removed = await asyncio.to_thread(file_server.unpublish, token)
    return "removed" if removed else "no such token"


# ---------------------------------------------------------------------------
# Playbook tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_playbooks(url_match: str = "") -> str:
    """List saved playbooks. ALWAYS check first — if a playbook exists for
    your task, run it instead of re-discovering navigation.

    Args:
        url_match: Optional substring to filter against each playbook's start_url.
    """
    playbooks = playbook_mgr.list_playbooks(url_match or None)
    if not playbooks:
        return "No playbooks found" + (f" matching '{url_match}'" if url_match else "")
    return json.dumps(playbooks, indent=2)


@mcp.tool()
@_with_tool_timeout(timeout=PLAYBOOK_TIMEOUT_SECONDS)
async def run_playbook(
    name: str, vars: dict[str, Any] | None = None
) -> list:
    """Execute a saved playbook. Returns screenshots + extracted text from
    observation steps. On failure, returns the error and the failed step index.

    ``vars`` fills ``{{key}}`` placeholders in any string leaf of any
    step — URL, run_js script, selector, fill value, assertion error.
    Strings substitute literally; numbers/bools/lists/dicts JSON-
    serialise so they embed as valid JS literals (``pickQty({{qty}})``
    with ``qty=5`` → ``pickQty(5)``). Missing keys fail the step with
    a readable error and still produce a failure dump.

    Args:
        name: Playbook name.
        vars: Optional ``{key: value}`` map of template substitutions.
              Omit for playbooks that have no placeholders.
    """
    result = await playbook_mgr.run_playbook(
        name, browser_mgr, bw_client=bw, variables=vars
    )

    output = []
    if not result["success"]:
        output.append(f"Playbook FAILED: {result.get('error', 'Unknown error')}")
        if "failed_step" in result:
            output.append(f"Failed at step {result['failed_step']}")
        dump = result.get("failure_dump")
        if dump and dump.get("dir"):
            output.append(
                f"Failure dump written to {dump['dir']} "
                f"(html={dump.get('html_bytes', '?')}B, "
                f"screenshot={dump.get('screenshot_bytes', '?')}B). "
                f"Inspect page.html + page.png to see the DOM at failure time, "
                f"then recover with browser tools when the account/site state "
                f"is safely recoverable, or update the playbook."
            )

    for r in result.get("results", []):
        if r["type"] == "screenshot":
            output.append(Image(data=base64.b64decode(r["data"]), format="png"))
        elif r["type"] == "text":
            desc = r.get("description", "")
            prefix = f"[{desc}] " if desc else ""
            output.append(f"{prefix}{r['text'][:5000]}")
        elif r["type"] == "login":
            output.append(f"Auto-login: {r['text']}")
        elif r["type"] == "warning":
            output.append(f"Warning: {r['text']}")
        elif r["type"] == "variant":
            output.append(f"Variant: {r['text']}")
        elif r["type"] == "assert":
            output.append(f"Assert: {r['text']}")

    if not output:
        output.append("Playbook completed successfully (no observation steps)")

    if result.get("run_id"):
        output.append(
            f"Run ledger: {result['run_id']} at {result.get('ledger_path', '')}"
        )

    return output


@mcp.tool()
async def playbook_run_get(run_id: str) -> str:
    """Return the saved JSON ledger for a playbook run.

    Args:
        run_id: Run id returned by run_playbook or playbook_run_list.
    """
    run = playbook_mgr.get_run(run_id)
    if run is None:
        return json.dumps({"error": f"playbook run not found: {run_id}"})
    return json.dumps(run, indent=2)


@mcp.tool()
async def playbook_run_list(
    name: str = "", success: str = "", limit: int = 20
) -> str:
    """List saved playbook run ledgers, newest first.

    Args:
        name: Optional exact playbook name filter.
        success: Optional success filter: "", "true", or "false".
        limit: Maximum number of runs to return.
    """
    normalized = success.strip().lower()
    if normalized == "":
        success_filter = None
    elif normalized == "true":
        success_filter = True
    elif normalized == "false":
        success_filter = False
    else:
        return json.dumps({
            "error": "success must be one of: '', 'true', 'false'"
        })

    runs = playbook_mgr.list_runs(
        name=name or None,
        success=success_filter,
        limit=limit,
    )
    return json.dumps(runs, indent=2)


@mcp.tool()
async def save_playbook(
    name: str, start_url: str, description: str, steps: str
) -> str:
    """Save a playbook — a reusable sequence of browser steps. Call after
    a successful first-time task so future attempts are 1 call.

    `steps` must be a JSON array. Step types:
      navigate:     {"action": "navigate", "url": "..."}
      click:        {"action": "click", "x": 100, "y": 200}
      type:         {"action": "type", "text": "hello"}
      press_key:    {"action": "press_key", "key": "Enter", "wait_after"?: 0.5}
      scroll:       {"action": "scroll", "direction": "up" | "down"}
      wait:         {"action": "wait", "seconds": 3}
      screenshot:   {"action": "screenshot"}
      extract_text: {"action": "extract_text", "description": "what to read"}
      run_js:       {"action": "run_js", "script": "...",
                     "description"?: "what it returns"}
      fill_login:   {"action": "fill_login", "url": "...",
                     "vault_item"?: "..." ,
                     "username_selector"?: "...", "password_selector"?: "...",
                     "password_mode"?: "value" | "keystroke",
                     "skip_username"?: bool}
      detect_variant:
                    {"action": "detect_variant",
                     "variants": [{"name": "fresh", "selector": "#x"},
                                  {"name": "remembered", "selector": "#y"}],
                     "fallback_error"?: "..."}
      when_variant: {"action": "when_variant", "name": "fresh",
                     "steps": [...sub-steps...]}
      assert_js:    {"action": "assert_js", "script": "...", 
                     "expect"?: "truthy" | "falsy", "error"?: "..."}
      fail:         {"action": "fail", "error": "..."}

    detect_variant + when_variant + assert_js + fail let a playbook
    branch on page state (e.g. fresh vs remembered-username login
    page) and bail with a readable error. On any playbook failure —
    including these — the runner dumps page HTML + screenshot to
    ./data/autopilot-failures/<ts>-<name>/ and surfaces the dump path
    in the tool result as `failure_dump`.

    screenshot / extract_text / run_js outputs come back to you when
    run_playbook is called. Prefer run_js over coordinate click/type
    for selector-based scraping — same semantics as the standalone
    run_js MCP tool. fill_login pulls creds from Bitwarden; password
    never enters the playbook file.

    Args:
        name: Unique playbook name (e.g., 'fidelity_portfolio_summary').
        start_url: Anchor URL — resolve_profile(start_url) picks the browser
                   profile the playbook runs in. Often the first navigate URL.
        description: What this playbook does (visible in list_playbooks).
        steps: JSON array of step objects.
    """
    try:
        parsed_steps = json.loads(steps)
        if not isinstance(parsed_steps, list):
            return "Error: steps must be a JSON array"
    except json.JSONDecodeError as e:
        return f"Error parsing steps JSON: {e}"

    return playbook_mgr.save_playbook(name, start_url, description, parsed_steps)


@mcp.tool()
async def delete_playbook(name: str) -> str:
    """Delete a saved playbook. Use for unfixably-broken playbooks —
    otherwise save_playbook with the same name overwrites.

    Args:
        name: Playbook name to delete.
    """
    return playbook_mgr.delete_playbook(name)


if __name__ == "__main__":
    mcp.run(transport="stdio")

"""Camoufox browser session management, keyed by per-domain profile.

Each registrable domain (eTLD+1) gets its own persistent user_data_dir so
cookies/sessions across sibling subdomains share state the way a real
browser does (app.example.com and www.example.com share `example.com`).
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import tldextract
from camoufox.async_api import AsyncCamoufox

DATA_DIR = Path(__file__).parent / "data" / "profiles"
HEADLESS = os.environ.get("HEADLESS", "true").lower() == "true"
# Persistent-profile contexts untouched this long are closed (cookies live on
# disk; the next tool call relaunches). This is what stops a days-old session
# from holding camoufox processes and profile locks forever — the 2026-08-14
# leak audit found browsers from four-day-old sessions still running. Idle
# instances (spawn_instance clones) are exempt: they have their own lifecycle.
# 0 disables.
IDLE_PROFILE_SECONDS = float(os.environ.get("AUTOPILOT_IDLE_PROFILE_MINUTES", "20")) * 60
# Playwright action timeout in ms. Applied via both set_default_timeout
# (selector waits, fill, click) AND set_default_navigation_timeout
# (page.goto, page.reload) — the two are independent in Playwright, and
# setting only the first leaves navigation bound by Playwright's built-in
# 30s default, which can miss under Camoufox humanize + SPA redirect loops.
TIMEOUT = int(os.environ.get("BROWSER_TIMEOUT", "30000"))

# include_psl_private_domains=True keeps per-user isolation on private
# suffixes like github.io / glitch.me — so alice.github.io gets its own
# profile instead of sharing with every other GitHub Pages user.
_tld_extract = tldextract.TLDExtract(include_psl_private_domains=True)


def resolve_profile(url: str) -> str:
    """Derive the per-domain profile key for a URL.

    Registrable domain (eTLD+1) when tldextract can compute one — e.g.
    `https://app.example.com/portfolio` → `example.com`. Falls back
    to the hostname for anything without a public suffix (IPs, localhost,
    custom internal hosts).
    """
    if not url or not url.strip():
        raise ValueError("resolve_profile: empty URL")

    candidate = url if "://" in url else f"https://{url}"

    ext = _tld_extract(candidate)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"

    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"resolve_profile: cannot derive profile from {url!r}")
    return host


class BrowserManager:
    """One Camoufox context per profile (eTLD+1). Pages are created lazily
    on first get_page(profile) call."""

    def __init__(self, headless: bool | None = None):
        self._contexts: dict[str, object] = {}
        self._pages: dict[str, object] = {}
        self._cms: dict[str, object] = {}
        self._last_used: dict[str, float] = {}
        self._reaper: object | None = None
        self.headless = headless if headless is not None else HEADLESS

    def _touch(self, profile: str) -> None:
        self._last_used[profile] = time.monotonic()
        if IDLE_PROFILE_SECONDS > 0 and (self._reaper is None or self._reaper.done()):
            self._reaper = asyncio.create_task(self._reap_idle())

    async def _reap_idle(self) -> None:
        """Close persistent contexts nobody has touched in IDLE_PROFILE_SECONDS."""
        while True:
            await asyncio.sleep(60)
            now = time.monotonic()
            for profile in list(self._cms):
                if "__inst_" in profile:
                    continue  # instances are closed by close_instance/atexit
                last = self._last_used.get(profile, now)
                if now - last > IDLE_PROFILE_SECONDS:
                    await self.close_profile(profile)

    async def get_page(self, profile: str):
        """Get or create a browser page for the given profile.

        Profile name is the eTLD+1; callers that only have a URL should run
        it through `resolve_profile(url)` first. A profile dir is created on
        first use and persists across MCP restarts.
        """
        if not profile:
            raise ValueError("get_page: profile is required")
        self._touch(profile)
        if profile in self._pages:
            page = self._pages[profile]
            # `page.url` is answered from the client-side cache, so it stays
            # healthy after the driver has died (e.g. the browser tree was
            # killed externally to free a profile for manual_login.py) and the
            # stale page then poisons every later call. Only a real round-trip
            # proves the driver: instant hard error = dead (rebuild from
            # disk); a slow answer = merely busy (still alive).
            try:
                await asyncio.wait_for(page.title(), timeout=3)
                return page
            except (TimeoutError, asyncio.TimeoutError):
                return page
            except Exception:
                self._pages.pop(profile, None)
                self._contexts.pop(profile, None)
                cm = self._cms.pop(profile, None)
                if cm:
                    try:
                        await cm.__aexit__(None, None, None)
                    except Exception:
                        pass

        profile_dir = str(DATA_DIR / profile)
        os.makedirs(profile_dir, exist_ok=True)

        # ``humanize=True`` synthesises human-like mouse trails before
        # actions. In headless mode there's no viewport to trace —
        # Camoufox's humanize logic is known to stall inside Playwright's
        # C-level IPC (see ``server.py``: "Camoufox humanize-mode stall").
        # The stall isn't cleanly cancellable by ``asyncio.wait_for``, so
        # the tool-timeout wrapper raises ``TimeoutError`` while the
        # underlying Playwright task keeps the shared browser context
        # pinned, making every subsequent tool call on the same profile
        # hang too. Tracking 2026-04-17 wedges against a bank / a lender portal /
        # Broker playbook-build jobs — all headless. Only humanize when
        # there's an actual viewport the operator can see.
        cm = AsyncCamoufox(
            persistent_context=True,
            user_data_dir=profile_dir,
            humanize=not self.headless,
            headless=self.headless,
        )
        context = await cm.__aenter__()
        self._cms[profile] = cm
        self._contexts[profile] = context

        pages = context.pages
        page = pages[0] if pages else await context.new_page()
        page.set_default_timeout(TIMEOUT)
        page.set_default_navigation_timeout(TIMEOUT)
        self._pages[profile] = page
        return page

    async def close_profile(self, profile: str):
        cm = self._cms.pop(profile, None)
        self._pages.pop(profile, None)
        self._contexts.pop(profile, None)
        self._last_used.pop(profile, None)
        if cm:
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass

    async def close_all(self):
        for profile in list(self._cms.keys()):
            await self.close_profile(profile)

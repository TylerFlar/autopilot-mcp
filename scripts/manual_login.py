"""Manual login helper — opens a visible browser so you can log in and
complete 2FA. The session persists in the per-domain profile.

Usage:
    uv run python scripts/manual_login.py <url>

The URL picks the browser profile (its eTLD+1). Opens the URL in a visible
Camoufox window. Log in, complete 2FA, check any "remember me" boxes, then
close the window. The profile at data/profiles/<eTLD+1>/ keeps the session
across headless MCP invocations.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browser import BrowserManager, resolve_profile


async def manual_login(url: str) -> None:
    profile = resolve_profile(url)
    print(f"Profile: {profile}")
    print(f"Opening: {url}")
    print("Log in, complete 2FA, check 'remember me', then close the browser.")
    print()

    mgr = BrowserManager(headless=False)
    page = await mgr.get_page(profile)
    context = mgr._contexts[profile]

    closed = asyncio.Event()
    context.on("close", lambda: closed.set())

    await page.goto(url, wait_until="domcontentloaded")

    await closed.wait()
    print(f"Session saved via profile: data/profiles/{profile}/")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: uv run python scripts/manual_login.py <url>")
        print("Example: uv run python scripts/manual_login.py https://www.sofi.com/login")
        sys.exit(1)

    url = sys.argv[1]
    asyncio.run(manual_login(url))


if __name__ == "__main__":
    main()

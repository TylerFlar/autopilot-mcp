"""resolve_profile(url) correctness — domain, subdomain, PSL, IP, localhost."""

from __future__ import annotations

import pytest

from browser import resolve_profile


@pytest.mark.parametrize(
    "url,expected",
    [
        # Basic scheme + host
        ("https://example.com", "example.com"),
        ("http://example.com/path?q=1", "example.com"),
        # Subdomains collapse to eTLD+1
        ("https://digital.fidelity.com/ftgw/digital/portfolio/summary", "fidelity.com"),
        ("https://www.instagram.com/accounts/login/", "instagram.com"),
        ("https://messages.google.com/web/", "google.com"),
        ("https://a.b.c.example.co.uk/x", "example.co.uk"),
        # Private suffix (github.io is on the PSL)
        ("https://user.github.io/project/", "user.github.io"),
        # Schemeless inputs fall through the https:// fallback
        ("example.com/foo", "example.com"),
        ("www.sofi.com", "sofi.com"),
    ],
)
def test_resolve_profile_standard(url: str, expected: str) -> None:
    assert resolve_profile(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        # Hosts without a public suffix fall back to the raw hostname.
        ("http://localhost:3000/ui", "localhost"),
        ("http://127.0.0.1:8080/api", "127.0.0.1"),
        ("http://my-internal-box/", "my-internal-box"),
    ],
)
def test_resolve_profile_non_public_hosts(url: str, expected: str) -> None:
    assert resolve_profile(url) == expected


def test_resolve_profile_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty URL"):
        resolve_profile("")
    with pytest.raises(ValueError, match="empty URL"):
        resolve_profile("   ")


def test_resolve_profile_rejects_unresolvable() -> None:
    # Missing hostname entirely after scheme.
    with pytest.raises(ValueError, match="cannot derive profile"):
        resolve_profile("https:///no-host")

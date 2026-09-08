"""Per-profile device-fingerprint pinning.

The whole point of pinning is that a profile presents the SAME device on every
relaunch (otherwise "remember this device" trust churns away). These tests lock
that guarantee in at the config layer, without launching a real browser.
"""

from __future__ import annotations

import json
import warnings

import browser


def _resolved_config(launch_opts: dict) -> dict:
    """Reassemble the config dict Camoufox chunks into CAMOU_CONFIG_* env vars."""
    chunks = sorted(
        (int(key.rsplit("_", 1)[1]), value)
        for key, value in launch_opts["env"].items()
        if key.startswith("CAMOU_CONFIG_")
    )
    return json.loads("".join(value for _, value in chunks))


def test_build_pinned_fingerprint_is_windows_and_complete() -> None:
    bundle = browser._build_pinned_fingerprint()
    assert bundle.keys() >= {"config", "firefox_user_prefs", "fingerprint"}
    ua = bundle["config"]["navigator.userAgent"]
    assert "Windows" in ua and "Firefox" in ua
    # WebGL renderer/vendor are pinned in the config (a top device signal).
    assert bundle["config"].get("webGl:renderer")
    assert bundle["config"].get("webGl:vendor")


def test_load_or_create_is_idempotent(tmp_path) -> None:
    profile_dir = str(tmp_path / "example.com")
    first = browser._load_or_create_profile_fingerprint(profile_dir)
    # File was written and is reused verbatim on the next call.
    assert (tmp_path / "example.com" / browser.FINGERPRINT_FILENAME).exists()
    second = browser._load_or_create_profile_fingerprint(profile_dir)
    assert first == second
    assert first["config"]["navigator.userAgent"] == second["config"]["navigator.userAgent"]


def test_pinned_overrides_reproduce_byte_identical_config(tmp_path) -> None:
    from camoufox.utils import launch_options

    profile_dir = str(tmp_path / "pinned.com")
    overrides = browser._profile_fingerprint_overrides(profile_dir)
    assert overrides, "pinning should be active"

    def relaunch(headless: bool, humanize: bool) -> dict:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            opts = launch_options(
                headless=headless,
                humanize=humanize,
                config=dict(overrides["config"]),
                firefox_user_prefs=dict(overrides["firefox_user_prefs"]),
                fingerprint=overrides["fingerprint"],
                i_know_what_im_doing=True,
                env={},
            )
        return _resolved_config(opts)

    headless_a = relaunch(True, False)
    headless_b = relaunch(True, False)
    headed = relaunch(False, True)  # the manual-login path

    # Two headless relaunches are byte-identical -- no churn.
    assert headless_a == headless_b
    # Every hardware device signal survives the headless -> headed crossover, so
    # a device trusted during a hand sign-in matches the daemon's headless runs.
    for key in (
        "navigator.userAgent",
        "navigator.platform",
        "navigator.oscpu",
        "navigator.maxTouchPoints",
        "screen.width",
        "screen.height",
        "webGl:renderer",
        "webGl:vendor",
        "canvas:aaOffset",
        "fonts:spacing_seed",
    ):
        assert headless_a.get(key) == headed.get(key), key


def test_overrides_degrade_to_empty_on_failure(monkeypatch, tmp_path) -> None:
    def boom() -> dict:
        raise RuntimeError("generation broke")

    monkeypatch.setattr(browser, "_build_pinned_fingerprint", boom)
    # No cached file -> build is attempted -> raises -> caller swallows it.
    overrides = browser._profile_fingerprint_overrides(str(tmp_path / "fresh.com"))
    assert overrides == {}

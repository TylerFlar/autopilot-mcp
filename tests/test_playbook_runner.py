"""Playbook runner step dispatch — press_key + fill_login threading,
branching (detect_variant / when_variant), and failure-dump capture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import playbooks


class FakeKeyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []
        self.pressed: list[tuple[str, float]] = []

    async def type(self, text: str) -> None:
        self.typed.append(text)

    async def press(self, key: str) -> None:
        self.pressed.append((key, 0.0))


class FakePage:
    def __init__(self) -> None:
        self.keyboard = FakeKeyboard()
        self.fills: list[tuple[str, str]] = []
        self.clicks: list[str] = []
        self.navigations: list[str] = []
        self.js_calls: list[str] = []
        self.js_return: Any = None
        # Tests set `present_selectors` to a set of selector strings the
        # fake page should claim exist; detect_variant's probe goes through
        # _selector_present which prefers query_selector.
        self.present_selectors: set[str] = set()
        # assert_js evaluates scripts against this mapping if provided;
        # otherwise falls back to js_return.
        self.js_results_by_script: dict[str, Any] = {}
        self.url: str = "https://example.com/"
        self.html: str = "<html><body>fake</body></html>"
        self.screenshot_bytes: bytes = b"\x89PNG\r\n\x1a\nfake"

    async def goto(self, url: str, *, wait_until: str = "load") -> None:
        self.navigations.append(url)
        self.url = url

    async def fill(self, selector: str, value: str) -> None:
        self.fills.append((selector, value))

    async def click(self, selector: str) -> None:
        self.clicks.append(selector)

    async def evaluate(self, script: str) -> Any:
        self.js_calls.append(script)
        if script in self.js_results_by_script:
            return self.js_results_by_script[script]
        return self.js_return

    async def query_selector(self, selector: str) -> Any:
        return object() if selector in self.present_selectors else None

    async def content(self) -> str:
        return self.html

    async def screenshot(self) -> bytes:
        return self.screenshot_bytes

    async def inner_text(self, _selector: str) -> str:
        return "fake body text"


class FakeBrowserManager:
    def __init__(self, page: FakePage) -> None:
        self._page = page

    async def get_page(self, profile: str) -> FakePage:
        return self._page


def _seed_playbook(tmp_dir: Path, name: str, steps: list[dict[str, Any]]) -> None:
    payload = {
        "name": name,
        "start_url": "https://example.com/",
        "description": "test",
        "steps": steps,
        "created": "2026-01-01",
        "last_success": None,
        "success_count": 0,
        "fail_count": 0,
    }
    (tmp_dir / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture
def playbooks_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Route playbook storage + asyncio.sleep to tmp_path + no-op."""
    monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", tmp_path)
    monkeypatch.setattr(playbooks, "PLAYBOOK_RUNS_DIR", tmp_path / "runs")

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(playbooks.asyncio, "sleep", _no_sleep)
    return tmp_path


def _read_ledger(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(Path(result["ledger_path"]).read_text(encoding="utf-8"))


async def test_press_key_step_presses_configured_key(playbooks_tmp: Path) -> None:
    _seed_playbook(
        playbooks_tmp,
        "enter_only",
        [{"action": "press_key", "key": "Enter", "wait_after": 0}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("enter_only", FakeBrowserManager(page))

    assert result["success"] is True
    assert [k for k, _ in page.keyboard.pressed] == ["Enter"]


async def test_press_key_defaults_to_enter(playbooks_tmp: Path) -> None:
    _seed_playbook(playbooks_tmp, "default_key", [{"action": "press_key"}])
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("default_key", FakeBrowserManager(page))

    assert result["success"] is True
    assert [k for k, _ in page.keyboard.pressed] == ["Enter"]


async def test_fill_login_step_forwards_password_mode(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(
        playbooks_tmp,
        "kb_login",
        [{
            "action": "fill_login",
            "url": "https://example.com/",
            "password_mode": "keystroke",
        }],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    captured: dict[str, Any] = {}

    async def fake_fill_login(client, _page, url, **kwargs):
        captured.update(kwargs)
        captured["url"] = url
        return {"item_name": "stub", "password_mode": kwargs.get("password_mode")}

    monkeypatch.setattr(playbooks._credentials, "fill_login", fake_fill_login)

    result = await mgr.run_playbook(
        "kb_login", FakeBrowserManager(page), bw_client=object()
    )

    assert result["success"] is True
    assert captured["password_mode"] == "keystroke"
    assert captured["url"] == "https://example.com/"


async def test_fill_login_step_defaults_to_value_mode(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(
        playbooks_tmp,
        "default_login",
        [{"action": "fill_login", "url": "https://example.com/"}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    captured: dict[str, Any] = {}

    async def fake_fill_login(client, _page, url, **kwargs):
        captured.update(kwargs)
        return {"item_name": "stub", "password_mode": kwargs.get("password_mode")}

    monkeypatch.setattr(playbooks._credentials, "fill_login", fake_fill_login)

    await mgr.run_playbook(
        "default_login", FakeBrowserManager(page), bw_client=object()
    )
    assert captured["password_mode"] == "value"


async def test_run_js_step_forwards_script_and_captures_result(
    playbooks_tmp: Path,
) -> None:
    """``run_js`` step calls page.evaluate and stores the stringified
    result in results[] under type='js'."""
    script = "[...document.querySelectorAll('.balance')].map(e => e.innerText)"
    _seed_playbook(
        playbooks_tmp,
        "scrape_balances",
        [{"action": "run_js", "script": script, "description": "balances"}],
    )
    page = FakePage()
    page.js_return = ["$1,234.56", "$9,876.54"]
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("scrape_balances", FakeBrowserManager(page))

    assert result["success"] is True
    assert page.js_calls == [script]
    js_results = [r for r in result["results"] if r.get("type") == "js"]
    assert len(js_results) == 1
    assert js_results[0]["description"] == "balances"
    assert "$1,234.56" in js_results[0]["result"]


async def test_run_js_step_renders_none_as_ok_marker(playbooks_tmp: Path) -> None:
    """A JS expression with no return value renders as a stable marker
    string, not the Python literal 'None' — matches the standalone
    run_js MCP tool's semantics."""
    _seed_playbook(
        playbooks_tmp,
        "side_effect_only",
        [{"action": "run_js", "script": "document.body.click()"}],
    )
    page = FakePage()
    page.js_return = None
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("side_effect_only", FakeBrowserManager(page))
    assert result["success"] is True
    js_results = [r for r in result["results"] if r.get("type") == "js"]
    assert js_results[0]["result"] == "OK (no return value)"


async def test_run_js_step_rejects_empty_script(playbooks_tmp: Path) -> None:
    """Missing/empty script fails the step cleanly rather than calling
    page.evaluate('') (which some Playwright versions crash on)."""
    _seed_playbook(
        playbooks_tmp,
        "bad_js",
        [{"action": "run_js", "script": "   "}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("bad_js", FakeBrowserManager(page))
    assert result["success"] is False
    assert "non-empty 'script'" in str(result.get("error", ""))
    assert page.js_calls == []


async def test_successful_playbook_writes_run_ledger(
    playbooks_tmp: Path,
) -> None:
    _seed_playbook(
        playbooks_tmp,
        "ledger_ok",
        [{"action": "run_js", "script": "return 'ok'", "description": "probe"}],
    )
    page = FakePage()
    page.js_return = "ok"
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("ledger_ok", FakeBrowserManager(page))

    assert result["success"] is True
    assert result["run_id"]
    ledger_path = Path(result["ledger_path"])
    assert ledger_path.exists()
    ledger = _read_ledger(result)
    assert ledger["run_id"] == result["run_id"]
    assert ledger["name"] == "ledger_ok"
    assert ledger["start_url"] == "https://example.com/"
    assert ledger["profile"] == "example.com"
    assert ledger["success"] is True
    assert ledger["error"] is None
    assert ledger["failed_step"] is None
    assert ledger["failure_dump"] is None
    assert ledger["ledger_path"] == result["ledger_path"]
    assert mgr.get_run(result["run_id"]) == ledger

    trace = ledger["step_trace"]
    assert len(trace) == 1
    assert trace[0]["step"] == 0
    assert trace[0]["action"] == "run_js"
    assert trace[0]["status"] == "completed"
    assert trace[0]["url_before"] == "https://example.com/"
    assert trace[0]["url_after"] == "https://example.com/"
    assert trace[0]["result_type"] == "js"
    assert "ok" in trace[0]["result_summary"]


async def test_failing_playbook_writes_run_ledger_with_failure_details(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dump_root = tmp_path / "dumps"
    monkeypatch.setattr(playbooks, "FAILURE_DUMP_DIR", dump_root)
    _seed_playbook(
        playbooks_tmp,
        "ledger_fail",
        [{"action": "fail", "error": "intentional ledger failure"}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("ledger_fail", FakeBrowserManager(page))

    assert result["success"] is False
    assert result["run_id"]
    assert Path(result["ledger_path"]).exists()
    assert result["failed_step"] == 0
    assert result["failure_dump"] is not None

    ledger = _read_ledger(result)
    assert ledger["success"] is False
    assert "intentional ledger failure" in ledger["error"]
    assert ledger["failed_step"] == 0
    assert ledger["failure_dump"] == result["failure_dump"]
    assert ledger["step_trace"][0]["status"] == "failed"
    assert "intentional ledger failure" in ledger["step_trace"][0]["error"]


async def test_list_runs_filters_and_returns_newest_first(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(playbooks, "FAILURE_DUMP_DIR", tmp_path / "dumps")
    _seed_playbook(
        playbooks_tmp,
        "ledger_alpha",
        [{"action": "run_js", "script": "return 'alpha'"}],
    )
    _seed_playbook(
        playbooks_tmp,
        "ledger_beta",
        [{"action": "fail", "error": "beta failed"}],
    )
    page = FakePage()
    page.js_return = "ok"
    mgr = playbooks.PlaybookManager()

    alpha_old = await mgr.run_playbook("ledger_alpha", FakeBrowserManager(page))
    beta = await mgr.run_playbook("ledger_beta", FakeBrowserManager(page))
    alpha_new = await mgr.run_playbook("ledger_alpha", FakeBrowserManager(page))

    for result, started_at in [
        (alpha_old, "2026-01-01T00:00:00Z"),
        (beta, "2026-01-01T00:00:01Z"),
        (alpha_new, "2026-01-01T00:00:02Z"),
    ]:
        ledger = _read_ledger(result)
        ledger["started_at"] = started_at
        Path(result["ledger_path"]).write_text(
            json.dumps(ledger, indent=2), encoding="utf-8"
        )

    assert [r["run_id"] for r in mgr.list_runs(limit=10)] == [
        alpha_new["run_id"],
        beta["run_id"],
        alpha_old["run_id"],
    ]
    assert [r["run_id"] for r in mgr.list_runs(name="ledger_alpha", limit=10)] == [
        alpha_new["run_id"],
        alpha_old["run_id"],
    ]
    assert [r["run_id"] for r in mgr.list_runs(success=True, limit=10)] == [
        alpha_new["run_id"],
        alpha_old["run_id"],
    ]
    assert [r["run_id"] for r in mgr.list_runs(
        name="ledger_beta", success=False, limit=10
    )] == [beta["run_id"]]


async def test_list_runs_ignores_malformed_ledger_files(
    playbooks_tmp: Path,
) -> None:
    runs_dir = playbooks.PLAYBOOK_RUNS_DIR
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / "broken.json").write_text("{not-json", encoding="utf-8")
    (runs_dir / "array.json").write_text("[]", encoding="utf-8")
    _seed_playbook(
        playbooks_tmp,
        "ledger_survivor",
        [{"action": "run_js", "script": "return 'ok'"}],
    )
    page = FakePage()
    page.js_return = "ok"
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook("ledger_survivor", FakeBrowserManager(page))

    runs = mgr.list_runs(limit=10)
    assert [r["run_id"] for r in runs] == [result["run_id"]]
    assert mgr.get_run("broken") is None


# ---------------------------------------------------------------------------
# detect_variant / when_variant / assert_js branching
# ---------------------------------------------------------------------------

FIDELITY_FRESH_SEL = "#dom-username-input"
FIDELITY_REMEMBERED_SEL = (
    "[role=\"combobox\"], select[id*=\"username\" i], "
    "select[id*=\"rememberme\" i], "
    "[data-testid*=\"username\" i][aria-haspopup=\"listbox\"]"
)
FIDELITY_AUTH_CHECK = "POST_LOGIN_AUTH_CHECK"


def _fidelity_login_steps() -> list[dict[str, Any]]:
    """Mirror the production fidelity_login.json flow so the branching
    assertions stay locked to the shipping playbook structure."""
    return [
        {
            "action": "detect_variant",
            "variants": [
                {"name": "fresh", "selector": FIDELITY_FRESH_SEL},
                {"name": "remembered", "selector": FIDELITY_REMEMBERED_SEL},
            ],
            "fallback_error": "neither variant visible",
        },
        {
            "action": "when_variant",
            "name": "fresh",
            "steps": [
                {
                    "action": "fill_login",
                    "url": "https://digital.fidelity.com/prgw/digital/signin/retail",
                    "vault_item": "fidelity.com",
                    "username_selector": "#dom-username-input",
                    "password_selector": "#dom-pswd-input",
                    "password_mode": "keystroke",
                },
            ],
        },
        {
            "action": "when_variant",
            "name": "remembered",
            "steps": [
                {
                    "action": "assert_js",
                    "script": "SUFFIX_CHECK",
                    "expect": "truthy",
                    "error": "masked username suffix mismatch",
                },
                {
                    "action": "fill_login",
                    "url": "https://digital.fidelity.com/prgw/digital/signin/retail",
                    "vault_item": "fidelity.com",
                    "password_selector": "#dom-pswd-input",
                    "password_mode": "keystroke",
                    "skip_username": True,
                },
            ],
        },
        {
            "action": "run_js",
            "script": FIDELITY_AUTH_CHECK,
            "description": "post-login diagnostic",
        },
    ]


def _install_fake_fill_login(
    monkeypatch: pytest.MonkeyPatch, captured: list[dict[str, Any]]
) -> None:
    async def fake_fill_login(_client, _page, url, **kwargs):
        captured.append({"url": url, **kwargs})
        return {"item_name": "fidelity.com", **kwargs}

    monkeypatch.setattr(playbooks._credentials, "fill_login", fake_fill_login)


async def test_fidelity_login_shape_matches_production_playbook(
    playbooks_tmp: Path,
) -> None:
    """The shipping fidelity_login.json must keep the branching shape the
    runner expects — detect_variant first, then two when_variant blocks."""
    fidelity_path = (
        Path(playbooks.__file__).parent
        / "data"
        / "playbooks"
        / "fidelity_login.json"
    )
    data = json.loads(fidelity_path.read_text(encoding="utf-8"))
    steps = data["steps"]
    actions = [s.get("action") for s in steps]
    assert "detect_variant" in actions
    # Both fresh and remembered branches must exist.
    when_variant_names = [
        s.get("name") for s in steps if s.get("action") == "when_variant"
    ]
    assert "fresh" in when_variant_names
    assert "remembered" in when_variant_names
    # The remembered branch must assert_js before touching fill_login — we
    # never want to type a password into a stranger's combobox.
    remembered_branch = next(
        s for s in steps if s.get("action") == "when_variant"
        and s.get("name") == "remembered"
    )
    sub_actions = [s.get("action") for s in remembered_branch["steps"]]
    assert sub_actions.index("assert_js") < sub_actions.index("fill_login")
    # And the password-only fill must carry skip_username=True so the
    # credentials helper doesn't try to fill a non-existent text input.
    pw_step = next(
        s for s in remembered_branch["steps"] if s.get("action") == "fill_login"
    )
    assert pw_step.get("skip_username") is True
    extract_idx = actions.index("extract_text")
    post_login_diagnostics = [
        (idx, step)
        for idx, step in enumerate(steps)
        if step.get("action") == "run_js" and idx < extract_idx
    ]
    assert post_login_diagnostics
    diagnostic = post_login_diagnostics[-1][1]
    assert "incorrect username or password" in diagnostic["script"]
    assert "Post-login diagnostic" in diagnostic["description"]


async def test_detect_variant_fresh_runs_fresh_branch(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(playbooks_tmp, "fid", _fidelity_login_steps())
    page = FakePage()
    page.present_selectors = {FIDELITY_FRESH_SEL}
    page.js_results_by_script = {FIDELITY_AUTH_CHECK: True}
    captured: list[dict[str, Any]] = []
    _install_fake_fill_login(monkeypatch, captured)

    result = await mgr_run(page, "fid")

    assert result["success"] is True
    # Exactly one fill_login call, and it's the fresh branch (no
    # skip_username, has username_selector).
    assert len(captured) == 1
    assert captured[0].get("skip_username") is not True
    assert captured[0].get("username_selector") == "#dom-username-input"


async def test_detect_variant_remembered_runs_remembered_branch_when_suffix_matches(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(playbooks_tmp, "fid", _fidelity_login_steps())
    page = FakePage()
    page.present_selectors = {FIDELITY_REMEMBERED_SEL}
    # Suffix check returns truthy — mimic Fidelity's masked '******lar'.
    page.js_results_by_script = {
        "SUFFIX_CHECK": True,
        FIDELITY_AUTH_CHECK: True,
    }
    captured: list[dict[str, Any]] = []
    _install_fake_fill_login(monkeypatch, captured)

    result = await mgr_run(page, "fid")

    assert result["success"] is True
    # Exactly one fill_login, remembered branch (skip_username=True, no
    # username_selector passed).
    assert len(captured) == 1
    assert captured[0].get("skip_username") is True
    assert captured[0].get("password_selector") == "#dom-pswd-input"


async def test_fidelity_login_diagnostic_does_not_bail_on_recoverable_login_state(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(playbooks_tmp, "fid", _fidelity_login_steps())
    page = FakePage()
    page.present_selectors = {FIDELITY_FRESH_SEL}
    page.js_results_by_script = {FIDELITY_AUTH_CHECK: False}
    captured: list[dict[str, Any]] = []
    _install_fake_fill_login(monkeypatch, captured)

    result = await mgr_run(page, "fid")

    assert result["success"] is True
    assert {"step": 3, "type": "js", "description": "post-login diagnostic", "result": "False"} in result["results"]
    assert len(captured) == 1


async def test_detect_variant_remembered_bails_when_suffix_mismatches(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(playbooks_tmp, "fid", _fidelity_login_steps())
    page = FakePage()
    page.present_selectors = {FIDELITY_REMEMBERED_SEL}
    # Suffix check returns falsy — masked username is NOT ours.
    page.js_results_by_script = {"SUFFIX_CHECK": False}
    captured: list[dict[str, Any]] = []
    _install_fake_fill_login(monkeypatch, captured)

    result = await mgr_run(page, "fid")

    assert result["success"] is False
    assert "suffix mismatch" in str(result.get("error", ""))
    # Critically: no fill_login called, so no password was typed into a
    # stranger's box.
    assert captured == []


async def test_detect_variant_neither_selector_fails_with_fallback_error(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_playbook(playbooks_tmp, "fid", _fidelity_login_steps())
    page = FakePage()
    page.present_selectors = set()  # neither variant visible
    captured: list[dict[str, Any]] = []
    _install_fake_fill_login(monkeypatch, captured)

    result = await mgr_run(page, "fid")

    assert result["success"] is False
    assert "neither variant visible" in str(result.get("error", ""))
    assert captured == []


async def test_failure_dump_writes_html_and_screenshot(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Any step failure must drop HTML + screenshot + meta.json into
    FAILURE_DUMP_DIR so the next debug pass has ground-truth artefacts."""
    dump_root = tmp_path / "dumps"
    monkeypatch.setattr(playbooks, "FAILURE_DUMP_DIR", dump_root)

    _seed_playbook(
        playbooks_tmp,
        "dump_me",
        [{"action": "fail", "error": "intentional"}],
    )
    page = FakePage()
    page.html = "<html><body>captured</body></html>"
    page.screenshot_bytes = b"\x89PNGfake"

    result = await mgr_run(page, "dump_me")

    assert result["success"] is False
    dump = result["failure_dump"]
    assert dump is not None
    dump_dir = Path(dump["dir"])
    assert dump_dir.exists()
    assert (dump_dir / "page.html").read_text(encoding="utf-8") == page.html
    assert (dump_dir / "page.png").read_bytes() == page.screenshot_bytes
    meta = json.loads((dump_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["playbook"] == "dump_me"
    assert meta["action"] == "fail"


async def test_failure_dump_survives_screenshot_error(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If page.screenshot() itself raises during dump, the runner still
    returns a failure result (never mask the original step error)."""
    dump_root = tmp_path / "dumps"
    monkeypatch.setattr(playbooks, "FAILURE_DUMP_DIR", dump_root)

    _seed_playbook(
        playbooks_tmp,
        "dump_shot_err",
        [{"action": "fail", "error": "primary"}],
    )

    class ScreenshotBoomPage(FakePage):
        async def screenshot(self) -> bytes:
            raise RuntimeError("camoufox dead")

    page = ScreenshotBoomPage()

    result = await mgr_run(page, "dump_shot_err")

    assert result["success"] is False
    assert "primary" in str(result["error"])
    dump = result["failure_dump"]
    assert dump is not None
    # HTML still captured, screenshot error recorded on the meta record.
    assert "screenshot_error" in dump


async def mgr_run(page: FakePage, name: str) -> dict[str, Any]:
    mgr = playbooks.PlaybookManager()
    return await mgr.run_playbook(name, FakeBrowserManager(page), bw_client=object())


# ---------------------------------------------------------------------------
# {{var}} substitution — parameterised playbooks (fidelity trade ticket,
# Lyca autopay amount, wire-xfer recipient, etc.)
# ---------------------------------------------------------------------------


async def test_run_playbook_substitutes_vars_in_navigate_url(
    playbooks_tmp: Path,
) -> None:
    """``{{var}}`` in a navigate URL resolves before page.goto so a
    parameterised playbook can target /orders/<id>, /symbol/<sym>, etc."""
    _seed_playbook(
        playbooks_tmp,
        "nav_vars",
        [{"action": "navigate", "url": "https://example.com/orders/{{id}}"}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook(
        "nav_vars",
        FakeBrowserManager(page),
        variables={"id": "42"},
    )

    assert result["success"] is True
    assert page.navigations == ["https://example.com/orders/42"]


async def test_run_playbook_substitutes_vars_in_run_js_script(
    playbooks_tmp: Path,
) -> None:
    """Numbers embed as JS literals (``5`` not ``'5'``) and strings
    substitute as-is so template authors can quote them explicitly."""
    _seed_playbook(
        playbooks_tmp,
        "js_vars",
        [{
            "action": "run_js",
            "script": "return placeOrder({{qty}}, '{{symbol}}')",
        }],
    )
    page = FakePage()
    page.js_return = "ok"
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook(
        "js_vars",
        FakeBrowserManager(page),
        variables={"qty": 5, "symbol": "VTI"},
    )

    assert result["success"] is True
    assert page.js_calls == ["return placeOrder(5, 'VTI')"]


async def test_run_playbook_missing_var_fails_with_readable_error(
    playbooks_tmp: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Omitting a required var fails the owning step with a message that
    names the missing placeholder — callers can fix the invocation
    without reading the playbook source."""
    monkeypatch.setattr(playbooks, "FAILURE_DUMP_DIR", tmp_path / "dumps")
    _seed_playbook(
        playbooks_tmp,
        "missing_var",
        [{"action": "navigate", "url": "https://example.com/{{missing}}"}],
    )
    page = FakePage()
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook(
        "missing_var",
        FakeBrowserManager(page),
        variables={},
    )

    assert result["success"] is False
    err = str(result.get("error", ""))
    assert "{{missing}}" in err
    # navigate never fired because substitution failed before page.goto.
    assert page.navigations == []


async def test_run_playbook_substitutes_vars_inside_when_variant(
    playbooks_tmp: Path,
) -> None:
    """``when_variant`` sub-steps go through the same substitution pass
    so a branched playbook (fresh vs remembered login) can still use
    template variables in either branch."""
    steps = [
        {
            "action": "detect_variant",
            "variants": [{"name": "fresh", "selector": "#go"}],
        },
        {
            "action": "when_variant",
            "name": "fresh",
            "steps": [
                {"action": "run_js", "script": "pickSymbol('{{symbol}}')"},
            ],
        },
    ]
    _seed_playbook(playbooks_tmp, "branched_vars", steps)
    page = FakePage()
    page.present_selectors = {"#go"}
    page.js_return = "ok"
    mgr = playbooks.PlaybookManager()

    result = await mgr.run_playbook(
        "branched_vars",
        FakeBrowserManager(page),
        variables={"symbol": "VTI"},
    )

    assert result["success"] is True
    assert page.js_calls == ["pickSymbol('VTI')"]

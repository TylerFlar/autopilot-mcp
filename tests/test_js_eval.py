"""run_js accepts statement bodies, not just expressions.

Playwright evaluates a bare string as an expression, so `return ...` and
top-level `await` — the natural way to write anything past a one-liner —
failed outright. Those two errors were the largest single class of failed
autopilot calls in the 2026-08 transcript audit, all of them recoverable by
wrapping the body in an async IIFE.
"""

from __future__ import annotations

import pytest

import server


class FakePage:
    """Approximates Playwright's expression-only evaluate()."""

    def __init__(self, result: object = "ok") -> None:
        self.scripts: list[str] = []
        self.result = result

    async def evaluate(self, script: str) -> object:
        self.scripts.append(script)
        stripped = script.strip()
        wrapped = stripped.startswith(("(", "async", "function")) or "=>" in stripped
        if not wrapped:
            if "return" in stripped:
                raise RuntimeError(
                    "Page.evaluate: return not in function\n"
                    "evaluate@debugger eval code:1:30"
                )
            if "await" in stripped:
                raise RuntimeError(
                    "Page.evaluate: await is only valid in async functions, "
                    "async generators and modules"
                )
        return self.result


@pytest.mark.asyncio
async def test_statement_body_with_return_is_wrapped_up_front() -> None:
    page = FakePage(result="42")

    out = await server._eval_js(page, "const x = 42;\nreturn x;")

    assert out == "42"
    assert len(page.scripts) == 1, "should not need a failed attempt first"
    assert page.scripts[0].startswith("(async () =>")


@pytest.mark.asyncio
async def test_top_level_await_is_wrapped() -> None:
    page = FakePage(result="done")

    out = await server._eval_js(page, "await fetch('/x');\nreturn 'done';")

    assert out == "done"
    assert page.scripts[0].startswith("(async () =>")


@pytest.mark.asyncio
async def test_plain_expression_is_left_alone() -> None:
    page = FakePage(result="hello")

    out = await server._eval_js(page, "document.title")

    assert out == "hello"
    assert page.scripts == ["document.title"]


@pytest.mark.asyncio
async def test_existing_arrow_function_is_left_alone() -> None:
    page = FakePage(result="7")
    script = "() => { return 7 }"

    await server._eval_js(page, script)

    assert page.scripts == [script]


@pytest.mark.asyncio
async def test_unexpected_return_error_triggers_one_wrapped_retry() -> None:
    """`returnValue` has no word-boundary `return`, so the heuristic misses it
    and the retry has to carry the recovery."""
    page = FakePage(result="ok")

    class SneakyPage(FakePage):
        async def evaluate(self, script: str) -> object:
            self.scripts.append(script)
            if len(self.scripts) == 1:
                raise RuntimeError("Page.evaluate: Illegal return statement")
            return self.result

    page = SneakyPage()
    out = await server._eval_js(page, "document.querySelector('a').click()")

    assert out == "ok"
    assert len(page.scripts) == 2
    assert page.scripts[1].startswith("(async () =>")


@pytest.mark.asyncio
async def test_real_page_errors_are_not_retried() -> None:
    class BrokenPage(FakePage):
        async def evaluate(self, script: str) -> object:
            self.scripts.append(script)
            raise RuntimeError("Page.evaluate: document.getElementById(...) is null")

    page = BrokenPage()
    with pytest.raises(RuntimeError, match="is null"):
        await server._eval_js(page, "document.getElementById('x').value")

    assert len(page.scripts) == 1, "a genuine page error must not be retried"


@pytest.mark.asyncio
async def test_none_result_reports_no_return_value() -> None:
    assert await server._eval_js(FakePage(result=None), "void 0") == "OK (no return value)"


# --- press_key --------------------------------------------------------------


class KeyPage:
    url = "https://example.com/"

    def __init__(self) -> None:
        self.presses: list[tuple[str, str | None]] = []
        self.keyboard = self

    async def press(self, selector: str, key: str) -> None:  # page.press
        self.presses.append((key, selector))

    async def keyboard_press(self, key: str) -> None:
        self.presses.append((key, None))


@pytest.mark.asyncio
async def test_press_key_sends_a_real_key_to_the_focused_element(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = KeyPage()
    page.keyboard = type("KB", (), {"press": staticmethod(page.keyboard_press)})()

    out = await server._press_key(page, "Enter")

    assert page.presses == [("Enter", None)]
    assert "Enter" in out


@pytest.mark.asyncio
async def test_press_key_can_target_a_selector() -> None:
    page = KeyPage()

    await server._press_key(page, "Enter", "input[name=q]")

    assert page.presses == [("Enter", "input[name=q]")]


@pytest.mark.asyncio
async def test_press_key_requires_a_key() -> None:
    assert "Error" in await server._press_key(KeyPage(), "  ")

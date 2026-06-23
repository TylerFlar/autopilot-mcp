"""Playbook CRUD and runner — saved browser action sequences.

Playbook schema:
    name: str              file basename (unique)
    start_url: str         anchor URL; resolve_profile(start_url) picks the
                           browser profile the playbook runs in
    description: str       human summary
    steps: list[dict]      action sequence (see run_playbook)
    created, last_success, success_count, fail_count: bookkeeping
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import credentials as _credentials
from browser import resolve_profile

# Matches ``{{name}}`` / ``{{ name }}`` placeholders in playbook string
# leaves. Keys are restricted to identifier-shaped tokens so accidental
# JS literal braces (e.g. ``{{foo: 1}}`` as an object literal in a
# run_js script) don't get picked up as templates. Templates author
# intent is always explicit — a single identifier in double braces.
_VAR_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


def _substitute_vars(obj: Any, variables: dict[str, Any]) -> Any:
    """Recursively replace ``{{key}}`` placeholders in string leaves.

    Strings substitute as-is so ``"url": "{{base}}/x"`` produces clean
    URLs. Non-string var values (int, bool, list, dict) are JSON-
    serialised so they embed as valid JS literals inside ``run_js``
    scripts — ``pickQty({{qty}})`` with ``qty=5`` becomes
    ``pickQty(5)``, not ``pickQty('5')``. Raises ``KeyError`` on the
    first missing key so the step-runner can wrap it in a readable
    ``_PlaybookStepError`` tied to the offending step index.
    """
    if isinstance(obj, str):
        def _replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in variables:
                raise KeyError(key)
            value = variables[key]
            return value if isinstance(value, str) else json.dumps(value)
        return _VAR_PATTERN.sub(_replace, obj)
    if isinstance(obj, dict):
        return {k: _substitute_vars(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_vars(v, variables) for v in obj]
    return obj

PLAYBOOKS_DIR = Path(__file__).parent / "data" / "playbooks"
# Where to dump full HTML + screenshot when a playbook step raises. Keyed by
# timestamp + playbook name so concurrent failures don't collide and every
# dump survives long enough for a human (or a subsequent LLM pass) to
# reverse-engineer what the page was actually rendering at failure time.
FAILURE_DUMP_DIR = Path(__file__).parent / "data" / "autopilot-failures"
PLAYBOOK_RUNS_DIR = Path(__file__).parent / "data" / "playbook-runs"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).isoformat().replace("+00:00", "Z")


def _new_run_id(started_at: datetime) -> str:
    ts = started_at.strftime("%Y%m%dT%H%M%S%fZ")
    return f"{ts}-{uuid.uuid4().hex[:8]}"


def _page_url(page: Any) -> str | None:
    try:
        url = page.url
        return str(url) if url is not None else None
    except Exception:
        return None


def _summarize_result(result: dict[str, Any]) -> tuple[str | None, str | None]:
    result_type = result.get("type")
    if not result_type:
        return None, None

    if result_type == "screenshot":
        data = result.get("data") or ""
        return "screenshot", f"base64_png_chars={len(str(data))}"

    if result_type == "text":
        text = str(result.get("text", ""))
        description = result.get("description") or ""
        prefix = f"{description}: " if description else ""
        return "text", f"{prefix}{text[:500]}"

    if result_type == "js":
        rendered = str(result.get("result", ""))
        description = result.get("description") or ""
        prefix = f"{description}: " if description else ""
        return "js", f"{prefix}{rendered[:500]}"

    if result_type in {"login", "warning", "variant", "assert"}:
        text = str(result.get("text", ""))
        return str(result_type), text[:500]

    return str(result_type), None


class _PlaybookStepError(Exception):
    """Internal wrapper: attaches the offending step index + action so the
    top-level run_playbook handler can both update bookkeeping AND dump
    screenshot/HTML against the page the failure occurred on, regardless
    of how deeply nested the step was (e.g. inside `when_variant`)."""

    def __init__(self, index: int, action: str, original: Exception) -> None:
        super().__init__(f"step {index} ({action}): {original}")
        self.index = index
        self.action = action
        self.original = original


async def _selector_present(page: Any, selector: str) -> bool:
    """True if `selector` currently matches an element in the DOM.

    Prefers Playwright's ``query_selector`` (cheap, no wait) so the branch
    probe doesn't stall for the default action timeout when a variant is
    absent. Falls back to ``is_visible`` if the page object is a stub that
    only implements the latter (used by the unit-test fakes).
    """
    try:
        qs = getattr(page, "query_selector", None)
        if qs is not None:
            handle = await qs(selector)
            return handle is not None
        is_visible = getattr(page, "is_visible", None)
        if is_visible is not None:
            return bool(await is_visible(selector))
    except Exception:
        return False
    return False


class PlaybookManager:
    def __init__(self):
        PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            PLAYBOOK_RUNS_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Ledger creation is telemetry only; individual writes are also
            # best-effort so playbook execution remains the primary outcome.
            pass

    def _run_path(self, run_id: str) -> Path | None:
        if not run_id or Path(run_id).name != run_id:
            return None
        return PLAYBOOK_RUNS_DIR / f"{run_id}.json"

    def _write_run_ledger(self, record: dict[str, Any]) -> str:
        run_id = str(record.get("run_id", ""))
        path = self._run_path(run_id)
        if path is None:
            return ""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_name(f"{path.name}.tmp")
            tmp_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            tmp_path.replace(path)
        except Exception:
            pass
        return str(path)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        path = self._run_path(run_id)
        if path is None or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return data if isinstance(data, dict) else None

    def list_runs(
        self,
        name: str | None = None,
        success: bool | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        try:
            max_items = max(0, int(limit))
        except (TypeError, ValueError):
            max_items = 20

        runs: list[dict[str, Any]] = []
        try:
            files = list(PLAYBOOK_RUNS_DIR.glob("*.json"))
        except OSError:
            return []

        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(data, dict):
                continue
            if name is not None and data.get("name") != name:
                continue
            if success is not None and data.get("success") is not success:
                continue
            runs.append(data)

        runs.sort(
            key=lambda run: (
                str(run.get("started_at") or ""),
                str(run.get("run_id") or ""),
            ),
            reverse=True,
        )
        return runs[:max_items]

    def list_playbooks(self, url_match: str | None = None) -> list[dict[str, Any]]:
        """List all playbooks, optionally filtered by substring of start_url."""
        playbooks: list[dict[str, Any]] = []
        for f in PLAYBOOKS_DIR.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                start_url = data.get("start_url", "")
                if url_match and url_match not in start_url:
                    continue
                playbooks.append({
                    "name": data.get("name", f.stem),
                    "start_url": start_url,
                    "description": data.get("description", ""),
                    "steps": len(data.get("steps", [])),
                    "success_count": data.get("success_count", 0),
                    "fail_count": data.get("fail_count", 0),
                    "last_success": data.get("last_success"),
                })
            except (json.JSONDecodeError, OSError):
                continue
        return playbooks

    def get_playbook(self, name: str) -> dict[str, Any] | None:
        path = PLAYBOOKS_DIR / f"{name}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_playbook(
        self, name: str, start_url: str, description: str, steps: list[dict[str, Any]]
    ) -> str:
        path = PLAYBOOKS_DIR / f"{name}.json"
        existing: dict[str, Any] | None = None
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        data: dict[str, Any] = {
            "name": name,
            "start_url": start_url,
            "description": description,
            "steps": steps,
            "created": (
                existing.get("created", str(date.today())) if existing else str(date.today())
            ),
            "last_success": existing.get("last_success") if existing else None,
            "success_count": existing.get("success_count", 0) if existing else 0,
            "fail_count": existing.get("fail_count", 0) if existing else 0,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return f"Playbook '{name}' saved ({len(steps)} steps)"

    def delete_playbook(self, name: str) -> str:
        path = PLAYBOOKS_DIR / f"{name}.json"
        if not path.exists():
            return f"Playbook '{name}' not found"
        path.unlink()
        return f"Playbook '{name}' deleted"

    async def run_playbook(
        self,
        name: str,
        browser_manager,
        *,
        bw_client: _credentials.BitwardenClient | None = None,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a playbook against the profile derived from `start_url`.

        ``variables`` supplies values for ``{{key}}`` placeholders inside
        any string leaf of any step (URL, run_js script, selector,
        fill value, assertion error). Strings substitute literally;
        non-string values JSON-serialise so they embed as valid JS
        literals. A missing key fails the step with a readable error
        AND still triggers the standard HTML + screenshot failure dump.

        Step types:
            navigate:     {"action": "navigate", "url": "..."}
            click:        {"action": "click", "x": int, "y": int}
            type:         {"action": "type", "text": "..."}
            press_key:    {"action": "press_key", "key": "Enter",
                           "wait_after"?: float}
            scroll:       {"action": "scroll", "direction": "up"|"down"}
            wait:         {"action": "wait", "seconds": int}
            screenshot:   {"action": "screenshot"}
            extract_text: {"action": "extract_text", "description": "..."}
            run_js:       {"action": "run_js", "script": "...",
                           "description"?: "..."}
                           # page.evaluate() — stringified result appears
                           # in results[] under type="js". Use for
                           # selector-based scraping, form-fill escapes
                           # that need targeted DOM interaction, and any
                           # step where coordinate click/type is too
                           # fragile. Matches the standalone run_js MCP
                           # tool's semantics.
            fill_login:   {"action": "fill_login", "url": "...",
                           "vault_item"?: "...",
                           "username_selector"?: "...",
                           "password_selector"?: "...",
                           "password_mode"?: "value"|"keystroke",
                           "skip_username"?: bool}
                           # skip_username=true fills only the password —
                           # for remembered-username pages where the
                           # username is pre-populated in a combobox and
                           # the text-input selector is absent. Verify the
                           # pre-filled username with an `assert_js` step
                           # BEFORE this fill to avoid typing a password
                           # into a stranger's account.
            detect_variant:
                          {"action": "detect_variant",
                           "variants": [
                               {"name": "fresh",      "selector": "#x"},
                               {"name": "remembered", "selector": "#y"},
                           ],
                           "fallback_error"?: "..."}
                           # Probe each selector in order (first match wins)
                           # and stash the matching variant name on the
                           # runner. Subsequent `when_variant` steps
                           # dispatch on this value. If no selector
                           # matches, the step raises with
                           # `fallback_error` (or a generic message) so
                           # the failure-dump path captures the unfamiliar
                           # page layout for later triage.
            when_variant: {"action": "when_variant", "name": "fresh",
                           "steps": [...sub-steps...]}
                           # Execute the sub-steps only if the last
                           # detect_variant matched `name`. Single layer —
                           # do not nest when_variant inside when_variant.
            assert_js:    {"action": "assert_js", "script": "...",
                           "expect"?: "truthy"|"falsy",
                           "error"?: "..."}
                           # Evaluate `script`; fail the playbook with
                           # `error` (or a default) if the result isn't
                           # truthy/falsy as declared. Use to verify a
                           # remembered-username suffix before typing a
                           # password into a stranger's box, or any other
                           # cheap sanity check that should abort the run.
            fail:         {"action": "fail", "error": "..."}
                           # Unconditional bail with a human-readable
                           # error. Useful as the fall-through branch when
                           # all known variants are absent.
        """
        run_started = _utc_now()
        run_id = _new_run_id(run_started)
        ledger_path = str(PLAYBOOK_RUNS_DIR / f"{run_id}.json")
        results: list[dict[str, Any]] = []
        step_trace: list[dict[str, Any]] = []
        start_url: str | None = None
        profile: str | None = None

        def _finish(
            *,
            success: bool,
            error: str | None = None,
            failed_step: int | None = None,
            failure_dump: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            record: dict[str, Any] = {
                "run_id": run_id,
                "name": name,
                "start_url": start_url,
                "profile": profile,
                "started_at": _utc_iso(run_started),
                "ended_at": _utc_iso(),
                "success": success,
                "error": error,
                "failed_step": failed_step,
                "failure_dump": failure_dump,
                "step_trace": step_trace,
                "ledger_path": ledger_path,
            }
            self._write_run_ledger(record)

            payload: dict[str, Any] = {
                "success": success,
                "results": results,
                "run_id": run_id,
                "ledger_path": ledger_path,
            }
            if error is not None:
                payload["error"] = error
            if failed_step is not None:
                payload["failed_step"] = failed_step
            if failure_dump is not None or not success:
                payload["failure_dump"] = failure_dump
            return payload

        try:
            playbook = self.get_playbook(name)
        except Exception as read_err:
            return _finish(
                success=False,
                error=f"Unable to read playbook '{name}': {read_err}",
            )
        if not playbook:
            return _finish(success=False, error=f"Playbook '{name}' not found")

        start_url = playbook.get("start_url")
        if not start_url:
            return _finish(
                success=False,
                error=f"Playbook '{name}' has no start_url",
            )

        try:
            steps = playbook["steps"]
        except Exception as steps_err:
            return _finish(
                success=False,
                error=f"Playbook '{name}' has invalid steps: {steps_err}",
            )
        if not isinstance(steps, list):
            return _finish(
                success=False,
                error=f"Playbook '{name}' has invalid steps: expected a list",
            )
        state: dict[str, Any] = {"variant": None}

        try:
            profile = resolve_profile(start_url)
            page = await browser_manager.get_page(profile)
            await self._run_steps(
                steps, page, name, results, state, bw_client, start_url,
                trace=step_trace, variables=variables,
            )
        except _PlaybookStepError as step_err:
            self._update_count(name, success=False)
            dump = await self._dump_failure(
                page, name, step_err.index, step_err.action, step_err.original
            )
            return _finish(
                success=False,
                error=(
                    f"Step {step_err.index} ({step_err.action}) failed: "
                    f"{step_err.original}"
                ),
                failed_step=step_err.index,
                failure_dump=dump,
            )
        except Exception as setup_err:
            self._update_count(name, success=False)
            return _finish(success=False, error=str(setup_err))

        self._update_count(name, success=True)
        return _finish(success=True)

    async def _run_steps(
        self,
        steps: list[dict[str, Any]],
        page: Any,
        playbook_name: str,
        results: list[dict[str, Any]],
        state: dict[str, Any],
        bw_client: _credentials.BitwardenClient | None,
        start_url: str,
        trace: list[dict[str, Any]] | None = None,
        variables: dict[str, Any] | None = None,
    ) -> None:
        """Execute a list of steps against the already-resolved page.

        Recurses into `when_variant` sub-step lists so a single conditional
        dispatch reads top-to-bottom — the alternative (flattening + a
        skip-cursor) makes the JSON playbook harder to author. On any step
        failure, raises _PlaybookStepError so the top-level caller can both
        update success/fail counts AND capture a screenshot + HTML dump
        against the same `page` the failure occurred on.
        """
        for i, raw_step in enumerate(steps):
            action = raw_step.get("action") if isinstance(raw_step, dict) else None
            trace_item: dict[str, Any] = {
                "step": i,
                "action": str(action),
                "started_at": _utc_iso(),
                "url_before": _page_url(page),
            }
            if trace is not None:
                trace.append(trace_item)

            result_count_before = len(results)
            try:
                if not isinstance(raw_step, dict):
                    raise TypeError("playbook step must be an object")

                step = raw_step
                if variables is not None:
                    try:
                        step = _substitute_vars(step, variables)
                    except KeyError as key_err:
                        raise RuntimeError(
                            f"playbook var not provided: "
                            f"{{{{{key_err.args[0]}}}}}"
                        ) from key_err

                action = step.get("action")
                trace_item["action"] = str(action)

                if action == "navigate":
                    url = step.get("url", start_url)
                    await page.goto(url, wait_until="domcontentloaded")
                    await asyncio.sleep(2)

                elif action == "click":
                    x, y = step["x"], step["y"]
                    await page.mouse.click(x, y)
                    await asyncio.sleep(1)

                elif action == "type":
                    await page.keyboard.type(step["text"])

                elif action == "press_key":
                    key = step.get("key", "Enter")
                    await page.keyboard.press(key)
                    await asyncio.sleep(float(step.get("wait_after", 0.5)))

                elif action == "scroll":
                    direction = step.get("direction", "down")
                    delta = -500 if direction == "up" else 500
                    await page.mouse.wheel(0, delta)
                    await asyncio.sleep(0.5)

                elif action == "wait":
                    await asyncio.sleep(step.get("seconds", 2))

                elif action == "screenshot":
                    b64 = base64.b64encode(await page.screenshot()).decode("utf-8")
                    results.append({"step": i, "type": "screenshot", "data": b64})

                elif action == "extract_text":
                    text = await page.inner_text("body")
                    results.append({
                        "step": i,
                        "type": "text",
                        "description": step.get("description", ""),
                        "text": text[:10000],
                    })

                elif action == "run_js":
                    script = step.get("script")
                    if not isinstance(script, str) or not script.strip():
                        raise ValueError("run_js step requires a non-empty 'script' string")
                    js_result = await page.evaluate(script)
                    # Stringify so the JSON serialisation in the caller's
                    # result dict never blows up on an exotic return type
                    # (DOM element refs, functions, etc.). Matches the
                    # standalone run_js MCP tool's return shape.
                    rendered = "OK (no return value)" if js_result is None else str(js_result)
                    results.append({
                        "step": i,
                        "type": "js",
                        "description": step.get("description", ""),
                        "result": rendered[:10000],
                    })

                elif action == "fill_login":
                    if bw_client is None:
                        raise RuntimeError(
                            "fill_login step requires bw_client; "
                            "pass it to PlaybookManager.run_playbook"
                        )
                    fill_result = await _credentials.fill_login(
                        bw_client,
                        page,
                        step.get("url", start_url),
                        username_selector=step.get("username_selector"),
                        password_selector=step.get("password_selector"),
                        vault_item=step.get("vault_item"),
                        password_mode=step.get("password_mode", "value"),
                        skip_username=bool(step.get("skip_username", False)),
                    )
                    results.append({
                        "step": i,
                        "type": "login",
                        "text": f"filled {fill_result.get('item_name')}",
                    })

                elif action == "detect_variant":
                    variants = step.get("variants") or []
                    if not isinstance(variants, list) or not variants:
                        raise ValueError(
                            "detect_variant requires a non-empty 'variants' list"
                        )
                    matched: str | None = None
                    for v in variants:
                        sel = v.get("selector")
                        vname = v.get("name")
                        if not sel or not vname:
                            continue
                        if await _selector_present(page, sel):
                            matched = vname
                            break
                    if matched is None:
                        raise RuntimeError(
                            step.get("fallback_error")
                            or (
                                "detect_variant: none of the expected "
                                f"selectors matched (tried "
                                f"{[v.get('name') for v in variants]})"
                            )
                        )
                    state["variant"] = matched
                    results.append({
                        "step": i,
                        "type": "variant",
                        "text": f"detected variant: {matched}",
                    })

                elif action == "when_variant":
                    target = step.get("name")
                    if state.get("variant") == target:
                        sub_steps = step.get("steps") or []
                        await self._run_steps(
                            sub_steps,
                            page,
                            playbook_name,
                            results,
                            state,
                            bw_client,
                            start_url,
                            trace=trace,
                            variables=variables,
                        )
                    else:
                        trace_item["result_type"] = "variant"
                        trace_item["result_summary"] = (
                            f"skipped branch {target!r}; "
                            f"current variant={state.get('variant')!r}"
                        )

                elif action == "assert_js":
                    script = step.get("script")
                    if not isinstance(script, str) or not script.strip():
                        raise ValueError(
                            "assert_js step requires a non-empty 'script' string"
                        )
                    expect = step.get("expect", "truthy")
                    js_result = await page.evaluate(script)
                    truthy = bool(js_result)
                    ok = truthy if expect == "truthy" else not truthy
                    if not ok:
                        raise RuntimeError(
                            step.get("error")
                            or (
                                "assert_js failed — expected "
                                f"{expect}, got {js_result!r}"
                            )
                        )
                    results.append({
                        "step": i,
                        "type": "assert",
                        "text": f"assert_js ok (expect={expect})",
                    })

                elif action == "fail":
                    raise RuntimeError(
                        step.get("error") or "playbook fail step reached"
                    )

                else:
                    results.append({
                        "step": i,
                        "type": "warning",
                        "text": f"Unknown action: {action}",
                    })

            except _PlaybookStepError as nested:
                # Already wrapped by a nested _run_steps call — propagate
                # unchanged so the original step index/action bubble up.
                trace_item["status"] = "failed"
                trace_item["error"] = str(nested)
                raise
            except Exception as e:
                trace_item["status"] = "failed"
                trace_item["error"] = str(e)
                raise _PlaybookStepError(
                    index=i, action=str(action), original=e
                ) from e
            else:
                trace_item["status"] = "completed"
                new_results = results[result_count_before:]
                if new_results and "result_type" not in trace_item:
                    result_type, result_summary = _summarize_result(new_results[-1])
                    if result_type:
                        trace_item["result_type"] = result_type
                    if result_summary:
                        trace_item["result_summary"] = result_summary
            finally:
                trace_item["ended_at"] = _utc_iso()
                trace_item["url_after"] = _page_url(page)

    async def _dump_failure(
        self,
        page: Any,
        playbook_name: str,
        step_index: int,
        action: str,
        error: Exception,
    ) -> dict[str, Any] | None:
        """Persist a screenshot + HTML snapshot for any failed playbook run.

        Returns a dict describing what was dumped (paths, size hints) so the
        caller can surface it in the playbook result payload. Never raises —
        a dump failure must not mask the original step error.
        """
        try:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_name = "".join(
                c if c.isalnum() or c in ("-", "_") else "_" for c in playbook_name
            )
            out_dir = FAILURE_DUMP_DIR / f"{ts}-{safe_name}"
            out_dir.mkdir(parents=True, exist_ok=True)

            info: dict[str, Any] = {
                "dir": str(out_dir),
                "playbook": playbook_name,
                "step": step_index,
                "action": action,
                "error": str(error),
                "ts": ts,
            }

            try:
                url = page.url
                if not isinstance(url, str):
                    url = str(url)
                info["url"] = url
            except Exception:
                pass

            try:
                html = await page.content()
                (out_dir / "page.html").write_text(html, encoding="utf-8")
                info["html_bytes"] = len(html)
            except Exception as html_err:
                info["html_error"] = str(html_err)

            try:
                png = await page.screenshot()
                (out_dir / "page.png").write_bytes(png)
                info["screenshot_bytes"] = len(png)
            except Exception as shot_err:
                info["screenshot_error"] = str(shot_err)

            (out_dir / "meta.json").write_text(
                json.dumps(info, indent=2), encoding="utf-8"
            )
            return info
        except Exception:
            # Never mask the real failure — dump is best-effort telemetry.
            return None

    def _update_count(self, name: str, success: bool):
        path = PLAYBOOKS_DIR / f"{name}.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if success:
                data["success_count"] = data.get("success_count", 0) + 1
                data["last_success"] = str(date.today())
            else:
                data["fail_count"] = data.get("fail_count", 0) + 1
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except (json.JSONDecodeError, OSError):
            pass

# @tasque/autopilot-mcp

Free-roam browser automation MCP with learned playbooks and Bitwarden-backed
credentials. The calling LLM drives a Camoufox browser via screenshot + click
+ type + JS, fills logins without ever seeing the password, and caches
successful step sequences as "playbooks" for 1-call replay.

> **Why** — Hardcoded CSS selectors break every site update; per-site env-var
> credentials break every new site. This MCP exposes generic browser tools
> that work on any URL, and pulls credentials from your Bitwarden vault so
> passwords never enter the LLM's context.

## Tools

### Browser (free-roam)

Each registrable domain (eTLD+1) gets its own persistent browser profile
under `data/profiles/<profile>/`. `navigate(url)` auto-derives the profile
from the URL; everything else takes `profile` explicitly.

| Tool | Description |
|------|-------------|
| `navigate` | Open a URL. Auto-derives profile from eTLD+1 (overridable). Returns visible text. |
| `screenshot` | PNG screenshot of the profile's current page. |
| `get_text` | Visible text only — cheaper than a screenshot. |
| `get_url` | Current URL for the profile. |
| `run_js` | **Preferred** for form fills / button clicks. Selector-based. |
| `click` | Click at (x, y). Use when run_js can't target the element. |
| `type_text` | Type into the focused element. |
| `attach_file` | Attach a local file to a `<input type="file">` (incl. hidden inputs). |
| `scroll` | Scroll up or down. |

For parallel workers that need the same site/profile, use isolated browser
instances instead of the legacy shared-profile tools:

| Tool | Description |
|------|-------------|
| `spawn_instance` | Clone a base profile into a temporary isolated browser profile and open a URL. Returns `instance_id`. |
| `list_instances` | List live spawned instances and TTLs. |
| `close_instance` | Close an instance and delete its temporary profile. |
| `instance_navigate` / `instance_screenshot` / `instance_get_text` / `instance_get_url` | Browser navigation/inspection scoped to one `instance_id`. |
| `instance_run_js` / `instance_click` / `instance_type_text` / `instance_scroll` | Page interaction scoped to one `instance_id`. |
| `instance_attach_file` / `instance_fill_login` | Upload/login helpers scoped to one `instance_id`. |

Example: `spawn_instance(url="https://accounts.google.com/...", clone_from_profile="google.com")`
lets each Gmail cleanup branch use its own cloned Google session. Always call
`close_instance(instance_id)` when the branch is finished; timed-out instances
are also cleaned up automatically.

### Credentials (Bitwarden, fill-don't-reveal)

| Tool | Description |
|------|-------------|
| `list_logins` | Search the vault. Returns id/name/urls/username — **never passwords**. |
| `fill_login` | Inject creds from Bitwarden straight into form fields. Password never returns. |
| `get_totp` | Current 6-digit TOTP from Bitwarden (single source of truth). |
| `create_login` | New vault entry. Refuses name collision. |
| `update_login` | Patch fields on an existing entry. |
| `upsert_login` | Create-or-update by (url, username). The signup convenience path. |
| `delete_login` | Send to Bitwarden trash. Requires `confirm=True`. |
| `reveal_credentials` | ESCAPE HATCH — returns plaintext. Requires `reason`, audited. |

### Local file server (uploads)

For sites that ask the user to upload a local file. Two paths:

1. **Standard `<input type="file">`** — use `attach_file(profile, selector,
   path)`. Works even when the input is hidden inside a custom dropzone
   widget; target the input itself, not the visible drop area.
2. **Pure-JS uploader (no real input element)** — use the local CORS file
   server below. The MCP publishes the file at an unguessable URL on
   `127.0.0.1`; the LLM uses `run_js` to `fetch()` it inside the page,
   wrap the Blob in a `File`, and dispatch a synthetic `drop` event (or
   set it on a hidden input via `DataTransfer`).

| Tool | Description |
|------|-------------|
| `serve_local_file` | Publish a local file at `http://127.0.0.1:<port>/file/<token>` with CORS. Returns url, token, content_type, size, expires_at. TTL default 30 min. |
| `list_served_files` | List currently-published files. |
| `unserve_local_file` | Revoke a token immediately. |

Security envelope: server binds 127.0.0.1 only; tokens are uuid4 hex (122
bits of entropy); one token = one file path (no directory traversal); idle
entries reaped on every request. Override the bind via
`AUTOPILOT_FILE_SERVER_HOST` / `AUTOPILOT_FILE_SERVER_PORT` env vars.

### Playbooks

| Tool | Description |
|------|-------------|
| `list_playbooks` | List saved playbooks (filter by `start_url` substring). |
| `run_playbook` | Execute a playbook. Returns screenshots/text from observation steps. |
| `save_playbook` | Save a step sequence. **Call after a successful task.** |
| `delete_playbook` | Remove a broken playbook. |

## Workflow

1. `list_playbooks(url_match)` — is there already a playbook for this task?
2. `run_playbook(name)` — if yes, run it. Done.
3. Otherwise: `navigate(url)` → `screenshot` / `get_text` → `run_js` / `click` / `type_text`.
4. On a login page: `fill_login(url)` — Bitwarden injects creds directly. If the form needs 2FA: `get_totp(vault_item)` then `type_text(profile, code)`.
5. For SMS 2FA: `navigate("https://messages.google.com/web/")` and read the code from Google Messages.
6. After the task succeeds, `save_playbook(...)` so next time is one call.
7. Just signed up somewhere new? `upsert_login(url, username, password)` stores it and Bitwarden sync pushes to your other devices.

## Credentials setup

The MCP unlocks Bitwarden via a master password stashed in the OS keyring
(DPAPI on Windows). See [`docs/bw_setup.md`](docs/bw_setup.md) for the
one-time setup: install `bw`, `bw login`, `keyring.set_password`, smoke-test.

Subsequent MCP starts call the keyring, `bw unlock --raw`, and cache the
session token in RAM only. Idle-expires after 15 minutes; re-locks on
shutdown. Master password never hits disk outside the OS keyring.

## Initial browser session setup

Each profile gets one persistent browser profile the first time it's opened.
For sites where you want the session pre-established (to handle 2FA challenges
/ "remember me" outside the MCP flow):

```bash
uv run python scripts/manual_login.py <url>
```

A visible Camoufox window opens at the URL. Log in, complete 2FA, check
"remember me", close the window. The profile at `data/profiles/<eTLD+1>/`
persists across headless MCP invocations.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HEADLESS` | No | `"false"` to show the browser for debugging (default: `true`) |
| `BROWSER_TIMEOUT` | No | Page timeout in ms (default: `30000`) |
| `TASQUE_LOG_JSON` | No | `"true"` for JSON log output; else human-readable console |
| `TASQUE_LOG_LEVEL` | No | Log level for the `autopilot.credentials` audit logger (default: `INFO`) |
| `AUTOPILOT_FILE_SERVER_HOST` | No | Bind interface for the local file server (default: `127.0.0.1`) |
| `AUTOPILOT_FILE_SERVER_PORT` | No | Bind port for the local file server (default: `0` = ephemeral) |

Per-site username/password env vars are **no longer used** — everything goes
through Bitwarden.

## Development

```bash
uv sync --extra dev
uv run camoufox fetch
uv run ruff check .
uv run pytest
uv run python server.py    # stdio mode
```

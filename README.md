# autopilot-mcp

A browser-automation [MCP](https://modelcontextprotocol.io) server. It hands an
LLM a generic set of browser tools — navigate, screenshot, read text, run JS,
click, type — that work on any URL, with each site backed by its own persistent
[Camoufox](https://github.com/daijro/camoufox) browser profile. Logins are
filled straight from a [Bitwarden](https://bitwarden.com) vault so passwords
never enter the model's context, and any sequence of steps that works can be
saved as a "playbook" for one-call replay next time.

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

For parallel work on the same site, use isolated browser **instances** — each
clones the site's base profile so concurrent sessions don't collide:

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
| `playbook_run_list` | List run-ledger entries (one record per execution), newest first; filter by name/success. |
| `playbook_run_get` | Fetch one run ledger's full JSON by `run_id`. |

## Workflow

1. `list_playbooks(url_match)` — is there already a playbook for this task?
2. `run_playbook(name)` — if yes, run it. Done.
3. Otherwise: `navigate(url)` → `screenshot` / `get_text` → `run_js` / `click` / `type_text`.
4. On a login page: `fill_login(url)` — Bitwarden injects creds directly. If the form needs 2FA: `get_totp(vault_item)` then `type_text(profile, code)`.
5. For SMS 2FA: `navigate("https://messages.google.com/web/")` and read the code from Google Messages.
6. After the task succeeds, `save_playbook(...)` so next time is one call.
7. Just signed up somewhere new? `upsert_login(url, username, password)` stores it and Bitwarden sync pushes to your other devices.

## Credentials setup (Bitwarden)

The MCP unlocks Bitwarden with a master password stashed in the OS keyring
(DPAPI-encrypted on Windows, scoped to your user). On each start it pulls the
master password from the keyring, runs `bw unlock --raw`, and caches the
session token in RAM only — idle-expires after 15 minutes, re-locks on
shutdown. The master password never lands on disk outside the OS keyring, and
never enters the model's context.

One-time setup for a fresh machine, top to bottom:

### 1. Install the Bitwarden CLI

```powershell
winget install --id Bitwarden.CLI --accept-source-agreements --accept-package-agreements
```

winget puts `bw.exe` on PATH via a shim — **open a new shell** afterward so the
update takes effect. (No winget? `npm install -g @bitwarden/cli`, or grab a
binary from <https://bitwarden.com/download/>.) Verify:

```bash
bw --version   # e.g. 2026.3.0
bw status      # {"status":"unauthenticated", ...}
```

### 2. Log in

Interactive — only your terminal sees the master password.

```bash
bw login
```

Prompts for email, master password, and a two-step token. On success
`bw status` reports `"status":"locked"` — leave it locked; the MCP unlocks on
demand.

### 3. Stash the master password in the OS keyring

Keep it out of `.env` and off the command line. After `uv sync`, stash it at
the hidden prompt:

```bash
uv run python -c "import keyring, getpass; keyring.set_password('autopilot-mcp', 'bw_master', getpass.getpass('Master password: ')); print('stored')"
```

This writes to service `autopilot-mcp`, username `bw_master`. Confirm without
printing the value:

```bash
uv run python -c "import keyring; v = keyring.get_password('autopilot-mcp', 'bw_master'); print(f'present={v is not None} length={len(v) if v else 0} backend={keyring.get_keyring().__class__.__name__}')"
# present=True length=<your pw length> backend=WinVaultKeyring
```

### 4. Smoke-test the unlock loop

Runs the real path — keyring read, `bw unlock`, list, lock — without printing
the password:

```bash
uv run python -c "
import json, os, subprocess, keyring
pw = keyring.get_password('autopilot-mcp', 'bw_master')
assert pw, 'keyring empty'
subprocess.run(['bw', 'sync'], check=True)
u = subprocess.run(['bw', 'unlock', '--raw', '--passwordenv', 'BW_PW'],
                   env={**os.environ, 'BW_PW': pw}, capture_output=True, text=True, check=True)
session = u.stdout.strip()
items = json.loads(subprocess.run(['bw', 'list', 'items', '--search', 'example',
                                   '--session', session],
                                  capture_output=True, text=True, check=True).stdout)
print(f'vault items matching \"example\": {len(items)}')
subprocess.run(['bw', 'lock', '--session', session], check=True)
"
```

If it completes without errors, setup is done.

### Maintenance

- **Rotate the master password** — re-stash; the entry is overwritten in place:
  ```bash
  uv run python -c "import keyring, getpass; keyring.set_password('autopilot-mcp', 'bw_master', getpass.getpass('New master password: '))"
  ```
- **Remove the keyring entry** (the MCP then fails at startup until restored):
  ```bash
  uv run python -c "import keyring; keyring.delete_password('autopilot-mcp', 'bw_master')"
  ```
- **`bw` fell off PATH** — open a new shell (winget's PATH update doesn't reach
  already-open shells); if still missing, re-run the install from step 1.
- **Force a full re-sync** — `bw sync --force`. The MCP runs `bw sync` after
  every write, so this is only needed if the vault was edited elsewhere and you
  want the in-RAM cache to refresh before idle expiry.
- **Log out** — `bw logout` drops the account from local `bw` state; repeat
  steps 2–3 to restore.

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

All optional — defaults are sane for local use.

| Variable | Default | Description |
|----------|---------|-------------|
| `HEADLESS` | `true` | Set `"false"` to show the browser window for debugging. |
| `BROWSER_TIMEOUT` | `30000` | Per-page navigation/action timeout, in ms. |
| `AUTOPILOT_TOOL_TIMEOUT_SECONDS` | `60` | Wall-clock cap on a single tool call. |
| `AUTOPILOT_PLAYBOOK_TIMEOUT_SECONDS` | `300` | Wall-clock cap on a `run_playbook` call. |
| `AUTOPILOT_BW_TIMEOUT_SECONDS` | `45` | Timeout for a single `bw` CLI invocation. |
| `AUTOPILOT_FILE_SERVER_HOST` | `127.0.0.1` | Bind interface for the local file server. |
| `AUTOPILOT_FILE_SERVER_PORT` | `0` | Bind port for the local file server (`0` = ephemeral). |
| `AUTOPILOT_LOG_JSON` | `false` | `"true"` for JSON logs; otherwise human-readable console output. |
| `AUTOPILOT_LOG_LEVEL` | `INFO` | Root log level for all `autopilot.*` loggers. |
| `BITWARDENCLI_APPDATA_DIR` | — | Override the Bitwarden CLI data directory (standard `bw` variable). |

Credentials are pulled from Bitwarden — there are no per-site username/password
environment variables.

## Development

```bash
uv sync --extra dev
uv run camoufox fetch
uv run ruff check .
uv run pytest
uv run python server.py    # stdio mode
```

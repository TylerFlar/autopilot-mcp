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
| `press_key` | Send a real key (`Enter`, `Tab`, `Control+A`, …). Beats synthetic `KeyboardEvent`s, which pages ignore as untrusted. |
| `attach_file` | Attach a local file to a `<input type="file">` (incl. hidden inputs). |
| `scroll` | Scroll up or down. |

`run_js` takes either an expression or a statement body — scripts using
`return` or top-level `await` are wrapped in an async IIFE automatically.

For parallel work on the same site, use isolated browser **instances** — each
clones the site's base profile so concurrent sessions don't collide:

| Tool | Description |
|------|-------------|
| `spawn_instance` | Clone a base profile into a temporary isolated browser profile and open a URL. Returns `instance_id`. |
| `list_instances` | List live spawned instances and TTLs. |
| `close_instance` | Close an instance and delete its temporary profile. |
| `instance_navigate` / `instance_screenshot` / `instance_get_text` / `instance_get_url` | Browser navigation/inspection scoped to one `instance_id`. |
| `instance_run_js` / `instance_click` / `instance_type_text` / `instance_press_key` / `instance_scroll` | Page interaction scoped to one `instance_id`. |
| `instance_attach_file` / `instance_fill_login` | Upload/login helpers scoped to one `instance_id`. |

Example: `spawn_instance(url="https://accounts.example.com/...", clone_from_profile="google.com")`
lets each webmail cleanup branch use its own cloned Google session. Always call
`close_instance(instance_id)` when the branch is finished; timed-out instances
are also cleaned up automatically.

### Credentials (Bitwarden, fill-don't-reveal)

| Tool | Description |
|------|-------------|
| `list_logins` | Search the vault. Returns id/name/urls/username/has_totp — **never passwords**. |
| `fill_login` | Inject creds from Bitwarden straight into form fields. Password never returns. |
| `get_totp` | Current 6-digit TOTP, computed locally from the stored seed. |
| `vault_status` | Transport, lock state, item count, snapshot age. `sync=True` forces a refresh. |
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
5. For SMS 2FA: `navigate("https://messages.example.com/web/")` and read the code from a messages-on-web client.
6. After the task succeeds, `save_playbook(...)` so next time is one call.
7. Just signed up somewhere new? `upsert_login(url, username, password)` stores it and Bitwarden sync pushes to your other devices.

## Credentials setup (Bitwarden)

The MCP unlocks Bitwarden with a master password stashed in the OS keyring
(DPAPI-encrypted on Windows, scoped to your user). It never lands on disk
outside the keyring, and never enters the model's context.

### How the vault is reached

The MCP drives a **`bw serve` daemon** — one `bw` process, unlocked once, that
answers over loopback HTTP. It starts on the first credential call and is
locked and killed after 15 idle minutes (and on shutdown).

**One daemon per box, not per MCP process.** Every worker run spawns its own
autopilot MCP, so they rendezvous through `data/bw-serve.json` (port + a shared
last-touch stamp, guarded by a lock file): the first process in spawns and owns
the daemon, later ones adopt its port. Only the owner locks or kills it, and
only once *every* process has been idle past the window — otherwise a sibling
mid-login would have the vault yanked out from under it. A state file pointing
at a dead port is detected by probe and replaced.

This replaced a per-operation `bw <cmd> --session …` design, which is broken on
Bitwarden CLI ≥ 2026.3.0: `bw unlock --raw` returns a session that every
*subsequent* process rejects with `Vault is locked.` Reads survived on a
local-decryption fallback (`LocalBitwardenVault`); writes had no fallback and
failed outright, and nothing ever synced. Reproduce the underlying bug with:

```bash
S=$(bw unlock --raw --passwordenv BW_PW); bw list items --session "$S"   # Vault is locked.
```

Set `AUTOPILOT_BW_TRANSPORT=cli` to force the old path (it still works for
reads); `serve` to require the daemon and fail loudly if it can't start;
`auto` (default) prefers the daemon and falls back to the CLI.

Security posture: `bw serve` has no authentication, so the daemon binds
`127.0.0.1` on a **random** port (never the well-known 8087), keeps Bitwarden's
origin protection on, and does not outlive its idle window. Any local process
running as you could still reach it while it is up — that is the same exposure
as the keyring master password itself, but keep the idle window short.

### Staying in sync

`vault_status()` reports lock state, item count, and `sync_age_minutes`. The
daemon syncs on start, before the first read once the local snapshot is older
than `AUTOPILOT_BW_SYNC_TTL_MINUTES` (default 30), and after every write.
Without that TTL the snapshot silently drifts: on the CLI path sync only ever
ran after a write, and writes were failing, so the vault could go weeks stale
and logins added in the Bitwarden app simply did not exist as far as the model
could tell.

### TOTP

Codes are computed locally with `pyotp` from the seed stored on the vault item.
Bitwarden's own `bw get totp` / `GET /object/totp` are Premium-gated and answer
`Premium status is required to use this feature.` without it. Only items whose
`list_logins` row shows `has_totp: true` can produce a code.

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

Runs the real path — keyring read, daemon start, unlock, list, lock — without
printing the password:

```bash
uv run python -c "
import credentials
c = credentials.BitwardenClient()
print(c.vault_status())
c.lock()
"
```

A `transport: serve`, `status: unlocked`, and a non-zero `item_count` mean
setup is done. A `transport: cli` line means the daemon could not start —
`serve_unavailable` in the same output says why.

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
- **Force a re-sync** — `vault_status(sync=True)` from the MCP, or `bw sync`
  from a shell. Only needed if the vault was edited elsewhere and you don't
  want to wait out `AUTOPILOT_BW_SYNC_TTL_MINUTES`.
- **Duplicate entries for one site** — several logins can legitimately share a
  URL (one per account). Lookups refuse to guess between them; pass
  `account="<username>"` to `fill_login` / `get_totp`, or `vault_item=<id>`
  from the ids the error lists.
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
| `AUTOPILOT_BW_TIMEOUT_SECONDS` | `45` | Timeout for a single `bw` CLI invocation / serve request. |
| `AUTOPILOT_BW_TRANSPORT` | `auto` | `auto` \| `serve` \| `cli` — how the vault is reached. |
| `AUTOPILOT_BW_SYNC_TTL_MINUTES` | `30` | How stale the local snapshot may get before a read re-syncs. |
| `AUTOPILOT_BW_SERVE_STARTUP_SECONDS` | `45` | How long to wait for `bw serve` to answer `/status`. |
| `AUTOPILOT_BW_STATE_DIR` | `./data` | Where sibling MCP processes rendezvous on one shared daemon. |
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

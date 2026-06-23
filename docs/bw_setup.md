# Bitwarden CLI setup for autopilot-mcp

The autopilot MCP reads and writes credentials through the Bitwarden CLI
(`bw`). The master password is stored in Windows Credential Manager via
`keyring` (DPAPI-encrypted, per-user). The MCP unlocks Bitwarden at startup by
pulling the master password from keyring, caches the session token in RAM,
and re-locks on shutdown. No secret lands on disk.

This doc is the runbook for a fresh machine. Run it top-to-bottom.

## 1. Install the Bitwarden CLI

```powershell
winget install --id Bitwarden.CLI --accept-source-agreements --accept-package-agreements
```

winget adds `bw.exe` to PATH via a shim at
`%LOCALAPPDATA%\Microsoft\WinGet\Packages\Bitwarden.CLI_*\bw.exe`. **Open a
new shell** after install so the PATH update takes effect.

Verify:

```bash
bw --version   # should print e.g. 2026.3.0
bw status      # should print {"status":"unauthenticated", ...}
```

Alternative install paths (if winget is unavailable):

- `npm install -g @bitwarden/cli` (needs Node)
- Direct binary from <https://bitwarden.com/download/>

## 2. Log in

Interactive — only your terminal sees the master password. Claude does not.

```bash
bw login
```

It prompts for email, master password, and a two-step token. On success
`bw status` reports `"status":"locked"`. We leave it locked on purpose —
the MCP unlocks on demand.

## 3. Stash the master password in Windows Credential Manager

We keep the master password out of `.env` and off the command line. Instead
it goes into the OS keyring, which on Windows is DPAPI-encrypted and scoped
to your Windows user.

First make sure `keyring` is available in the MCP venv:

```bash
cd mcps/autopilot-mcp
uv sync
```

Then stash the password (you type it at the hidden prompt):

```bash
uv run python -c "import keyring, getpass; keyring.set_password('tasque-autopilot', 'bw_master', getpass.getpass('Master password: ')); print('stored')"
```

`keyring` writes to service `tasque-autopilot`, username `bw_master`. To
confirm without printing the value:

```bash
uv run python -c "import keyring; v = keyring.get_password('tasque-autopilot', 'bw_master'); print(f'present={v is not None} length={len(v) if v else 0} backend={keyring.get_keyring().__class__.__name__}')"
```

Expected: `present=True length=<your pw length> backend=WinVaultKeyring`.

## 4. End-to-end smoke test

The MCP's `credentials.BitwardenClient.unlock()` calls `bw unlock --raw
--passwordenv BW_PW`, where `BW_PW` is injected into the subprocess env only
for that one call. Session token lives in the MCP process's RAM, idle-expires
after 15 minutes, and is wiped on shutdown.

To smoke-test the loop manually:

```bash
cd mcps/autopilot-mcp
uv run python -c "
import json, os, subprocess, keyring
pw = keyring.get_password('tasque-autopilot', 'bw_master')
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

This runs entirely through the real code paths — keyring read, `bw unlock`,
list, lock. No password ever hits stdout. If it completes without errors,
Phase 0 is done.

## Maintenance

### Rotate the master password

If you change your Bitwarden master password, re-stash it:

```bash
uv run python -c "import keyring, getpass; keyring.set_password('tasque-autopilot', 'bw_master', getpass.getpass('New master password: '))"
```

The old entry is overwritten in-place.

### Remove the keyring entry

```bash
uv run python -c "import keyring; keyring.delete_password('tasque-autopilot', 'bw_master')"
```

After this the MCP will fail at startup until the entry is restored.

### `bw` falls off PATH

Open a new shell first — winget's PATH update doesn't propagate to already-open
shells. If it's still missing, re-run the `winget install` command from
section 1. The MCP's `credentials.startup_check()` hard-fails with a pointer
back to this doc.

### Force a full re-sync

```bash
bw sync --force
```

The MCP calls `bw sync` after every write operation (create / update / upsert
/ delete), so manual syncs are only needed if the vault was edited outside
the MCP and you want the MCP's in-RAM cache to pick it up before idle expiry.

### Log out entirely

```bash
bw logout
```

This drops the account from local `bw` state. You'll need to repeat sections
2 and 3 to get the MCP working again.

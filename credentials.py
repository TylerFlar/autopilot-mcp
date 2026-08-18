"""Bitwarden wrapper + fill-don't-reveal login helper.

Design notes worth reading before editing:

- There are two transports to the vault, chosen by AUTOPILOT_BW_TRANSPORT
  ("auto" — the default — - "serve", or "cli"):

  * **serve** (preferred): one long-lived `bw serve` daemon bound to
    127.0.0.1 on a random port, unlocked once over its REST API. Every
    later op is an HTTP call against that already-unlocked process.
  * **cli**: the historical path — one `bw` subprocess per operation with
    a BW_SESSION token.

  The CLI path is *broken for decryption* on Bitwarden CLI >= 2026.3.0:
  `bw unlock --raw` returns a session that every subsequent process
  rejects with "Vault is locked." (verified 2026-08-17 against 2026.3.0,
  `crypto_accountCryptographicState: V1`). Reads limped along via
  LocalBitwardenVault, which decrypts data.json in-process; *writes* had
  no fallback at all and simply failed. `bw serve` unlocks in-process and
  never round-trips a session token, so it sidesteps the bug entirely —
  reads, writes, and TOTP all work, and each op costs ~10ms instead of a
  ~1-3s process spawn.

- Master password comes from the OS keyring — see the README (Credentials
  setup). It is passed to `bw serve` over loopback once, at unlock.
- The daemon idle-expires: after `idle_minutes` without a call it is
  locked and torn down, so an unlocked vault is not left listening for the
  life of the MCP. `lock()` does the same thing explicitly.
- Sync is on a TTL (AUTOPILOT_BW_SYNC_TTL_MINUTES). Before the first read
  of a stale window, and after every write, the vault syncs with the
  server. Without this the local snapshot silently drifts: on the CLI path
  sync only ever ran after a write, and writes were failing, so the vault
  could go weeks stale and entries added in the Bitwarden app were
  invisible to autopilot.
- Reads are cached per unlocked session (get_item, list_items). Any write
  op must call `invalidate_cache()`.
- `fill_login` is the default login path: it pulls the vault item, then
  injects username/password directly into Playwright form fields. The
  password string never crosses back to the caller. `reveal_credentials`
  is the escape hatch when fill_login can't autodetect selectors.
- All ops emit structlog events to the "autopilot.credentials" logger.
  Values (passwords, TOTPs, session tokens) are NEVER logged.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
from typing import Any
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse

import keyring
import pyotp
import structlog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEYRING_SERVICE = "autopilot-mcp"
KEYRING_USERNAME = "bw_master"
BW_BINARY = "bw"
BW_TIMEOUT_SECONDS = float(os.environ.get("AUTOPILOT_BW_TIMEOUT_SECONDS", "45"))
# How long a local snapshot may go unsynced before the next read refreshes it.
SYNC_TTL_SECONDS = float(os.environ.get("AUTOPILOT_BW_SYNC_TTL_MINUTES", "30")) * 60
# Seconds to wait for `bw serve` to answer /status after spawn.
SERVE_STARTUP_SECONDS = float(os.environ.get("AUTOPILOT_BW_SERVE_STARTUP_SECONDS", "45"))
# Where sibling MCP processes rendezvous on a single shared daemon. A client
# that starts one autopilot MCP per job has several running at once; without
# this each would stand up its own unlocked `bw serve` and they would all
# write data.json concurrently.
SERVE_STATE_DIR = Path(
    os.environ.get("AUTOPILOT_BW_STATE_DIR") or (Path(__file__).parent / "data")
)
SERVE_STATE_PATH = SERVE_STATE_DIR / "bw-serve.json"
SERVE_LOCK_PATH = SERVE_STATE_DIR / "bw-serve.lock"
# A lock file older than this is assumed abandoned by a crashed process.
SERVE_LOCK_STALE_SECONDS = 90.0
# How often a process refreshes the shared last-touch stamp.
SERVE_TOUCH_INTERVAL_SECONDS = 30.0

log = structlog.stdlib.get_logger("autopilot.credentials")


class BitwardenError(RuntimeError):
    """Non-recoverable error from the bw CLI or credential pipeline."""


class BitwardenTimeout(BitwardenError):
    """A bw CLI command exceeded the configured wall-clock cap."""


class BitwardenVaultLocked(BitwardenError):
    """The bw CLI rejected a command because the vault session was unusable."""


def _transport_mode(override: str | None = None) -> str:
    mode = (override or os.environ.get("AUTOPILOT_BW_TRANSPORT") or "auto").strip().lower()
    if mode not in ("auto", "serve", "cli"):
        raise BitwardenError(
            f"AUTOPILOT_BW_TRANSPORT must be auto|serve|cli, got {mode!r}"
        )
    return mode


def _master_password() -> str:
    master = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    if not master:
        raise BitwardenError(
            f"no master password in keyring under "
            f"{KEYRING_SERVICE}/{KEYRING_USERNAME} — see the README"
        )
    return master


def startup_check() -> None:
    """Verify `bw` is on PATH. Raises with a pointer to setup docs if not."""
    if shutil.which(BW_BINARY) is None:
        raise BitwardenError(
            "Bitwarden CLI not found on PATH. "
            "Run the Bitwarden setup from the README (Credentials setup) "
            "and restart the MCP."
        )


def _looks_like_url(s: str) -> bool:
    return "://" in s or s.startswith("www.")


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _looks_like_uuid(s: str) -> bool:
    return bool(_UUID_RE.match(s.strip()))


def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


def _pick_one(
    matches: list[dict[str, Any]], username: str | None
) -> dict[str, Any] | None:
    """The single intended item, or None when the caller must disambiguate.

    A `username` narrows first (exact, then case-insensitive) — several vault
    entries legitimately share a URL, one per account on that site.
    """
    if not matches:
        return None
    if username:
        exact = [
            m for m in matches if (m.get("login") or {}).get("username") == username
        ]
        if len(exact) == 1:
            return exact[0]
        loose = [
            m
            for m in matches
            if _safe_lower((m.get("login") or {}).get("username")) == username.lower()
        ]
        if len(loose) == 1:
            return loose[0]
        matches = exact or loose or matches
    return matches[0] if len(matches) == 1 else None


def _describe_candidates(matches: list[dict[str, Any]]) -> str:
    """Render ambiguous matches so the caller can retry with one of them.

    Names alone are often useless here: entries for two accounts on the same
    site are commonly given the same name, so lead with id and username.
    """
    parts = []
    for m in matches[:8]:
        login = m.get("login") or {}
        parts.append(
            f"{{id={m.get('id')}, name={m.get('name')!r}, "
            f"username={login.get('username')!r}}}"
        )
    if len(matches) > 8:
        parts.append(f"... +{len(matches) - 8} more")
    return (
        "[" + ", ".join(parts) + "] — retry with `username=` or with "
        "`vault_item=<id>` from this list"
    )


def _totp_now(secret: str, item_name: Any = None) -> str:
    """Six-digit code from a stored seed: bare base32 or an otpauth:// URI."""
    cleaned = secret.strip()
    try:
        if cleaned.lower().startswith("otpauth://"):
            return pyotp.parse_uri(cleaned).now()
        return pyotp.TOTP(cleaned.replace(" ", "")).now()
    except Exception as exc:  # noqa: BLE001 - pyotp raises bare ValueError/binascii
        raise BitwardenError(
            f"vault item {item_name!r} has a TOTP seed that could not be parsed "
            f"({type(exc).__name__}); expected base32 or an otpauth:// URI"
        ) from exc


def _age_minutes(iso_timestamp: Any) -> float | None:
    epoch = _parse_iso_epoch(iso_timestamp)
    if not epoch:
        return None
    return round((time.time() - epoch) / 60, 1)


def _local_vault_data_path() -> Path:
    custom_dir = os.environ.get("BITWARDENCLI_APPDATA_DIR")
    if custom_dir:
        return Path(custom_dir) / "data.json"
    return Path(os.environ["APPDATA"]) / "Bitwarden CLI" / "data.json"


class LocalBitwardenVault:
    """Read-only fallback for a logged-in Bitwarden CLI data.json.

    This is intentionally narrow: it exists for the Windows CLI state where
    `bw unlock --raw` succeeds but the returned session is rejected by later
    commands as "Vault is locked." It never writes vault data and never logs
    decrypted values.
    """

    def __init__(self, data: dict[str, Any], master_password: str) -> None:
        self.data = data
        self.master_password = master_password
        self.user_id = str(data.get("global_account_activeAccountId") or "")
        accounts = data.get("global_account_accounts") or {}
        account = accounts.get(self.user_id) or {}
        self.email = str(account.get("email") or "")
        if not self.user_id or not self.email:
            raise BitwardenError("local Bitwarden data has no active account/email")
        self._user_key: bytes | None = None
        self._items: list[dict[str, Any]] | None = None

    @classmethod
    def from_disk(cls) -> "LocalBitwardenVault":
        master = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if not master:
            raise BitwardenError(
                f"no master password in keyring under "
                f"{KEYRING_SERVICE}/{KEYRING_USERNAME} - see the README"
            )
        path = _local_vault_data_path()
        if not path.exists():
            raise BitwardenError(f"Bitwarden CLI data file not found: {path}")
        return cls(json.loads(path.read_text(encoding="utf-8")), master)

    def list_items(self, query: str | None = None) -> list[dict[str, Any]]:
        items = self._load_items()
        if not query:
            return items
        needle = query.lower()
        return [item for item in items if self._matches_search(item, needle)]

    def list_by_url(self, url: str) -> list[dict[str, Any]]:
        items = self._load_items()
        return [item for item in items if self._matches_url(item, url)]

    def get_item(self, id_or_url: str, username: str | None = None) -> dict[str, Any]:
        items = self._load_items()
        if _looks_like_url(id_or_url):
            return self._single_match(self.list_by_url(id_or_url), id_or_url, username)

        needle = id_or_url.lower()
        matches = [
            item
            for item in items
            if item.get("id") == id_or_url or _safe_lower(item.get("name")) == needle
        ]
        if not matches:
            matches = self.list_by_url(id_or_url)
        return self._single_match(matches, id_or_url, username)

    def _load_items(self) -> list[dict[str, Any]]:
        if self._items is not None:
            return self._items

        ciphers = self.data.get(f"user_{self.user_id}_ciphers_ciphers") or {}
        items: list[dict[str, Any]] = []
        for cipher in ciphers.values():
            if cipher.get("deletedDate") or cipher.get("type") != 1:
                continue
            try:
                items.append(self._decrypt_cipher(cipher))
            except BitwardenError:
                continue
        self._items = items
        log.info("credentials.local_vault_loaded", count=len(items))
        return items

    def _decrypt_cipher(self, cipher: dict[str, Any]) -> dict[str, Any]:
        key = self._cipher_key(cipher)
        name = self._decrypt_optional_text(cipher.get("name"), key) or ""
        notes = self._decrypt_optional_text(cipher.get("notes"), key)
        login = cipher.get("login") or {}
        username = self._decrypt_optional_text(login.get("username"), key)
        password = self._decrypt_optional_text(login.get("password"), key)
        totp = self._decrypt_optional_text(login.get("totp"), key)
        uris = []
        for uri in login.get("uris") or []:
            decrypted_uri = self._decrypt_optional_text(uri.get("uri"), key)
            if decrypted_uri:
                uris.append({"uri": decrypted_uri, "match": uri.get("match")})
        return {
            "id": cipher.get("id"),
            "name": name,
            "notes": notes,
            "type": cipher.get("type"),
            "login": {
                "username": username,
                "password": password,
                "totp": totp,
                "uris": uris,
            },
        }

    def _cipher_key(self, cipher: dict[str, Any]) -> bytes:
        user_key = self._get_user_key()
        encrypted_key = cipher.get("key")
        if not encrypted_key:
            return user_key
        return self._decrypt_bytes(encrypted_key, user_key)

    def _get_user_key(self) -> bytes:
        if self._user_key is not None:
            return self._user_key

        kdf_config = self.data.get(f"user_{self.user_id}_kdfConfig_kdfConfig") or {}
        if kdf_config.get("kdfType", 0) != 0:
            raise BitwardenError("local Bitwarden fallback only supports PBKDF2 vaults")
        iterations = int(kdf_config.get("iterations") or 600000)
        master_key = hashlib.pbkdf2_hmac(
            "sha256",
            self.master_password.encode("utf-8"),
            self.email.lower().encode("utf-8"),
            iterations,
            dklen=32,
        )
        stretched_master_key = self._stretch_key(master_key)
        encrypted_user_key = self.data.get(
            f"user_{self.user_id}_masterPassword_masterKeyEncryptedUserKey"
        )
        if not encrypted_user_key:
            raise BitwardenError("local Bitwarden data has no encrypted user key")
        self._user_key = self._decrypt_bytes(encrypted_user_key, stretched_master_key)
        if len(self._user_key) < 64:
            raise BitwardenError("local Bitwarden user key is incomplete")
        return self._user_key

    @staticmethod
    def _stretch_key(key: bytes) -> bytes:
        return LocalBitwardenVault._hkdf_expand(key, b"enc", 32) + LocalBitwardenVault._hkdf_expand(
            key, b"mac", 32
        )

    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        okm = b""
        previous = b""
        counter = 1
        while len(okm) < length:
            previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
            okm += previous
            counter += 1
        return okm[:length]

    def _decrypt_optional_text(self, value: Any, key: bytes) -> str | None:
        if not value:
            return None
        return self._decrypt_bytes(str(value), key).decode("utf-8")

    @staticmethod
    def _decrypt_bytes(encrypted: str, key: bytes) -> bytes:
        try:
            enc_type, payload = encrypted.split(".", 1)
            if int(enc_type) != 2:
                raise BitwardenError(f"unsupported Bitwarden encrypted string type {enc_type}")
            iv_b64, ciphertext_b64, mac_b64 = payload.split("|", 2)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            expected_mac = base64.b64decode(mac_b64)
        except ValueError as exc:
            raise BitwardenError("invalid Bitwarden encrypted string") from exc

        enc_key = key[:32]
        mac_key = key[32:64]
        actual_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_mac, expected_mac):
            raise BitwardenError("Bitwarden encrypted string MAC check failed")

        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
            raise BitwardenError("Bitwarden encrypted string padding check failed")
        return padded[:-pad_len]

    @staticmethod
    def _matches_search(item: dict[str, Any], needle: str) -> bool:
        login = item.get("login") or {}
        haystack = [
            item.get("name"),
            login.get("username"),
            *(uri.get("uri") for uri in login.get("uris") or []),
        ]
        return any(needle in _safe_lower(value) for value in haystack)

    @staticmethod
    def _matches_url(item: dict[str, Any], url: str) -> bool:
        login = item.get("login") or {}
        wanted = _safe_lower(url)
        wanted_host = _safe_lower(urlparse(url if "://" in url else f"https://{url}").hostname)
        for uri in login.get("uris") or []:
            candidate = _safe_lower(uri.get("uri"))
            candidate_host = _safe_lower(urlparse(candidate).hostname)
            if wanted and wanted in candidate:
                return True
            if wanted_host and candidate_host and (
                wanted_host == candidate_host
                or wanted_host.endswith(f".{candidate_host}")
                or candidate_host.endswith(f".{wanted_host}")
            ):
                return True
        return False

    @staticmethod
    def _single_match(
        matches: list[dict[str, Any]], query: str, username: str | None = None
    ) -> dict[str, Any]:
        picked = _pick_one(matches, username)
        if picked is not None:
            return picked
        if not matches:
            raise BitwardenError(f"no local vault item matches {query!r}")
        raise BitwardenError(
            f"{len(matches)} local vault items match {query!r}: "
            f"{_describe_candidates(matches)}"
        )


class BitwardenServe:
    """A managed `bw serve` daemon: the vault, unlocked in one process.

    Why this exists: see the module docstring. `bw unlock --raw` hands back
    a session token that the CLI then refuses to honour, which breaks every
    decrypting command including all writes. `bw serve` unlocks in-process
    and answers over loopback HTTP, so the token never has to survive a
    process boundary.

    One daemon is shared by every autopilot MCP process on the box. They
    rendezvous through a small state file (port + shared last-touch) guarded
    by a lock file; the first process in spawns and owns the daemon, the rest
    adopt its port. Only the owner ever locks or kills it.

    Security posture — the serve API is unauthenticated by design, so:
      * it binds 127.0.0.1 only (never `all`),
      * on a random free port, not the well-known 8087,
      * origin protection stays on (no --disable-origin-protection), which
        is what stops a page in the automation browser from reaching it,
      * and it is locked + killed once `idle_seconds` pass with no call from
        *any* process, not just this one.
    """

    def __init__(self, *, idle_seconds: float, host: str = "127.0.0.1") -> None:
        self._host = host
        self._port: int | None = None
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.RLock()
        self._last_touch = 0.0
        self._shared_touch_at = 0.0
        self._idle_seconds = idle_seconds
        self._last_sync = 0.0

    # --- lifecycle ------------------------------------------------------

    @property
    def running(self) -> bool:
        if self._port is None:
            return False
        # An adopted daemon has no handle here; a dead one is caught by the
        # unreachable-retry in request().
        return self._proc is None or self._proc.poll() is None

    @property
    def owned(self) -> bool:
        """True when this process spawned the daemon (and may retire it)."""
        return self._proc is not None

    def ensure_ready(self) -> None:
        """Guarantee a live, unlocked daemon. Cheap when already up."""
        with self._lock:
            if self.running:
                if self._idle_expired():
                    log.info("credentials.serve_idle_expire")
                    self.shutdown()
                else:
                    self._touch()
                    return
            self._acquire()

    def shutdown(self) -> None:
        """Release this process's hold on the daemon.

        The owner locks the vault and kills it; an adopter only drops its
        reference — tearing down a daemon a sibling process is mid-login on
        would be worse than leaving it to idle out.
        """
        with self._lock:
            proc, self._proc = self._proc, None
            port, self._port = self._port, None
            if proc is None or port is None:
                return
            if proc.poll() is None:
                try:
                    self._http("POST", "/lock", {}, port=port, timeout=10)
                except Exception:  # noqa: BLE001 - teardown is best effort
                    pass
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            _clear_shared_state(port)
            log.info("credentials.serve_stopped")

    def _acquire(self) -> None:
        """Adopt the shared daemon if one is answering, else spawn it."""
        with _shared_state_lock():
            state = _read_shared_state()
            port = state.get("port")
            if isinstance(port, int) and self._adopt(port):
                return
            self._start()
            _write_shared_state(self._port, owner_pid=os.getpid())

    def _adopt(self, port: int) -> bool:
        """Attach to a daemon another process started, if it is still alive."""
        try:
            body = self._http("GET", "/status", port=port, timeout=5)
        except BitwardenError:
            return False
        template = body.get("template") if isinstance(body, dict) else None
        status = (template or {}).get("status") if isinstance(template, dict) else None
        self._port = port
        self._proc = None
        try:
            if status != "unlocked":
                self._http(
                    "POST", "/unlock", {"password": _master_password()},
                    port=port, timeout=120,
                )
            self._last_sync = _parse_iso_epoch((template or {}).get("lastSync"))
        except BitwardenError:
            self._port = None
            return False
        self._last_touch = time.monotonic()
        self._touch(force=True)
        log.info("credentials.serve_adopted", port=port)
        return True

    def _idle_expired(self) -> bool:
        """Idle is measured across every process sharing the daemon."""
        if not self._idle_seconds:
            return False
        if time.monotonic() - self._last_touch <= self._idle_seconds:
            return False
        shared = _read_shared_state().get("last_touch")
        if isinstance(shared, (int, float)) and time.time() - shared <= self._idle_seconds:
            self._last_touch = time.monotonic()
            return False
        return True

    def _touch(self, *, force: bool = False) -> None:
        now = time.monotonic()
        self._last_touch = now
        if self._port is None:
            return
        if force or now - self._shared_touch_at > SERVE_TOUCH_INTERVAL_SECONDS:
            self._shared_touch_at = now
            _write_shared_state(self._port, owner_pid=None)

    def _start(self) -> None:
        master = _master_password()
        port = _free_port(self._host)
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed binary, no shell
                [BW_BINARY, "serve", "--hostname", self._host, "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            raise BitwardenError(f"could not start `bw serve`: {exc}") from exc

        self._proc = proc
        self._port = port
        deadline = time.monotonic() + SERVE_STARTUP_SECONDS
        while True:
            if proc.poll() is not None:
                self._proc = None
                self._port = None
                raise BitwardenError(
                    f"`bw serve` exited immediately (rc={proc.returncode})"
                )
            try:
                self._http("GET", "/status", port=port, timeout=10)
                break
            except BitwardenError:
                if time.monotonic() > deadline:
                    self.shutdown()
                    raise BitwardenError(
                        f"`bw serve` did not answer /status within "
                        f"{SERVE_STARTUP_SECONDS:.0f}s"
                    ) from None
                time.sleep(0.25)

        self._http("POST", "/unlock", {"password": master}, port=port, timeout=120)
        status = self.status()
        if status.get("status") != "unlocked":
            self.shutdown()
            raise BitwardenError(
                f"`bw serve` unlock did not take (status={status.get('status')!r}); "
                f"the master password in the keyring may be stale"
            )
        self._last_sync = _parse_iso_epoch(status.get("lastSync"))
        self._touch(force=True)
        log.info(
            "credentials.serve_started",
            port=port,
            last_sync=status.get("lastSync"),
        )
        self.sync_if_stale()

    # --- vault ops ------------------------------------------------------

    def status(self) -> dict[str, Any]:
        body = self.request("GET", "/status")
        if isinstance(body, dict) and isinstance(body.get("template"), dict):
            return body["template"]
        return body if isinstance(body, dict) else {}

    def sync(self) -> None:
        self.request("POST", "/sync", {}, timeout=180)
        self._last_sync = time.time()
        log.info("credentials.sync")

    def sync_if_stale(self) -> bool:
        """Sync when the local snapshot is older than the TTL. Returns True
        if a sync actually ran."""
        if SYNC_TTL_SECONDS <= 0:
            return False
        if time.time() - self._last_sync <= SYNC_TTL_SECONDS:
            return False
        try:
            self.sync()
        except BitwardenError as exc:
            # Offline / server hiccup: keep serving the local snapshot rather
            # than failing the caller's login, but don't retry every call.
            self._last_sync = time.time()
            log.warning("credentials.sync_failed", error=str(exc))
            return False
        return True

    def list_items(self, query: str | None = None, url: str | None = None) -> list[dict[str, Any]]:
        path = "/list/object/items"
        params = []
        if query:
            params.append(f"search={quote(query)}")
        if url:
            params.append(f"url={quote(url, safe='')}")
        if params:
            path = f"{path}?{'&'.join(params)}"
        result = self.request("GET", path)
        return result if isinstance(result, list) else []

    def get_item_by_id(self, item_id: str) -> dict[str, Any]:
        result = self.request("GET", f"/object/item/{quote(item_id, safe='')}")
        if not isinstance(result, dict):
            raise BitwardenError(f"no vault item with id {item_id!r}")
        return result

    def create_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self.request("POST", "/object/item", payload)
        if not isinstance(result, dict):
            raise BitwardenError("bw serve create returned no item")
        return result

    def edit_item(self, item_id: str, full_item: dict[str, Any]) -> dict[str, Any]:
        result = self.request(
            "PUT", f"/object/item/{quote(item_id, safe='')}", full_item
        )
        if not isinstance(result, dict):
            raise BitwardenError("bw serve edit returned no item")
        return result

    def delete_item(self, item_id: str) -> None:
        self.request("DELETE", f"/object/item/{quote(item_id, safe='')}")

    # --- transport ------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        """One REST call, restarting the daemon once if it died under us."""
        with self._lock:
            self.ensure_ready()
            port = self._port
            assert port is not None
            try:
                return self._http(method, path, payload, port=port, timeout=timeout)
            except _ServeUnreachable as exc:
                log.warning("credentials.serve_unreachable", error=str(exc))
                self.shutdown()
                self.ensure_ready()
                assert self._port is not None
                return self._http(
                    method, path, payload, port=self._port, timeout=timeout
                )

    def _http(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        port: int,
        timeout: float | None = None,
    ) -> Any:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"http://{self._host}:{port}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - loopback only
                req, timeout=timeout or BW_TIMEOUT_SECONDS
            ) as resp:
                body = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            message = raw
            try:
                message = json.loads(raw).get("message") or raw
            except json.JSONDecodeError:
                pass
            if "locked" in message.lower():
                raise BitwardenVaultLocked(f"bw serve {method} {path}: {message}") from exc
            raise BitwardenError(f"bw serve {method} {path} failed: {message}") from exc
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
            raise _ServeUnreachable(f"bw serve {method} {path}: {exc}") from exc

        self._touch()
        if not body.get("success", False):
            message = body.get("message") or json.dumps(body)[:200]
            raise BitwardenError(f"bw serve {method} {path} failed: {message}")
        return _unwrap(body.get("data"))


class _ServeUnreachable(BitwardenError):
    """The serve daemon did not answer — it died or never came up."""


def _unwrap(data: Any) -> Any:
    """bw serve wraps lists as {"object": "list", "data": [...]}."""
    if isinstance(data, dict) and data.get("object") == "list":
        return data.get("data") or []
    return data


def _free_port(host: str) -> int:
    with socket.socket() as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


# --- shared-daemon rendezvous ----------------------------------------------
#
# Several autopilot MCP processes can run at once. Left alone, each would
# start a separate `bw serve`, so N unlocked vaults would sit listening and N
# processes would write data.json at once. These three functions let
# them agree on a single daemon: a tiny JSON state file with the port and a
# shared last-touch stamp, guarded by an O_EXCL lock file (no new deps, and
# Windows-safe, unlike fcntl).


@contextlib.contextmanager
def _shared_state_lock(timeout: float = 30.0) -> Any:
    """Cross-process mutex around the state file. Best effort: if the lock
    can't be taken in `timeout`, proceed anyway — a missed rendezvous costs
    one redundant daemon, a hang costs the whole login."""
    SERVE_STATE_DIR.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    acquired = False
    while time.monotonic() < deadline:
        try:
            fd = os.open(SERVE_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            try:
                age = time.time() - SERVE_LOCK_PATH.stat().st_mtime
            except OSError:
                continue
            if age > SERVE_LOCK_STALE_SECONDS:
                log.warning("credentials.serve_lock_stale", age_seconds=round(age))
                SERVE_LOCK_PATH.unlink(missing_ok=True)
                continue
            time.sleep(0.1)
    else:
        log.warning("credentials.serve_lock_timeout")
    try:
        yield
    finally:
        if acquired:
            SERVE_LOCK_PATH.unlink(missing_ok=True)


def _read_shared_state() -> dict[str, Any]:
    try:
        data = json.loads(SERVE_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_shared_state(port: int | None, *, owner_pid: int | None) -> None:
    """Record the live port and refresh the shared idle stamp.

    `owner_pid=None` means "I'm only touching it" — the existing owner is
    preserved so an adopter's heartbeat doesn't claim ownership.
    """
    if port is None:
        return
    state = _read_shared_state()
    payload = {
        "port": port,
        "owner_pid": owner_pid if owner_pid is not None else state.get("owner_pid"),
        "last_touch": time.time(),
    }
    tmp = SERVE_STATE_PATH.with_suffix(f".{os.getpid()}.tmp")
    try:
        SERVE_STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, SERVE_STATE_PATH)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        log.warning("credentials.serve_state_write_failed", error=str(exc))


def _clear_shared_state(port: int) -> None:
    """Drop the record, but only if it still points at the port we killed."""
    try:
        if _read_shared_state().get("port") == port:
            SERVE_STATE_PATH.unlink(missing_ok=True)
    except OSError:
        pass


def _parse_iso_epoch(value: Any) -> float:
    """Epoch seconds for a bw ISO timestamp; 0.0 when absent/unparseable."""
    if not value:
        return 0.0
    text = str(value).replace("Z", "+00:00")
    try:
        import datetime as _dt

        return _dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


class BitwardenClient:
    """One instance per MCP process. Thread-safe for the single-request
    pattern the MCP actually uses; not tuned for heavy concurrency."""

    def __init__(self, *, idle_minutes: int = 15, transport: str | None = None) -> None:
        self._idle_seconds = idle_minutes * 60
        self._session: str | None = None
        self._last_touch: float = 0.0
        self._lock = threading.Lock()
        self._item_cache: dict[str, Any] = {}
        self._local_vault: LocalBitwardenVault | None = None
        self._transport_pref = transport
        self._serve: BitwardenServe | None = None
        self._serve_error: str | None = None

    # --- transport selection --------------------------------------------

    def _backend(self) -> BitwardenServe | None:
        """A ready `bw serve` daemon, or None when the CLI path is in play.

        Mode "auto" tries serve once; if it can't start (no `bw`, port
        blocked, bad keyring entry) it records why and falls back to the CLI
        for the rest of the process rather than paying a failed spawn per
        call. Mode "serve" propagates the failure; mode "cli" never tries.
        """
        mode = _transport_mode(self._transport_pref)
        if mode == "cli":
            return None
        if self._serve_error is not None and mode == "auto":
            return None
        if self._serve is None:
            self._serve = BitwardenServe(idle_seconds=self._idle_seconds)
        try:
            self._serve.ensure_ready()
        except BitwardenError as exc:
            self._serve = None
            if mode == "serve":
                raise
            self._serve_error = str(exc)
            log.warning("credentials.serve_unavailable", error=str(exc))
            return None
        return self._serve

    def _read_backend(self) -> BitwardenServe | None:
        """`_backend()` plus the staleness check that read paths need."""
        serve = self._backend()
        if serve is None:
            self._ensure_unlocked()
            return None
        if serve.sync_if_stale():
            self._item_cache.clear()
        return serve

    @property
    def transport(self) -> str:
        """Which path the last op used: "serve" or "cli"."""
        return "serve" if self._serve is not None and self._serve.running else "cli"

    # --- public API -----------------------------------------------------

    def unlock(self) -> None:
        if self._backend() is not None:
            return
        with self._lock:
            self._unlock_locked()

    def lock(self) -> None:
        if self._serve is not None:
            self._serve.shutdown()
            self._serve = None
        with self._lock:
            self._item_cache.clear()
            self._local_vault = None
            if self._session is None:
                return
            try:
                self._run(["lock"], with_session=True)
            except BitwardenError:
                pass
            self._session = None
            log.info("credentials.lock")

    def vault_status(self) -> dict[str, Any]:
        """Lock state / item count / last sync, for diagnostics."""
        serve = self._read_backend()
        if serve is not None:
            status = serve.status()
            items = serve.list_items()
            last_sync = status.get("lastSync")
            return {
                "transport": "serve",
                "status": status.get("status"),
                "email": status.get("userEmail"),
                "last_sync": last_sync,
                "sync_age_minutes": _age_minutes(last_sync),
                "item_count": len(items),
                "items_with_totp": sum(
                    1 for it in items if ((it.get("login") or {}).get("totp"))
                ),
            }
        items = self.list_items(None)
        return {
            "transport": "cli",
            "status": "unknown (CLI transport)",
            "serve_unavailable": self._serve_error,
            "item_count": len(items),
            "items_with_totp": sum(
                1 for it in items if ((it.get("login") or {}).get("totp"))
            ),
        }

    def list_items(self, query: str | None) -> list[dict[str, Any]]:
        serve = self._read_backend()
        cache_key = f"list:{query or ''}"
        if cache_key in self._item_cache:
            return self._item_cache[cache_key]
        if serve is not None:
            result: Any = serve.list_items(query)
        else:
            args = ["list", "items"]
            if query:
                args += ["--search", query]
            try:
                result = self._bw_json(args)
            except BitwardenVaultLocked:
                result = self._get_local_vault().list_items(query)
        if not isinstance(result, list):
            result = []
        self._item_cache[cache_key] = result
        log.info("credentials.list", query=query, count=len(result))
        return result

    def get_item(self, id_or_url: str, username: str | None = None) -> dict[str, Any]:
        """Resolve a vault item by id, name, or URL.

        `username` disambiguates when several items share a URL — the common
        case being one vault entry per account on a shared site. Without it, an
        ambiguous lookup raises rather than guessing, and the message lists
        every candidate's id/name/username so the caller can retry precisely.
        """
        serve = self._read_backend()
        cache_key = f"get:{id_or_url}:{username or ''}"
        if cache_key in self._item_cache:
            return self._item_cache[cache_key]

        item: dict[str, Any] | None = None
        errors: list[str] = []

        if serve is not None:
            item = self._resolve_via_serve(serve, id_or_url, username, errors)
        elif _looks_like_url(id_or_url):
            item = self._find_unique_by_url(id_or_url, errors, username)
        else:
            try:
                item = self._bw_json(["get", "item", id_or_url])
            except BitwardenTimeout:
                raise
            except BitwardenVaultLocked:
                item = self._get_local_vault().get_item(id_or_url, username)
            except BitwardenError as e:
                errors.append(str(e))
                item = self._find_unique_by_url(id_or_url, errors, username)

        if item is None:
            hint = "" if username else " (pass `username` to disambiguate)"
            raise BitwardenError(
                f"no unique vault item matches {id_or_url!r}{hint}: {'; '.join(errors)}"
            )
        self._item_cache[cache_key] = item
        log.info(
            "credentials.get",
            item_id=item.get("id"),
            item_name=item.get("name"),
        )
        return item

    def get_totp(self, id_or_url: str, username: str | None = None) -> str:
        """Current TOTP code for a vault item.

        Computed locally from the stored seed with pyotp. Bitwarden's own
        `get totp` / `/object/totp` endpoints are gated behind Premium and
        answer "Premium status is required to use this feature." without it,
        so the local computation is the primary path, not a fallback.
        """
        item = self.get_item(id_or_url, username)
        secret = ((item.get("login") or {}).get("totp") or "").strip()
        if not secret:
            raise BitwardenError(
                f"vault item {item.get('name')!r} (id {item.get('id')}) has no TOTP "
                f"secret stored, so there is no code to generate. This account's "
                f"second factor is not TOTP — look for an SMS code, an email code, "
                f"a push/passkey prompt, or a different vault item "
                f"(list_logins shows has_totp for each entry)."
            )
        token = _totp_now(secret, item.get("name"))
        log.info("credentials.totp", item_id=item["id"], item_name=item.get("name"))
        return token

    def sync(self) -> None:
        serve = self._backend()
        if serve is not None:
            serve.sync()
        else:
            self._ensure_unlocked()
            self._run(["sync"], with_session=True)
            log.info("credentials.sync")
        self._item_cache.clear()
        self._local_vault = None

    def invalidate_cache(self) -> None:
        self._item_cache.clear()

    def list_by_url(self, url: str) -> list[dict[str, Any]]:
        """Vault items whose URIs match `url` (bw-side matching)."""
        serve = self._read_backend()
        if serve is not None:
            return serve.list_items(url=url)
        try:
            result = self._bw_json(["list", "items", "--url", url])
        except BitwardenVaultLocked:
            result = self._get_local_vault().list_by_url(url)
        return result if isinstance(result, list) else []

    # --- write ops ------------------------------------------------------

    def create_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a vault item from a raw bw JSON payload."""
        serve = self._backend()
        if serve is not None:
            result = serve.create_item(payload)
        else:
            self._ensure_unlocked()
            encoded = base64.b64encode(json.dumps(payload).encode()).decode()
            try:
                result = self._bw_json(["create", "item", encoded])
            except BitwardenVaultLocked as exc:
                raise self._write_locked_error(exc) from exc
        self._post_write()
        log.info(
            "credentials.create",
            item_id=result.get("id"),
            item_name=result.get("name"),
        )
        return result

    def edit_item(
        self, item_id: str, patch: dict[str, Any]
    ) -> dict[str, Any]:
        """Shallow-merge `patch` onto the existing item's JSON, then save.
        `patch.login` is merged into existing login sub-object so partial
        updates don't wipe unrelated fields."""
        serve = self._backend()
        if serve is not None:
            current: Any = serve.get_item_by_id(item_id)
        else:
            self._ensure_unlocked()
            try:
                current = self._bw_json(["get", "item", item_id])
            except BitwardenVaultLocked as exc:
                raise self._write_locked_error(exc) from exc
        if not isinstance(current, dict):
            raise BitwardenError(f"bw get item returned non-object for {item_id!r}")

        updated = dict(current)
        for key, value in patch.items():
            if key == "login" and isinstance(value, dict):
                updated["login"] = {**(current.get("login") or {}), **value}
            else:
                updated[key] = value

        if serve is not None:
            result = serve.edit_item(item_id, updated)
        else:
            encoded = base64.b64encode(json.dumps(updated).encode()).decode()
            try:
                result = self._bw_json(["edit", "item", item_id, encoded])
            except BitwardenVaultLocked as exc:
                raise self._write_locked_error(exc) from exc
        self._post_write()
        log.info(
            "credentials.edit",
            item_id=result.get("id"),
            item_name=result.get("name"),
        )
        return result

    def delete_item(self, item_id: str) -> None:
        """Soft-delete (to trash) a vault item."""
        serve = self._backend()
        if serve is not None:
            serve.delete_item(item_id)
        else:
            self._ensure_unlocked()
            try:
                self._run(["delete", "item", item_id], with_session=True)
            except BitwardenVaultLocked as exc:
                raise self._write_locked_error(exc) from exc
        self._post_write()
        log.info("credentials.delete", item_id=item_id)

    def _post_write(self) -> None:
        """Run after any write: push to the server, drop the stale cache."""
        try:
            if self._serve is not None and self._serve.running:
                self._serve.sync()
            else:
                self._run(["sync"], with_session=True)
        except BitwardenError as e:
            log.warning("credentials.sync_failed", error=str(e))
        self._item_cache.clear()

    def _write_locked_error(self, exc: BitwardenError) -> BitwardenVaultLocked:
        """Explain a CLI-transport write failure instead of echoing bw.

        Reads survive a rejected session via LocalBitwardenVault; writes have
        no such fallback, and a bare "Vault is locked" sent past runs chasing
        a lock that was never the problem.
        """
        return BitwardenVaultLocked(
            "the bw CLI rejected its own unlock session "
            '("Vault is locked"), which breaks every vault write. Reads still '
            "work off the local snapshot; writes cannot. Fix: leave "
            "AUTOPILOT_BW_TRANSPORT unset (or set it to `serve`) so the MCP "
            "drives a `bw serve` daemon, which unlocks in-process. Serve was "
            f"skipped here: {self._serve_error or 'transport forced to cli'}. "
            f"Underlying error: {exc}"
        )

    # --- internals ------------------------------------------------------

    def _resolve_via_serve(
        self,
        serve: BitwardenServe,
        id_or_url: str,
        username: str | None,
        errors: list[str],
    ) -> dict[str, Any] | None:
        """id → name → url, in that order, narrowing by username each time."""
        if not _looks_like_url(id_or_url) and _looks_like_uuid(id_or_url):
            try:
                return serve.get_item_by_id(id_or_url)
            except BitwardenError as exc:
                errors.append(str(exc))

        if not _looks_like_url(id_or_url):
            needle = id_or_url.lower()
            by_name = [
                it
                for it in serve.list_items(query=id_or_url)
                if _safe_lower(it.get("name")) == needle
            ]
            picked = _pick_one(by_name, username)
            if picked is not None:
                return picked
            if by_name:
                errors.append(
                    f"{len(by_name)} items named {id_or_url!r}: "
                    f"{_describe_candidates(by_name)}"
                )
                return None

        matches = serve.list_items(url=id_or_url)
        if not matches:
            errors.append(f"no items with url matching {id_or_url!r}")
            return None
        picked = _pick_one(matches, username)
        if picked is None:
            errors.append(
                f"{len(matches)} items match url {id_or_url!r}: "
                f"{_describe_candidates(matches)}"
            )
        return picked

    def _find_unique_by_url(
        self, url: str, errors: list[str], username: str | None = None
    ) -> dict[str, Any] | None:
        try:
            matches = self._bw_json(["list", "items", "--url", url])
        except BitwardenVaultLocked:
            matches = self._get_local_vault().list_by_url(url)
        if not isinstance(matches, list) or not matches:
            errors.append(f"no items with url matching {url!r}")
            return None
        picked = _pick_one(matches, username)
        if picked is None:
            errors.append(
                f"{len(matches)} items match url {url!r}: {_describe_candidates(matches)}"
            )
        return picked

    def _get_local_vault(self) -> LocalBitwardenVault:
        if self._local_vault is None:
            self._local_vault = LocalBitwardenVault.from_disk()
        return self._local_vault

    def _ensure_unlocked(self) -> None:
        with self._lock:
            if self._session is None:
                self._unlock_locked()
                return
            if time.monotonic() - self._last_touch > self._idle_seconds:
                log.info("credentials.idle_expire")
                try:
                    self._run(["lock"], with_session=True)
                except BitwardenError:
                    pass
                self._session = None
                self._item_cache.clear()
                self._local_vault = None
                self._unlock_locked()
            else:
                self._last_touch = time.monotonic()

    def _unlock_locked(self) -> None:
        master = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        if not master:
            raise BitwardenError(
                f"no master password in keyring under "
                f"{KEYRING_SERVICE}/{KEYRING_USERNAME} — see the README"
            )
        env = {**os.environ, "BW_PW": master}
        try:
            result = subprocess.run(
                [BW_BINARY, "--nointeraction", "unlock", "--raw", "--passwordenv", "BW_PW"],
                env=env,
                capture_output=True,
                text=True,
                timeout=BW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise BitwardenTimeout(
                f"bw unlock timed out after {BW_TIMEOUT_SECONDS:.0f}s"
            ) from exc
        if result.returncode != 0:
            raise BitwardenError(f"bw unlock failed: {result.stderr.strip()}")
        self._session = result.stdout.strip()
        self._last_touch = time.monotonic()
        log.info("credentials.unlock")

    def _run(
        self, args: list[str], *, with_session: bool
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        if with_session:
            if self._session is None:
                raise BitwardenError("no active session")
            env["BW_SESSION"] = self._session
        try:
            result = subprocess.run(
                [BW_BINARY, "--nointeraction", *args],
                env=env,
                capture_output=True,
                text=True,
                timeout=BW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise BitwardenTimeout(
                f"bw {' '.join(args)} timed out after {BW_TIMEOUT_SECONDS:.0f}s"
            ) from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "Vault is locked" in stderr:
                raise BitwardenVaultLocked(f"bw {' '.join(args)} failed: {stderr}")
            raise BitwardenError(f"bw {' '.join(args)} failed: {stderr}")
        return result

    def _bw_json(self, args: list[str]) -> Any:
        text = self._run(args, with_session=True).stdout.strip()
        return json.loads(text) if text else None


# --- module-level helpers --------------------------------------------------

_DEFAULT_USERNAME_SELECTOR = (
    "input[autocomplete='username'], "
    "input[type='email']:visible, "
    "input[name='username'], "
    "input[name='email'], "
    "input[id*='user' i], "
    "input[id*='email' i]"
)


async def fill_login(
    client: BitwardenClient,
    page: Any,  # playwright.async_api.Page; Any to keep tests playwright-free
    url: str,
    *,
    username_selector: str | None = None,
    password_selector: str | None = None,
    vault_item: str | None = None,
    password_mode: str = "value",
    skip_username: bool = False,
    account: str | None = None,
) -> dict[str, Any]:
    """Inject vault credentials into a Playwright form. Password never returns.

    account:
        Username/email to disambiguate when several vault entries share the
        URL (several accounts on one provider, two banks, ...). Without it an
        ambiguous
        URL raises rather than picking one at random.

    password_mode:
        "value"     — set the field via page.fill (fast; DOM .value + events).
        "keystroke" — click + clear + page.keyboard.type. Required for sites
                      whose framework ignores .value-assigned passwords
                      (e.g. some bank login forms).

    skip_username:
        When True, fill only the password field. Used by the remembered-
        username variant of a login page (the username is pre-filled in
        a masked combobox; attempting to fill a text input would fail with
        no matching selector). Callers that set this must have already
        verified the pre-filled username is the expected one \u2014 see the
        `assert_js` step in a two-variant login playbook for the pattern.
    """
    if password_mode not in ("value", "keystroke"):
        raise ValueError(
            f"password_mode must be 'value' or 'keystroke', got {password_mode!r}"
        )

    lookup_key = vault_item or url
    item = await asyncio.to_thread(client.get_item, lookup_key, account)
    login_blob = item.get("login") or {}
    username = login_blob.get("username")
    password = login_blob.get("password")
    if not username or not password:
        raise BitwardenError(
            f"vault item {item.get('name')!r} has no username or password"
        )

    user_sel = username_selector or _DEFAULT_USERNAME_SELECTOR
    pw_sel = password_selector or "input[type=password]"

    filled: list[str] = []
    if not skip_username:
        await page.fill(user_sel, username)
        filled.append("username")
    if password_mode == "keystroke":
        await page.click(pw_sel)
        await page.fill(pw_sel, "")
        await page.keyboard.type(password)
    else:
        await page.fill(pw_sel, password)
    filled.append("password")

    log.info(
        "credentials.fill",
        item_id=item.get("id"),
        item_name=item.get("name"),
        url=url,
        fields_filled=filled,
        password_mode=password_mode,
    )
    return {
        "filled": True,
        "item_id": item.get("id"),
        "item_name": item.get("name"),
        "username": username,
        # Surfaced so the caller knows up front whether get_totp can produce
        # anything for this entry — most logins store no TOTP seed.
        "has_totp": bool((login_blob.get("totp") or "").strip()),
        "fields_filled": filled,
        "password_mode": password_mode,
    }


def reveal_credentials(
    client: BitwardenClient, vault_item: str, reason: str, account: str | None = None
) -> dict[str, str | None]:
    """Escape hatch. `reason` is mandatory and audited. Prefer fill_login."""
    if not reason or not reason.strip():
        raise ValueError("reason must be a non-empty string")
    item = client.get_item(vault_item, account)
    login_blob = item.get("login") or {}
    log.warning(
        "credentials.reveal",
        item_id=item.get("id"),
        item_name=item.get("name"),
        reason=reason.strip(),
    )
    return {
        "item_id": item.get("id"),
        "item_name": item.get("name"),
        "username": login_blob.get("username"),
        "password": login_blob.get("password"),
    }


# --- write-op helpers -------------------------------------------------------


def _build_login_payload(
    *,
    name: str,
    url: str,
    username: str,
    password: str,
    totp_secret: str | None,
    folder_id: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": 1,  # 1 = Login
        "name": name,
        "notes": None,
        "favorite": False,
        "fields": [],
        "login": {
            "uris": [{"uri": url, "match": None}],
            "username": username,
            "password": password,
            "totp": totp_secret,
        },
    }
    if folder_id:
        payload["folderId"] = folder_id
    return payload


def create_login(
    client: BitwardenClient,
    *,
    name: str,
    url: str,
    username: str,
    password: str,
    totp_secret: str | None = None,
    folder_id: str | None = None,
) -> dict[str, Any]:
    """Create a new Login item. Raises if a vault item with `name` exists."""
    for item in client.list_items(name):
        if item.get("name") == name:
            raise BitwardenError(f"vault item named {name!r} already exists")
    payload = _build_login_payload(
        name=name,
        url=url,
        username=username,
        password=password,
        totp_secret=totp_secret,
        folder_id=folder_id,
    )
    return client.create_item(payload)


def update_login(
    client: BitwardenClient,
    id_or_url: str,
    *,
    name: str | None = None,
    url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    totp_secret: str | None = None,
) -> dict[str, Any]:
    """Patch specific fields on an existing login. Raises if not found."""
    item = client.get_item(id_or_url)
    patch: dict[str, Any] = {}
    login_patch: dict[str, Any] = {}
    if name is not None:
        patch["name"] = name
    if url is not None:
        login_patch["uris"] = [{"uri": url, "match": None}]
    if username is not None:
        login_patch["username"] = username
    if password is not None:
        login_patch["password"] = password
    if totp_secret is not None:
        login_patch["totp"] = totp_secret
    if not patch and not login_patch:
        raise ValueError("update_login: no fields provided to update")
    if login_patch:
        patch["login"] = login_patch
    return client.edit_item(item["id"], patch)


def upsert_login(
    client: BitwardenClient,
    *,
    url: str,
    username: str,
    password: str,
    name: str | None = None,
    totp_secret: str | None = None,
) -> dict[str, Any]:
    """Create-or-update match by (url, username). Raises on ambiguous match.

    This is the "I just signed up, remember these creds" path. If exactly one
    vault item has this URL AND this username, its password / totp / name are
    updated in place. Zero matches creates fresh. Multiple matches on the
    same (url, username) is a data-integrity error — refuse to mutate.
    """
    matches = client.list_by_url(url)
    same_user = [
        m for m in matches if (m.get("login") or {}).get("username") == username
    ]
    if len(same_user) > 1:
        names = [m.get("name") for m in same_user]
        raise BitwardenError(
            f"{len(same_user)} vault items match url={url!r} username={username!r}: {names}"
        )
    if same_user:
        return update_login(
            client,
            same_user[0]["id"],
            name=name,
            url=url,
            username=username,
            password=password,
            totp_secret=totp_secret,
        )
    return create_login(
        client,
        name=name or url,
        url=url,
        username=username,
        password=password,
        totp_secret=totp_secret,
    )


def delete_login(
    client: BitwardenClient, id_or_url: str, *, confirm: bool = False
) -> dict[str, Any]:
    """Delete a login. `confirm=True` is required to prevent accidents."""
    if not confirm:
        raise ValueError("delete_login requires confirm=True")
    item = client.get_item(id_or_url)
    client.delete_item(item["id"])
    return {"deleted": True, "item_id": item["id"], "item_name": item.get("name")}

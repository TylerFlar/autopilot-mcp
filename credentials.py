"""Bitwarden CLI wrapper + fill-don't-reveal login helper.

Design notes worth reading before editing:

- BitwardenClient wraps the `bw` CLI via subprocess. Session token lives in
  RAM only (no file, no env persisted beyond the subprocess call). Master
  password comes from the OS keyring — see docs/bw_setup.md.
- Session idle-expires; any op after `idle_minutes` of inactivity re-locks
  and re-unlocks transparently. `lock()` clears the session explicitly.
- Reads are cached per unlocked session (get_item, list_items). Any write
  op must call `invalidate_cache()`; Slice 1 only does reads so the cache
  is steady until idle-lock.
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
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
from typing import Any
from urllib.parse import urlparse

import keyring
import pyotp
import structlog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEYRING_SERVICE = "autopilot-mcp"
KEYRING_USERNAME = "bw_master"
BW_BINARY = "bw"
BW_TIMEOUT_SECONDS = float(os.environ.get("AUTOPILOT_BW_TIMEOUT_SECONDS", "45"))

log = structlog.stdlib.get_logger("autopilot.credentials")


class BitwardenError(RuntimeError):
    """Non-recoverable error from the bw CLI or credential pipeline."""


class BitwardenTimeout(BitwardenError):
    """A bw CLI command exceeded the configured wall-clock cap."""


class BitwardenVaultLocked(BitwardenError):
    """The bw CLI rejected a command because the vault session was unusable."""


def startup_check() -> None:
    """Verify `bw` is on PATH. Raises with a pointer to setup docs if not."""
    if shutil.which(BW_BINARY) is None:
        raise BitwardenError(
            "Bitwarden CLI not found on PATH. "
            "Run the Phase 0 setup from mcps/autopilot-mcp/docs/bw_setup.md "
            "and restart the MCP."
        )


def _looks_like_url(s: str) -> bool:
    return "://" in s or s.startswith("www.")


def _safe_lower(value: Any) -> str:
    return str(value or "").lower()


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
                f"{KEYRING_SERVICE}/{KEYRING_USERNAME} - see bw_setup.md"
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

    def get_item(self, id_or_url: str) -> dict[str, Any]:
        items = self._load_items()
        if _looks_like_url(id_or_url):
            return self._single_match(self.list_by_url(id_or_url), id_or_url)

        needle = id_or_url.lower()
        matches = [
            item
            for item in items
            if item.get("id") == id_or_url or _safe_lower(item.get("name")) == needle
        ]
        if not matches:
            matches = self.list_by_url(id_or_url)
        return self._single_match(matches, id_or_url)

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
    def _single_match(matches: list[dict[str, Any]], query: str) -> dict[str, Any]:
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise BitwardenError(f"no local vault item matches {query!r}")
        names = [match.get("name") for match in matches]
        raise BitwardenError(f"{len(matches)} local vault items match {query!r}: {names}")


class BitwardenClient:
    """One instance per MCP process. Thread-safe for the single-request
    pattern the MCP actually uses; not tuned for heavy concurrency."""

    def __init__(self, *, idle_minutes: int = 15) -> None:
        self._idle_seconds = idle_minutes * 60
        self._session: str | None = None
        self._last_touch: float = 0.0
        self._lock = threading.Lock()
        self._item_cache: dict[str, Any] = {}
        self._local_vault: LocalBitwardenVault | None = None

    # --- public API -----------------------------------------------------

    def unlock(self) -> None:
        with self._lock:
            self._unlock_locked()

    def lock(self) -> None:
        with self._lock:
            if self._session is None:
                return
            try:
                self._run(["lock"], with_session=True)
            except BitwardenError:
                pass
            self._session = None
            self._item_cache.clear()
            self._local_vault = None
            log.info("credentials.lock")

    def list_items(self, query: str | None) -> list[dict[str, Any]]:
        self._ensure_unlocked()
        cache_key = f"list:{query or ''}"
        if cache_key in self._item_cache:
            return self._item_cache[cache_key]
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

    def get_item(self, id_or_url: str) -> dict[str, Any]:
        """Resolve a vault item by id, name, or URL."""
        self._ensure_unlocked()
        cache_key = f"get:{id_or_url}"
        if cache_key in self._item_cache:
            return self._item_cache[cache_key]

        item: dict[str, Any] | None = None
        errors: list[str] = []

        if _looks_like_url(id_or_url):
            item = self._find_unique_by_url(id_or_url, errors)
        else:
            try:
                item = self._bw_json(["get", "item", id_or_url])
            except BitwardenTimeout:
                raise
            except BitwardenVaultLocked:
                item = self._get_local_vault().get_item(id_or_url)
            except BitwardenError as e:
                errors.append(str(e))
                item = self._find_unique_by_url(id_or_url, errors)

        if item is None:
            raise BitwardenError(
                f"no unique vault item matches {id_or_url!r}: {'; '.join(errors)}"
            )
        self._item_cache[cache_key] = item
        log.info(
            "credentials.get",
            item_id=item.get("id"),
            item_name=item.get("name"),
        )
        return item

    def get_totp(self, id_or_url: str) -> str:
        self._ensure_unlocked()
        item = self.get_item(id_or_url)
        try:
            token = self._run(["get", "totp", item["id"]], with_session=True).stdout.strip()
        except BitwardenVaultLocked:
            totp_secret = ((item.get("login") or {}).get("totp") or "").strip()
            if not totp_secret:
                raise BitwardenError(f"vault item {item.get('name')!r} has no TOTP secret")
            token = pyotp.TOTP(totp_secret).now()
        log.info("credentials.totp", item_id=item["id"], item_name=item.get("name"))
        return token

    def sync(self) -> None:
        self._ensure_unlocked()
        self._run(["sync"], with_session=True)
        self._item_cache.clear()
        self._local_vault = None
        log.info("credentials.sync")

    def invalidate_cache(self) -> None:
        self._item_cache.clear()

    def list_by_url(self, url: str) -> list[dict[str, Any]]:
        """Vault items whose URIs match `url` (bw-side matching)."""
        self._ensure_unlocked()
        try:
            result = self._bw_json(["list", "items", "--url", url])
        except BitwardenVaultLocked:
            result = self._get_local_vault().list_by_url(url)
        return result if isinstance(result, list) else []

    # --- write ops ------------------------------------------------------

    def create_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a vault item from a raw bw JSON payload."""
        self._ensure_unlocked()
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        result = self._bw_json(["create", "item", encoded])
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
        self._ensure_unlocked()
        current = self._bw_json(["get", "item", item_id])
        if not isinstance(current, dict):
            raise BitwardenError(f"bw get item returned non-object for {item_id!r}")

        updated = dict(current)
        for key, value in patch.items():
            if key == "login" and isinstance(value, dict):
                updated["login"] = {**(current.get("login") or {}), **value}
            else:
                updated[key] = value

        encoded = base64.b64encode(json.dumps(updated).encode()).decode()
        result = self._bw_json(["edit", "item", item_id, encoded])
        self._post_write()
        log.info(
            "credentials.edit",
            item_id=result.get("id"),
            item_name=result.get("name"),
        )
        return result

    def delete_item(self, item_id: str) -> None:
        """Soft-delete (to trash) a vault item."""
        self._ensure_unlocked()
        self._run(["delete", "item", item_id], with_session=True)
        self._post_write()
        log.info("credentials.delete", item_id=item_id)

    def _post_write(self) -> None:
        """Run after any write. bw sync pushes to server; cache is stale."""
        try:
            self._run(["sync"], with_session=True)
        except BitwardenError as e:
            log.warning("credentials.sync_failed", error=str(e))
        self._item_cache.clear()

    # --- internals ------------------------------------------------------

    def _find_unique_by_url(
        self, url: str, errors: list[str]
    ) -> dict[str, Any] | None:
        try:
            matches = self._bw_json(["list", "items", "--url", url])
        except BitwardenVaultLocked:
            matches = self._get_local_vault().list_by_url(url)
        if not isinstance(matches, list) or not matches:
            errors.append(f"no items with url matching {url!r}")
            return None
        if len(matches) > 1:
            names = [m.get("name") for m in matches]
            errors.append(f"{len(matches)} items match url {url!r}: {names}")
            return None
        return matches[0]

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
                f"{KEYRING_SERVICE}/{KEYRING_USERNAME} — see bw_setup.md"
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
) -> dict[str, Any]:
    """Inject vault credentials into a Playwright form. Password never returns.

    password_mode:
        "value"     — set the field via page.fill (fast; DOM .value + events).
        "keystroke" — click + clear + page.keyboard.type. Required for sites
                      whose framework ignores .value-assigned passwords
                      (e.g. Fidelity's login form).

    skip_username:
        When True, fill only the password field. Used by the remembered-
        username variant of Fidelity's login (the username is pre-filled in
        a masked combobox; attempting to fill a text input would fail with
        no matching selector). Callers that set this must have already
        verified the pre-filled username is the expected one \u2014 see the
        `assert_js` step in fidelity_login.json for the reference pattern.
    """
    if password_mode not in ("value", "keystroke"):
        raise ValueError(
            f"password_mode must be 'value' or 'keystroke', got {password_mode!r}"
        )

    lookup_key = vault_item or url
    item = await asyncio.to_thread(client.get_item, lookup_key)
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
        "fields_filled": filled,
        "password_mode": password_mode,
    }


def reveal_credentials(
    client: BitwardenClient, vault_item: str, reason: str
) -> dict[str, str | None]:
    """Escape hatch. `reason` is mandatory and audited. Prefer fill_login."""
    if not reason or not reason.strip():
        raise ValueError("reason must be a non-empty string")
    item = client.get_item(vault_item)
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

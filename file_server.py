"""Local CORS-enabled HTTP server for handing files to in-browser uploaders.

Use case: sites whose upload widget is a custom JS handler (drag-drop zone,
fetch+FormData) instead of a standard ``<input type="file">``. The MCP can't
hand a Path into those — the file has to materialize in browser-land. This
server publishes a single file at an unguessable URL on 127.0.0.1 with
``Access-Control-Allow-Origin: *`` so any page running in the controlled
browser profile can ``fetch()`` it and synthesize a ``File`` / dispatch a
drop event.

Security envelope:
  - Bound to 127.0.0.1 only (no external reachability).
  - URL token is uuid4 hex (122 bits of entropy) — even with CORS open,
    other origins can't guess it.
  - One token = one file path (no directory traversal, no listing).
  - TTL per entry (default 30 min); idle entries reaped on every request.
  - Server starts lazily on first publish, runs in a background thread.
"""

from __future__ import annotations

import mimetypes
import os
import threading
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar


@dataclass(frozen=True)
class _Entry:
    token: str
    path: Path
    content_type: str
    size: int
    registered_at: float
    expires_at: float
    download_filename: str


class _FileRegistry:
    def __init__(self) -> None:
        self._items: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def add(
        self, path: Path, ttl: float, download_filename: str | None
    ) -> _Entry:
        token = uuid.uuid4().hex
        ct, _ = mimetypes.guess_type(path.name)
        ct = ct or "application/octet-stream"
        size = path.stat().st_size
        now = time.time()
        entry = _Entry(
            token=token,
            path=path,
            content_type=ct,
            size=size,
            registered_at=now,
            expires_at=now + ttl,
            download_filename=download_filename or path.name,
        )
        with self._lock:
            self._items[token] = entry
        return entry

    def get(self, token: str) -> _Entry | None:
        with self._lock:
            entry = self._items.get(token)
            if entry is None:
                return None
            if time.time() > entry.expires_at:
                del self._items[token]
                return None
        return entry

    def remove(self, token: str) -> bool:
        with self._lock:
            return self._items.pop(token, None) is not None

    def reap(self) -> int:
        now = time.time()
        with self._lock:
            expired = [t for t, e in self._items.items() if now > e.expires_at]
            for t in expired:
                del self._items[t]
        return len(expired)

    def snapshot(self) -> list[_Entry]:
        with self._lock:
            return list(self._items.values())


class _Handler(BaseHTTPRequestHandler):
    registry: ClassVar[_FileRegistry]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Silence the default stderr access log; the MCP has its own logger.
        return

    def _send_cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Methods", "GET, HEAD, OPTIONS"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Range, Content-Type"
        )
        self.send_header(
            "Access-Control-Expose-Headers",
            "Content-Length, Content-Range, Content-Disposition",
        )

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors()
        self.end_headers()

    def _resolve(self) -> _Entry | None:
        path = self.path.lstrip("/")
        # Accept both /file/<token> (canonical) and /<token> for convenience.
        if path.startswith("file/"):
            token = path[len("file/") :].split("?", 1)[0]
        else:
            token = path.split("?", 1)[0]
        if not token:
            return None
        self.registry.reap()
        return self.registry.get(token)

    def _send_error_cors(self, status: HTTPStatus, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(status)
        self._send_cors()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_metadata_headers(self, entry: _Entry) -> None:
        self.send_header("Content-Type", entry.content_type)
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{entry.download_filename}"',
        )
        self.send_header("Accept-Ranges", "bytes")

    def do_HEAD(self) -> None:  # noqa: N802
        entry = self._resolve()
        if entry is None:
            self._send_error_cors(HTTPStatus.NOT_FOUND, "not found or expired")
            return
        self.send_response(HTTPStatus.OK)
        self._send_cors()
        self._send_metadata_headers(entry)
        self.send_header("Content-Length", str(entry.size))
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        entry = self._resolve()
        if entry is None:
            self._send_error_cors(HTTPStatus.NOT_FOUND, "not found or expired")
            return

        range_header = self.headers.get("Range", "")
        try:
            with entry.path.open("rb") as fh:
                if range_header.startswith("bytes="):
                    start_s, _, end_s = range_header[len("bytes=") :].partition("-")
                    try:
                        start_i = int(start_s) if start_s else 0
                        end_i = int(end_s) if end_s else entry.size - 1
                    except ValueError:
                        self._send_error_cors(
                            HTTPStatus.BAD_REQUEST, "malformed Range header"
                        )
                        return
                    if start_i < 0 or end_i >= entry.size or start_i > end_i:
                        self.send_response(
                            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE
                        )
                        self._send_cors()
                        self.send_header(
                            "Content-Range", f"bytes */{entry.size}"
                        )
                        self.end_headers()
                        return
                    fh.seek(start_i)
                    length = end_i - start_i + 1
                    self.send_response(HTTPStatus.PARTIAL_CONTENT)
                    self._send_cors()
                    self._send_metadata_headers(entry)
                    self.send_header("Content-Length", str(length))
                    self.send_header(
                        "Content-Range",
                        f"bytes {start_i}-{end_i}/{entry.size}",
                    )
                    self.end_headers()
                    self._stream(fh, length)
                else:
                    self.send_response(HTTPStatus.OK)
                    self._send_cors()
                    self._send_metadata_headers(entry)
                    self.send_header("Content-Length", str(entry.size))
                    self.end_headers()
                    self._stream(fh, entry.size)
        except FileNotFoundError:
            self.registry.remove(entry.token)
            self._send_error_cors(
                HTTPStatus.GONE, "file no longer exists on disk"
            )

    def _stream(self, fh: Any, length: int) -> None:
        chunk = 64 * 1024
        remaining = length
        try:
            while remaining > 0:
                data = fh.read(min(chunk, remaining))
                if not data:
                    break
                self.wfile.write(data)
                remaining -= len(data)
        except (BrokenPipeError, ConnectionResetError):
            return


class FileServer:
    """Lazy-start CORS file server bound to 127.0.0.1.

    A single FileServer per autopilot process. The HTTP server runs in a
    background thread; ``publish()`` starts it on first call.
    """

    DEFAULT_TTL_SECONDS = 30 * 60

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.requested_port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._registry = _FileRegistry()
        self._lock = threading.Lock()

    @property
    def port(self) -> int | None:
        return self._server.server_address[1] if self._server else None

    @property
    def base_url(self) -> str | None:
        if self._server is None:
            return None
        return f"http://{self.host}:{self.port}"

    def _ensure_started(self) -> None:
        with self._lock:
            if self._server is not None:
                return
            handler_cls = type(
                "_BoundHandler",
                (_Handler,),
                {"registry": self._registry},
            )
            self._server = ThreadingHTTPServer(
                (self.host, self.requested_port), handler_cls
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="autopilot-file-server",
                daemon=True,
            )
            self._thread.start()

    def publish(
        self,
        path: str | os.PathLike[str],
        *,
        ttl_seconds: float | None = None,
        download_filename: str | None = None,
    ) -> dict[str, Any]:
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"not a regular file: {p}")
        ttl = (
            float(ttl_seconds)
            if ttl_seconds is not None
            else float(self.DEFAULT_TTL_SECONDS)
        )
        if ttl <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ensure_started()
        entry = self._registry.add(p, ttl, download_filename)
        return self._describe(entry)

    def unpublish(self, token: str) -> bool:
        return self._registry.remove(token)

    def list_entries(self) -> list[dict[str, Any]]:
        return [self._describe(e) for e in self._registry.snapshot()]

    def _describe(self, entry: _Entry) -> dict[str, Any]:
        return {
            "token": entry.token,
            "url": (
                f"{self.base_url}/file/{entry.token}"
                if self.base_url
                else None
            ),
            "path": str(entry.path),
            "filename": entry.download_filename,
            "content_type": entry.content_type,
            "size": entry.size,
            "expires_at": entry.expires_at,
        }

    def shutdown(self) -> None:
        with self._lock:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
                self._server = None
                self._thread = None

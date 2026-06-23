"""Tests for the local CORS file server."""

from __future__ import annotations

import time
import urllib.request
from pathlib import Path

import pytest

from file_server import FileServer


@pytest.fixture
def server() -> FileServer:
    s = FileServer(host="127.0.0.1", port=0)
    yield s
    s.shutdown()


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "hello.txt"
    p.write_bytes(b"hello world")
    return p


def _http_get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req) as resp:  # noqa: S310 - 127.0.0.1 only
        return resp.status, dict(resp.headers), resp.read()


def _http_request(
    url: str,
    method: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def test_publish_returns_metadata(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    assert info["filename"] == "hello.txt"
    assert info["size"] == len(b"hello world")
    assert info["content_type"] == "text/plain"
    assert info["url"].startswith("http://127.0.0.1:")
    assert len(info["token"]) == 32  # uuid4 hex
    assert info["expires_at"] > time.time()


def test_get_returns_file_bytes(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    status, headers, body = _http_get(info["url"])
    assert status == 200
    assert body == b"hello world"
    assert headers["Content-Type"] == "text/plain"
    assert headers["Content-Length"] == "11"
    assert "hello.txt" in headers["Content-Disposition"]
    # CORS header must be present so any-origin fetch() works.
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_options_preflight_returns_cors(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    status, headers, _ = _http_request(info["url"], method="OPTIONS")
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in headers["Access-Control-Allow-Methods"]


def test_head_returns_metadata_only(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    status, headers, body = _http_request(info["url"], method="HEAD")
    assert status == 200
    assert headers["Content-Length"] == "11"
    assert body == b""


def test_range_request_returns_partial(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    status, headers, body = _http_get(info["url"], headers={"Range": "bytes=0-4"})
    assert status == 206
    assert headers["Content-Range"] == "bytes 0-4/11"
    assert body == b"hello"


def test_unknown_token_returns_404(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)  # forces server start
    base = info["url"].rsplit("/", 1)[0]
    status, _, _ = _http_request(f"{base}/deadbeef", method="GET")
    assert status == 404


def test_unpublish_revokes_url(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file)
    assert server.unpublish(info["token"]) is True
    status, _, _ = _http_request(info["url"], method="GET")
    assert status == 404
    # Idempotent: second unpublish returns False.
    assert server.unpublish(info["token"]) is False


def test_expired_entry_is_reaped(server: FileServer, sample_file: Path) -> None:
    info = server.publish(sample_file, ttl_seconds=0.05)
    time.sleep(0.1)
    status, _, _ = _http_request(info["url"], method="GET")
    assert status == 404


def test_publish_rejects_missing_file(server: FileServer, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        server.publish(tmp_path / "nope.txt")


def test_publish_rejects_directory(server: FileServer, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        server.publish(tmp_path)


def test_publish_rejects_zero_ttl(server: FileServer, sample_file: Path) -> None:
    with pytest.raises(ValueError):
        server.publish(sample_file, ttl_seconds=0)


def test_list_entries_reflects_published(server: FileServer, sample_file: Path) -> None:
    a = server.publish(sample_file, download_filename="renamed.txt")
    b = server.publish(sample_file)
    entries = server.list_entries()
    tokens = {e["token"] for e in entries}
    assert tokens == {a["token"], b["token"]}
    by_token = {e["token"]: e for e in entries}
    assert by_token[a["token"]]["filename"] == "renamed.txt"


def test_disk_deletion_after_publish_returns_410(
    server: FileServer, tmp_path: Path
) -> None:
    p = tmp_path / "vanish.txt"
    p.write_bytes(b"bye")
    info = server.publish(p)
    p.unlink()
    status, _, _ = _http_request(info["url"], method="GET")
    assert status == 410
    # Entry should have been auto-removed.
    assert not any(e["token"] == info["token"] for e in server.list_entries())

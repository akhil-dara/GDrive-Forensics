import sqlite3

import pytest

from gdrive_forensics.storage import thumbnail_cache as thumbnail_cache_module
from gdrive_forensics.storage.thumbnail_cache import ThumbnailCache


class _CloseTrackingConnection:
    """Wraps a real sqlite3 connection, records close() calls and can fail on demand."""

    def __init__(self, real_conn, fail_on_create_table=False):
        self._real = real_conn
        self.closed = False
        self._fail_on_create_table = fail_on_create_table

    def execute(self, sql, *args, **kwargs):
        if self._fail_on_create_table and sql.strip().upper().startswith("CREATE TABLE"):
            raise sqlite3.OperationalError("simulated failure creating table")
        return self._real.execute(sql, *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._real.executemany(*args, **kwargs)

    def close(self):
        self.closed = True
        self._real.close()

    def __enter__(self):
        self._real.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._real.__exit__(exc_type, exc, tb)


def test_bootstrap_connection_is_closed_on_success_and_on_failure(tmp_path, monkeypatch):
    # --- error path: CREATE TABLE raises -> __init__ must still close the connection ---
    failing_connections: list[_CloseTrackingConnection] = []

    def fake_connect_failing(self):
        wrapper = _CloseTrackingConnection(sqlite3.connect(":memory:"), fail_on_create_table=True)
        failing_connections.append(wrapper)
        return wrapper

    monkeypatch.setattr(thumbnail_cache_module.ThumbnailCache, "_connect", fake_connect_failing)
    with pytest.raises(sqlite3.OperationalError):
        ThumbnailCache(tmp_path / "fail.db")
    assert len(failing_connections) == 1
    assert failing_connections[0].closed is True

    # --- success path: normal construction must also close the bootstrap connection ---
    ok_connections: list[_CloseTrackingConnection] = []

    def fake_connect_ok(self):
        wrapper = _CloseTrackingConnection(sqlite3.connect(":memory:"), fail_on_create_table=False)
        ok_connections.append(wrapper)
        return wrapper

    monkeypatch.setattr(thumbnail_cache_module.ThumbnailCache, "_connect", fake_connect_ok)
    ThumbnailCache(tmp_path / "ok.db")
    assert len(ok_connections) == 1
    assert ok_connections[0].closed is True


def test_cache_persists_and_evicts(tmp_path):
    path = tmp_path / "thumbs.db"
    cache = ThumbnailCache(path, memory_limit=2)
    assert cache.get("thumb", "a") is None
    cache.put("thumb", "a", b"A")
    cache.put("avatar", "a", b"AV")
    cache.put("thumb", "b", b"B")
    assert cache.get("thumb", "a") == b"A"          # served from disk after memory eviction
    reopened = ThumbnailCache(path)
    assert reopened.get("avatar", "a") == b"AV"
    reopened.delete("thumb", ["a", "zz"])
    assert reopened.get("thumb", "a") is None and reopened.get("thumb", "b") == b"B"
    reopened.clear("avatar")
    assert reopened.get("avatar", "a") is None and reopened.get("thumb", "b") == b"B"
    reopened.clear()
    assert reopened.get("thumb", "b") is None

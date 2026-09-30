"""Persistent thumbnail/avatar byte cache (SQLite + small in-memory LRU)."""
from __future__ import annotations

import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Iterable, Optional

from ..core.formatting import now_iso


class ThumbnailCache:
    def __init__(self, path, memory_limit: int = 2000) -> None:
        self.path = Path(path)
        self.memory_limit = memory_limit
        self._memory: "OrderedDict[tuple[str, str], bytes]" = OrderedDict()
        self._lock = threading.Lock()
        conn = self._connect()
        try:
            with conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("CREATE TABLE IF NOT EXISTS images (kind TEXT NOT NULL, cache_key TEXT NOT NULL, "
                             "data BLOB NOT NULL, created_at TEXT, PRIMARY KEY (kind, cache_key))")
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def _remember(self, key: tuple[str, str], data: bytes) -> None:
        with self._lock:
            self._memory[key] = data
            self._memory.move_to_end(key)
            while len(self._memory) > self.memory_limit:
                self._memory.popitem(last=False)

    def get(self, kind: str, key: Optional[str]) -> Optional[bytes]:
        if not key:
            return None
        mk = (kind, key)
        with self._lock:
            if mk in self._memory:
                self._memory.move_to_end(mk)
                return self._memory[mk]
        conn = self._connect()
        try:
            row = conn.execute("SELECT data FROM images WHERE kind = ? AND cache_key = ?", mk).fetchone()
        finally:
            conn.close()
        if row:
            self._remember(mk, bytes(row[0]))
            return bytes(row[0])
        return None

    def put(self, kind: str, key: Optional[str], data: bytes) -> None:
        if not key or not data:
            return
        self._remember((kind, key), data)
        conn = self._connect()
        try:
            with conn:
                conn.execute("INSERT OR REPLACE INTO images (kind, cache_key, data, created_at) VALUES (?, ?, ?, ?)",
                             (kind, key, sqlite3.Binary(data), now_iso()))
        finally:
            conn.close()

    def delete(self, kind: str, keys: Iterable[str]) -> None:
        keys = [k for k in keys if k]
        with self._lock:
            for k in keys:
                self._memory.pop((kind, k), None)
        conn = self._connect()
        try:
            with conn:
                conn.executemany("DELETE FROM images WHERE kind = ? AND cache_key = ?", [(kind, k) for k in keys])
        finally:
            conn.close()

    def clear(self, kind: Optional[str] = None) -> None:
        with self._lock:
            if kind is None:
                self._memory.clear()
            else:
                for mk in [mk for mk in self._memory if mk[0] == kind]:
                    del self._memory[mk]
        conn = self._connect()
        try:
            with conn:
                if kind is None:
                    conn.execute("DELETE FROM images")
                else:
                    conn.execute("DELETE FROM images WHERE kind = ?", (kind,))
        finally:
            conn.close()

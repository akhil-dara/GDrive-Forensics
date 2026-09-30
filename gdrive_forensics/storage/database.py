"""SQLite evidence database: connections, schema, additive migrations."""
from __future__ import annotations

import logging
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

FILES_COLUMNS = (
    "id", "name", "mime_type", "size", "created_time", "modified_time", "trashed", "shared",
    "starred", "owned_by_me", "parent_id", "full_path", "source", "md5_checksum", "sha1_checksum",
    "sha256_checksum", "web_view_link", "thumbnail_link", "version", "viewed_by_me", "metadata_json",
    "last_scan", "file_category", "file_extension", "can_download", "owner_email", "owner_name",
    "owner_photo", "is_shortcut", "shortcut_target_id", "is_public",
)

_FILES_TYPES = {
    "id": "TEXT PRIMARY KEY", "size": "INTEGER", "version": "INTEGER",
    "trashed": "BOOLEAN", "shared": "BOOLEAN", "starred": "BOOLEAN", "owned_by_me": "BOOLEAN",
    "viewed_by_me": "BOOLEAN", "can_download": "BOOLEAN", "is_shortcut": "BOOLEAN", "is_public": "BOOLEAN",
}


def _files_ddl(table: str = "files", if_not_exists: bool = True) -> str:
    cols = ",\n    ".join(f"{c} {_FILES_TYPES.get(c, 'TEXT')}" for c in FILES_COLUMNS)
    guard = "IF NOT EXISTS " if if_not_exists else ""
    return f"CREATE TABLE {guard}{table} (\n    {cols}\n)"


SCHEMA = [
    _files_ddl(),
    """CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, permission_id TEXT, type TEXT, role TEXT,
        email_address TEXT, display_name TEXT, photo_link TEXT, deleted BOOLEAN, pending_owner BOOLEAN,
        FOREIGN KEY (file_id) REFERENCES files (id))""",
    """CREATE TABLE IF NOT EXISTS user_analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT, email_address TEXT UNIQUE, display_name TEXT, photo_link TEXT,
        files_owned_count INTEGER, files_shared_with_count INTEGER, files_shared_by_count INTEGER,
        last_updated TEXT)""",
    """CREATE TABLE IF NOT EXISTS revisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, revision_id TEXT, modified_time TEXT, size INTEGER,
        md5_checksum TEXT, original_filename TEXT, mime_type TEXT, modified_by_email TEXT,
        modified_by_name TEXT, keep_forever BOOLEAN, published BOOLEAN,
        FOREIGN KEY (file_id) REFERENCES files (id))""",
    """CREATE TABLE IF NOT EXISTS session_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_email TEXT, session_start TEXT, session_end TEXT,
        total_files_scanned INTEGER, scan_duration_seconds REAL)""",
    """CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, request_type TEXT, request_url TEXT,
        request_params TEXT, response_status INTEGER, response_data TEXT, processing_time REAL)""",
    """CREATE TABLE IF NOT EXISTS export_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT UNIQUE, added_time TEXT,
        FOREIGN KEY (file_id) REFERENCES files (id))""",
    """CREATE TABLE IF NOT EXISTS export_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, export_time TEXT, local_path TEXT,
        original_hash TEXT, exported_hash TEXT, hash_verified BOOLEAN, status TEXT,
        FOREIGN KEY (file_id) REFERENCES files (id))""",
    """CREATE TABLE IF NOT EXISTS drive_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT, timestamp TEXT, actor_email TEXT,
        actor_name TEXT, action_type TEXT, target_id TEXT, target_name TEXT, target_mime_type TEXT,
        target_path TEXT, details_json TEXT, fetched_at TEXT)""",
]

# Columns added after v1; applied with ALTER TABLE ADD COLUMN when missing.
ADDITIVE_COLUMNS = {
    "export_history": [("hash_algorithm", "TEXT"), ("md5_local", "TEXT"), ("sha256_local", "TEXT"),
                       ("source", "TEXT"), ("error", "TEXT")],
    "drive_activity": [("activity_key", "TEXT"), ("actor_person", "TEXT")],
}

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_files_owner_email ON files(owner_email)",
    "CREATE INDEX IF NOT EXISTS idx_files_parent_id ON files(parent_id)",
    "CREATE INDEX IF NOT EXISTS idx_files_mime_type ON files(mime_type)",
    "CREATE INDEX IF NOT EXISTS idx_files_full_path ON files(full_path)",
    "CREATE INDEX IF NOT EXISTS idx_files_name ON files(name)",
    "CREATE INDEX IF NOT EXISTS idx_permissions_file_id ON permissions(file_id)",
    "CREATE INDEX IF NOT EXISTS idx_permissions_email ON permissions(email_address)",
    "CREATE INDEX IF NOT EXISTS idx_permissions_permission_id ON permissions(permission_id)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_file_id ON revisions(file_id)",
    "CREATE INDEX IF NOT EXISTS idx_activity_target ON drive_activity(target_id)",
    "CREATE INDEX IF NOT EXISTS idx_activity_actor ON drive_activity(actor_email)",
    "CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON drive_activity(timestamp)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_activity_key ON drive_activity(activity_key)",
]


class Database:
    """Thin wrapper: one short-lived connection per unit of work (safe across threads)."""

    def __init__(self, path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        started = time.monotonic()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.session() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            for statement in SCHEMA:
                conn.execute(statement)
            self._migrate_legacy_files_table(conn)
            self._add_missing_columns(conn)
            for statement in INDEXES:
                conn.execute(statement)
        logger.info("Database ready at %s (%.2fs)", self.path, time.monotonic() - started)

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
        return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]

    def _migrate_legacy_files_table(self, conn: sqlite3.Connection) -> None:
        if "folder_size" not in self._columns(conn, "files"):
            return
        logger.info("Migrating files table to drop legacy folder_size column")
        cols = ", ".join(FILES_COLUMNS)
        conn.execute("ALTER TABLE files RENAME TO files_legacy")
        conn.execute(_files_ddl("files", if_not_exists=False))
        conn.execute(f"INSERT INTO files ({cols}) SELECT {cols} FROM files_legacy")
        conn.execute("DROP TABLE files_legacy")

    def _add_missing_columns(self, conn: sqlite3.Connection) -> None:
        for table, additions in ADDITIVE_COLUMNS.items():
            existing = set(self._columns(conn, table))
            for name, sql_type in additions:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")

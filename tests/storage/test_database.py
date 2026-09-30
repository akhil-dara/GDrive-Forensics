import sqlite3

import pytest

from gdrive_forensics.storage.database import FILES_COLUMNS, Database


def tables(db):
    with db.session() as conn:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def columns(db, table):
    with db.session() as conn:
        return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def test_initialize_creates_schema(tmp_path):
    db = Database(tmp_path / "t.db")
    db.initialize()
    db.initialize()  # idempotent
    assert {"files", "permissions", "user_analytics", "revisions", "session_metadata", "api_logs",
            "export_queue", "export_history", "drive_activity"} <= tables(db)
    assert tuple(columns(db, "files")) == FILES_COLUMNS
    assert {"hash_algorithm", "md5_local", "sha256_local", "source", "error"} <= set(columns(db, "export_history"))
    assert {"activity_key", "actor_person"} <= set(columns(db, "drive_activity"))
    with db.session() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_session_rolls_back_on_error(tmp_path):
    db = Database(tmp_path / "t.db")
    db.initialize()
    with pytest.raises(RuntimeError):
        with db.session() as conn:
            conn.execute("INSERT INTO export_queue (file_id, added_time) VALUES ('x', 't')")
            raise RuntimeError("boom")
    with db.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM export_queue").fetchone()[0] == 0


def test_migrates_legacy_folder_size_and_old_tables(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE files (id TEXT PRIMARY KEY, name TEXT, mime_type TEXT, size INTEGER, "
                 "created_time TEXT, modified_time TEXT, trashed BOOLEAN, shared BOOLEAN, starred BOOLEAN, "
                 "owned_by_me BOOLEAN, parent_id TEXT, full_path TEXT, source TEXT, md5_checksum TEXT, "
                 "sha1_checksum TEXT, sha256_checksum TEXT, web_view_link TEXT, thumbnail_link TEXT, "
                 "version INTEGER, viewed_by_me BOOLEAN, metadata_json TEXT, last_scan TEXT, file_category TEXT, "
                 "file_extension TEXT, can_download BOOLEAN, owner_email TEXT, owner_name TEXT, owner_photo TEXT, "
                 "is_shortcut BOOLEAN, shortcut_target_id TEXT, is_public BOOLEAN, folder_size INTEGER)")
    conn.execute("INSERT INTO files (id, name, folder_size) VALUES ('a', 'A', 5)")
    conn.execute("CREATE TABLE export_history (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, export_time TEXT, "
                 "local_path TEXT, original_hash TEXT, exported_hash TEXT, hash_verified BOOLEAN, status TEXT)")
    conn.execute("CREATE TABLE drive_activity (id INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT, timestamp TEXT, "
                 "actor_email TEXT, actor_name TEXT, action_type TEXT, target_id TEXT, target_name TEXT, "
                 "target_mime_type TEXT, target_path TEXT, details_json TEXT, fetched_at TEXT)")
    conn.commit()
    conn.close()
    db = Database(path)
    db.initialize()
    assert "folder_size" not in columns(db, "files")
    with db.session() as c:
        assert c.execute("SELECT name FROM files WHERE id='a'").fetchone()[0] == "A"
    assert "sha256_local" in columns(db, "export_history")
    assert "activity_key" in columns(db, "drive_activity")

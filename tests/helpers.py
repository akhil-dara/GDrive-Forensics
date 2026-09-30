"""Shared test helpers for building small evidence databases."""
from __future__ import annotations

from gdrive_forensics.storage.database import FILES_COLUMNS, Database

FILE_DEFAULTS = {
    "name": "file.txt", "mime_type": "text/plain", "size": 10, "created_time": "2025-03-01T10:00:00.000Z",
    "modified_time": "2025-03-02T10:00:00.000Z", "trashed": 0, "shared": 0, "starred": 0, "owned_by_me": 1,
    "parent_id": None, "full_path": "/file.txt", "source": "my_drive", "md5_checksum": None,
    "sha1_checksum": None, "sha256_checksum": None, "web_view_link": None, "thumbnail_link": None,
    "version": 1, "viewed_by_me": 1, "metadata_json": "{}", "last_scan": "2025-03-03T00:00:00",
    "file_category": "file", "file_extension": "txt", "can_download": 1, "owner_email": "me@x.com",
    "owner_name": "Me", "owner_photo": None, "is_shortcut": 0, "shortcut_target_id": None, "is_public": 0,
}


def make_db(tmp_path) -> Database:
    db = Database(tmp_path / "evidence.db")
    db.initialize()
    return db


def insert_file(db: Database, **overrides) -> dict:
    row = dict(FILE_DEFAULTS, **overrides)
    row.setdefault("id", overrides.get("id") or f"id-{row['name']}")
    values = [row.get(c) for c in FILES_COLUMNS]
    with db.session() as conn:
        conn.execute(f"INSERT INTO files ({','.join(FILES_COLUMNS)}) VALUES ({','.join('?' * len(FILES_COLUMNS))})", values)
    return row


def insert_permission(db: Database, **overrides) -> None:
    row = {"file_id": "f1", "permission_id": "p1", "type": "user", "role": "reader",
           "email_address": "a@x.com", "display_name": "Alice", "photo_link": None,
           "deleted": 0, "pending_owner": 0}
    row.update(overrides)
    cols = list(row)
    with db.session() as conn:
        conn.execute(f"INSERT INTO permissions ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                     [row[c] for c in cols])

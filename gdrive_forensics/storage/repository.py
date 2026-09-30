"""All SQL used by the UI and jobs. Returns plain dicts/lists."""
from __future__ import annotations

import json
import logging
from typing import Iterable, Iterator, Optional

from ..core.filters import FilterState
from ..core.formatting import now_iso
from .database import Database

logger = logging.getLogger(__name__)
_CHUNK = 900  # stay under SQLite's host-parameter limit


def _chunks(items: Iterable, size: int = _CHUNK) -> Iterator[list]:
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _ph(n: int) -> str:
    return ",".join("?" * n)


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---------------------------------------------------------------- files
    def count_files(self, filters: FilterState) -> int:
        where, params = filters.where_clause()
        with self.db.session() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM files WHERE {where}", params).fetchone()[0]

    def list_files(self, filters: FilterState, limit: Optional[int] = None, offset: int = 0) -> list[dict]:
        where, params = filters.where_clause()
        sql = f"SELECT * FROM files WHERE {where} ORDER BY {filters.order_by()}"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = [*params, int(limit), int(offset)]
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def total_file_count(self) -> int:
        with self.db.session() as conn:
            return conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def get_file(self, file_id: str) -> Optional[dict]:
        with self.db.session() as conn:
            row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        return dict(row) if row else None

    def get_files(self, file_ids: Iterable[str]) -> list[dict]:
        ids = list(dict.fromkeys(file_ids))
        found: dict[str, dict] = {}
        with self.db.session() as conn:
            for chunk in _chunks(ids):
                for row in conn.execute(f"SELECT * FROM files WHERE id IN ({_ph(len(chunk))})", chunk):
                    found[row["id"]] = dict(row)
        return [found[i] for i in ids if i in found]

    def list_children(self, folder_id: str) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM files WHERE parent_id = ? ORDER BY name, id", (folder_id,))]

    def get_parent_link(self, file_id: str) -> Optional[tuple]:
        with self.db.session() as conn:
            row = conn.execute("SELECT id, name, parent_id FROM files WHERE id = ?", (file_id,)).fetchone()
        return (row["id"], row["name"], row["parent_id"]) if row else None

    def duplicate_keys(self, names: Iterable[str]) -> set:
        wanted = [n for n in dict.fromkeys(names) if n is not None]
        result: set = set()
        with self.db.session() as conn:
            for chunk in _chunks(wanted):
                for row in conn.execute(
                        f"SELECT full_path, name FROM files WHERE trashed = 0 AND name IN ({_ph(len(chunk))}) "
                        "GROUP BY full_path, name HAVING COUNT(*) > 1", chunk):
                    result.add((row["full_path"], row["name"]))
        return result

    def revision_counts(self, file_ids: Iterable[str]) -> dict[str, int]:
        ids = list(dict.fromkeys(file_ids))
        counts = {fid: 0 for fid in ids}
        with self.db.session() as conn:
            for chunk in _chunks(ids):
                for row in conn.execute(
                        f"SELECT file_id, COUNT(*) AS n FROM revisions WHERE file_id IN ({_ph(len(chunk))}) "
                        "GROUP BY file_id", chunk):
                    counts[row["file_id"]] = row["n"]
        return counts

    def get_permissions(self, file_id: str) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM permissions WHERE file_id = ? ORDER BY role DESC, display_name", (file_id,))]

    def permissions_map(self, file_ids: Iterable[str]) -> dict[str, list[dict]]:
        ids = list(dict.fromkeys(file_ids))
        result: dict[str, list[dict]] = {fid: [] for fid in ids}
        with self.db.session() as conn:
            for chunk in _chunks(ids):
                for row in conn.execute(
                        "SELECT file_id, display_name, email_address, role, type FROM permissions "
                        f"WHERE file_id IN ({_ph(len(chunk))}) ORDER BY id", chunk):
                    result[row["file_id"]].append({
                        "name": row["display_name"] or row["email_address"] or "Unknown",
                        "email": row["email_address"], "role": row["role"], "type": row["type"],
                    })
        return result

    def list_owners(self) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT owner_email AS email, MAX(owner_name) AS name, MAX(owner_photo) AS photo "
                "FROM files WHERE owner_email IS NOT NULL GROUP BY owner_email "
                "ORDER BY COALESCE(MAX(owner_name), owner_email) COLLATE NOCASE")]

    def user_analytics(self, search: str = "", limit: Optional[int] = None) -> list[dict]:
        sql = "SELECT * FROM user_analytics"
        params: list = []
        if search:
            sql += " WHERE display_name LIKE ? OR email_address LIKE ?"
            params = [f"%{search}%", f"%{search}%"]
        sql += " ORDER BY (files_owned_count + files_shared_with_count + files_shared_by_count) DESC, email_address"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

    def update_thumbnail_metadata(self, file_id: str, *, thumbnail_link, owner_photo,
                                  owner_name=None, owner_email=None) -> None:
        with self.db.session() as conn:
            conn.execute(
                "UPDATE files SET thumbnail_link = ?, owner_photo = ?, owner_name = COALESCE(owner_name, ?), "
                "owner_email = COALESCE(owner_email, ?) WHERE id = ?",
                (thumbnail_link, owner_photo, owner_name, owner_email, file_id))

    def file_paths(self, file_ids: Iterable[str]) -> dict[str, str]:
        ids = [i for i in dict.fromkeys(file_ids) if i]
        paths: dict[str, str] = {}
        with self.db.session() as conn:
            for chunk in _chunks(ids):
                for row in conn.execute(f"SELECT id, full_path FROM files WHERE id IN ({_ph(len(chunk))})", chunk):
                    paths[row["id"]] = row["full_path"]
        return paths

    # ---------------------------------------------------------------- queue
    def queue_ids(self) -> list[str]:
        with self.db.session() as conn:
            return [r[0] for r in conn.execute("SELECT file_id FROM export_queue ORDER BY added_time, id")]

    def queue_files(self) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT f.* FROM export_queue eq JOIN files f ON f.id = eq.file_id ORDER BY eq.added_time, eq.id")]

    def add_to_queue(self, file_ids: Iterable[str]) -> int:
        added = 0
        stamp = now_iso()
        with self.db.session() as conn:
            for fid in dict.fromkeys(file_ids):
                cur = conn.execute("INSERT OR IGNORE INTO export_queue (file_id, added_time) VALUES (?, ?)", (fid, stamp))
                added += cur.rowcount
        return added

    def remove_from_queue(self, file_ids: Iterable[str]) -> None:
        with self.db.session() as conn:
            for chunk in _chunks(dict.fromkeys(file_ids)):
                conn.execute(f"DELETE FROM export_queue WHERE file_id IN ({_ph(len(chunk))})", chunk)

    def clear_queue(self) -> None:
        with self.db.session() as conn:
            conn.execute("DELETE FROM export_queue")

    # ------------------------------------------------------ history/revisions
    def record_export(self, *, file_id, local_path, status, original_hash=None, exported_hash=None,
                      hash_verified=None, hash_algorithm=None, md5_local=None, sha256_local=None,
                      source=None, error=None) -> None:
        with self.db.session() as conn:
            conn.execute(
                "INSERT INTO export_history (file_id, export_time, local_path, original_hash, exported_hash, "
                "hash_verified, status, hash_algorithm, md5_local, sha256_local, source, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, now_iso(), local_path, original_hash, exported_hash, hash_verified, status,
                 hash_algorithm, md5_local, sha256_local, source, error))

    def replace_revisions(self, file_id: str, revisions: list[dict]) -> None:
        with self.db.session() as conn:
            conn.execute("DELETE FROM revisions WHERE file_id = ?", (file_id,))
            for rev in revisions:
                user = rev.get("lastModifyingUser") or {}
                conn.execute(
                    "INSERT INTO revisions (file_id, revision_id, modified_time, size, md5_checksum, "
                    "original_filename, mime_type, modified_by_email, modified_by_name, keep_forever, published) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (file_id, rev.get("id"), rev.get("modifiedTime"), rev.get("size"), rev.get("md5Checksum"),
                     rev.get("originalFilename"), rev.get("mimeType"), user.get("emailAddress"),
                     user.get("displayName"), rev.get("keepForever", False), rev.get("published", False)))

    def list_revisions(self, file_id: str) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM revisions WHERE file_id = ? ORDER BY modified_time DESC", (file_id,))]

    # ------------------------------------------------------------ analytics
    def analytics_summary(self) -> dict:
        with self.db.session() as conn:
            row = conn.execute(
                "SELECT "
                "SUM(CASE WHEN trashed = 0 THEN 1 ELSE 0 END) AS total_files, "
                "SUM(CASE WHEN trashed = 0 AND owned_by_me = 1 THEN 1 ELSE 0 END) AS owned_files, "
                "SUM(CASE WHEN trashed = 0 AND owned_by_me = 0 THEN 1 ELSE 0 END) AS shared_files, "
                "SUM(CASE WHEN trashed = 0 THEN COALESCE(size, 0) ELSE 0 END) AS total_size, "
                "SUM(CASE WHEN trashed = 0 AND starred = 1 THEN 1 ELSE 0 END) AS starred, "
                "SUM(CASE WHEN trashed = 0 AND is_public = 1 THEN 1 ELSE 0 END) AS public, "
                "SUM(CASE WHEN trashed = 1 THEN 1 ELSE 0 END) AS trashed_count, "
                "SUM(CASE WHEN trashed = 1 THEN COALESCE(size, 0) ELSE 0 END) AS trashed_size "
                "FROM files").fetchone()
        return {key: (row[key] or 0) for key in row.keys()}

    def top_largest_files(self, limit: int = 100) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT id, name, size, owner_name, owner_email, mime_type FROM files "
                "WHERE trashed = 0 AND size > 0 ORDER BY size DESC LIMIT ?", (limit,))]

    def type_distribution(self, limit: int = 15) -> list[tuple[str, int]]:
        with self.db.session() as conn:
            return [(r[0], r[1]) for r in conn.execute(
                "SELECT mime_type, COUNT(*) AS n FROM files WHERE trashed = 0 "
                "GROUP BY mime_type ORDER BY n DESC LIMIT ?", (limit,))]

    def storage_by_owner(self, limit: int = 20) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT owner_email, MAX(owner_name) AS owner_name, COALESCE(SUM(size), 0) AS total_size, "
                "COUNT(*) AS file_count FROM files WHERE trashed = 0 AND owner_email IS NOT NULL "
                "GROUP BY owner_email ORDER BY total_size DESC LIMIT ?", (limit,))]

    # --------------------------------------------------------------- api log
    def log_api_call(self, *, request_type, url, params, status, response, elapsed) -> None:
        with self.db.session() as conn:
            conn.execute(
                "INSERT INTO api_logs (timestamp, request_type, request_url, request_params, response_status, "
                "response_data, processing_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now_iso(), request_type, url, json.dumps(params, default=str) if params else None, status,
                 json.dumps(response, default=str), elapsed))

    # -------------------------------------------------------------- activity
    _ACTIVITY_COLS = ("activity_key", "activity_id", "timestamp", "actor_person", "actor_email", "actor_name",
                      "action_type", "target_id", "target_name", "target_mime_type", "target_path",
                      "details_json", "fetched_at")

    def store_activities(self, records: Iterable[dict]) -> int:
        stamp = now_iso()
        rows = [tuple({**r, "fetched_at": stamp}.get(c) for c in self._ACTIVITY_COLS) for r in records]
        with self.db.session() as conn:
            before = conn.total_changes
            conn.executemany(
                f"INSERT OR IGNORE INTO drive_activity ({','.join(self._ACTIVITY_COLS)}) "
                f"VALUES ({_ph(len(self._ACTIVITY_COLS))})", rows)
            return conn.total_changes - before

    def file_activity(self, file_id: str, limit: int = 10) -> list[dict]:
        with self.db.session() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM drive_activity WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?", (file_id, limit))]

    def activity_count(self) -> int:
        with self.db.session() as conn:
            return conn.execute("SELECT COUNT(*) FROM drive_activity").fetchone()[0]

    def activity_stats(self, top: int = 5) -> dict:
        with self.db.session() as conn:
            total = conn.execute("SELECT COUNT(*) FROM drive_activity").fetchone()[0]
            by_type = [(r[0], r[1]) for r in conn.execute(
                "SELECT action_type, COUNT(*) AS n FROM drive_activity GROUP BY action_type ORDER BY n DESC, action_type")]
            actors = [(r[0], r[1]) for r in conn.execute(
                "SELECT COALESCE(actor_email, actor_name, actor_person, 'Unknown') AS actor, COUNT(*) AS n "
                "FROM drive_activity GROUP BY actor ORDER BY n DESC, actor LIMIT ?", (top,))]
        return {"total": total, "by_type": by_type, "top_actors": actors}

    def resolve_people(self, person_names: Iterable[str]) -> dict[str, tuple]:
        """Map 'people/<id>' (Drive Activity actor) to (name, email) using Drive permission ids."""
        wanted = {p: p.split("/", 1)[1] for p in dict.fromkeys(person_names) if p and p.startswith("people/")}
        by_id: dict[str, tuple] = {}
        with self.db.session() as conn:
            for chunk in _chunks(set(wanted.values())):
                for row in conn.execute(
                        "SELECT permission_id, MAX(display_name) AS name, MAX(email_address) AS email "
                        f"FROM permissions WHERE permission_id IN ({_ph(len(chunk))}) GROUP BY permission_id", chunk):
                    by_id[row["permission_id"]] = (row["name"], row["email"])
        return {person: by_id[pid] for person, pid in wanted.items() if pid in by_id}

"""Full Drive metadata scan. Evidence in SQLite is replaced atomically only when a scan succeeds."""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.formatting import now_iso
from ..core.mime import FOLDER_MIME, SHORTCUT_MIME
from ..storage.database import FILES_COLUMNS, Database

logger = logging.getLogger(__name__)

SCAN_FIELDS = ("nextPageToken, files(id, name, mimeType, parents, size, createdTime, modifiedTime, trashed, "
               "shared, ownedByMe, starred, owners, permissions, webViewLink, thumbnailLink, version, "
               "md5Checksum, sha1Checksum, sha256Checksum, viewedByMe, capabilities, quotaBytesUsed, "
               "shortcutDetails)")

_FILES_INSERT = (f"INSERT OR REPLACE INTO files ({', '.join(FILES_COLUMNS)}) "
                 f"VALUES ({', '.join('?' * len(FILES_COLUMNS))})")
_PERM_INSERT = ("INSERT INTO permissions (file_id, permission_id, type, role, email_address, display_name, "
                "photo_link, deleted, pending_owner) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")


@dataclass
class ScanProgress:
    status: str = "idle"          # idle | running | completed | cancelled | error
    message: str = ""
    current: int = 0
    total: int = 0
    files_processed: int = 0
    folders_processed: int = 0
    errors: int = 0
    speed: str = ""
    eta: str = "Calculating..."

    def fraction(self) -> Optional[float]:
        return min(self.current / self.total, 1.0) if self.total else None


class ScanCancelled(Exception):
    pass


def build_full_paths(files: list[dict], root_ids: set) -> None:
    """Set file['fullPath'] ('/Folder/Sub/name') iteratively; cycles and missing parents become roots."""
    folders = {f["id"]: f for f in files if f.get("mimeType") == FOLDER_MIME}
    cache: dict[str, str] = {}
    for item in files:
        chain: list[dict] = []
        seen: set = set()
        current = item
        base = ""
        while True:
            if current["id"] in cache:
                base = cache[current["id"]]
                break
            chain.append(current)
            seen.add(current["id"])
            parents = current.get("parents") or []
            if not parents or parents[0] in root_ids:
                break
            parent = folders.get(parents[0])
            if parent is None or parent["id"] in seen:
                break
            current = parent
        path = base
        for node in reversed(chain):
            path = f"{path}/{node.get('name', '')}"
            cache[node["id"]] = path
        item["fullPath"] = cache[item["id"]]


def file_row(file_data: dict, viewer_email: Optional[str], scanned_at: str) -> tuple[tuple, list[tuple]]:
    """Translate one Drive file into a `files` row and `permissions` rows (mutates file_data markers)."""
    owned = bool(file_data.get("ownedByMe", False))
    mime = file_data.get("mimeType") or ""
    size = file_data.get("size") or file_data.get("quotaBytesUsed") or 0
    parents = file_data.get("parents") or []
    owners = file_data.get("owners") or []
    owner = owners[0] if owners else {}
    owner_emails = {(o.get("emailAddress") or "").lower() for o in owners if o.get("emailAddress")}
    owner_perm_ids = {o.get("permissionId") for o in owners if o.get("permissionId")}
    is_shortcut = mime == SHORTCUT_MIME
    shortcut_target = (file_data.get("shortcutDetails") or {}).get("targetId") if is_shortcut else None
    permissions = [dict(p) for p in (file_data.get("permissions") or [])]

    is_public = any(p.get("type") == "anyone" and not p.get("deleted", False) for p in permissions)
    viewer = (viewer_email or "").lower()
    viewer_explicit = bool(viewer) and any((p.get("emailAddress") or "").lower() == viewer for p in permissions)

    def matches_owner(p: dict) -> bool:
        if (p.get("role") or "").lower() != "owner":
            return False
        email = (p.get("emailAddress") or "").lower()
        return bool(email and email in owner_emails) or p.get("id") in owner_perm_ids

    owner_only = not permissions or all(matches_owner(p) for p in permissions)
    if not is_public and not owned and owner_only and not viewer_explicit:
        # Visible to us without any grant naming us -> reachable by link.
        is_public = True
        file_data["inferredPublicLink"] = True
        file_data["inferredPublicReason"] = "owner_only_permissions_missing_viewer"

    name = file_data.get("name") or ""
    row = (
        file_data["id"], file_data.get("name"), file_data.get("mimeType"), int(size) if size else 0,
        file_data.get("createdTime"), file_data.get("modifiedTime"), file_data.get("trashed", False),
        file_data.get("shared", False), file_data.get("starred", False), owned,
        parents[0] if parents else None, file_data.get("fullPath", ""),
        "my_drive" if owned else "shared_with_me",
        file_data.get("md5Checksum"), file_data.get("sha1Checksum"), file_data.get("sha256Checksum"),
        file_data.get("webViewLink"), file_data.get("thumbnailLink"), file_data.get("version"),
        file_data.get("viewedByMe", False), json.dumps(file_data, default=str), scanned_at,
        "folder" if "folder" in mime else "file", os.path.splitext(name)[1].lower().lstrip("."),
        (file_data.get("capabilities") or {}).get("canDownload", False),
        owner.get("emailAddress"), owner.get("displayName"), owner.get("photoLink"),
        is_shortcut, shortcut_target, is_public,
    )

    perm_rows: list[tuple] = []
    seen: set = set()
    for p in permissions:
        key = p.get("emailAddress") or p.get("id") or ""
        if key and key not in seen:
            seen.add(key)
            perm_rows.append((file_data["id"], p.get("id"), p.get("type"), p.get("role"),
                              p.get("emailAddress") or p.get("type", "unknown"),
                              p.get("displayName") or p.get("type", "Unknown"), p.get("photoLink"),
                              p.get("deleted", False), p.get("pendingOwner", False)))
    for o in owners:
        email = o.get("emailAddress") or ""
        if email and email not in seen:
            seen.add(email)
            perm_rows.append((file_data["id"], o.get("permissionId"), "user", "owner", email,
                              o.get("displayName"), o.get("photoLink"), False, False))
    return row, perm_rows


def update_user_analytics(conn) -> None:
    conn.execute("DELETE FROM user_analytics")
    conn.execute(
        "INSERT INTO user_analytics (email_address, display_name, photo_link, files_owned_count, "
        "files_shared_with_count, files_shared_by_count, last_updated) "
        "SELECT u.email, u.name, u.photo, "
        "(SELECT COUNT(*) FROM files f WHERE f.owner_email = u.email AND f.trashed = 0), "
        "(SELECT COUNT(DISTINCT p.file_id) FROM permissions p JOIN files f ON p.file_id = f.id "
        " WHERE p.email_address = u.email AND p.role != 'owner' AND f.owned_by_me = 0 AND f.trashed = 0), "
        "(SELECT COUNT(*) FROM files f WHERE f.owner_email = u.email AND f.shared = 1 AND f.trashed = 0), ? "
        "FROM (SELECT owner_email AS email, MAX(owner_name) AS name, MAX(owner_photo) AS photo "
        "      FROM files WHERE owner_email IS NOT NULL GROUP BY owner_email) u",
        (now_iso(),))


def detect_duplicates(conn) -> int:
    """Flag same path+name files whose content hashes differ (metadata_json.is_duplicate='true')."""
    groups = conn.execute(
        "SELECT full_path, name FROM files WHERE trashed = 0 AND mime_type != ? "
        "GROUP BY full_path, name HAVING COUNT(*) > 1", (FOLDER_MIME,)).fetchall()
    flagged = 0
    for full_path, name in groups:
        rows = conn.execute("SELECT id, md5_checksum, sha1_checksum, sha256_checksum FROM files "
                            "WHERE full_path = ? AND name = ? AND trashed = 0", (full_path, name)).fetchall()
        hashes = {r[3] or r[2] or r[1] for r in rows if (r[3] or r[2] or r[1])}
        if len(hashes) > 1:
            flagged += 1
            conn.executemany("UPDATE files SET metadata_json = json_set(metadata_json, '$.is_duplicate', 'true') "
                             "WHERE id = ?", [(r[0],) for r in rows])
    return flagged


class DriveScanner:
    def __init__(self, client, db: Database, viewer_email: Optional[str]) -> None:
        self.client = client
        self.db = db
        self.viewer_email = viewer_email

    def scan(self, progress: Optional[Callable[[ScanProgress], None]] = None,
             cancel: Optional[threading.Event] = None) -> ScanProgress:
        state = ScanProgress(status="running", message="Initializing scan...")
        started = time.monotonic()
        session_start = now_iso()

        def emit() -> None:
            if progress:
                progress(dataclasses.replace(state))

        def check_cancel() -> None:
            if cancel is not None and cancel.is_set():
                raise ScanCancelled()

        emit()
        try:
            check_cancel()
            root_ids = {"root"}
            root_id = self.client.root_folder_id()
            if root_id:
                root_ids.add(root_id)

            files: list[dict] = []
            token: Optional[str] = None
            state.message = "Fetching file list from Google Drive..."
            emit()
            while True:
                check_cancel()
                page = self.client.list_files_page(token, SCAN_FIELDS)
                files.extend(page.get("files", []))
                elapsed = max(time.monotonic() - started, 1e-6)
                state.current = len(files)
                state.speed = f"{len(files) / elapsed:.1f} files/sec"
                state.message = f"Fetched {len(files)} files... ({state.speed})"
                emit()
                token = page.get("nextPageToken")
                if not token:
                    break

            state.total = len(files)
            state.message = "Building folder hierarchy..."
            emit()
            build_full_paths(files, root_ids)

            scanned_at = now_iso()
            file_rows: list[tuple] = []
            perm_rows: list[tuple] = []
            transform_start = time.monotonic()
            for index, item in enumerate(files, start=1):
                if index % 200 == 0:
                    check_cancel()
                try:
                    row, perms = file_row(item, self.viewer_email, scanned_at)
                    file_rows.append(row)
                    perm_rows.extend(perms)
                    if item.get("mimeType") == FOLDER_MIME:
                        state.folders_processed += 1
                    else:
                        state.files_processed += 1
                except Exception:
                    logger.exception("Error processing file %s", item.get("id"))
                    state.errors += 1
                state.current = index
                if index % 250 == 0 or index == len(files):
                    elapsed = max(time.monotonic() - transform_start, 1e-6)
                    speed = index / elapsed
                    remaining = (len(files) - index) / speed if speed else 0
                    state.speed = f"{speed:.1f} files/sec"
                    state.eta = f"{int(remaining // 60)}m {int(remaining % 60)}s"
                    state.message = (f"Processing {index}/{len(files)} | ETA: {state.eta} | "
                                     f"Speed: {state.speed}")
                    emit()

            check_cancel()
            state.message = "Saving evidence database..."
            emit()
            with self.db.session() as conn:
                conn.execute("DELETE FROM files")
                conn.execute("DELETE FROM permissions")
                conn.executemany(_FILES_INSERT, file_rows)
                conn.executemany(_PERM_INSERT, perm_rows)
                state.message = "Updating user analytics..."
                emit()
                update_user_analytics(conn)
                state.message = "Detecting duplicate files..."
                emit()
                groups = detect_duplicates(conn)
                duration = time.monotonic() - started
                conn.execute("INSERT INTO session_metadata (user_email, session_start, session_end, "
                             "total_files_scanned, scan_duration_seconds) VALUES (?, ?, ?, ?, ?)",
                             (self.viewer_email, session_start, now_iso(), len(files), duration))
            logger.info("Scan completed: %d items, %d duplicate groups, %.2fs", len(files), groups, duration)
            state.status = "completed"
            state.message = (f"Scan complete! {state.files_processed} files, {state.folders_processed} folders, "
                             f"{state.errors} errors in {int(duration)}s")
        except ScanCancelled:
            state.status = "cancelled"
            state.message = "Scan cancelled - existing evidence left unchanged"
            logger.info("Scan cancelled by user")
        except Exception as exc:
            state.status = "error"
            state.message = f"Scan failed: {exc} - existing evidence left unchanged"
            logger.exception("Scan failed")
        emit()
        return state

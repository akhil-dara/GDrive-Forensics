"""Queue / folder / filtered-set exports and metadata-only reports."""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from ..core.formatting import eta_text, format_duration, format_speed, timezone_display
from ..core.mime import FOLDER_MIME
from ..core.paths import ensure_directory, sanitize_filename, unique_file_path
from ..drive.downloads import DownloadCancelled, download_file
from ..logging_setup import EXPORT_LOGGER
from . import reports

logger = logging.getLogger(EXPORT_LOGGER)


@dataclass
class ExportProgress:
    status: str
    detail: str = ""
    fraction: Optional[float] = None
    eta: str = ""


@dataclass
class ExportResult:
    export_dir: str
    csv_path: Optional[str] = None
    json_path: Optional[str] = None
    total_files: int = 0
    processed: int = 0
    downloaded: int = 0
    failed: int = 0                  # real failures (skipped shortcuts are counted in `skipped`)
    skipped: int = 0
    verified: int = 0
    mismatched: int = 0              # exported, but Drive's checksum did not match (still exported)
    cancelled: bool = False
    # Ids of the given roots whose own record or any descendant failed to export: a queue export
    # keeps exactly these in the queue.
    failed_root_ids: set[str] = field(default_factory=set)


class PathResolver:
    """Drive path segments via parent links, caching every resolved ancestor."""

    def __init__(self, repo) -> None:
        self.repo = repo
        self._cache: dict[str, list[str]] = {}

    def segments(self, record: dict) -> list[str]:
        file_id = record.get("id")
        if file_id in self._cache:
            return self._cache[file_id]
        chain = [(file_id, record.get("name") or file_id or "Unknown")]
        visited = {file_id}
        prefix: list[str] = []
        parent = record.get("parent_id")
        while parent and parent not in visited:
            if parent in self._cache:
                prefix = self._cache[parent]
                break
            visited.add(parent)
            link = self.repo.get_parent_link(parent)
            if not link:
                break
            pid, pname, grandparent = link
            chain.append((pid, pname or pid))
            parent = grandparent
        segments = list(prefix)
        for node_id, name in reversed(chain):
            segments = segments + [name]
            self._cache[node_id] = segments
        return self._cache[file_id]

    def drive_path(self, record: dict) -> str:
        return " / ".join(self.segments(record)) or (record.get("full_path") or "/")


def gather_export_records(repo, roots: list[dict]) -> list[dict]:
    """Roots plus every descendant (depth-first, each id once)."""
    seen: set = set()
    records: list[dict] = []
    stack = list(reversed(roots))
    while stack:
        record = stack.pop()
        if record["id"] in seen:
            continue
        seen.add(record["id"])
        records.append(record)
        if record.get("mime_type") == FOLDER_MIME:
            stack.extend(reversed(repo.list_children(record["id"])))
    return records


def roots_containing(records: list[dict], root_ids: set, failed_ids: set) -> set:
    """Ids in `root_ids` whose subtree (the root itself or a descendant) contains a failed id.

    Walks each failed record up its parent folders among the gathered records, so a failure is
    attributed to every root that contains it - also when queued roots overlap (a folder and a
    file inside it both queued)."""
    folder_ids = {r["id"] for r in records if r.get("mime_type") == FOLDER_MIME}
    parent_of = {r["id"]: r.get("parent_id") for r in records}
    found: set = set()
    for failed_id in failed_ids:
        node, visited = failed_id, set()
        while node is not None and node not in visited:
            visited.add(node)
            if node in root_ids:
                found.add(node)
            parent = parent_of.get(node)
            node = parent if parent in folder_ids else None   # gather only descends into folders
    return found


def build_local_path(export_dir: str, segments: list[str], *, strip_root_dup: bool = True) -> str:
    """Join sanitized segments under export_dir; with no segments this is export_dir itself.

    strip_root_dup drops a leading segment equal to export_dir's own name, so a full-path export of a
    folder that is called like the export root does not nest it twice. Folder exports (paths already
    relative to the exported folder) pass False: there a same-named child is a real subfolder.
    """
    safe = [sanitize_filename(s) for s in segments if s]
    if strip_root_dup and safe and safe[0] == os.path.basename(export_dir):
        safe = safe[1:]
    return os.path.join(export_dir, *safe) if safe else export_dir


class QueueExporter:
    def __init__(self, repo, client, tz_name: str, download=download_file) -> None:
        self.repo = repo
        self.client = client
        self.tz_name = tz_name
        self.download = download

    def run(self, base_path: str, roots: list[dict], *, export_root_name: str = "Export",
            include_reports: bool = True, source: str = "queue", relative_to_root: bool = False,
            progress: Optional[Callable[[ExportProgress], None]] = None,
            cancel: Optional[threading.Event] = None) -> ExportResult:
        """Queue/filtered exports keep the full Drive path under Export/. A folder export
        (relative_to_root=True, single root) lays files out relative to that folder."""
        emit = progress or (lambda p: None)
        export_dir = os.path.join(base_path, export_root_name or "Export")
        ensure_directory(export_dir)
        records = gather_export_records(self.repo, roots)
        folders = [r for r in records if r.get("mime_type") == FOLDER_MIME]
        files = [r for r in records if r.get("mime_type") != FOLDER_MIME]
        total = len(files)
        result = ExportResult(export_dir=export_dir, total_files=total)
        resolver = PathResolver(self.repo)
        prefix_len = len(resolver.segments(roots[0])) if relative_to_root and len(roots) == 1 else 0

        strip_root_dup = not relative_to_root

        def local_segments(record: dict) -> list[str]:
            return resolver.segments(record)[prefix_len:]

        perms = self.repo.permissions_map([r["id"] for r in records])
        entries: list[dict] = []
        failed_ids: set = set()
        logger.info("Export (%s) of %d files / %d folders to %s", source, total, len(folders), export_dir)

        emit(ExportProgress("Preparing export...", f"Creating {len(folders)} folders", 0.02))
        for folder in folders:
            if cancel is not None and cancel.is_set():
                result.cancelled = True
                break
            local = build_local_path(export_dir, local_segments(folder), strip_root_dup=strip_root_dup)
            ensure_directory(local)
            entries.append(reports.build_report_entry(
                folder, drive_path=resolver.drive_path(folder), permissions=perms.get(folder["id"], []),
                local_path=os.path.relpath(local, base_path), tz_name=self.tz_name))

        started = time.monotonic()
        if not result.cancelled:
            for index, record in enumerate(files, start=1):
                if cancel is not None and cancel.is_set():
                    result.cancelled = True
                    break
                segments = resolver.segments(record)
                # the file's *parent* segments: with none this is export_dir itself, never its parent
                dest_dir = build_local_path(export_dir, local_segments(record)[:-1], strip_root_dup=strip_root_dup)
                label = " / ".join(segments) or record.get("name")
                size = int(record.get("size") or 0)
                file_started = time.monotonic()

                def on_progress(value: float, idx=index, name=record.get("name"), label=label, size=size,
                                file_started=file_started) -> None:
                    frac = max(0.0, min(1.0, value or 0.0))
                    done_bytes = int(size * frac)
                    elapsed = max(time.monotonic() - file_started, 0.001)
                    speed = format_speed(done_bytes / elapsed) if size else "Measuring…"
                    file_eta = format_duration((size - done_bytes) / (done_bytes / elapsed)) if done_bytes else format_duration(None)
                    emit(ExportProgress(
                        f"Downloading {name} ({idx}/{total}) – {int(frac * 100)}%",
                        f"{label}\nSpeed: {speed} • File ETA: {file_eta}",
                        ((idx - 1) + frac) / total if total else frac,
                        eta_text((idx - 1) + frac, total, time.monotonic() - started)))

                download, error, status = None, None, "failed"
                if record.get("is_shortcut"):
                    error, status = "Shortcut - export the target file itself", "skipped"
                    result.skipped += 1
                else:
                    try:
                        download = self.download(self.client, record, dest_dir, progress=on_progress, cancel=cancel)
                    except DownloadCancelled:
                        result.cancelled = True
                        break
                    except Exception as exc:
                        error = str(exc)
                        logger.error("Failed to download %s (%s): %s", record.get("name"), record["id"], exc)
                if download is not None:
                    result.downloaded += 1
                    if download.verified is True:
                        result.verified += 1
                        status = "success"
                    elif download.verified is False:
                        result.mismatched += 1
                        status = "hash_mismatch"
                    else:
                        status = "success"
                elif status == "failed":
                    result.failed += 1
                    failed_ids.add(record["id"])
                try:
                    self.repo.record_export(
                        file_id=record["id"], local_path=download.path if download else None, status=status,
                        original_hash=download.expected_hash if download else None,
                        exported_hash=download.local_hash if download else None,
                        hash_verified=download.verified if download else None,
                        hash_algorithm=download.algorithm if download else None,
                        md5_local=download.md5 if download else None,
                        sha256_local=download.sha256 if download else None, source=source, error=error)
                except Exception:
                    logger.exception("Could not write export_history for %s", record["id"])
                entries.append(reports.build_report_entry(
                    record, drive_path=resolver.drive_path(record), permissions=perms.get(record["id"], []),
                    local_path=os.path.relpath(download.path, base_path) if download else None,
                    tz_name=self.tz_name, download=download, error=error))
                result.processed = index
                emit(ExportProgress(f"Processed {record.get('name')} ({index}/{total})", label,
                                    index / total if total else 1.0,
                                    eta_text(index, total, time.monotonic() - started)))

        result.failed_root_ids = roots_containing(records, {r["id"] for r in roots}, failed_ids)
        if result.cancelled:
            emit(ExportProgress("Export cancelled",
                                f"Finished {result.processed} of {total} files. Remaining items stay in the queue.",
                                None))
            logger.info("Export cancelled after %d/%d files", result.processed, total)
            return result

        if include_reports:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Never overwrite an earlier report (two exports in the same second); the JSON follows the CSV's name.
            result.csv_path = unique_file_path(os.path.join(base_path, f"ExportReport_{stamp}.csv"))
            result.json_path = unique_file_path(os.path.splitext(result.csv_path)[0] + ".json")
            reports.write_export_csv(result.csv_path, entries)
            reports.write_export_json(result.json_path, entries, {
                "base_folder": base_path, "export_dir": export_dir, "total_records": len(entries),
                "downloaded_files": result.downloaded, "failed_files": result.failed,
                "skipped_files": result.skipped,
                "verified_files": result.verified, "hash_mismatches": result.mismatched,
                "timezone": timezone_display(self.tz_name)})
        emit(ExportProgress(f"Export complete! Files: {total}",
                            f"CSV: {result.csv_path}\nJSON: {result.json_path}" if include_reports else export_dir,
                            1.0))
        logger.info("Export finished: %s", result)
        return result


def export_metadata_report(repo, records: list[dict], fmt: str, base_path: str, tz_name: str,
                           filters_summary: str, progress: Optional[Callable[[ExportProgress], None]] = None,
                           cancel: Optional[threading.Event] = None) -> Optional[str]:
    """Metadata-only report (no downloads). Returns the written path, or None if cancelled."""
    if fmt not in ("csv", "json", "xlsx"):
        raise ValueError(f"Unsupported report format: {fmt}")
    emit = progress or (lambda p: None)
    ensure_directory(base_path)
    path = unique_file_path(os.path.join(base_path, f"FilteredReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"))
    perms = repo.permissions_map([r["id"] for r in records])
    resolver = PathResolver(repo)
    entries: list[dict] = []
    total = len(records)
    for index, record in enumerate(records, start=1):
        if cancel is not None and cancel.is_set():
            return None
        entries.append(reports.build_report_entry(
            record, drive_path=resolver.drive_path(record), permissions=perms.get(record["id"], []),
            local_path=None, tz_name=tz_name))
        if index % 50 == 0 or index == total:
            emit(ExportProgress(f"Processing {index}/{total}", entries[-1]["drive_path"], index / total))
    tz_display = timezone_display(tz_name)
    if fmt == "csv":
        reports.write_metadata_csv(path, entries, tz_display)
    elif fmt == "json":
        reports.write_metadata_json(path, entries, tz_display, filters_summary)
    else:
        reports.write_metadata_xlsx(path, entries, tz_display)
    logger.info("Metadata report (%s, %d rows) written to %s", fmt, total, path)
    return path

"""Background jobs: Drive scan, activity scan, downloads, exports and thumbnail refresh.

Threading contract: job entry points run on the Flet loop; the slow part runs on one worker thread
per job; every UI effect (dialogs, toasts, events, begin/end_job, footer activity) happens on the
loop, reached from workers only through `ctx.dispatcher.ui`. A job's UI effects are dropped when
the session that started it is no longer current (logout / re-login); its DB effects stand.
"""
from __future__ import annotations

import asyncio
import copy
import logging
import os
import threading
import time
from typing import Any, Callable, Optional

import flet as ft

from ..config import ACTIVITY_SCOPE
from ..core.mime import FOLDER_MIME
from ..core.paths import sanitize_filename
from ..drive.activity import ActivityCancelled, ActivityScanner, ActivityUnavailable
from ..drive.downloads import DownloadCancelled, DownloadResult, download_file
from ..drive.scanner import DriveScanner, ScanProgress
from ..exporting.exporter import ExportProgress, ExportResult, QueueExporter, export_metadata_report
from .context import EV_ACTIVITY_CHANGED, EV_DATA_CHANGED, EV_FILTERS_CHANGED, EV_QUEUE_CHANGED, AppContext
from .dialogs import shortcut
from .dialogs.progress import ProgressDialog

logger = logging.getLogger(__name__)

SCOPE_MESSAGE = ("Drive Activity needs extra permission. Log out and sign in again, approving "
                 "'See activity record of files in your Google Drive'.")
ACTIVITY_UNAVAILABLE_MESSAGE = (
    "The Drive Activity API is not available for this app's Google Cloud project.\n\n"
    "To enable it:\n"
    "1. Open Google Cloud Console → APIs & Services → Library\n"
    "2. Search for \"Google Drive Activity API\" and click Enable\n"
    "3. Run the activity scan again")
ACTIVITY_DAYS = 30
FINAL_STATUS_PAUSE = 1.0     # seconds a finished download's hash verdict stays on screen
EXPORT_BUSY = "An export is already running…"
_CANCELLATIONS = (DownloadCancelled, ActivityCancelled)


def quiet(fn: Callable) -> Callable:
    """Progress callbacks run inside backend loops (and after the scan's commit): never raise into them."""
    def wrapper(*args, **kwargs) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.exception("Progress callback failed")
    return wrapper


def download_verdict(result: DownloadResult) -> str:
    if result.verified is True:
        return "✅ Download complete! Hash verified."
    if result.verified is False:
        return "⚠️ Download complete! Hash mismatch!"
    return "✅ Download complete! (No hash to verify)"


def resolve_viewer(client, viewer: Optional[str]) -> Optional[str]:
    """Worker thread: the signed-in account's email when the shell's identity lookup has not landed yet.

    Scans attribute evidence to it (session_metadata.user_email, activity actor fallback); on failure
    the job still runs, unattributed, as before.
    """
    if viewer:
        return viewer
    try:
        return (client.about_user() or {}).get("emailAddress")
    except Exception as exc:
        logger.warning("Could not resolve the signed-in account for this job: %s", exc)
        return None


def record_download(repo, record: dict, result: DownloadResult, source: str) -> None:
    """Worker thread: chain-of-custody row for a single download (never fails the download)."""
    try:
        repo.record_export(
            file_id=record["id"], local_path=result.path,
            status="hash_mismatch" if result.verified is False else "success",
            original_hash=result.expected_hash, exported_hash=result.local_hash, hash_verified=result.verified,
            hash_algorithm=result.algorithm, md5_local=result.md5, sha256_local=result.sha256, source=source)
    except Exception:
        logger.exception("Could not write export_history for %s", record.get("id"))


class _Slot:
    """A claimed job name (ctx.begin_job succeeded) plus what the job captured at start.

    On exit the job is ended - and its dialog closed - unless a worker took it over (`launched`); an
    exception inside the block is logged and reported as "<failure>: <exc>" instead of propagating.
    """

    def __init__(self, ctx: AppContext, name: str, failure: str) -> None:
        self.ctx = ctx
        self.name = name
        self.failure = failure
        self.client = ctx.client
        self.session = ctx.state          # identity marker only
        self.dialog: Optional[ProgressDialog] = None
        self.launched = False

    def stale(self) -> bool:
        return self.ctx.state is not self.session

    def __enter__(self) -> "_Slot":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.launched:
            return False
        if self.dialog is not None:
            self.dialog.close()
        self.ctx.end_job(self.name)
        if exc_type is not None and issubclass(exc_type, Exception):
            logger.error("%s", self.failure, exc_info=(exc_type, exc, tb))
            if not self.stale():
                self.ctx.error(f"{self.failure}: {exc}")
            return True
        return False


class JobRunner:
    """One per signed-in session (ForensicsApp.on_authenticated). Test seams: the three factories."""

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.scanner_factory: Callable[..., Any] = DriveScanner
        self.activity_factory: Callable[..., Any] = ActivityScanner
        self.download_fn: Callable[..., DownloadResult] = download_file
        self._cancels: dict[str, threading.Event] = {}

    def cancel_all(self) -> None:
        """App closing / logout: ask every running job to stop (thread-safe)."""
        for event in list(self._cancels.values()):
            event.set()

    # ------------------------------------------------------------ plumbing
    def _begin(self, name: str, busy: str, failure: str, *, needs_client: bool = True) -> Optional[_Slot]:
        ctx = self.ctx
        if needs_client and ctx.client is None:
            ctx.error("Authenticate first to use Google Drive")
            return None
        if not ctx.begin_job(name):
            ctx.toast(busy)
            return None
        return _Slot(ctx, name, failure)

    async def _destination(self, slot: _Slot, title: str, cancelled: str) -> Optional[str]:
        path = await self.ctx.pick_directory(title)
        if not path:
            self.ctx.toast(cancelled)
            return None
        return None if slot.stale() else path

    async def _load(self, file_id: str, failure: str, missing: str) -> Optional[dict]:
        """The file's row, or None once the problem was reported (or the session changed meanwhile)."""
        session = self.ctx.state
        try:
            record = await asyncio.to_thread(self.ctx.repo.get_file, file_id)
        except Exception as exc:
            logger.exception("Loading %s failed", file_id)
            self.ctx.error(f"{failure}: {exc}")
            return None
        if self.ctx.state is not session:
            return None
        if record is None:
            self.ctx.error(missing)
        return record

    def _launch(self, slot: _Slot, work: Callable[[], Any], on_done: Callable[[Any], None],
                on_error: Callable[[Exception], None]) -> None:
        """Run `work()` on a worker thread; its outcome is handled on the loop by `_finish`."""
        def worker() -> None:
            try:
                result = work()
            except Exception as exc:
                if isinstance(exc, _CANCELLATIONS):
                    logger.info("Job %s cancelled", slot.name)
                else:
                    logger.exception("Job %s failed", slot.name)
                self.ctx.dispatcher.ui(self._finish, slot, on_error, exc)
            else:
                self.ctx.dispatcher.ui(self._finish, slot, on_done, result)

        self._cancels[slot.name] = slot.dialog.cancel_event
        try:
            self.ctx.dispatcher.background(worker, name=f"job-{slot.name}")
        except BaseException:
            self._cancels.pop(slot.name, None)
            raise
        slot.launched = True

    def _finish(self, slot: _Slot, effect: Callable[[Any], None], value: Any) -> None:
        """Loop: always close the dialog and end the job; UI effects only for the same session."""
        if self._cancels.get(slot.name) is slot.dialog.cancel_event:
            del self._cancels[slot.name]
        slot.dialog.close()
        self.ctx.end_job(slot.name)
        if slot.stale():
            logger.info("Job %s finished after the session changed; UI effects dropped", slot.name)
            return
        try:
            effect(value)
        except Exception as exc:
            logger.exception("Finishing job %s failed", slot.name)
            self.ctx.error(f"{slot.failure}: {exc}")
        if not self.ctx.active_jobs:
            self.ctx.activity(None)          # footer back to "No active downloads"

    # ---------------------------------------------------------------- scans
    def start_scan(self) -> None:
        ctx = self.ctx
        slot = self._begin("scan", "Scan already running…", "Scan failed")
        if slot is None:
            return
        with slot:
            client, db, viewer = slot.client, ctx.db, ctx.state.viewer_email
            dialog = slot.dialog = ProgressDialog(ctx, "🔍 Scanning Google Drive")
            dialog.show("Initializing scan…")

            @quiet
            def progress(p: ScanProgress) -> None:
                dialog.update(status=p.message or "Scanning…",
                              detail=f"Files: {p.files_processed} • Folders: {p.folders_processed} • "
                                     f"Errors: {p.errors}",
                              fraction=p.fraction(), eta=f"ETA: {p.eta}" if p.total else None,
                              force=p.status != "running")

            def work() -> ScanProgress:
                return self.scanner_factory(client, db, resolve_viewer(client, viewer)).scan(
                    progress=progress, cancel=dialog.cancel_event)

            def done(result: ScanProgress) -> None:
                if result.status == "completed":
                    ctx.toast("✅ Scan complete")
                    ctx.events.emit(EV_DATA_CHANGED)
                elif result.status == "cancelled":
                    ctx.toast(f"⏹ {result.message or 'Scan cancelled'}")
                else:   # evidence left unchanged by the scanner
                    ctx.error(result.message or "Scan failed", title="Scan failed")

            self._launch(slot, work, done, lambda exc: ctx.error(f"Scan failed: {exc}", title="Scan failed"))

    def start_activity_scan(self) -> None:
        ctx = self.ctx
        if ctx.client is not None and not ctx.auth.has_scope(ACTIVITY_SCOPE):
            ctx.error(SCOPE_MESSAGE, title="Permission needed")
            return
        slot = self._begin("activity", "Activity scan already running…", "Activity scan failed")
        if slot is None:
            return
        with slot:
            client, repo, viewer = slot.client, ctx.repo, ctx.state.viewer_email
            dialog = slot.dialog = ProgressDialog(ctx, "📈 Scanning Drive Activity", color=ft.Colors.AMBER_700)
            dialog.show("Fetching activity…")

            @quiet
            def progress(fetched: int, stored: int) -> None:
                dialog.update(status=f"Fetched {fetched} activity records…",
                              detail=f"{stored} new records stored • last {ACTIVITY_DAYS} days")

            def work() -> tuple:
                return self.activity_factory(client, repo, resolve_viewer(client, viewer)).scan(
                    days_back=ACTIVITY_DAYS, progress=progress, cancel=dialog.cancel_event)

            def done(counts: tuple) -> None:
                fetched, stored = counts
                ctx.events.emit(EV_ACTIVITY_CHANGED)
                ctx.toast(f"✅ Activity scan complete: {fetched} fetched, {stored} new")

            def failed(exc: Exception) -> None:
                ctx.events.emit(EV_ACTIVITY_CHANGED)   # records stored before a cancel/failure stand
                if isinstance(exc, ActivityCancelled):
                    ctx.toast("⏹ Activity scan cancelled")
                elif isinstance(exc, ActivityUnavailable):
                    ctx.error(ACTIVITY_UNAVAILABLE_MESSAGE, title="Drive Activity API unavailable")
                else:
                    ctx.error(f"Activity scan failed: {exc}")

            self._launch(slot, work, done, failed)

    # ------------------------------------------------------------ downloads
    async def download_file(self, file_id: str) -> None:
        ctx = self.ctx
        record = await self._load(file_id, "Download failed", "File not found in database")
        if record is None:
            return
        if record.get("is_shortcut"):
            if ctx.state.skip_all_shortcuts:
                ctx.toast("⏭️ Skipped shortcut")
            else:
                shortcut.show(ctx, record, on_export=lambda target: ctx.dispatcher.spawn(self.download_file, target))
            return
        if record.get("mime_type") == FOLDER_MIME:
            await self._export_folder(record)
            return
        slot = self._begin(f"download:{file_id}", "This file is already downloading…", "Download failed")
        if slot is None:
            return
        with slot:
            path = await self._destination(slot, "Select download folder", "Download cancelled")
            if path is None:
                return
            client, repo, download = slot.client, ctx.repo, self.download_fn
            dialog = slot.dialog = ProgressDialog(ctx, "⬇️ Downloading File", subtitle=(record.get("name") or "")[:60])
            dialog.show("Downloading from Google Drive…")

            @quiet
            def progress(value: float) -> None:
                dialog.update(status=f"Downloading… {int((value or 0) * 100)}%", fraction=value or 0.0)

            def work() -> DownloadResult:
                result = download(client, record, path, progress=progress, cancel=dialog.cancel_event)
                record_download(repo, record, result, "single")
                dialog.update(status=download_verdict(result), detail=result.path, fraction=1.0, force=True)
                if not dialog.backgrounded:
                    time.sleep(FINAL_STATUS_PAUSE)
                return result

            def failed(exc: Exception) -> None:
                if isinstance(exc, DownloadCancelled):
                    ctx.toast("⏹ Download cancelled")
                else:
                    ctx.error(f"Download failed: {exc}")

            self._launch(slot, work, lambda result: ctx.toast(f"✅ Downloaded: {os.path.basename(result.path)}"),
                         failed)

    # -------------------------------------------------------------- exports
    async def export_queue(self) -> None:
        slot = self._begin("export", EXPORT_BUSY, "Export failed")
        if slot is None:
            return
        with slot:
            records = await asyncio.to_thread(self.ctx.repo.queue_files)
            if not records:
                self.ctx.toast("Queue is empty")
                return
            path = await self._destination(slot, "Select export folder", "Export cancelled")
            if path is None:
                return

            def message(result: ExportResult) -> str:
                text = (f"✅ Export complete – reports saved to {result.csv_path} (verified {result.verified}, "
                        f"mismatched {result.mismatched}, failed {result.failed}, skipped {result.skipped})")
                kept = len(result.failed_root_ids)
                if kept:
                    text += f" – {kept} queued item{'' if kept == 1 else 's'} with failures kept in the queue"
                return text

            self._run_export(slot, "🚚 Exporting Queue", path, records, message, clear_queue=True)

    async def export_folder(self, folder_id: str) -> None:
        record = await self._load(folder_id, "Unable to load folder metadata", "Folder not found in database")
        if record is not None:
            await self._export_folder(record)

    async def _export_folder(self, record: dict) -> None:
        slot = self._begin("export", EXPORT_BUSY, "Folder download failed")
        if slot is None:
            return
        with slot:
            path = await self._destination(slot, "Select download folder", "Folder download cancelled")
            if path is None:
                return
            name = record.get("name") or record["id"]
            root = sanitize_filename(name) or "Folder"
            self._run_export(slot, "📁 Downloading Folder", path, [record],
                             lambda result: f"✅ Folder '{name}' downloaded to {os.path.join(path, root)}",
                             export_root_name=root, include_reports=False, source="folder", relative_to_root=True)

    async def export_filtered(self) -> None:
        slot = self._begin("export", EXPORT_BUSY, "Export failed")
        if slot is None:
            return
        with slot:
            filters = copy.deepcopy(self.ctx.state.filters)   # the loop may change filters meanwhile
            records = await asyncio.to_thread(self.ctx.repo.list_files, filters)
            if not records:
                self.ctx.toast("No files match current filters")
                return
            path = await self._destination(slot, "Select export folder", "Export cancelled")
            if path is None:
                return
            self._run_export(slot, "🚚 Exporting Filtered Results", path, records,
                             lambda result: f"✅ Exported {len(records)} filtered items", source="filtered")

    def _run_export(self, slot: _Slot, title: str, base_path: str, roots: list[dict],
                    message: Callable[[ExportResult], str], *, clear_queue: bool = False,
                    export_root_name: str = "Export", include_reports: bool = True, source: str = "queue",
                    relative_to_root: bool = False) -> None:
        ctx = self.ctx
        repo = ctx.repo
        exporter = QueueExporter(repo, slot.client, ctx.state.timezone, download=self.download_fn)
        dialog = slot.dialog = ProgressDialog(ctx, title, subtitle=base_path)
        dialog.show("Preparing export…")

        @quiet
        def progress(p: ExportProgress) -> None:
            dialog.update(status=p.status, detail=p.detail, fraction=p.fraction, eta=p.eta,
                          force=p.fraction is None or p.fraction >= 1.0)

        def work() -> tuple:
            result = exporter.run(base_path, roots, export_root_name=export_root_name,
                                  include_reports=include_reports, source=source,
                                  relative_to_root=relative_to_root, progress=progress, cancel=dialog.cancel_event)
            if not clear_queue or result.cancelled:
                return result, None, None      # a cancelled export keeps the whole queue
            try:
                # Only roots whose whole subtree was exported (hash mismatches and skipped shortcuts
                # count as processed); a root with any failure stays queued for a retry.
                repo.remove_from_queue([r["id"] for r in roots if r["id"] not in result.failed_root_ids])
                return result, repo.queue_ids(), None
            except Exception as exc:
                logger.exception("Could not clear exported items from the queue")
                return result, None, exc

        def done(outcome: tuple) -> None:
            result, queue_ids, queue_error = outcome
            if queue_ids is not None:
                ctx.state.queue_ids = queue_ids
                ctx.events.emit(EV_QUEUE_CHANGED)
            if result.cancelled:
                ctx.toast(f"⏹ Export cancelled after {result.processed} file(s)")
            else:
                ctx.toast(message(result))
            if queue_error is not None:
                ctx.error(f"Export finished, but the queue could not be cleared: {queue_error}")

        self._launch(slot, work, done, lambda exc: ctx.error(f"{slot.failure}: {exc}"))

    async def export_metadata(self, fmt: str) -> None:
        ctx = self.ctx
        label = fmt.upper()
        slot = self._begin(f"metadata:{fmt}", f"{label} export already running…", f"{label} export failed",
                           needs_client=False)
        if slot is None:
            return
        with slot:
            filters = copy.deepcopy(ctx.state.filters)
            tz_name = ctx.state.timezone
            records = await asyncio.to_thread(ctx.repo.list_files, filters)
            if not records:
                ctx.toast("No files match current filters")
                return
            path = await self._destination(slot, f"Select folder for the {label} report", "Export cancelled")
            if path is None:
                return
            repo, summary = ctx.repo, filters.summary()
            dialog = slot.dialog = ProgressDialog(ctx, f"📝 Exporting Metadata ({label})",
                                                  subtitle=f"Destination: {path}")
            dialog.show("Preparing metadata report…")

            @quiet
            def progress(p: ExportProgress) -> None:
                dialog.update(status=p.status, detail=p.detail, fraction=p.fraction,
                              force=p.fraction is not None and p.fraction >= 1.0)

            def work() -> Optional[str]:
                return export_metadata_report(repo, records, fmt, path, tz_name, summary,
                                              progress=progress, cancel=dialog.cancel_event)

            def done(written: Optional[str]) -> None:
                ctx.toast("⏹ Metadata export cancelled" if written is None else f"✅ {label} saved to {written}")

            self._launch(slot, work, done, lambda exc: ctx.error(f"{label} export failed: {exc}"))

    # ----------------------------------------------------------- thumbnails
    def refresh_thumbnails(self) -> None:
        ctx = self.ctx
        ids = list(ctx.state.current_file_ids)
        if not ids:
            ctx.toast("Load some files first")
            return
        slot = self._begin("thumbnails", "Thumbnail refresh already running…", "Failed to refresh thumbnails")
        if slot is None:
            return
        with slot:
            client, repo, thumbs, total = slot.client, ctx.repo, ctx.thumbnails, len(ids)
            dialog = slot.dialog = ProgressDialog(ctx, "🖼️ Refreshing Thumbnails")
            dialog.show("Refreshing thumbnails…")

            def work() -> tuple:
                refreshed = processed = 0
                for file_id in ids:
                    if dialog.cancel_event.is_set():
                        break
                    try:
                        meta = client.thumbnail_metadata(file_id)
                        if meta:
                            repo.update_thumbnail_metadata(
                                file_id, thumbnail_link=meta.get("thumbnail_link"),
                                owner_photo=meta.get("owner_photo"), owner_name=meta.get("owner_name"),
                                owner_email=meta.get("owner_email"))
                            refreshed += 1
                    except Exception:
                        logger.exception("Thumbnail refresh failed for %s", file_id)
                    processed += 1
                    dialog.update(status=f"Updated {processed}/{total} files", fraction=processed / total,
                                  force=processed == total)
                if thumbs is not None and processed:
                    thumbs.invalidate("thumb", ids[:processed])   # SQLite: this worker, never the loop
                    thumbs.clear("avatar")
                return refreshed, processed < total

            def done(outcome: tuple) -> None:
                refreshed, cancelled = outcome
                ctx.events.emit(EV_FILTERS_CHANGED, message="Refreshing thumbnails…")
                ctx.toast(f"⏹ Thumbnail refresh cancelled – {refreshed} refreshed" if cancelled
                          else f"✅ Refreshed {refreshed} thumbnails")

            self._launch(slot, work, done, lambda exc: ctx.error(f"Failed to refresh thumbnails: {exc}"))

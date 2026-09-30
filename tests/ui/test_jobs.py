import csv
import os
import threading

import flet as ft
import pytest

from gdrive_forensics.config import ACTIVITY_SCOPE
from gdrive_forensics.drive.activity import ActivityCancelled, ActivityUnavailable
from gdrive_forensics.drive.downloads import DownloadResult
from gdrive_forensics.drive.scanner import ScanProgress
from gdrive_forensics.ui import jobs as jobs_module
from gdrive_forensics.ui.context import EV_ACTIVITY_CHANGED, EV_DATA_CHANGED, EV_FILTERS_CHANGED
from gdrive_forensics.ui.dialogs.progress import ProgressDialog
from gdrive_forensics.ui.footer import IDLE_ACTIVITY
from tests.fakes import FakeDownloader, FakeDriveClient
from tests.fixtures.drive_samples import SAMPLE_PAGES
from tests.ui.harness import click, find, find_text, make_app, run_ui, settle, wait_until


def stub_picker(app, path):
    async def pick(title="Select folder"):
        return str(path)
    app.ctx.pick_directory = pick


def fake_download(client, record, dest_dir, progress=None, cancel=None):
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, record["name"])
    with open(path, "wb") as fh:   # closed explicitly: an unclosed handle is a ResourceWarning under -W error
        fh.write(b"x")
    if progress:
        progress(1.0)
    return DownloadResult(path=path, size=1, md5="m", sha1="s", sha256="h", algorithm=None,
                          expected_hash=None, verified=None)


@pytest.fixture(autouse=True)
def no_verdict_pause(monkeypatch):
    """A finished download lingers on its hash verdict for a second in the app; not in tests."""
    monkeypatch.setattr(jobs_module, "FINAL_STATUS_PAUSE", 0)


def test_scan_job_updates_data(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path, seeded=False, client=FakeDriveClient(pages=SAMPLE_PAGES))
        seen = []
        app.ctx.events.subscribe("data_changed", lambda **kw: seen.append(True))
        app.ctx.jobs.start_scan()
        app.ctx.jobs.start_scan()   # second click while running
        await wait_until(lambda: seen, timeout=10)
        await wait_until(lambda: "scan" not in app.ctx.active_jobs)
        assert app.ctx.repo.total_file_count() == 10
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        # Let the post-scan thumbnail batches (2 thumbs + 1 avatar) land before the loop closes.
        await wait_until(lambda: len(app.ctx.client.images) == 3)
        await settle()
    run_ui(body)


def test_scan_cancel_keeps_data(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        gate = threading.Event()

        class SlowScanner:
            def __init__(self, *a):
                pass

            def scan(self, progress=None, cancel=None):
                gate.wait(5)
                return ScanProgress(status="cancelled" if cancel.is_set() else "completed", message="done")

        app.ctx.jobs.scanner_factory = SlowScanner
        app.ctx.jobs.start_scan()
        await wait_until(lambda: find_text(session.page, "Cancel") is not None)
        await click(session, find_text(session.page, "Cancel"))
        gate.set()
        await wait_until(lambda: "scan" not in app.ctx.active_jobs)
        assert app.ctx.repo.total_file_count() == 10
    run_ui(body)


def test_single_download_and_queue_export(tmp_path):
    async def body():
        client = FakeDriveClient(contents={"pdf1": b"hello"})
        app, session, _ = await make_app(tmp_path, client=client)
        out = tmp_path / "out"
        stub_picker(app, out)
        from gdrive_forensics.drive import downloads
        app.ctx.jobs.download_fn = lambda c, r, d, progress=None, cancel=None: downloads.download_file(
            c, r, d, progress=progress, cancel=cancel, downloader_factory=FakeDownloader)
        await app.ctx.jobs.download_file("pdf1")
        await wait_until(lambda: (out / "invoice-001.pdf").exists())
        await wait_until(lambda: "download" not in " ".join(app.ctx.active_jobs))
        app.ctx.jobs.download_fn = fake_download
        app.ctx.repo.add_to_queue(["fold1", "img1"])
        app.ctx.state.queue_ids = app.ctx.repo.queue_ids()
        await app.ctx.jobs.export_queue()
        await wait_until(lambda: app.ctx.repo.queue_ids() == [], timeout=10)
        reports = [p for p in os.listdir(out) if p.startswith("ExportReport_") and p.endswith(".csv")]
        assert reports
        with open(out / reports[0], encoding="utf-8") as fh:
            ids = {r["File_ID"] for r in csv.DictReader(fh)}
        assert {"fold1", "pdf1", "img1"} <= ids
    run_ui(body)


def test_metadata_exports_and_queue_dialog(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "meta"
        stub_picker(app, out)
        for fmt in ("csv", "json", "xlsx"):
            await app.ctx.jobs.export_metadata(fmt)
        await wait_until(lambda: out.exists() and len(os.listdir(out)) == 3, timeout=10)
        app.ctx.repo.add_to_queue(["pdf1"])
        app.ctx.state.queue_ids = ["pdf1"]
        from gdrive_forensics.ui.dialogs import export_queue
        export_queue.show(app.ctx)
        await wait_until(lambda: find_text(session.page, "📋 Export Queue (1 items)") is not None)
        await click(session, find_text(session.page, "Clear All"))
        await wait_until(lambda: app.ctx.repo.queue_ids() == [])
    run_ui(body)


def test_activity_scan_requires_scope(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        app.ctx.jobs.start_activity_scan()
        await wait_until(lambda: find_text(session.page, "Drive Activity needs extra permission") is not None)
    run_ui(body)


# ------------------------------------------------------------------------------------ beyond the brief
def toolbar_button(session, tooltip):
    return find(session.page, lambda c: isinstance(c, ft.IconButton) and c.tooltip == tooltip)[0]


def report_ids(folder):
    name = next(p for p in os.listdir(folder) if p.startswith("ExportReport_") and p.endswith(".csv"))
    with open(os.path.join(folder, name), encoding="utf-8") as fh:
        return {r["File_ID"] for r in csv.DictReader(fh)}


def history(app):
    with app.ctx.db.session() as conn:
        return [tuple(r) for r in conn.execute("SELECT file_id, source, status FROM export_history ORDER BY id")]


def test_page_close_cancels_jobs_and_stops_thumbnails(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        cancelled = []

        class WaitingScanner:
            def __init__(self, *a):
                pass

            def scan(self, progress=None, cancel=None):
                cancelled.append(cancel.wait(5))
                return ScanProgress(status="cancelled", message="Scan cancelled")

        app.ctx.jobs.scanner_factory = WaitingScanner
        app.ctx.jobs.start_scan()
        assert "scan" in app.ctx.active_jobs
        pool = app.ctx.thumbnails._pool
        await click(session, session.page, "close")       # Flet dispatches page.on_close when the session ends
        await wait_until(lambda: cancelled == [True])
        await wait_until(lambda: "scan" not in app.ctx.active_jobs)
        assert app.ctx.thumbnails is None and pool._shutdown
    run_ui(body)


def test_job_finishing_after_relogin_leaves_new_session_alone(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        gate = threading.Event()

        class GatedScanner:
            def __init__(self, *a):
                pass

            def scan(self, progress=None, cancel=None):
                gate.wait(5)
                return ScanProgress(status="completed", message="done")

        app.ctx.jobs.scanner_factory = GatedScanner
        app.ctx.jobs.start_scan()
        app.on_authenticated(credentials=object(), client=FakeDriveClient())   # new session mid-job
        await settle(10)
        seen = []
        app.ctx.events.subscribe(EV_DATA_CHANGED, lambda **kw: seen.append(True))
        gate.set()
        await wait_until(lambda: "scan" not in app.ctx.active_jobs)   # the job still ends
        await settle()
        assert seen == [] and find_text(session.page, "✅ Scan complete") is None
    run_ui(body)


def test_progress_callbacks_never_raise_into_the_backend(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        raised = []

        class OddScanner:
            def __init__(self, *a):
                pass

            def scan(self, progress=None, cancel=None):
                try:
                    progress(None)        # malformed payload: the job's callback must swallow it
                except Exception as exc:
                    raised.append(exc)
                return ScanProgress(status="completed", message="ok")

        app.ctx.jobs.scanner_factory = OddScanner
        app.ctx.jobs.start_scan()
        await wait_until(lambda: find_text(session.page, "✅ Scan complete") is not None)
        assert raised == []

        dialog = ProgressDialog(app.ctx, "Broken dispatcher")

        def explode(*a, **k):
            raise RuntimeError("loop gone")

        app.ctx.dispatcher.ui = explode
        dialog.update(status="x", force=True)   # must not raise
        dialog.close()
    run_ui(body)


def test_scan_run_in_background_keeps_footer_updated(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        step, finish = threading.Event(), threading.Event()

        class SteppedScanner:
            def __init__(self, *a):
                pass

            def scan(self, progress=None, cancel=None):
                step.wait(5)
                progress(ScanProgress(status="running", message="Fetched 5 files...", current=5, total=10,
                                      files_processed=4, folders_processed=1))
                finish.wait(5)
                return ScanProgress(status="completed", message="done")

        app.ctx.jobs.scanner_factory = SteppedScanner
        footer, header = app.main_view.footer, app.main_view.header
        app.ctx.jobs.start_scan()
        app.ctx.jobs.start_scan()
        await wait_until(lambda: find_text(session.page, "Scan already running…") is not None)
        dialog = next(d for d in session.page._dialogs.controls
                      if isinstance(d, ft.AlertDialog) and find_text(d, "Scanning Google Drive"))
        await click(session, find_text(dialog, "Run in background"))
        assert not dialog.open and "scan" in app.ctx.active_jobs and header.logout_button.disabled
        step.set()
        await wait_until(lambda: footer.activity_text.value == "Fetched 5 files...")
        assert find_text(dialog, "Files: 4 • Folders: 1 • Errors: 0")
        finish.set()
        await wait_until(lambda: find_text(session.page, "✅ Scan complete") is not None)
        assert footer.activity_text.value == IDLE_ACTIVITY and not header.logout_button.disabled
    run_ui(body)


def test_toolbar_and_queue_dialog_drive_jobs(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "tb"
        stub_picker(app, out)
        app.ctx.jobs.download_fn = fake_download
        scans = []

        class RecordingScanner:
            def __init__(self, client, db, viewer):
                scans.append(viewer)

            def scan(self, progress=None, cancel=None):
                return ScanProgress(status="cancelled", message="Scan cancelled")

        app.ctx.jobs.scanner_factory = RecordingScanner
        await wait_until(lambda: app.ctx.state.viewer_email == "me@x.com")
        await click(session, toolbar_button(session, "Scan Drive"))
        await wait_until(lambda: find_text(session.page, "⏹ Scan cancelled") is not None)
        assert scans == ["me@x.com"]
        await click(session, toolbar_button(session, "Scan Drive Activity"))
        await wait_until(lambda: find_text(session.page, "Drive Activity needs extra permission") is not None)
        await click(session, toolbar_button(session, "Export JSON"))
        await wait_until(lambda: find_text(session.page, "✅ JSON saved to") is not None)
        assert [p for p in os.listdir(out) if p.startswith("FilteredReport_") and p.endswith(".json")]

        app.ctx.repo.add_to_queue(["pdf1", "img1"])
        await click(session, toolbar_button(session, "Export Queue"))
        await wait_until(lambda: find_text(session.page, "📋 Export Queue (2 items)") is not None)
        row = find(session.page, lambda c: isinstance(c, ft.ListTile) and c.title.value == "invoice-001.pdf")[0]
        assert row.trailing.tooltip == "Remove"
        await click(session, row.trailing)
        await wait_until(lambda: find_text(session.page, "📋 Export Queue (1 items)") is not None)
        assert app.ctx.state.queue_ids == ["img1"] and app.main_view.toolbar.queue_badge.label == "1"
        await click(session, find(session.page, lambda c: isinstance(c, ft.Button) and c.content == "Export Queue")[0])
        await wait_until(lambda: find_text(session.page, "✅ Export complete – reports saved to") is not None, 10)
        assert find_text(session.page, "(verified 0, mismatched 0, failed 0, skipped 0)")
        assert app.ctx.state.queue_ids == [] and app.main_view.toolbar.queue_badge.label == "0"
        assert report_ids(out) == {"img1"}
        assert history(app) == [("img1", "queue", "success")]
    run_ui(body)


def test_download_shortcut_folder_cancel_and_failure(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "dl"
        stub_picker(app, out)
        jobs = app.ctx.jobs
        jobs.download_fn = fake_download

        await jobs.download_file("cut1")                       # shortcut -> ask
        await click(session, find_text(session.page, "Export Target"))
        await wait_until(lambda: (out / "invoice-001.pdf").exists())
        await wait_until(lambda: find_text(session.page, "✅ Downloaded: invoice-001.pdf") is not None)
        assert history(app) == [("pdf1", "single", "success")]
        await jobs.download_file("cut1")
        await click(session, find_text(session.page, "Skip All Shortcuts"))
        assert app.ctx.state.skip_all_shortcuts
        await jobs.download_file("cut1")
        assert find_text(session.page, "⏭️ Skipped shortcut")

        await jobs.download_file("fold1")                      # folder -> folder export, relative layout
        await wait_until(lambda: (out / "Case Files" / "Invoices" / "invoice-001.pdf").exists())
        expected = f"✅ Folder 'Case Files' downloaded to {os.path.join(str(out), 'Case Files')}"
        await wait_until(lambda: find_text(session.page, expected) is not None)
        assert not [p for p in os.listdir(out) if p.startswith("ExportReport_")]   # no reports for folders

        async def no_pick(title="Select folder"):
            return None

        app.ctx.pick_directory = no_pick
        await jobs.download_file("img1")
        assert find_text(session.page, "Download cancelled") and not app.ctx.active_jobs

        stub_picker(app, out)

        def broken(*a, **k):
            raise RuntimeError("disk full")

        jobs.download_fn = broken
        await jobs.download_file("img1")
        await wait_until(lambda: find_text(session.page, "Download failed: disk full") is not None)
        assert not app.ctx.active_jobs and app.main_view.footer.activity_text.value == IDLE_ACTIVITY
    run_ui(body)


def test_queue_export_cancel_keeps_queue(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "q"
        stub_picker(app, out)
        started, release = threading.Event(), threading.Event()

        def slow_download(client, record, dest_dir, progress=None, cancel=None):
            started.set()
            release.wait(5)
            return fake_download(client, record, dest_dir, progress, cancel)

        app.ctx.jobs.download_fn = slow_download
        app.ctx.repo.add_to_queue(["pdf1", "img1"])
        await app.ctx.jobs.export_queue()
        await app.ctx.jobs.export_filtered()                   # one export at a time
        await wait_until(lambda: find_text(session.page, "An export is already running…") is not None)
        await wait_until(started.is_set)
        await click(session, find_text(session.page, "Cancel"))
        assert find_text(session.page, "Stopping…")
        release.set()
        await wait_until(lambda: find_text(session.page, "⏹ Export cancelled after 1 file(s)") is not None)
        assert app.ctx.repo.queue_ids() == ["pdf1", "img1"] and not app.ctx.active_jobs
    run_ui(body)


def test_filtered_and_metadata_exports_follow_filters(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "f"
        stub_picker(app, out)
        app.ctx.jobs.download_fn = fake_download
        app.ctx.repo.add_to_queue(["img1"])
        app.ctx.state.filters.search = "no-such-file"
        await app.ctx.jobs.export_filtered()
        assert find_text(session.page, "No files match current filters") and not app.ctx.active_jobs
        await app.ctx.jobs.export_metadata("csv")
        assert not app.ctx.active_jobs and not out.exists()
        app.ctx.state.filters.search = ""
        app.ctx.state.filters.starred_only = True
        await app.ctx.jobs.export_filtered()
        await wait_until(lambda: find_text(session.page, "✅ Exported 1 filtered items") is not None, 10)
        assert report_ids(out) == {"pdf1"} and app.ctx.repo.queue_ids() == ["img1"]   # queue untouched
        assert history(app) == [("pdf1", "filtered", "success")]
    run_ui(body)


def test_refresh_thumbnails_updates_links_and_reloads(tmp_path):
    async def body():
        client = FakeDriveClient()
        app, session, _ = await make_app(tmp_path, client=client)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        await wait_until(lambda: len(client.images) == 3)            # first paint: 2 thumbs + 1 avatar
        reloads = []
        app.ctx.events.subscribe(EV_FILTERS_CHANGED, lambda **kw: reloads.append(kw.get("message")))
        app.ctx.jobs.refresh_thumbnails()
        await wait_until(lambda: find_text(session.page, "✅ Refreshed 9 thumbnails") is not None)
        assert reloads == ["Refreshing thumbnails…"]
        assert app.ctx.repo.get_file("doc1")["thumbnail_link"] == "https://lh3.googleusercontent.com/doc1=s220"
        # memory + disk caches were invalidated: pdf1's thumbnail is fetched again by the reload
        await wait_until(lambda: client.images.count("https://lh3.googleusercontent.com/pdf1=s220") == 2)
        await wait_until(lambda: len(client.images) == 3 + 9)
        await settle()
    run_ui(body)


def test_activity_scan_success_and_unavailable(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: app.ctx.state.viewer_email == "me@x.com")

        class Creds:
            granted_scopes = [ACTIVITY_SCOPE]

        app.ctx.auth.credentials = Creds()
        viewers = []

        class FakeActivity:
            def __init__(self, client, repository, viewer_email):
                viewers.append(viewer_email)

            def scan(self, days_back=30, progress=None, cancel=None):
                progress(5, 3)
                return 5, 3

        app.ctx.jobs.activity_factory = FakeActivity
        app.ctx.jobs.start_activity_scan()
        await wait_until(lambda: find_text(session.page, "✅ Activity scan complete: 5 fetched, 3 new") is not None)
        assert viewers == ["me@x.com"]

        class Disabled(FakeActivity):
            def scan(self, days_back=30, progress=None, cancel=None):
                raise ActivityUnavailable("403 accessNotConfigured")

        app.ctx.jobs.activity_factory = Disabled
        app.ctx.jobs.start_activity_scan()
        await wait_until(lambda: find_text(session.page, "Google Drive Activity API") is not None)
        assert find_text(session.page, "APIs & Services") and not app.ctx.active_jobs
    run_ui(body)


def test_queue_export_keeps_roots_with_failures_and_removes_the_rest(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        out = tmp_path / "keep"
        stub_picker(app, out)
        failing = {"doc1"}

        def download(client, record, dest_dir, progress=None, cancel=None):
            if record["id"] in failing:
                raise RuntimeError("HTTP 403")
            result = fake_download(client, record, dest_dir, progress, cancel)
            if record["id"] == "img1":            # exported, but Drive's checksum did not match
                result.algorithm, result.expected_hash, result.verified = "md5", "0" * 32, False
            return result

        app.ctx.jobs.download_fn = download
        # fold1 holds doc1 (fails) and cut1 (shortcut); cut1 is also queued on its own
        app.ctx.repo.add_to_queue(["fold1", "cut1", "img1", "shared1"])
        await app.ctx.jobs.export_queue()
        await wait_until(lambda: find_text(session.page, "✅ Export complete") is not None, 10)
        assert app.ctx.repo.queue_ids() == ["fold1"]                  # only the root whose subtree failed
        assert app.ctx.state.queue_ids == ["fold1"] and app.main_view.toolbar.queue_badge.label == "1"
        assert find_text(session.page, "(verified 0, mismatched 1, failed 1, skipped 1)")
        assert find_text(session.page, "1 queued item with failures kept in the queue")
        await wait_until(lambda: not app.ctx.active_jobs)

        failing.clear()                                                # retry: everything exports now
        await app.ctx.jobs.export_queue()
        await wait_until(lambda: app.ctx.repo.queue_ids() == [], timeout=10)
        await wait_until(lambda: app.ctx.state.queue_ids == [])
    run_ui(body)


class ActivityCreds:
    granted_scopes = [ACTIVITY_SCOPE]


def activity_row(key):
    return {"activity_key": key, "timestamp": "2025-03-06T08:00:00Z", "action_type": "edit",
            "actor_email": "bob@x.com", "target_id": "pdf1"}


def test_activity_scan_outcomes_refresh_the_visible_analytics(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        ctx.auth.credentials = ActivityCreds()
        on_loop = []
        ctx.events.subscribe(EV_ACTIVITY_CHANGED,
                             lambda **kw: on_loop.append(threading.current_thread() is threading.main_thread()))
        await click(session, app.main_view.tabs, "change", 2)
        view = app.main_view.views[2]
        await wait_until(lambda: find_text(view.root, "Storage by Owner") is not None)
        assert find_text(view.root, "Activity Summary") is None

        def scanner(key, error=None):
            class Scanner:
                def __init__(self, client, repository, viewer_email):
                    self.repo = repository

                def scan(self, days_back=30, progress=None, cancel=None):
                    self.repo.store_activities([activity_row(key)])     # stored before the outcome
                    if error is not None:
                        raise error
                    return 1, 1
            return Scanner

        for count, (key, error) in enumerate([("k1", None), ("k2", ActivityCancelled()),
                                              ("k3", RuntimeError("quota exceeded"))], start=1):
            ctx.jobs.activity_factory = scanner(key, error)
            ctx.jobs.start_activity_scan()
            await wait_until(lambda: find_text(view.root, f"Total activity records: {count}") is not None)
            await wait_until(lambda: not ctx.active_jobs)
            assert on_loop == [True] * count
        ctx.close_dialog()

        await click(session, app.main_view.tabs, "change", 0)            # hidden: no analytics query
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        calls = []
        original = ctx.repo.analytics_summary
        monkeypatch.setattr(ctx.repo, "analytics_summary", lambda: calls.append(1) or original())
        ctx.jobs.activity_factory = scanner("k4")
        ctx.jobs.start_activity_scan()
        await wait_until(lambda: len(on_loop) == 4)
        await settle(10)
        assert calls == []
    run_ui(body)


def test_scan_and_activity_resolve_a_missing_viewer_in_the_worker(tmp_path, caplog):
    async def body():
        client = FakeDriveClient(pages=SAMPLE_PAGES)
        app, session, _ = await make_app(tmp_path, seeded=False, client=client)
        ctx = app.ctx
        await wait_until(lambda: ctx.state.viewer_email == "me@x.com")
        ctx.state.viewer_email = None                  # the identity lookup has not landed yet
        threads = []
        original = client.about_user
        client.about_user = lambda: threads.append(threading.current_thread()) or original()
        ctx.jobs.start_scan()                          # the real DriveScanner
        await wait_until(lambda: find_text(session.page, "✅ Scan complete") is not None, 10)
        await wait_until(lambda: "scan" not in ctx.active_jobs)
        with ctx.db.session() as conn:
            assert conn.execute("SELECT user_email FROM session_metadata ORDER BY id DESC").fetchone()[0] == "me@x.com"
        assert threads and all(t is not threading.main_thread() for t in threads)

        ctx.auth.credentials = ActivityCreds()
        viewers = []

        class FakeActivity:
            def __init__(self, client, repository, viewer_email):
                viewers.append(viewer_email)

            def scan(self, days_back=30, progress=None, cancel=None):
                return 0, 0

        ctx.jobs.activity_factory = FakeActivity
        ctx.state.viewer_email = None
        ctx.jobs.start_activity_scan()
        await wait_until(lambda: viewers == ["me@x.com"])
        await wait_until(lambda: not ctx.active_jobs)

        def offline():
            raise RuntimeError("no route to host")

        client.about_user = offline                    # lookup fails: logged, the job still runs
        with caplog.at_level("WARNING", logger="gdrive_forensics.ui.jobs"):
            ctx.jobs.start_activity_scan()
            await wait_until(lambda: viewers == ["me@x.com", None])
            await wait_until(lambda: not ctx.active_jobs)
        assert any("no route to host" in r.getMessage() for r in caplog.records)
        await wait_until(lambda: len(client.images) == 3)    # post-scan thumbnails landed before the loop closes
        await settle()
    run_ui(body)

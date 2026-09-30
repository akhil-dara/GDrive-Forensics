import flet as ft

from gdrive_forensics.ui.context import EV_FILTERS_CHANGED
from tests.fakes import FakeDriveClient
from tests.ui.harness import click, find, find_text, make_app, run_ui, settle, wait_until


def files_view(app):
    return app.main_view.views[0]


def test_initial_listing_and_thumbnails(tmp_path):
    async def body():
        client = FakeDriveClient()
        app, session, _ = await make_app(tmp_path, client=client)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)   # 10 seeded minus 1 trashed
        assert find_text(fv.root, "Case Files") and find_text(fv.root, "Path conflict")
        assert app.main_view.footer.status_text.value == "Showing 9 of 9 items | Folder: Root"
        await wait_until(lambda: len(find(fv.root, lambda c: isinstance(c, ft.Image) and isinstance(c.src, bytes))) >= 2)
        assert all("access_token" not in u for u in client.images)
    run_ui(body)


def test_folder_navigation_and_breadcrumbs(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: app.ctx.state.current_file_ids)
        fv.enter_folder("fold1", "Case Files")
        await wait_until(lambda: set(app.ctx.state.current_file_ids) == {"sub1", "doc1", "cut1"})
        assert find_text(fv.breadcrumbs, "Case Files")
        await click(session, find_text(fv.breadcrumbs, "📁 Drive Home"))
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
    run_ui(body)


def test_filters_pending_when_other_tab(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: app.ctx.state.current_file_ids)
        await click(session, app.main_view.tabs, "change", 1)
        app.ctx.state.filters.public_only = True
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Updating public filter…")
        await wait_until(lambda: find_text(session.page, "(will apply on Files tab)") is not None)
        await click(session, app.main_view.tabs, "change", 0)
        # img1 has an 'anyone' permission; shared1 is inferred public (owner-only perms, viewer not listed)
        await wait_until(lambda: set(app.ctx.state.current_file_ids) == {"img1", "shared1"})
    run_ui(body)


def test_queue_selection_and_view_mode(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: app.ctx.state.current_file_ids)
        fv.add_to_queue("pdf1")
        await wait_until(lambda: app.ctx.state.queue_ids == ["pdf1"])
        assert app.main_view.toolbar.queue_badge.label == "1"
        fv.toggle_selection_mode()
        await settle(10)
        fv.set_selected("img1", True)
        fv.add_selected_to_queue()
        await wait_until(lambda: set(app.ctx.state.queue_ids) == {"pdf1", "img1"})
        fv.add_current_page_to_queue()
        await wait_until(lambda: len(app.ctx.state.queue_ids) == 9)
        fv.set_view_mode("list")
        await settle(10)
        assert app.ctx.state.view_mode == "list"
    run_ui(body)


def test_details_context_menu_and_preview(tmp_path):
    async def body():
        client = FakeDriveClient(revisions={"pdf1": [{"id": "r1", "modifiedTime": "2025-03-01T00:00:00Z"}]})
        app, session, _ = await make_app(tmp_path, client=client)
        fv = files_view(app)
        await wait_until(lambda: app.ctx.state.current_file_ids)
        fv.show_info("pdf1")
        await wait_until(lambda: find_text(session.page, "📄 File Details") is not None)
        assert find_text(session.page, "5d41402abc4b2a76b9719d911017c592")
        await click(session, find_text(session.page, "Fetch revisions"))
        await wait_until(lambda: app.ctx.repo.revision_counts(["pdf1"])["pdf1"] == 1)
        fv.show_context_menu("pdf1")
        await wait_until(lambda: find_text(session.page, "Copy Link") is not None)
        await click(session, find_text(session.page, "Copy ID"))
        from gdrive_forensics.ui.dialogs import thumbnail_preview
        thumbnail_preview.show(app.ctx, "pdf1")
        await wait_until(lambda: find_text(session.page, "🖼️ Thumbnail Preview") is not None)
    run_ui(body)


# --------------------------------------------------------------- beyond the brief's tests

import threading  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from gdrive_forensics.ui import files_view as files_view_module  # noqa: E402
from gdrive_forensics.ui.context import EV_NAVIGATE_FILES  # noqa: E402
from gdrive_forensics.ui.dialogs import file_details, thumbnail_preview  # noqa: E402


def card_of(fv, name):
    """The card (GestureDetector) whose name text is exactly `name` (paths in tooltips also contain names)."""
    def shows(card):
        return find(card, lambda c: isinstance(c, ft.Text) and c.value == name)

    cards = [c for c in find(fv.results, lambda c: isinstance(c, ft.GestureDetector)) if shows(c)]
    assert len(cards) == 1, (name, cards)
    return cards[0]


def open_dialogs(page):
    return find(page, lambda c: isinstance(c, ft.AlertDialog) and c.open)


def open_dialog(page):
    dialogs = open_dialogs(page)
    assert len(dialogs) == 1, dialogs
    return dialogs[0]


def count_queries(monkeypatch, gate=None):
    calls = []
    original = files_view_module.query_listing

    def counting(*args):
        calls.append(args)
        if gate is not None:
            gate.wait(5)
        return original(*args)

    monkeypatch.setattr(files_view_module, "query_listing", counting)
    return calls


def test_drill_down_navigation_reloads_once(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, mv = app.ctx, app.main_view
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        calls = count_queries(monkeypatch)

        # Files already visible: FILTERS_CHANGED + NAVIGATE_FILES (select_tab(0) re-activates) -> one query.
        ctx.state.filters.owner = "others"
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering files involving Bob…")
        ctx.events.emit(EV_NAVIGATE_FILES, message="Filtering files involving Bob…")
        await wait_until(lambda: ctx.state.current_file_ids == ["shared1"])
        await settle(10)
        assert len(calls) == 1

        # From another tab: the change is deferred (toast), then applied by one activation query.
        await click(session, mv.tabs, "change", 1)
        ctx.state.filters.owner = "me"
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering my files…")
        assert find_text(session.page, "Filtering my files… (will apply on Files tab)")
        assert len(calls) == 1
        ctx.events.emit(EV_NAVIGATE_FILES)
        await wait_until(lambda: len(ctx.state.current_file_ids) == 8)
        await settle(10)
        assert len(calls) == 2 and ctx.state.active_tab == 0

        # A plain revisit reloads (data may have changed while away); a timezone switch queries once.
        await click(session, mv.tabs, "change", 2)
        await click(session, mv.tabs, "change", 0)
        await wait_until(lambda: len(calls) == 3)
        mv.header.timezone_dropdown.value = "Asia/Kolkata"
        await click(session, mv.header.timezone_dropdown, "select", "Asia/Kolkata")
        await settle(10)
        assert len(calls) == 4
        assert find_text(files_view(app).results, "Updated: 2025-03-05 15:30:00")
    run_ui(body)


def test_reload_finishing_after_logout_does_not_touch_next_session(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        gate = threading.Event()
        count_queries(monkeypatch, gate)
        app.ctx.state.filters.starred_only = True
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Applying starred filter…")
        await settle(3)                                  # the old view's query is now blocked in a worker
        app.logout()
        monkeypatch.undo()
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        gate.set()                                       # the stale starred-only listing completes now
        await settle(15)
        assert len(app.ctx.state.current_file_ids) == 9
        assert app.main_view.footer.status_text.value == "Showing 9 of 9 items | Folder: Root"
    run_ui(body)


def test_avatars_fetched_once_per_owner_and_empty_state(tmp_path):
    async def body():
        client = FakeDriveClient()
        app, session, _ = await make_app(tmp_path, client=client)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)

        def avatars():
            return find(fv.results, lambda c: isinstance(c, ft.Image) and c.width == 22)

        await wait_until(lambda: len(avatars()) == 8)    # every file owned by me (Bob has no photo)
        assert client.images.count("https://lh3.googleusercontent.com/me=s64") == 1
        assert find_text(fv.results, "Shortcut") and find_text(fv.results, "Starred")
        assert find_text(fv.results, "MD5: 5d41402abc4b2a76b9719d911017c592")

        app.ctx.state.page = 7
        app.ctx.state.filters.search = "no such file"
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Searching files…")
        await wait_until(lambda: find_text(fv.results, "No files found") is not None)
        assert app.ctx.state.current_file_ids == [] and app.ctx.state.page == 1
        assert app.main_view.footer.status_text.value == "Showing 0 of 0 items | Folder: Root"
        assert app.main_view.footer.pagination_text.value == "Page 1 of 1"
    run_ui(body)


def test_card_hover_context_menu_and_folder_double_tap(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        card = card_of(fv, "Case Files")
        tile = card.content
        await click(session, tile, "hover", True)
        assert tile.border.top.width == 2 and tile.border.top.color == ft.Colors.BLUE_200
        await click(session, tile, "hover", False)
        assert tile.border.top.color == ft.Colors.GREY_200

        await click(session, card, "secondary_tap")
        await wait_until(lambda: find_text(session.page, "Copy Path") is not None)
        menu = open_dialog(session.page)
        labels = [a.content for a in menu.actions]
        assert labels == ["Info", "Add to Queue", "Copy ID", "Copy Path", "Copy Link", "Close"]   # folder: no Download
        assert all(a.icon is not None for a in menu.actions)
        await click(session, find_text(menu, "Close"))
        assert not menu.open

        await click(session, card, "double_tap")
        await wait_until(lambda: set(app.ctx.state.current_file_ids) == {"sub1", "doc1", "cut1"})
        await click(session, card_of(fv, "Invoices"), "double_tap")
        await wait_until(lambda: app.ctx.state.current_file_ids == ["pdf1"])
        assert app.main_view.footer.status_text.value == "Showing 1 of 1 items | Folder: Case Files / Invoices"
        await click(session, find_text(fv.breadcrumbs, "Case Files"))
        await wait_until(lambda: set(app.ctx.state.current_file_ids) == {"sub1", "doc1", "cut1"})
        assert app.ctx.state.folder_stack == [("fold1", "Case Files")]
    run_ui(body)


def test_card_download_and_queue_buttons(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)

        def button(name, tooltip):
            return find(card_of(fv, name), lambda c: isinstance(c, ft.IconButton) and c.tooltip == tooltip)[0]

        app.ctx.jobs = None                 # the shell always creates a JobRunner now; test the fallback
        await click(session, button("photo.png", "Download"))
        await wait_until(lambda: find_text(session.page, "Downloads not available yet") is not None)
        downloads = []

        class Jobs:
            async def download_file(self, file_id):
                downloads.append(file_id)

        app.ctx.jobs = Jobs()
        await click(session, button("photo.png", "Download"))
        await wait_until(lambda: downloads == ["img1"])

        await click(session, button("photo.png", "Add to Queue"))
        await wait_until(lambda: app.ctx.state.queue_ids == ["img1"])
        await wait_until(lambda: find_text(session.page, "✅ Added to export queue (1 items)") is not None)
        assert app.main_view.footer.activity_text.value == "Queue size: 1 items"
        await click(session, button("photo.png", "Add to Queue"))
        await wait_until(lambda: find_text(session.page, "⚠️ File already in queue") is not None)
        fv.add_current_page_to_queue()
        await wait_until(lambda: find_text(session.page, "✅ Added 8 files from this page to queue") is not None)
        fv.add_current_page_to_queue()
        await wait_until(lambda: find_text(session.page, "All files on this page are already in queue") is not None)
        assert app.ctx.repo.queue_ids() == app.ctx.state.queue_ids and len(app.ctx.state.queue_ids) == 9
    run_ui(body)


def test_toolbar_selection_and_view_mode_drive_files_view(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, fv, toolbar = app.ctx, files_view(app), app.main_view.toolbar
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        assert not toolbar.add_page_button.disabled and toolbar.add_selected_button.disabled

        fv.add_selected_to_queue()                                          # nothing selected yet
        await wait_until(lambda: find_text(session.page, "Select files first") is not None)
        await click(session, toolbar.selection_button)
        assert ctx.state.selection_mode and toolbar.selection_button.tooltip == "Disable multi-select"
        card = card_of(fv, "photo.png")
        checkbox = card.data
        assert isinstance(checkbox, ft.Checkbox) and checkbox.value is False
        await click(session, card, "tap")
        assert ctx.state.selected_ids == {"img1"} and checkbox.value is True
        assert not toolbar.add_selected_button.disabled
        checkbox.value = False
        await click(session, checkbox, "change", False)
        assert ctx.state.selected_ids == set()
        fv.set_selected("pdf1", True)
        assert card_of(fv, "invoice-001.pdf").data.value is True
        await click(session, toolbar.add_selected_button)
        await wait_until(lambda: ctx.state.queue_ids == ["pdf1"])
        await wait_until(lambda: find_text(session.page, "✅ Added 1 files to queue") is not None)
        assert not ctx.state.selection_mode and ctx.state.selected_ids == set()
        assert card_of(fv, "photo.png").data is None                        # checkboxes gone

        await click(session, toolbar.list_button)
        assert ctx.state.view_mode == "list" and isinstance(fv.results.controls[0], ft.Column)
        assert toolbar.list_button.style.bgcolor == ft.Colors.BLUE_100
        await click(session, toolbar.tiles_button)
        assert ctx.state.view_mode == "tiles" and isinstance(fv.results.controls[0], ft.ResponsiveRow)
        await click(session, toolbar.add_page_button)
        await wait_until(lambda: len(ctx.state.queue_ids) == 9)
    run_ui(body)


def test_advanced_filters_panel(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, fv = app.ctx, files_view(app)
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        panel = fv.advanced_filters
        assert panel.body.visible is False
        await click(session, find(fv.advanced_panel, lambda c: isinstance(c, ft.GestureDetector))[0], "tap")
        assert panel.body.visible and panel.header_icon.icon == ft.Icons.REMOVE

        panel.scope_group.value = "folders"
        await click(session, panel.scope_group, "change", "folders")
        await wait_until(lambda: set(ctx.state.current_file_ids) == {"fold1", "sub1"})
        assert "Folders only" in app.main_view.sidebar.summary_text.value
        await click(session, find_text(fv.advanced_panel, "Clear"))
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        assert ctx.state.filters.scope == "all" and panel.scope_group.value == "all"
        assert find_text(session.page, "Advanced filters reset")

        pdf = panel.type_checkboxes["pdf"]
        pdf.value = True
        await click(session, pdf, "change", True)
        await wait_until(lambda: ctx.state.current_file_ids == ["pdf1"])
        await click(session, find_text(session.page, "Clear All Filters"))   # sidebar reset is mirrored here
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        assert pdf.value is False and ctx.state.filters.types == set()
    run_ui(body)


def test_advanced_filters_clear_also_drops_the_analytics_mime_filter(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, fv = app.ctx, files_view(app)
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        ctx.state.filters.mime_types = {"image/png"}                     # as set by an Analytics type chip
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering by image/png…")
        await wait_until(lambda: ctx.state.current_file_ids == ["img1"])
        await click(session, find_text(fv.advanced_panel, "Clear"))
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        assert ctx.state.filters.mime_types == set()
        assert "MIME" not in app.main_view.sidebar.summary_text.value
    run_ui(body)


def test_details_dialog_sections_and_revision_errors(tmp_path):
    async def body():
        client = FakeDriveClient()

        def broken(file_id):
            raise RuntimeError("revisions API exploded")

        client.list_revisions = broken
        app, session, _ = await make_app(tmp_path, client=client)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        app.ctx.repo.store_activities([{"activity_key": "k1", "timestamp": "2025-03-06T08:00:00Z",
                                        "actor_email": "bob@x.com", "action_type": "edit", "target_id": "pdf1"}])
        fv.show_info("pdf1")
        await wait_until(lambda: find_text(session.page, "RECENT ACTIVITY (1)") is not None)
        dialog = open_dialog(session.page)
        assert dialog.content.width == 550                       # page size unknown headless
        assert find_text(dialog, "bob@x.com • 2025-03-06 08:00:00")
        assert find_text(dialog, "SHARED WITH (1)") and find_text(dialog, "me@x.com • OWNER")
        assert find_text(dialog, "Preview Thumbnail").disabled is False
        await click(session, find_text(dialog, "Fetch revisions"))
        await wait_until(lambda: find_text(session.page, "Could not fetch revisions: revisions API exploded"))

        fv.show_info("doc1")
        await wait_until(lambda: any(find_text(d, "Meeting notes") for d in open_dialogs(session.page)))
        doc = open_dialog(session.page)
        assert find_text(doc, "Preview Thumbnail").disabled is True
        assert find_text(doc, "RECENT ACTIVITY") is None          # only shown when rows exist
        assert find_text(doc, "No revisions stored yet.")
        await click(session, find_text(doc, "Add to Queue"))
        await wait_until(lambda: app.ctx.state.queue_ids == ["doc1"])
        assert not doc.open
    run_ui(body)


def test_details_raw_metadata_field_spans_the_dialog(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        fv.show_info("pdf1")
        await wait_until(lambda: find_text(session.page, "RAW METADATA (JSON)") is not None)
        dialog = open_dialog(session.page)
        raw = find(dialog, lambda c: isinstance(c, ft.TextField) and c.multiline and c.read_only)
        assert len(raw) == 1 and '"id": "pdf1"' in raw[0].value
        column = dialog.content.content                          # the scrolling body inside the sized container
        assert raw[0] in column.controls
        assert column.horizontal_alignment == ft.CrossAxisAlignment.STRETCH   # full dialog width
    run_ui(body)


def test_dialog_size_follows_window():
    assert file_details.dialog_size(SimpleNamespace(width=None, height=None)) == (550, 500)
    assert file_details.dialog_size(SimpleNamespace(width=800, height=500)) == (560, 400)
    assert file_details.dialog_size(SimpleNamespace(width=1600, height=950)) == (650, 600)


def test_preview_refreshes_missing_link_and_opens_drive_page(tmp_path, monkeypatch):
    async def body():
        client = FakeDriveClient()
        app, session, _ = await make_app(tmp_path, client=client)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        opened = []
        monkeypatch.setattr(thumbnail_preview.webbrowser, "open", opened.append)

        thumbnail_preview.show(app.ctx, "doc1")                   # no stored thumbnail link
        await wait_until(lambda: "https://lh3.googleusercontent.com/doc1=s2048" in client.images)
        record = app.ctx.repo.get_file("doc1")
        assert record["thumbnail_link"] == "https://lh3.googleusercontent.com/doc1=s220"
        assert record["owner_photo"] == "https://lh3.googleusercontent.com/me=s64"   # not clobbered by None
        dialog = open_dialog(session.page)
        await wait_until(lambda: isinstance(dialog.content.content, ft.Image))
        image = dialog.content.content
        assert isinstance(image.src, bytes) and image.width == 620 and image.fit == ft.BoxFit.CONTAIN
        button = find_text(dialog, "Open in Browser")
        assert button.disabled is False
        await click(session, button)
        await wait_until(lambda: opened == ["https://drive.google.com/file/d/doc1/view"])
        assert all("access_token" not in url for url in client.images + opened)

        class NoThumbClient(FakeDriveClient):
            def thumbnail_metadata(self, file_id):
                return {"thumbnail_link": None, "owner_photo": None, "owner_name": None, "owner_email": None}

        app.ctx.client = NoThumbClient()
        thumbnail_preview.show(app.ctx, "fold1")
        await wait_until(lambda: find_text(session.page, "No thumbnail available") is not None)
    run_ui(body)


def test_failed_query_shows_error_and_clears_page(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        fv = files_view(app)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)

        def boom(*args):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(files_view_module, "query_listing", boom)
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Loading files…")
        await wait_until(lambda: find_text(session.page, "Failed to load files: database is locked") is not None)
        assert app.ctx.state.current_file_ids == [] and find_text(fv.results, "Could not load files.")
        assert app.main_view.toolbar.add_page_button.disabled
        fv.set_view_mode("list")                         # nothing stale gets re-rendered
        assert find_text(fv.results, "Could not load files.")
    run_ui(body)

from datetime import date, datetime, timedelta, timezone

import flet as ft

from gdrive_forensics.config import AppPaths
from gdrive_forensics.ui.dialogs.date_filter import as_date
from gdrive_forensics.ui.context import (
    EV_FILTERS_CHANGED,
    EV_LISTING,
    EV_NAVIGATE_FILES,
    EV_QUEUE_CHANGED,
    EV_SELECTION_CHANGED,
    EV_TIMEZONE_CHANGED,
)
from gdrive_forensics.ui.main_view import MainView
from gdrive_forensics.ui.shell import ForensicsApp
from gdrive_forensics.ui.toolbar import ToolbarActions
from tests.fakes import FakeDriveClient
from tests.ui.harness import click, find, find_text, make_app, new_session, run_ui, settle, wait_until


def test_main_view_renders_chrome(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        page = session.page
        for label in ("GDrive Forensics", "Filters", "Clear All Filters", "Quick Filters", "Sort & Date"):
            assert find_text(page, label), label
        tabs = find(page, lambda c: isinstance(c, ft.Tabs))[0]
        assert tabs.length == 3
        assert find(page, lambda c: isinstance(c, ft.IconButton) and c.tooltip == "Export XLSX")
        assert find(page, lambda c: isinstance(c, ft.IconButton) and c.tooltip == "Scan Drive Activity")
        await wait_until(lambda: app.main_view.header.user_text.value == "me@x.com")
    run_ui(body)


def test_filters_emit_and_sync(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        messages = []
        ctx.events.subscribe(EV_FILTERS_CHANGED, lambda **kw: messages.append(kw.get("message")))
        starred = find(session.page, lambda c: isinstance(c, ft.Checkbox) and "Starred" in str(c.label))[0]
        starred.value = True
        await click(session, starred, "change", True)
        assert ctx.state.filters.starred_only and ctx.state.page == 1 and messages[-1] == "Applying starred filter…"
        source = app.main_view.sidebar.source_dropdown
        source.value = "my_drive"
        await click(session, source, "select", "my_drive")
        assert ctx.state.filters.source == "my_drive"
        await click(session, find_text(session.page, "Clear All Filters"))
        assert not ctx.state.filters.is_active() and source.value == "all" and starred.value is False
        await wait_until(lambda: find_text(session.page, "All filters cleared") is not None)
    run_ui(body)


def test_search_is_debounced(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        field = app.main_view.sidebar.search_field
        for text in ("i", "in", "inv"):
            field.value = text
            await session.dispatch_event(field._i, "change", text)
        assert app.ctx.state.filters.search == ""
        await settle(25)
        assert app.ctx.state.filters.search == "inv"
    run_ui(body)


def test_tabs_timezone_footer_and_logout_guard(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, mv = app.ctx, app.main_view
        await click(session, mv.tabs, "change", 2)
        assert ctx.state.active_tab == 2 and mv.content_host.content is mv.views[2].root
        tz = mv.header.timezone_dropdown
        tz.value = "Asia/Kolkata"
        await click(session, tz, "select", "Asia/Kolkata")
        assert ctx.state.timezone == "Asia/Kolkata"
        ctx.events.emit(EV_LISTING, shown=3, total=10, page=1, pages=4, folder_path="Case Files")
        assert mv.footer.status_text.value == "Showing 3 of 10 items | Folder: Case Files"
        assert mv.footer.pagination_text.value == "Page 1 of 4" and not mv.footer.next_button.disabled
        ctx.begin_job("scan")
        assert mv.header.logout_button.disabled
        ctx.end_job("scan")
        assert not mv.header.logout_button.disabled
    run_ui(body)


def test_date_filter_dialog(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await click(session, app.main_view.sidebar.date_button)
        assert find_text(session.page, "📅 Date Range Filter")
        await click(session, find_text(session.page, "Cancel"))
    run_ui(body)


# --------------------------------------------------------------- beyond the brief's tests

def _recorder(ctx, event=EV_FILTERS_CHANGED):
    seen = []
    ctx.events.subscribe(event, lambda **kw: seen.append(kw.get("message")))
    return seen


def _open_dialog(page):
    """The one open app dialog (closed ones stay in the stack until a real client dismisses them)."""
    dialogs = find(page, lambda c: isinstance(c, ft.AlertDialog) and c.open)
    assert len(dialogs) == 1, dialogs
    return dialogs[0]


async def _pick(session, dialog, button_label, value):
    """Open a DatePicker from the dialog and simulate the client confirming `value`."""
    before = {id(c) for c in find(session.page, lambda c: isinstance(c, ft.DatePicker))}
    await click(session, find_text(dialog, button_label))
    new = [c for c in find(session.page, lambda c: isinstance(c, ft.DatePicker)) if id(c) not in before]
    assert len(new) == 1 and new[0].open
    new[0].value = value
    await click(session, new[0], "change", None)


def test_date_filter_pick_apply_cancel_and_clear(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, sidebar = app.ctx, app.main_view.sidebar
        messages = _recorder(ctx)
        ctx.state.page = 3

        # Pick a "from" date then Apply: committed to the filter, button relabelled, event emitted.
        await click(session, sidebar.date_button)
        dialog = _open_dialog(session.page)
        assert find_text(dialog, "📅 Date Range Filter")
        await _pick(session, dialog, "Pick From Date", datetime(2025, 1, 2))
        assert find_text(dialog, "Selected: 2025-01-02")
        assert ctx.state.filters.date_from is None   # not applied until Apply
        await click(session, find_text(dialog, "Apply"))
        assert not dialog.open
        assert ctx.state.filters.date_from == date(2025, 1, 2)
        assert sidebar.date_button.content == "📅 From 2025-01-02"
        assert messages[-1] == "Applying date filter…" and ctx.state.page == 1

        # Cancel discards a pending pick.
        await click(session, sidebar.date_button)
        dialog = _open_dialog(session.page)
        assert find_text(dialog, "Selected: 2025-01-02")   # reopens with the applied value
        await _pick(session, dialog, "Pick To Date", datetime(2025, 2, 1))
        await click(session, find_text(dialog, "Cancel"))
        assert ctx.state.filters.date_to is None
        assert sidebar.date_button.content == "📅 From 2025-01-02"

        # Both dates -> arrow label; Clear Dates resets and emits its own message.
        await click(session, sidebar.date_button)
        dialog = _open_dialog(session.page)
        await _pick(session, dialog, "Pick To Date", datetime(2025, 2, 1))
        await click(session, find_text(dialog, "Apply"))
        assert sidebar.date_button.content == "📅 2025-01-02 → 2025-02-01"
        await click(session, sidebar.date_button)
        await click(session, find_text(_open_dialog(session.page), "Clear Dates"))
        assert ctx.state.filters.date_from is None and ctx.state.filters.date_to is None
        assert sidebar.date_button.content == "📅 Date Filter"
        assert messages[-1] == "Clearing date filter…"
    run_ui(body)


# What Flet 1.0.1's client really sends for a pick of 2025-01-02 made in IST: Flutter's local
# midnight converted with toUtc(), decoded by flet.messaging.protocol as an AWARE UTC datetime.
CLIENT_PICK_UTC = datetime(2025, 1, 1, 18, 30, tzinfo=timezone.utc)
IST = timezone(timedelta(hours=5, minutes=30))


def test_as_date_converts_client_utc_values_to_the_local_calendar_date():
    local_day = CLIENT_PICK_UTC.astimezone().date()          # 2025-01-02 when run in IST
    assert as_date(CLIENT_PICK_UTC) == local_day
    assert as_date("2025-01-01T18:30:00.000Z") == local_day
    # Same values pinned to IST, independent of the machine's zone (no process-TZ tricks needed).
    assert as_date(CLIENT_PICK_UTC, IST) == date(2025, 1, 2)
    assert as_date("2025-01-01T18:30:00.000Z", IST) == date(2025, 1, 2)
    assert as_date(datetime(2025, 1, 1, 22, 0, tzinfo=timezone.utc), timezone(timedelta(hours=-5)))         == date(2025, 1, 1)                                  # west of UTC keeps the same day
    # Naive values and plain dates are taken as-is; junk is ignored.
    assert as_date(datetime(2025, 1, 2, 0, 0)) == date(2025, 1, 2)
    assert as_date("2025-01-02T00:00:00") == date(2025, 1, 2)
    assert as_date(date(2025, 1, 2)) == date(2025, 1, 2)
    assert as_date("") is None and as_date("not a date") is None and as_date(None) is None


def test_date_filter_stores_local_date_of_client_utc_pick(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        local_day = CLIENT_PICK_UTC.astimezone().date()
        await click(session, app.main_view.sidebar.date_button)
        dialog = _open_dialog(session.page)
        await _pick(session, dialog, "Pick From Date", CLIENT_PICK_UTC)
        await _pick(session, dialog, "Pick To Date", "2025-01-01T18:30:00.000Z")
        assert find_text(dialog, f"Selected: {local_day:%Y-%m-%d}")
        await click(session, find_text(dialog, "Apply"))
        assert app.ctx.state.filters.date_from == local_day and app.ctx.state.filters.date_to == local_day
        assert app.main_view.sidebar.date_button.content == f"📅 {local_day:%Y-%m-%d} → {local_day:%Y-%m-%d}"
    run_ui(body)


def test_activate_loads_queue_and_user_filter(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, mv = app.ctx, app.main_view
        user_dd = mv.sidebar.user_dropdown
        await wait_until(lambda: len(user_dd.options) == 3)          # All Users + me + bob
        assert [o.text for o in user_dd.options] == ["All Users", "👤 Bob (bob@x.com)", "👤 Me (me@x.com)"]
        ctx.repo.add_to_queue(["pdf1", "img1"])
        await mv.activate()
        assert ctx.state.queue_ids == ["pdf1", "img1"] and mv.toolbar.queue_badge.label == "2"

        messages = _recorder(ctx)
        ctx.state.page = 4
        user_dd.value = "bob@x.com"
        await click(session, user_dd, "select", "bob@x.com")
        assert ctx.state.filters.user_email == "bob@x.com" and ctx.state.filters.user_label == "Bob"
        assert messages[-1] == "Filtering by Bob…" and ctx.state.page == 1
        assert mv.sidebar.summary_text.value == "User: Bob"
        user_dd.value = "all"
        await click(session, user_dd, "select", "all")
        assert ctx.state.filters.user_email is None and messages[-1] == "Clearing user filter…"
    run_ui(body)


def test_external_filter_changes_sync_sidebar(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, sidebar = app.ctx, app.main_view.sidebar
        filters = ctx.state.filters
        # e.g. a Users-tab drill-down on a collaborator who owns nothing (not in list_owners)
        filters.owner, filters.public_only = "me", True
        filters.user_email, filters.user_label = "carol@x.com", "Carol"
        filters.date_to = date(2024, 12, 31)
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering files involving Carol…")
        assert sidebar.owner_dropdown.value == "me" and sidebar.public_checkbox.value is True
        assert sidebar.user_dropdown.value == "carol@x.com"
        assert "carol@x.com" in [o.key for o in sidebar.user_dropdown.options]
        assert sidebar.date_button.content == "📅 Until 2024-12-31"
        assert "User: Carol" in sidebar.summary_text.value and "Public only" in sidebar.summary_text.value

        # A pending (debounced) search is not clobbered by an unrelated filters event.
        sidebar.search_field.value = "draft"
        await session.dispatch_event(sidebar.search_field._i, "change", "draft")
        ctx.events.emit(EV_FILTERS_CHANGED, message="Loading page 2…")
        assert sidebar.search_field.value == "draft"
        await wait_until(lambda: filters.search == "draft")
    run_ui(body)


def test_timezone_emits_both_events_and_sidebar_toggle(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, mv = app.ctx, app.main_view
        messages = _recorder(ctx)
        zones = []
        ctx.events.subscribe(EV_TIMEZONE_CHANGED, lambda **kw: zones.append(kw.get("timezone")))
        ctx.state.per_page = 5      # 9 seeded files -> 2 pages, so the Files reload keeps page 2 valid
        ctx.state.page = 2
        mv.header.timezone_dropdown.value = "Europe/London"
        await click(session, mv.header.timezone_dropdown, "select", "Europe/London")
        assert zones == ["Europe/London"] and messages[-1] == "Updating timezone…"
        assert ctx.state.page == 2                      # a timezone switch keeps the current page

        await click(session, mv.header.toggle_button)
        assert mv.sidebar.root.visible is False and mv.header.toggle_button.icon == ft.Icons.MENU
        await click(session, mv.header.toggle_button)
        assert mv.sidebar.root.visible is True and mv.header.toggle_button.icon == ft.Icons.MENU_OPEN
    run_ui(body)


def test_footer_pagination_page_size_and_activity(tmp_path):
    async def body():
        # Placeholder tabs: the synthetic 180-item EV_LISTING below must not race a real Files
        # listing (whose reload would clamp the page back to the seeded data's single page).
        session, _ = new_session()
        app = ForensicsApp(session.page, AppPaths(tmp_path), main_view_factory=lambda ctx: MainView(ctx))
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await settle(10)
        ctx, footer = app.ctx, app.main_view.footer
        messages = _recorder(ctx)
        ctx.events.emit(EV_LISTING, shown=50, total=180, page=1, pages=4, folder_path="")
        assert footer.status_text.value == "Showing 50 of 180 items | Folder: Root"
        assert footer.prev_button.disabled and not footer.next_button.disabled
        await click(session, footer.next_button)
        assert ctx.state.page == 2 and messages[-1] == "Loading page 2…"
        assert footer.pagination_text.value == "Page 2 of 4" and not footer.prev_button.disabled
        footer.per_page_dropdown.value = "100"
        await click(session, footer.per_page_dropdown, "select", "100")
        assert ctx.state.per_page == 100 and ctx.state.page == 1 and messages[-1] == "Updating page size…"
        ctx.activity("Downloading report.pdf (40%)", ft.Colors.BLUE_700)
        assert footer.activity_text.value == "Downloading report.pdf (40%)"
        ctx.activity(None)
        assert footer.activity_text.value == "No active downloads"
    run_ui(body)


def test_toolbar_actions_selection_and_view_mode(tmp_path):
    async def body():
        session, _ = new_session()
        called = []

        async def export_xlsx():
            called.append("xlsx")

        async def export_json():
            raise RuntimeError("json writer exploded")

        actions = ToolbarActions(scan=lambda: called.append("scan"), export_xlsx=export_xlsx,
                                 export_json=lambda: export_json(),   # a lambda returning a coroutine
                                 set_view_mode=lambda mode: called.append(mode))
        app = ForensicsApp(session.page, AppPaths(tmp_path),
                           main_view_factory=lambda ctx: MainView(ctx, actions=actions))
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await settle(10)
        ctx, toolbar = app.ctx, app.main_view.toolbar

        def button(tooltip):
            return find(session.page, lambda c: isinstance(c, ft.IconButton) and c.tooltip == tooltip)[0]

        await click(session, button("Scan Drive"))
        await click(session, button("Export XLSX"))
        await click(session, toolbar.list_button)
        await wait_until(lambda: called == ["scan", "xlsx", "list"])
        assert toolbar.list_button.style.bgcolor == ft.Colors.BLUE_100 and toolbar.tiles_button.style.bgcolor is None
        await click(session, button("Export CSV"))      # not wired -> explanatory toast, no crash
        await wait_until(lambda: find_text(session.page, "Not available yet") is not None)
        await click(session, button("Export JSON"))     # failing action -> error dialog, no session crash
        await wait_until(lambda: find_text(session.page, "Action failed: json writer exploded") is not None)

        assert toolbar.add_page_button.disabled and toolbar.add_selected_button.disabled
        ctx.state.selection_mode = True
        ctx.state.selected_ids = {"pdf1"}
        ctx.state.current_file_ids = ["pdf1", "img1"]
        ctx.events.emit(EV_SELECTION_CHANGED)
        assert not toolbar.add_page_button.disabled and not toolbar.add_selected_button.disabled
        assert toolbar.selection_button.tooltip == "Disable multi-select"
        ctx.state.queue_ids = ["a", "b", "c"]
        ctx.events.emit(EV_QUEUE_CHANGED)
        assert toolbar.queue_badge.label == "3"
    run_ui(body)


def test_navigate_files_event_selects_files_tab(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx, mv = app.ctx, app.main_view
        await click(session, mv.tabs, "change", 1)
        assert ctx.state.active_tab == 1
        ctx.events.emit(EV_NAVIGATE_FILES, message="Filtering files involving Bob…")
        await wait_until(lambda: ctx.state.active_tab == 0)
        assert mv.tabs.selected_index == 0 and mv.content_host.content is mv.views[0].root
    run_ui(body)


class CountingView:
    def __init__(self, name):
        self.root = ft.Container(content=ft.Text(f"{name} view"))
        self.calls = 0

    async def activate(self):
        self.calls += 1


def test_views_activate_once_per_switch(tmp_path):
    async def body():
        session, _ = new_session()
        views = [CountingView(n) for n in ("files", "users", "analytics")]
        app = ForensicsApp(session.page, AppPaths(tmp_path),
                           main_view_factory=lambda ctx: MainView(ctx, views=views))
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await wait_until(lambda: views[0].calls == 1)     # MainView.activate activates the current tab
        mv = app.main_view
        await mv.select_tab(2)
        assert views[2].calls == 1 and mv.tabs.selected_index == 2 and app.ctx.state.active_tab == 2
        await click(session, mv.tabs, "change", 2)         # client echoing the programmatic switch
        assert views[2].calls == 1
        await click(session, mv.tabs, "change", 0)
        assert views[0].calls == 2 and mv.content_host.content is views[0].root

        async def broken_activate():
            raise RuntimeError("users query failed")

        views[1].activate = broken_activate
        await click(session, mv.tabs, "change", 1)         # click() fails the test on a session crash
        assert mv.content_host.content is views[1].root
        await wait_until(lambda: find_text(session.page, "Could not load the Users tab: users query failed"))
    run_ui(body)


def test_relogin_gets_fresh_event_bus_and_state(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        old = app.main_view
        await wait_until(lambda: old.footer.status_text.value.startswith("Showing 9 of 9"))   # first listing
        old_status = old.footer.status_text.value
        app.ctx.state.filters.starred_only = True
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Applying starred filter…")
        assert old.sidebar.summary_text.value == "Starred only"

        app.logout()
        await settle()
        assert not app.ctx.state.filters.is_active()
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await settle(10)
        new = app.main_view
        assert new is not old and isinstance(new, MainView)
        assert not app.ctx.state.filters.is_active() and app.ctx.state.page == 1

        app.ctx.state.filters.public_only = True
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="Updating public filter…")
        app.ctx.events.emit(EV_LISTING, shown=1, total=1, page=1, pages=1, folder_path="")
        assert new.sidebar.summary_text.value == "Public only"
        assert new.footer.status_text.value == "Showing 1 of 1 items | Folder: Root"
        assert old.sidebar.summary_text.value == "Starred only"     # stale view no longer subscribed
        assert old.footer.status_text.value == old_status    # neither the new bus nor its late reload reach it
    run_ui(body)


def test_main_view_failure_returns_to_login_with_error(tmp_path):
    async def body():
        session, _ = new_session()

        def broken_factory(ctx):
            raise RuntimeError("layout exploded")

        app = ForensicsApp(session.page, AppPaths(tmp_path), main_view_factory=broken_factory)
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await settle()
        assert app.ctx.client is None and app.main_view is None
        assert find_text(session.page, "Start OAuth Login")
        assert find_text(session.page, "Could not open the main window: layout exploded")
    run_ui(body)

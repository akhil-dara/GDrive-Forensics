import flet as ft

from tests.ui.harness import click, find, find_text, make_app, run_ui, settle, wait_until


def test_users_view_search_and_filter(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await click(session, app.main_view.tabs, "change", 1)
        users = app.main_view.views[1]
        await wait_until(lambda: find_text(users.root, "bob@x.com") is not None)
        users.search_field.value = "bob"
        await session.dispatch_event(users.search_field._i, "change", "bob")
        await settle(25)
        assert find_text(users.root, "bob@x.com") and not find_text(users.root, "me@x.com")
        await click(session, find_text(users.root, "Filter files"))
        await wait_until(lambda: app.ctx.state.active_tab == 0)
        assert app.ctx.state.filters.user_email == "bob@x.com"
        await wait_until(lambda: "shared1" in app.ctx.state.current_file_ids)
    run_ui(body)


def test_analytics_sections_and_drilldown(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await click(session, app.main_view.tabs, "change", 2)
        view = app.main_view.views[2]
        await wait_until(lambda: find_text(view.root, "Storage by Owner") is not None)
        for label in ("Total Files", "Top Largest Files", "File Type Distribution", "Trashed Files Summary"):
            assert find_text(view.root, label), label
        assert all(c.on_sort is not None for c in view.top_table.columns if c.label.value in ("Name", "Size", "Owner"))
        chip = find(view.root, lambda c: isinstance(c, ft.Chip) and "png" in str(getattr(c.label, "value", c.label)))[0]
        await click(session, chip)
        await wait_until(lambda: app.ctx.state.active_tab == 0)
        await wait_until(lambda: app.ctx.state.current_file_ids == ["img1"])
        view.copy_csv()
        await settle()
    run_ui(body)


# --------------------------------------------------------------- beyond the brief's tests

import threading  # noqa: E402

from gdrive_forensics.ui import analytics_sections  # noqa: E402
from gdrive_forensics.ui import analytics_view as analytics_view_module  # noqa: E402
from gdrive_forensics.ui import users_view as users_view_module  # noqa: E402
from gdrive_forensics.ui.analytics_view import AnalyticsView  # noqa: E402
from gdrive_forensics.ui.context import EV_DATA_CHANGED, EV_FILTERS_CHANGED  # noqa: E402
from gdrive_forensics.ui.files_view import FilesView  # noqa: E402
from gdrive_forensics.ui.users_view import UsersView  # noqa: E402
from tests.fakes import FakeDriveClient  # noqa: E402
from tests.ui.test_files_view import count_queries  # noqa: E402

WILL_APPLY = "(will apply on Files tab)"


def count_calls(monkeypatch, obj, name, gate=None):
    calls = []
    original = getattr(obj, name)

    def counting(*args, **kwargs):
        calls.append(args)
        if gate is not None:
            gate.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(obj, name, counting)
    return calls


def capture_copies(app):
    copied = []
    app.ctx.copy = lambda text, toast="Copied to clipboard": copied.append((text, toast))
    return copied


async def open_tab(app, session, index, ready):
    await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)   # first Files listing done
    await click(session, app.main_view.tabs, "change", index)
    view = app.main_view.views[index]
    await wait_until(lambda: ready(view))
    return view


def user_card(users, email):
    def is_card(c):
        return isinstance(c, ft.Container) and isinstance(c.content, ft.ResponsiveRow)

    cards = [c for c in find(users.list, is_card) if find(c, lambda t: isinstance(t, ft.Text) and t.value == email)]
    assert len(cards) == 1, (email, cards)
    return cards[0]


def test_default_main_view_registers_users_and_analytics(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        views = app.main_view.views
        assert isinstance(views[0], FilesView) and isinstance(views[1], UsersView)
        assert isinstance(views[2], AnalyticsView)
    run_ui(body)


def test_users_drill_down_queries_once_without_deferred_toast(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        calls = count_queries(monkeypatch)
        await click(session, find_text(user_card(users, "bob@x.com"), "Filter files"))
        await wait_until(lambda: set(ctx.state.current_file_ids) == {"shared1", "doc1"})   # owner or collaborator
        await settle(10)
        assert len(calls) == 1 and ctx.state.active_tab == 0 and app.main_view.tabs.selected_index == 0
        assert find_text(session.page, WILL_APPLY) is None
        assert ctx.state.filters.user_label == "Bob" and ctx.state.page == 1
        assert app.main_view.sidebar.user_dropdown.value == "bob@x.com"
        assert find_text(app.main_view.views[0].root, "Filtering files involving Bob…") is None   # transition gone
    run_ui(body)


def test_users_clear_filter_button_and_active_chip(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        assert users.filter_button.disabled and users.filter_button.content == "Filter by user"
        assert not users.active_filter_chip.visible
        await click(session, find_text(user_card(users, "bob@x.com"), "Filter files"))
        await wait_until(lambda: ctx.state.active_tab == 0)
        await click(session, app.main_view.tabs, "change", 1)
        assert users.active_filter_chip.visible and find_text(users.active_filter_chip, "Bob")
        assert not users.filter_button.disabled and users.filter_button.content == "Clear Filter"
        await click(session, users.filter_button)
        assert ctx.state.filters.user_email is None and ctx.state.filters.user_label is None
        assert users.filter_button.disabled and not users.active_filter_chip.visible
        assert app.main_view.sidebar.user_dropdown.value == "all"
        await wait_until(lambda: find_text(session.page, f"Clearing user filter… {WILL_APPLY}") is not None)
        # A user filter picked in the sidebar shows up here too (no Users query needed).
        ctx.state.filters.user_email, ctx.state.filters.user_label = "me@x.com", "Me"
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering by Me…")
        assert users.active_filter_chip.visible and find_text(users.active_filter_chip, "Me")
    run_ui(body)


def test_users_search_is_debounced_and_clearable(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "me@x.com") is not None)
        calls = count_calls(monkeypatch, ctx.repo, "user_analytics")
        assert not users.clear_search_button.visible
        for text in ("b", "bo", "bob"):
            users.search_field.value = text
            await session.dispatch_event(users.search_field._i, "change", text)
        assert ctx.state.user_search == "" and calls == []
        await wait_until(lambda: find_text(users.root, "me@x.com") is None)
        await settle(10)
        assert calls == [("bob", 200)] and ctx.state.user_search == "bob"
        assert users.clear_search_button.visible
        await click(session, users.clear_search_button)
        await wait_until(lambda: find_text(users.root, "me@x.com") is not None)
        assert ctx.state.user_search == "" and users.search_field.value == ""
        assert not users.clear_search_button.visible

        users.search_field.value = "nobody"
        await session.dispatch_event(users.search_field._i, "change", "nobody")
        await wait_until(lambda: find_text(users.root, "No users yet") is not None)
        # Sidebar "Clear All Filters" also clears the Users search (v1) and re-queries the visible tab.
        await click(session, find_text(session.page, "Clear All Filters"))
        await wait_until(lambda: find_text(users.root, "bob@x.com") is not None)
        assert users.search_field.value == "" and ctx.state.user_search == ""
    run_ui(body)


def test_user_avatars_use_plain_urls_and_open_high_res(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        opened = []
        monkeypatch.setattr(users_view_module.webbrowser, "open", opened.append)
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        me_avatar = find(user_card(users, "me@x.com"), lambda c: isinstance(c, ft.CircleAvatar))[0]
        bob_avatar = find(user_card(users, "bob@x.com"), lambda c: isinstance(c, ft.CircleAvatar))[0]
        assert me_avatar.foreground_image_src == "https://lh3.googleusercontent.com/me=s64"
        assert me_avatar.content.value == "M" and bob_avatar.content.value == "B"
        assert bob_avatar.foreground_image_src is None
        me_tap = find(user_card(users, "me@x.com"), lambda c: isinstance(c, ft.GestureDetector))[0]
        await click(session, me_tap, "tap")
        await wait_until(lambda: opened == ["https://lh3.googleusercontent.com/me=s4096"])
        bob_tap = find(user_card(users, "bob@x.com"), lambda c: isinstance(c, ft.GestureDetector))[0]
        await click(session, bob_tap, "tap")
        await wait_until(lambda: find_text(session.page, "No avatar available") is not None)
        assert opened == ["https://lh3.googleusercontent.com/me=s4096"]
        chips = [t.value for t in find(user_card(users, "me@x.com"), lambda c: isinstance(c, ft.Text))]
        assert "Shared with" in chips and "Shared by" in chips
    run_ui(body)


def test_users_search_pending_at_logout_does_not_leak_into_next_session(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        users.search_field.value = "bob"
        await session.dispatch_event(users.search_field._i, "change", "bob")
        app.logout()
        app.on_authenticated(credentials=object(), client=FakeDriveClient())
        await settle(25)                                  # the old view's debounce has fired by now
        assert app.ctx.state.user_search == ""
    run_ui(body)


def test_users_reload_on_data_changed_only_when_visible(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        calls = count_calls(monkeypatch, ctx.repo, "user_analytics")
        ctx.events.emit(EV_DATA_CHANGED)
        await wait_until(lambda: len(calls) == 1)
        await click(session, app.main_view.tabs, "change", 0)
        ctx.events.emit(EV_DATA_CHANGED)
        await settle(10)
        assert len(calls) == 1
        assert users.root is not app.main_view.content_host.content
    run_ui(body)


def patched_ids(conn, start):
    from flet.messaging.protocol import MessageAction
    return {m.body.id for m in conn.sent[start:] if m.action == MessageAction.PATCH_CONTROL}


def test_hidden_tabs_send_no_patches(tmp_path, monkeypatch):
    """Flet 1.0 never clears a removed control's parent, so update() on a hidden tab would still
    patch ids the client already disposed of; the tab is re-sent whole when it is shown again."""
    async def body():
        app, session, conn = await make_app(tmp_path)
        ctx = app.ctx
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        await click(session, app.main_view.tabs, "change", 2)
        analytics = app.main_view.views[2]
        await wait_until(lambda: analytics_ready(analytics))
        gate = threading.Event()
        count_calls(monkeypatch, ctx.repo, "analytics_summary", gate)
        ctx.events.emit(EV_DATA_CHANGED)                     # analytics reload now blocked in a worker
        await settle(3)
        await click(session, app.main_view.tabs, "change", 0)
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        start = len(conn.sent)
        ctx.state.filters.user_email, ctx.state.filters.user_label = "bob@x.com", "Bob"
        ctx.events.emit(EV_FILTERS_CHANGED, message="Filtering by Bob…")
        gate.set()                                           # the hidden analytics result lands now
        await settle(15)
        hidden = {c._i for c in find(users.root, lambda c: True)} | {c._i for c in find(analytics.root, lambda c: True)}
        assert not patched_ids(conn, start) & hidden
        assert users.active_filter_chip.visible             # state kept; sent when the tab is shown
        await click(session, app.main_view.tabs, "change", 1)
        assert app.main_view.content_host._i in patched_ids(conn, start)
    run_ui(body)


def test_users_load_failure_reports_error(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)

        def boom(*args):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(app.ctx.repo, "user_analytics", boom)
        await click(session, app.main_view.tabs, "change", 1)
        await wait_until(lambda: find_text(session.page, "Failed to load users: database is locked") is not None)
        assert find_text(app.main_view.views[1].root, "Could not load users.")
    run_ui(body)


def analytics_ready(view):
    return find_text(view.root, "Storage by Owner") is not None


def type_chip(view, text):
    chips = find(view.root, lambda c: isinstance(c, ft.Chip) and text in str(getattr(c.label, "value", c.label)))
    assert len(chips) == 1, (text, chips)
    return chips[0]


def top_names(view):
    return [row.cells[2].content.value for row in view.top_table.rows]


def test_analytics_drill_down_queries_once_without_deferred_toast(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        view = await open_tab(app, session, 2, analytics_ready)
        ctx.state.filters.types = {"pdf"}
        ctx.state.page = 3
        calls = count_queries(monkeypatch)
        await click(session, type_chip(view, "png"))
        await wait_until(lambda: ctx.state.current_file_ids == ["img1"])
        await settle(10)
        assert len(calls) == 1 and ctx.state.active_tab == 0
        assert find_text(session.page, WILL_APPLY) is None
        assert ctx.state.filters.mime_types == {"image/png"} and ctx.state.filters.types == set()
        assert ctx.state.page == 1
        assert "MIME: image/png" in app.main_view.sidebar.summary_text.value
    run_ui(body)


def test_analytics_calls_every_query_in_one_worker_hop(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: len(app.ctx.state.current_file_ids) == 9)
        hops = count_calls(monkeypatch, analytics_view_module, "query_analytics")
        threads = []
        original = app.ctx.repo.analytics_summary
        monkeypatch.setattr(app.ctx.repo, "analytics_summary",
                            lambda: threads.append(threading.current_thread()) or original())
        await click(session, app.main_view.tabs, "change", 2)
        await wait_until(lambda: analytics_ready(app.main_view.views[2]))
        assert len(hops) == 1 and threads and threads[0] is not threading.main_thread()
    run_ui(body)


def test_analytics_stat_cards_trash_owner_bars_and_copy(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        copied = capture_copies(app)
        view = await open_tab(app, session, 2, analytics_ready)
        for label in ("Total Files", "Owned", "Shared", "Total Size", "Starred", "Public"):
            assert find_text(view.root, label), label
        copy_buttons = find(view.root, lambda c: isinstance(c, ft.IconButton) and c.tooltip == "Copy value")
        assert len(copy_buttons) == 6
        total_card = [c for c in find(view.root, lambda c: isinstance(c, ft.Card)) if find_text(c, "Total Files")][0]
        await click(session, find(total_card, lambda c: isinstance(c, ft.IconButton))[0])
        assert copied[-1] == ("9", "Copied: 9")                            # Total Files (trashed excluded)
        assert find_text(view.root, "1 trashed file  (10.00 B)")
        assert find_text(view.root, "Potential space recovery: 10.00 B")
        owners = [t for t in find(view.root, lambda c: isinstance(c, ft.DataTable))
                  if t.columns[-1].label.value == "Distribution"]
        assert len(owners) == 1
        bars = [row.cells[3].content for row in owners[0].rows]
        assert len(bars) == 2 and all(isinstance(b, ft.ProgressBar) and b.width == 160 for b in bars)
        low, high = sorted(b.value for b in bars)
        assert high == 1.0 and 0 < low < 1                                   # the biggest owner fills the bar
        assert not find(view.root, lambda c: isinstance(c, ft.Text) and isinstance(c.value, str) and "█" in c.value)
        assert find_text(view.root, "Activity Summary") is None               # no activity scanned
        await click(session, find_text(view.root, "Copy as CSV"))
        csv_text, toast = copied[-1]
        assert toast == "Analytics copied as CSV"
        for piece in ("Metric,Value", "Total Files,9", "Top Files", "photo.png", "File Type Distribution",
                      "image/png,1", "Storage by Owner", "bob@x.com,Bob"):
            assert piece in csv_text, piece
    run_ui(body)


def test_analytics_top_files_search_limit_sort_and_row_copy(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        copied = capture_copies(app)
        view = await open_tab(app, session, 2, analytics_ready)
        # size > 0 and not trashed, largest first
        assert top_names(view) == ["photo.png", "invoice-001.pdf", "bob-plan.xlsx", "same.txt", "same.txt"]
        table = view.top_table
        assert table.sort_column_index == 3 and table.sort_ascending is False
        name_col, size_col, owner_col = table.columns[2], table.columns[3], table.columns[4]
        await click(session, name_col, "sort", {"ci": 2, "asc": True})
        assert top_names(view) == ["bob-plan.xlsx", "invoice-001.pdf", "photo.png", "same.txt", "same.txt"]
        assert table.sort_column_index == 2 and table.sort_ascending is True
        await click(session, name_col, "sort", {"ci": 2, "asc": False})
        assert top_names(view)[0] == "same.txt" and table.sort_ascending is False
        await click(session, owner_col, "sort", {"ci": 4, "asc": True})
        assert top_names(view)[0] == "bob-plan.xlsx"                       # "Bob" < "Me"
        await click(session, size_col, "sort", {"ci": 3, "asc": True})
        assert top_names(view)[0] == "photo.png" and table.sort_ascending is False   # size starts largest-first

        view.top_search_field.value = "BOB"
        await click(session, view.top_search_field, "change", "BOB")
        assert top_names(view) == ["bob-plan.xlsx"]                        # name or owner, case-insensitive
        view.top_search_field.value = "me"
        await click(session, view.top_search_field, "change", "me")
        assert "bob-plan.xlsx" not in top_names(view) and len(top_names(view)) == 4
        view.top_search_field.value = ""
        await click(session, view.top_search_field, "change", "")

        view.top_limit_dropdown.value = "25"
        await click(session, view.top_limit_dropdown, "select", "25")
        assert len(table.rows) == 5
        rows = analytics_sections.select_top([{"name": f"f{i}", "size": i, "owner_name": "o"} for i in range(1, 60)],
                                             "", "size", False, 25)
        assert len(rows) == 25 and rows[0]["name"] == "f59"

        copy = find(table.rows[0], lambda c: isinstance(c, ft.IconButton) and c.tooltip == "Copy row")[0]
        await click(session, copy)
        assert copied[-1] == ("photo.png\t4.00 KB\tMe", "Row copied")
    run_ui(body)


def test_analytics_activity_summary_when_scanned(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        records = [{"activity_key": f"k{i}", "timestamp": f"2025-03-0{i}T08:00:00Z", "action_type": action,
                    "actor_email": actor, "target_id": "pdf1"}
                   for i, (action, actor) in enumerate([("edit", "bob@x.com"), ("edit", "bob@x.com"),
                                                        ("create", "me@x.com")], start=1)]
        app.ctx.repo.store_activities(records)
        view = await open_tab(app, session, 2, analytics_ready)
        assert find_text(view.root, "Activity Summary")
        assert find_text(view.root, "Total activity records: 3")
        assert find_text(view.root, "edit: 2") and find_text(view.root, "create: 1")
        tiles = find(view.root, lambda c: isinstance(c, ft.ListTile))
        assert [(t.title.value, t.trailing.value) for t in sorted(tiles, key=lambda t: t.leading.content.value)] == [
            ("bob@x.com", "2 actions"), ("me@x.com", "1 action")]
    run_ui(body)


def test_analytics_reload_on_data_changed_and_failure(tmp_path, monkeypatch):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        view = await open_tab(app, session, 2, analytics_ready)
        calls = count_calls(monkeypatch, ctx.repo, "analytics_summary")
        ctx.events.emit(EV_DATA_CHANGED)
        await wait_until(lambda: len(calls) == 1)
        await click(session, app.main_view.tabs, "change", 1)
        ctx.events.emit(EV_DATA_CHANGED)
        await settle(10)
        assert len(calls) == 1

        def boom():
            raise RuntimeError("disk I/O error")

        monkeypatch.setattr(ctx.repo, "analytics_summary", boom)
        await click(session, app.main_view.tabs, "change", 2)
        await wait_until(lambda: find_text(session.page, "Failed to load analytics: disk I/O error") is not None)
        assert find_text(view.root, "Could not load analytics.")
        assert not view.progress.visible
        copied = capture_copies(app)
        view.copy_csv()
        assert copied == [(None, "Analytics copied as CSV")]            # ctx.copy says "Nothing to copy"
    run_ui(body)


def test_analytics_csv_and_bar_helpers():
    share = analytics_sections.share
    assert share(0, 100) == 0.0 and share(None, 100) == 0.0 and share(5, 0) == 0.0 and share(5, None) == 0.0
    assert share(50, 100) == 0.5 and share(100, 100) == 1.0 and share(300, 100) == 1.0
    data = analytics_sections.AnalyticsData(
        summary={"total_files": 1, "owned_files": 1, "shared_files": 0, "total_size": 2048, "starred": 0,
                 "public": 0, "trashed_count": 0, "trashed_size": 0},
        top_files=[{"id": "a", "name": "a,b.txt", "size": 2048, "owner_name": None, "owner_email": "x@y",
                    "mime_type": "text/plain"}],
        types=[("text/plain", 1)], owners=[{"owner_email": "x@y", "owner_name": None, "total_size": 2048,
                                            "file_count": 1}],
        activity={"total": 0, "by_type": [], "top_actors": []})
    text = analytics_sections.analytics_csv(data)
    assert '1,"a,b.txt",2.00 KB,2048,x@y,text/plain' in text
    assert "Total Size (bytes),2048" in text and "x@y,,2.00 KB,2048,1" in text


def test_analytics_type_drill_down_leaves_folders_and_scope(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        ctx = app.ctx
        fv = app.main_view.views[0]
        await wait_until(lambda: len(ctx.state.current_file_ids) == 9)
        fv.enter_folder("fold1", "Case Files")
        await wait_until(lambda: set(ctx.state.current_file_ids) == {"sub1", "doc1", "cut1"})
        ctx.state.filters.scope = "files"
        view = await open_tab_any(app, session, 2, analytics_ready)
        await click(session, type_chip(view, "png"))
        await wait_until(lambda: ctx.state.active_tab == 0)
        await wait_until(lambda: ctx.state.current_file_ids == ["img1"])   # matches the chip's global count
        assert ctx.state.filters.folder_id is None and ctx.state.folder_stack == []
        assert ctx.state.filters.scope == "all" and fv.advanced_filters.scope_group.value == "all"
        assert find_text(fv.breadcrumbs, "Case Files") is None
    run_ui(body)


async def open_tab_any(app, session, index, ready):
    """Like open_tab, without waiting for the root listing first."""
    await click(session, app.main_view.tabs, "change", index)
    view = app.main_view.views[index]
    await wait_until(lambda: ready(view))
    return view


def test_user_avatar_falls_back_to_the_initial_when_the_photo_fails(tmp_path):
    async def body():
        app, session, conn = await make_app(tmp_path)
        users = await open_tab(app, session, 1, lambda v: find_text(v.root, "bob@x.com") is not None)
        me_avatar = find(user_card(users, "me@x.com"), lambda c: isinstance(c, ft.CircleAvatar))[0]
        assert me_avatar.foreground_image_src == "https://lh3.googleusercontent.com/me=s64"
        refreshed = []
        original_refresh = users._refresh
        users._refresh = lambda *controls: refreshed.extend(controls) or original_refresh(*controls)
        start = len(conn.sent)
        await click(session, me_avatar, "image_error", "foreground")      # Flutter could not load the photo
        assert me_avatar.foreground_image_src is None and me_avatar.content.value == "M"
        assert refreshed == [me_avatar]                                     # through the shown-tab gate
        assert me_avatar._i in patched_ids(conn, start)                     # repainted: the initial shows
        bob_avatar = find(user_card(users, "bob@x.com"), lambda c: isinstance(c, ft.CircleAvatar))[0]
        await click(session, bob_avatar, "image_error", "foreground")      # no photo: harmless
        assert bob_avatar.foreground_image_src is None and bob_avatar.content.value == "B"
    run_ui(body)

import logging
import threading

import flet as ft

from gdrive_forensics import app as app_module
from gdrive_forensics.config import AppPaths
from gdrive_forensics.drive.auth import OAuthCancelled
from gdrive_forensics.logging_setup import AUTH_LOGGER
from gdrive_forensics.ui.context import EV_FILTERS_CHANGED, Throttle
from gdrive_forensics.ui.login_view import LoginView
from gdrive_forensics.ui.shell import ForensicsApp
from tests.ui.harness import click, find_text, make_app, new_session, run_ui, settle, wait_until


def test_dispatcher_marshals_worker_updates(tmp_path):
    async def body():
        session, conn = new_session()
        app = ForensicsApp(session.page, AppPaths(tmp_path))
        text = ft.Text("before")
        session.page.add(text)
        done = threading.Event()

        def worker():
            app.ctx.dispatcher.ui(lambda: (setattr(text, "value", "after"), text.update(), done.set()))

        app.ctx.dispatcher.background(worker)
        await wait_until(done.is_set)
        assert text.value == "after"
    run_ui(body)


def test_dispatcher_spawn_and_later(tmp_path):
    async def body():
        session, _ = new_session()
        dispatcher = ForensicsApp(session.page, AppPaths(tmp_path)).ctx.dispatcher
        seen = []

        async def coro(value):
            seen.append(value)

        dispatcher.spawn(coro, "spawned")
        dispatcher.later(0.01, lambda: seen.append("later"))
        assert dispatcher.on_loop()
        await wait_until(lambda: {"spawned", "later"} <= set(seen))
    run_ui(body)


def test_event_bus_and_throttle(tmp_path):
    async def body():
        session, _ = new_session()
        app = ForensicsApp(session.page, AppPaths(tmp_path))
        seen = []
        app.ctx.events.subscribe(EV_FILTERS_CHANGED, lambda **kw: seen.append(kw))
        app.ctx.events.emit(EV_FILTERS_CHANGED, message="hi")
        assert seen == [{"message": "hi"}]
        t = Throttle(interval=60)
        assert t.ready() and not t.ready() and t.ready(force=True)
    run_ui(body)


def test_login_screen_without_token(tmp_path):
    async def body():
        session, _ = new_session()
        app = ForensicsApp(session.page, AppPaths(tmp_path))
        app.start()
        await wait_until(lambda: find_text(session.page, "Start OAuth Login") is not None)
        assert find_text(session.page, "Google Drive Forensics Suite")
        # credentials.json missing -> clicking shows the explanatory banner, no crash
        await click(session, find_text(session.page, "Start OAuth Login"))
        await wait_until(lambda: find_text(session.page, "credentials.json was not found") is not None)
    run_ui(body)


def test_unexpected_token_load_error_routes_to_login(tmp_path):
    async def body():
        session, _ = new_session()
        app = ForensicsApp(session.page, AppPaths(tmp_path))

        def boom():
            raise TypeError("proxy returned a non-JSON body")

        app.ctx.auth.load_saved = boom
        app.start()
        # Never stuck on "Checking saved session…": the login screen appears with the token_invalid banner.
        await wait_until(lambda: find_text(session.page, "Start OAuth Login") is not None)
        assert find_text(session.page, "The saved token.json could not be read")
        assert find_text(session.page, "Checking saved session") is None
    run_ui(body)


def test_credentials_removed_during_oauth_shows_missing_secrets_banner(tmp_path):
    async def body():
        session, _ = new_session()
        paths = AppPaths(tmp_path)
        paths.credentials_file.write_text("{}", encoding="utf-8")
        app = ForensicsApp(session.page, paths)

        def flow(on_auth_url, cancel=None, **kwargs):
            raise FileNotFoundError(str(paths.credentials_file))

        app.ctx.auth.run_oauth_flow = flow
        app.show_login()
        button = find_text(session.page, "Start OAuth Login")
        await click(session, button)
        await wait_until(lambda: find_text(session.page, "credentials.json was not found") is not None)
        assert button.disabled is False
    run_ui(body)


def test_oauth_flow_shows_url_cancels_and_completes(tmp_path):
    async def body():
        session, _ = new_session()
        paths = AppPaths(tmp_path)
        paths.credentials_file.write_text("{}", encoding="utf-8")
        ctx = ForensicsApp(session.page, paths).ctx
        signed_in = []
        view = LoginView(ctx, on_authenticated=signed_in.append)
        session.page.add(view.build())

        def waiting_flow(on_auth_url, cancel=None, **kwargs):
            on_auth_url("https://accounts.google.com/o/oauth2/auth?client_id=x")
            assert cancel.wait(5)
            raise OAuthCancelled()

        ctx.auth.run_oauth_flow = waiting_flow
        await click(session, view.login_button)
        await wait_until(lambda: "listening on 127.0.0.1 only" in view.status.value)
        assert "https://accounts.google.com/o/oauth2/auth?client_id=x" in view.status.value
        assert view.login_button.disabled and view.cancel_button.visible
        await click(session, view.cancel_button)
        await wait_until(lambda: view.status.value == "Sign-in cancelled.")
        assert not view.login_button.disabled and not view.cancel_button.visible

        ctx.auth.run_oauth_flow = lambda on_auth_url, cancel=None, **kwargs: "CREDS"
        await click(session, view.login_button)
        await wait_until(lambda: signed_in == ["CREDS"])
    run_ui(body)


def _login_view(tmp_path):
    session, _ = new_session()
    paths = AppPaths(tmp_path)
    paths.credentials_file.write_text("{}", encoding="utf-8")
    ctx = ForensicsApp(session.page, paths).ctx
    view = LoginView(ctx, on_authenticated=lambda creds: None)
    session.page.add(view.build())
    return session, ctx, view


def test_second_sign_in_click_while_waiting_is_ignored(tmp_path):
    async def body():
        session, ctx, view = _login_view(tmp_path)
        flows = []

        def waiting_flow(on_auth_url, cancel=None, **kwargs):
            flows.append(cancel)
            assert cancel.wait(5)
            raise OAuthCancelled()

        ctx.auth.run_oauth_flow = waiting_flow
        await click(session, view.login_button)
        await wait_until(lambda: len(flows) == 1)
        view.start_oauth()                          # a queued second click / double-click
        await click(session, view.login_button)
        await settle(10)
        assert len(flows) == 1 and view._cancel is flows[0]   # Cancel still reaches the running flow
        await click(session, view.cancel_button)
        await wait_until(lambda: view.status.value == "Sign-in cancelled.")
        assert not view.login_button.disabled
    run_ui(body)


def test_unexpected_sign_in_failure_is_logged_with_traceback(tmp_path, caplog):
    async def body():
        session, ctx, view = _login_view(tmp_path)

        def broken_flow(on_auth_url, cancel=None, **kwargs):
            raise RuntimeError("token endpoint returned HTML")

        ctx.auth.run_oauth_flow = broken_flow
        with caplog.at_level(logging.ERROR, logger=AUTH_LOGGER):
            await click(session, view.login_button)
            await wait_until(lambda: find_text(session.page, "Sign-in failed: token endpoint returned HTML") is not None)
        records = [r for r in caplog.records if r.name == AUTH_LOGGER and r.exc_info]
        assert records and "token endpoint returned HTML" in str(records[0].exc_info[1])
        assert not view.login_button.disabled
    run_ui(body)


def test_app_main_boots_to_login(tmp_path):
    async def body():
        session, _ = new_session()
        app_module.main(session.page, AppPaths(tmp_path))
        await wait_until(lambda: find_text(session.page, "Start OAuth Login") is not None)
        assert session.page.title == "Google Drive Forensics Suite"
    run_ui(body)


def test_run_shuts_every_app_down_after_the_window_closes(tmp_path, monkeypatch):
    """ft.run returning must leave nothing that keeps the process alive, even if on_close never fired."""
    async def body():
        app, session, _ = await make_app(tmp_path)
        pool = app.ctx.thumbnails._pool
        probe = threading.Event()
        app.ctx.jobs._cancels["probe"] = probe                   # a job still running at exit
        cwd = tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        monkeypatch.setattr(app_module, "setup_logging", lambda *a, **k: None)
        runs = []
        monkeypatch.setattr(app_module.ft, "run", lambda *a, **k: runs.append(k))   # window closed at once
        app_module.run()
        assert len(runs) == 1
        assert app.ctx.thumbnails is None and pool._shutdown and probe.is_set()

        second, _, _ = await make_app(tmp_path / "second")

        def crashed(*a, **k):
            raise RuntimeError("renderer crashed")

        monkeypatch.setattr(app_module.ft, "run", crashed)
        try:
            app_module.run()
        except RuntimeError:
            pass
        assert second.ctx.thumbnails is None                     # shut down on the error path too
    run_ui(body)


def test_signed_in_shell_fetches_identity_and_logs_out(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path)
        await wait_until(lambda: app.ctx.state.viewer_email == "me@x.com")
        assert app.ctx.auth.user_email == "me@x.com"
        assert app.ctx.client is not None
        assert app.ctx.repo.total_file_count() > 0          # make_app seeded the evidence DB
        assert find_text(session.page, "GDrive Forensics")  # default main view is MainView (Task 11)
        app.ctx.paths.token_file.write_text("{}", encoding="utf-8")
        app.logout()
        await settle()
        assert app.ctx.client is None
        assert app.ctx.state.viewer_email is None           # no stale attribution after logout
        assert app.ctx.auth.user_email is None
        assert not app.ctx.paths.token_file.exists()
        assert find_text(session.page, "Start OAuth Login")
    run_ui(body)


def test_logout_blocked_while_jobs_run(tmp_path):
    async def body():
        app, session, _ = await make_app(tmp_path, seeded=False)
        assert app.ctx.begin_job("scan")
        app.logout()
        await settle()
        assert app.ctx.client is not None
        assert find_text(session.page, "Finish or cancel running jobs")
        app.ctx.end_job("scan")
    run_ui(body)


def test_dialog_toast_error_helpers(tmp_path):
    async def body():
        session, _ = new_session()
        ctx = ForensicsApp(session.page, AppPaths(tmp_path)).ctx
        first = ft.AlertDialog(title=ft.Text("One"))
        second = ft.AlertDialog(title=ft.Text("Two"))
        ctx.show_dialog(first)
        ctx.show_dialog(second)          # replaces the first, never raises "already opened"
        assert not first.open and second.open
        ctx.close_dialog()
        assert not second.open
        ctx.toast("Saved")
        ctx.error("Bad thing")
        await settle()
        assert find_text(session.page, "Bad thing")
        ctx.safe_update(ft.Text("unmounted"))  # must not raise
        assert ctx.begin_job("scan") and not ctx.begin_job("scan")
        ctx.end_job("scan")
        assert ctx.begin_job("scan")
    run_ui(body)

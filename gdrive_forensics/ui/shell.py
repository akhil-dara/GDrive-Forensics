"""ForensicsApp: builds services, routes between login and main view."""
from __future__ import annotations

import logging
import weakref
from typing import Callable, Optional

import flet as ft

from ..config import APP_TITLE
from ..drive.auth import CredentialManager
from ..drive.client import DriveClient
from ..storage.database import Database
from ..storage.repository import Repository
from ..storage.thumbnail_cache import ThumbnailCache
from .context import AppContext, EventBus
from .jobs import JobRunner
from .login_view import LoginView
from .state import UIState
from .thumbnails import ThumbnailService
from .toolbar import ToolbarActions

logger = logging.getLogger(__name__)

# Every live ForensicsApp; app.run() shuts them all down once ft.run returns (weak: tests create many).
_APPS: "weakref.WeakSet[ForensicsApp]" = weakref.WeakSet()


def shutdown_all() -> None:
    """After the window is gone: stop every app's jobs and thumbnail pool, even if page.on_close never fired."""
    for app in list(_APPS):
        try:
            app.shutdown()
        except Exception:
            logger.exception("Shutting down the app failed")


def job_toolbar_actions(ctx: AppContext) -> ToolbarActions:
    """Toolbar buttons backed by the session's JobRunner (the Files-tab buttons are added separately)."""
    from .dialogs import export_queue

    jobs = ctx.jobs
    spawn = ctx.dispatcher.spawn
    return ToolbarActions(
        scan=jobs.start_scan,
        scan_activity=jobs.start_activity_scan,
        refresh_thumbnails=jobs.refresh_thumbnails,
        show_queue=lambda: export_queue.show(ctx),
        export_csv=lambda: spawn(jobs.export_metadata, "csv"),
        export_json=lambda: spawn(jobs.export_metadata, "json"),
        export_xlsx=lambda: spawn(jobs.export_metadata, "xlsx"),
        export_filtered=lambda: spawn(jobs.export_filtered),
    )


def _default_main_view(ctx: AppContext):
    # Lazy imports keep shell <-> view modules free of import cycles.
    from .analytics_view import AnalyticsView
    from .files_view import FilesView
    from .main_view import MainView, files_toolbar_actions
    from .users_view import UsersView

    files = FilesView(ctx)
    views = [files, UsersView(ctx), AnalyticsView(ctx)]   # order == main_view.TAB_LABELS
    return MainView(ctx, views=views, actions=files_toolbar_actions(files, job_toolbar_actions(ctx)))


class ForensicsApp:
    def __init__(self, page: ft.Page, paths, main_view_factory: Optional[Callable] = None) -> None:
        self.page = page
        self.paths = paths
        db = Database(paths.database_file)
        db.initialize()
        self.ctx = AppContext(page, paths, db, Repository(db), CredentialManager(paths),
                              ThumbnailCache(paths.thumbnail_cache_file))
        self.main_view_factory = main_view_factory or _default_main_view
        self.main_view = None
        self._setup_page()
        _APPS.add(self)

    def _setup_page(self) -> None:
        page = self.page
        page.title = APP_TITLE
        page.theme_mode = ft.ThemeMode.LIGHT
        page.padding = 0
        page.bgcolor = ft.Colors.GREY_50
        page.window.width = 1600
        page.window.height = 950
        page.window.min_width = 1100
        page.window.min_height = 700
        page.window.resizable = True
        page.on_close = self.shutdown

    def _show(self, control: ft.Control) -> None:
        self.page.controls.clear()
        self.page.controls.append(control)
        self.page.update()

    def start(self) -> None:
        self._show(ft.Container(
            content=ft.Column([ft.ProgressRing(), ft.Text("Checking saved session…", color=ft.Colors.GREY_700)],
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
            alignment=ft.Alignment.CENTER, expand=True))

        def worker() -> None:
            try:
                creds, reason = self.ctx.auth.load_saved()
            except Exception:
                # Never leave the UI stuck on "Checking saved session…" (e.g. a proxy's non-JSON
                # response or a wrong-shape token.json raising outside load_saved's own handling).
                logger.exception("Could not load the saved session")
                creds, reason = None, "token_invalid"
            if creds:
                self.ctx.dispatcher.ui(self.on_authenticated, creds)
            else:
                self.ctx.dispatcher.ui(self.show_login, reason)

        self.ctx.dispatcher.background(worker, name="load-token")

    def show_login(self, reason: Optional[str] = None) -> None:
        self.main_view = None
        self._show(LoginView(self.ctx, self.on_authenticated, reason).build())

    def _reset_session(self) -> None:
        """Fresh per-account state and event bus.

        EventBus has no unsubscribe, so a previous MainView's handlers stay on the old bus and can
        never fire for the new session; views reach the bus/state through `ctx`, never cached.
        """
        self.ctx.events = EventBus()
        self.ctx.state = UIState()

    def _cancel_jobs(self) -> None:
        if self.ctx.jobs is not None:
            self.ctx.jobs.cancel_all()   # thread-safe: only sets the jobs' cancel events

    def shutdown(self, e=None) -> None:
        """page.on_close: stop running jobs and the (non-daemon) thumbnail pool so the process can exit."""
        self._cancel_jobs()
        self._stop_thumbnails()

    def _stop_thumbnails(self) -> None:
        if self.ctx.thumbnails is not None:
            self.ctx.thumbnails.shutdown()   # non-blocking: safe on the loop
            self.ctx.thumbnails = None

    def on_authenticated(self, credentials, client=None) -> None:
        """Called on the loop thread. `client` is injectable for tests."""
        self._reset_session()
        self.ctx.auth.credentials = credentials
        self._stop_thumbnails()
        ctx = self.ctx
        ctx.thumbnails = ThumbnailService(lambda: ctx.client, ctx.cache, ctx.dispatcher)
        ctx.jobs = JobRunner(ctx)   # before the main view: the toolbar is wired to it
        try:
            self.ctx.client = client or DriveClient(credentials, self.ctx.repo)
            self.main_view = self.main_view_factory(self.ctx)
            # Flet 1.0 controls have their own build() lifecycle hook (returns None), so test for a
            # control first; view objects (MainView) expose build() -> ft.Control.
            root = self.main_view if isinstance(self.main_view, ft.BaseControl) else self.main_view.build()
            self._show(root)
        except Exception as exc:
            # Never leave the user on a spinner / disabled login button.
            logger.exception("Could not open the main window")
            self.ctx.client = None
            self.ctx.jobs = None
            self._stop_thumbnails()
            self._reset_session()   # drop subscriptions a half-built view may have made
            self.show_login(None)
            self.ctx.error(f"Could not open the main window: {exc}")
            return
        if hasattr(self.main_view, "on_logout"):
            self.main_view.on_logout = self.logout
        drive = self.ctx.client

        def fetch_identity() -> None:
            try:
                user = drive.about_user()
            except Exception as exc:
                logger.error("Could not fetch signed-in user: %s", exc)
                return
            email = user.get("emailAddress")

            def apply() -> None:
                if self.ctx.client is not drive:
                    return  # logged out (or re-authenticated) while the request was in flight
                self.ctx.auth.user_email = email
                self.ctx.state.viewer_email = email
                if hasattr(self.main_view, "set_user"):
                    self.main_view.set_user(email)
            self.ctx.dispatcher.ui(apply)

        self.ctx.dispatcher.background(fetch_identity, name="about-user")
        if hasattr(self.main_view, "activate"):
            self.ctx.dispatcher.spawn(self.main_view.activate)

    def logout(self) -> None:
        if self.ctx.active_jobs:
            self.ctx.toast("Finish or cancel running jobs before logging out")
            return
        self._cancel_jobs()             # none can be running (guard above); harmless
        self.ctx.jobs = None
        self.ctx.auth.logout()
        self.ctx.client = None
        # Drops viewer_email (scan/activity attribution), filters, queue ids… and every old subscription.
        self._reset_session()
        self._stop_thumbnails()
        self.show_login()
        self.ctx.toast("Logged out successfully")

"""AppContext: services + state + thread-safe UI dispatch shared by every view."""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Callable, Optional

import flet as ft

from .state import UIState

logger = logging.getLogger(__name__)

EV_FILTERS_CHANGED = "filters_changed"
EV_DATA_CHANGED = "data_changed"
EV_ACTIVITY_CHANGED = "activity_changed"   # an activity scan ended (done, failed or cancelled)
EV_QUEUE_CHANGED = "queue_changed"
EV_TIMEZONE_CHANGED = "timezone_changed"
EV_LISTING = "listing"
EV_SELECTION_CHANGED = "selection_changed"
EV_NAVIGATE_FILES = "navigate_files"
EV_JOBS_CHANGED = "jobs_changed"
EV_ACTIVITY = "activity"


class Dispatcher:
    """Flet 1.0: UI mutations must happen on the page's asyncio loop."""

    def __init__(self, page: ft.Page) -> None:
        self.page = page

    def on_loop(self) -> bool:
        try:
            return asyncio.get_running_loop() is self.page.loop
        except RuntimeError:
            return False

    @staticmethod
    def _safe(fn: Callable, *args, **kwargs) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:
            logger.exception("UI callback %s failed", getattr(fn, "__name__", fn))

    def ui(self, fn: Callable, *args, **kwargs) -> None:
        if self.on_loop():
            self._safe(fn, *args, **kwargs)
            return

        async def _run() -> None:
            self._safe(fn, *args, **kwargs)

        self.page.run_task(_run)

    def spawn(self, coro_fn: Callable[..., Any], *args) -> None:
        async def _run() -> None:
            try:
                await coro_fn(*args)
            except Exception:
                logger.exception("UI task %s failed", getattr(coro_fn, "__name__", coro_fn))

        self.page.run_task(_run)

    def background(self, fn: Callable, *args, name: Optional[str] = None) -> threading.Thread:
        def _run() -> None:
            try:
                fn(*args)
            except Exception:
                logger.exception("Background task %s failed", name or getattr(fn, "__name__", fn))

        thread = threading.Thread(target=_run, daemon=True, name=name or "gdf-worker")
        thread.start()
        return thread

    def later(self, delay: float, fn: Callable) -> asyncio.TimerHandle:
        return self.page.loop.call_later(delay, self._safe, fn)


class Throttle:
    """Rate-limit progress repaints from chatty worker callbacks."""

    def __init__(self, interval: float = 0.15) -> None:
        self.interval = interval
        self._last = 0.0

    def ready(self, force: bool = False) -> bool:
        now = time.monotonic()
        if force or now - self._last >= self.interval:
            self._last = now
            return True
        return False


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[..., None]]] = {}

    def subscribe(self, event: str, handler: Callable[..., None]) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def emit(self, event: str, **payload) -> None:
        for handler in list(self._handlers.get(event, [])):
            try:
                handler(**payload)
            except Exception:
                logger.exception("Handler for %s failed", event)


class AppContext:
    def __init__(self, page: ft.Page, paths, db, repo, auth, cache) -> None:
        self.page = page
        self.paths = paths
        self.db = db
        self.repo = repo
        self.auth = auth
        self.cache = cache
        self.state = UIState()
        self.events = EventBus()
        self.dispatcher = Dispatcher(page)
        self.client = None
        self.thumbnails = None
        self.jobs = None
        self.active_jobs: set[str] = set()
        self._dialog: Optional[ft.DialogControl] = None
        self.file_picker = ft.FilePicker()
        self.clipboard = ft.Clipboard()
        page.services.append(self.file_picker)
        page.services.append(self.clipboard)

    # ------------------------------------------------------------ dialogs
    def show_dialog(self, dialog: ft.DialogControl) -> None:
        """One app dialog at a time (v1 behaviour): closes the current one first."""
        if self._dialog is not None and self._dialog is not dialog:
            self.close_dialog(self._dialog)
        self._dialog = dialog
        if dialog.open:
            self.safe_update(dialog)
            return
        try:
            self.page.show_dialog(dialog)
        except RuntimeError:
            # Still in Flet's dialog stack (closed but not yet dismissed): just reopen it.
            dialog.open = True
            self.safe_update(dialog)

    def close_dialog(self, dialog: Optional[ft.DialogControl] = None) -> None:
        target = dialog or self._dialog
        if target is not None and target.open:
            target.open = False
            self.safe_update(target)
        if target is self._dialog:
            self._dialog = None

    def toast(self, message: str) -> None:
        self.page.show_dialog(ft.SnackBar(ft.Text(message, size=14), bgcolor=ft.Colors.GREY_800))

    def error(self, message: str, title: str = "Error") -> None:
        dialog = ft.AlertDialog(
            title=ft.Row([ft.Icon(ft.Icons.ERROR, color=ft.Colors.RED_700, size=32),
                          ft.Text(title, size=20, color=ft.Colors.RED_700)], spacing=12),
            content=ft.Text(message, size=14, selectable=True),
            actions=[ft.Button("OK", bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE,
                               on_click=lambda e: self.close_dialog(dialog))])
        self.show_dialog(dialog)

    # ---------------------------------------------------------- services
    async def pick_directory(self, title: str = "Select folder") -> Optional[str]:
        return await self.file_picker.get_directory_path(dialog_title=title)

    def copy(self, text: Optional[str], toast: str = "Copied to clipboard") -> None:
        if not text:
            self.toast("Nothing to copy")
            return

        async def _copy() -> None:
            try:
                await self.clipboard.set(text)
                self.toast(toast)
            except Exception as exc:
                logger.error("Clipboard copy failed: %s", exc)
                self.error(f"Could not copy text: {exc}")

        self.dispatcher.spawn(_copy)

    @staticmethod
    def safe_update(*controls) -> None:
        for control in controls:
            if control is None:
                continue
            try:
                control.update()
            except (RuntimeError, AssertionError):
                pass  # not mounted yet; it renders with current values when added

    # -------------------------------------------------------------- jobs
    def begin_job(self, name: str) -> bool:
        if name in self.active_jobs:
            return False
        self.active_jobs.add(name)
        self.events.emit(EV_JOBS_CHANGED)
        return True

    def end_job(self, name: str) -> None:
        self.active_jobs.discard(name)
        self.events.emit(EV_JOBS_CHANGED)

    def activity(self, message: Optional[str], color=None) -> None:
        self.events.emit(EV_ACTIVITY, message=message, color=color)

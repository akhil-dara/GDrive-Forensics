"""Modal progress dialog shared by the background jobs (scan, activity, downloads, exports, thumbnails)."""
from __future__ import annotations

import logging
import threading
from typing import Optional

import flet as ft

from ..context import Throttle

logger = logging.getLogger(__name__)

CANCEL_LABEL = "Cancel"
BACKGROUND_LABEL = "Run in background"


class ProgressDialog:
    """Status / detail / ETA texts over a ProgressBar, with "Run in background" and "Cancel".

    Construct and `show()` on the loop. `update()` and `close()` are thread-safe: worker callbacks call
    them directly; repaints are throttled (a forced update always goes through) and marshalled onto the
    loop. `update()` never raises, so a UI hiccup can never abort the job reporting progress. Updates
    arriving after a logout/re-login (session changed) are dropped instead of painting the new session.
    """

    def __init__(self, ctx, title: str, *, cancellable: bool = True, backgroundable: bool = True,
                 subtitle: Optional[str] = None, color=ft.Colors.BLUE_700) -> None:
        self.ctx = ctx
        self.cancel_event = threading.Event()
        self.backgrounded = False
        self.color = color
        self._session = ctx.state        # identity marker only
        self._throttle = Throttle(0.15)
        self._lock = threading.Lock()
        self._pending: dict = {}
        self.status_text = ft.Text("Starting…", size=13, weight=ft.FontWeight.BOLD)
        self.detail_text = ft.Text("", size=11, color=ft.Colors.GREY_600, selectable=True)
        self.eta_text = ft.Text("", size=11, color=ft.Colors.GREY_600)
        self.progress_bar = ft.ProgressBar(width=500, value=None)   # indeterminate until a fraction arrives
        rows: list[ft.Control] = []
        if subtitle:
            rows.append(ft.Text(subtitle, size=12, color=ft.Colors.GREY_700, max_lines=2,
                                overflow=ft.TextOverflow.ELLIPSIS))
        rows += [self.progress_bar, self.status_text, self.detail_text, self.eta_text]
        self.background_button = (ft.TextButton(BACKGROUND_LABEL, icon=ft.Icons.CLOSE_FULLSCREEN,
                                                on_click=lambda e: self.run_in_background())
                                  if backgroundable else None)
        self.cancel_button = (ft.TextButton(CANCEL_LABEL, icon=ft.Icons.STOP_CIRCLE,
                                            on_click=lambda e: self.cancel())
                              if cancellable else None)
        self.dialog = ft.AlertDialog(
            modal=True, title=ft.Text(title),
            content=ft.Container(width=540, content=ft.Column(rows, spacing=8, tight=True)),
            actions=[b for b in (self.background_button, self.cancel_button) if b is not None])

    # ------------------------------------------------------------- loop only
    def show(self, status: str = "Starting…") -> None:
        self.status_text.value = status
        self.ctx.show_dialog(self.dialog)
        self.ctx.activity(status, self.color)

    def run_in_background(self) -> None:
        self.backgrounded = True
        self.ctx.close_dialog(self.dialog)
        self.ctx.toast("Continuing in background – progress is shown in the footer")

    def cancel(self) -> None:
        if self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.status_text.value = "Stopping…"
        self.detail_text.value = "Finishing the current step before stopping."
        if self.cancel_button is not None:
            self.cancel_button.disabled = True
        self.ctx.safe_update(self.status_text, self.detail_text, self.cancel_button)
        self.ctx.activity("Cancelling…", ft.Colors.RED_600)

    # ---------------------------------------------------------- thread-safe
    def update(self, status: Optional[str] = None, detail: Optional[str] = None,
               fraction: Optional[float] = None, eta: Optional[str] = None, force: bool = False) -> None:
        try:
            with self._lock:
                for key, value in (("status", status), ("detail", detail), ("fraction", fraction), ("eta", eta)):
                    if value is not None:
                        self._pending[key] = value
                if force:
                    self._pending["force"] = True
                if not self._throttle.ready(force):
                    return   # kept in _pending: the next repaint carries it
                values, self._pending = self._pending, {}
            self.ctx.dispatcher.ui(self._apply, values)
        except Exception:
            logger.exception("Progress update failed")

    def close(self) -> None:
        try:
            self.ctx.dispatcher.ui(self.ctx.close_dialog, self.dialog)
        except Exception:
            logger.exception("Closing the progress dialog failed")

    def _apply(self, values: dict) -> None:
        if self.ctx.state is not self._session:
            return
        status = values.get("status")
        if status is not None and self.cancel_event.is_set() and not values.get("force"):
            status = None   # keep "Stopping…" until the job reports how it ended
        if status is not None:
            self.status_text.value = status
        if "detail" in values:
            self.detail_text.value = values["detail"]
        if "eta" in values:
            self.eta_text.value = values["eta"]
        if "fraction" in values:
            self.progress_bar.value = max(0.0, min(1.0, float(values["fraction"])))
        self.ctx.safe_update(self.status_text, self.detail_text, self.eta_text, self.progress_bar)
        if status is not None:
            self.ctx.activity(status, self.color)

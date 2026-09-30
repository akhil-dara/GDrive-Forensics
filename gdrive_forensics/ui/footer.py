"""Status footer: listing summary, background-activity line and pagination."""
from __future__ import annotations

from typing import Optional

import flet as ft

from .context import EV_ACTIVITY, EV_FILTERS_CHANGED, EV_LISTING, AppContext

IDLE_ACTIVITY = "No active downloads"
PER_PAGE_CHOICES = (25, 50, 100, 250)


class Footer:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self._pages = 1                     # page count of the last listing shown
        self.status_text = ft.Text("Ready", size=12, color=ft.Colors.GREY_600)
        self.activity_text = ft.Text(IDLE_ACTIVITY, size=11, color=ft.Colors.GREY_500)
        self.pagination_text = ft.Text("Page 1 of 1", size=12, color=ft.Colors.GREY_600)
        self.prev_button = ft.IconButton(icon=ft.Icons.CHEVRON_LEFT, tooltip="Previous page",
                                         on_click=lambda e: self._change_page(-1), disabled=True, icon_size=18)
        self.next_button = ft.IconButton(icon=ft.Icons.CHEVRON_RIGHT, tooltip="Next page",
                                         on_click=lambda e: self._change_page(1), disabled=True, icon_size=18)
        self.per_page_dropdown = ft.Dropdown(
            width=90, dense=True, value=str(ctx.state.per_page),
            options=[ft.dropdown.Option(str(n)) for n in PER_PAGE_CHOICES],
            on_select=self._on_per_page, content_padding=ft.Padding.symmetric(vertical=4, horizontal=0))
        self.root = ft.Container(
            content=ft.Row([
                ft.Column([
                    ft.Row([ft.Icon(ft.Icons.INFO_OUTLINED, size=14, color=ft.Colors.GREY_500), self.status_text],
                           spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    self.activity_text,
                ], spacing=4, expand=True),
                ft.Row([
                    self.prev_button,
                    self.pagination_text,
                    self.next_button,
                    ft.Text("Per page", size=11, color=ft.Colors.GREY_600),
                    self.per_page_dropdown,
                ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(vertical=6, horizontal=10),
            bgcolor=ft.Colors.WHITE,
            border=ft.Border.only(top=ft.BorderSide(1, ft.Colors.GREY_200)))
        ctx.events.subscribe(EV_LISTING, self._on_listing)
        # Activity lines come from job progress callbacks: marshal to the loop defensively.
        ctx.events.subscribe(EV_ACTIVITY, lambda **kw: self.ctx.dispatcher.ui(self._on_activity, **kw))

    def build(self) -> ft.Control:
        return self.root

    # ----------------------------------------------------------- events
    def _on_listing(self, shown: int = 0, total: int = 0, page: int = 1, pages: int = 1,
                    folder_path: Optional[str] = None, **_) -> None:
        self.status_text.value = f"Showing {shown} of {total} items | Folder: {folder_path or 'Root'}"
        self.ctx.safe_update(self.status_text)
        self._pages = max(1, int(pages or 1))
        self._render_pagination(page)

    def _on_activity(self, message: Optional[str] = None, color=None, **_) -> None:
        self.activity_text.value = message or IDLE_ACTIVITY
        self.activity_text.color = color or (ft.Colors.GREY_600 if message else ft.Colors.GREY_500)
        self.ctx.safe_update(self.activity_text)

    def _render_pagination(self, page: int) -> None:
        current = min(max(1, int(page or 1)), self._pages)
        self.pagination_text.value = f"Page {current} of {self._pages}"
        self.prev_button.disabled = current <= 1
        self.next_button.disabled = current >= self._pages
        per_page = str(self.ctx.state.per_page)
        if self.per_page_dropdown.value != per_page:
            self.per_page_dropdown.value = per_page
        self.ctx.safe_update(self.pagination_text, self.prev_button, self.next_button, self.per_page_dropdown)

    # --------------------------------------------------------- handlers
    def _change_page(self, delta: int) -> None:
        state = self.ctx.state
        new_page = min(max(1, state.page + delta), self._pages)
        if new_page == state.page:
            return
        state.page = new_page
        self._render_pagination(new_page)
        self.ctx.events.emit(EV_FILTERS_CHANGED, message=f"Loading page {new_page}…")

    def _on_per_page(self, e) -> None:
        try:
            value = int(e.control.value)
        except (TypeError, ValueError):
            return
        state = self.ctx.state
        if value <= 0 or value == state.per_page:
            return
        state.per_page = value
        state.page = 1
        self.ctx.events.emit(EV_FILTERS_CHANGED, message="Updating page size…")

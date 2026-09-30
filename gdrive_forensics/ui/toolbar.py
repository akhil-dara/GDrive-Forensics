"""Action toolbar: scans, queue, selection, exports and the tiles/list switch."""
from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from typing import Callable, Optional

import flet as ft

from .context import EV_QUEUE_CHANGED, EV_SELECTION_CHANGED, AppContext

logger = logging.getLogger(__name__)

NOT_AVAILABLE = "Not available yet"


@dataclass
class ToolbarActions:
    """What each toolbar button does. A field left as None toasts "Not available yet".

    Callables may be plain functions or coroutine functions (the latter are spawned on the loop).
    """
    scan: Optional[Callable[[], object]] = None
    scan_activity: Optional[Callable[[], object]] = None
    refresh_thumbnails: Optional[Callable[[], object]] = None
    show_queue: Optional[Callable[[], object]] = None
    add_page: Optional[Callable[[], object]] = None
    add_selected: Optional[Callable[[], object]] = None
    toggle_selection: Optional[Callable[[], object]] = None
    export_csv: Optional[Callable[[], object]] = None
    export_json: Optional[Callable[[], object]] = None
    export_xlsx: Optional[Callable[[], object]] = None
    export_filtered: Optional[Callable[[], object]] = None
    set_view_mode: Optional[Callable[[str], object]] = None


def _view_style(selected: bool) -> ft.ButtonStyle:
    return ft.ButtonStyle(bgcolor=ft.Colors.BLUE_100 if selected else None,
                          shape=ft.RoundedRectangleBorder(radius=4))


class ActionToolbar:
    def __init__(self, ctx: AppContext, actions: ToolbarActions) -> None:
        self.ctx = ctx
        self.actions = actions
        self.queue_badge = ft.Badge(label=str(len(ctx.state.queue_ids)), bgcolor=ft.Colors.RED_700,
                                    text_color=ft.Colors.WHITE, small_size=10)
        self.queue_button = ft.IconButton(
            icon=ft.Icons.PLAYLIST_ADD_CHECK, tooltip="Export Queue", on_click=self._handler("show_queue"),
            icon_color=ft.Colors.ORANGE_700, icon_size=20, badge=self.queue_badge,
            style=ft.ButtonStyle(padding=8))
        self.add_page_button = ft.IconButton(
            icon=ft.Icons.SELECT_ALL, tooltip="Add current page to queue", on_click=self._handler("add_page"),
            icon_color=ft.Colors.TEAL_700, icon_size=20, style=ft.ButtonStyle(padding=8), disabled=True)
        self.add_selected_button = ft.IconButton(
            icon=ft.Icons.LIBRARY_ADD, tooltip="Add selected files to queue",
            on_click=self._handler("add_selected"), icon_color=ft.Colors.PURPLE_700, icon_size=20,
            style=ft.ButtonStyle(padding=8), disabled=True)
        self.selection_button = ft.IconButton(
            icon=ft.Icons.CHECK_BOX_OUTLINE_BLANK, tooltip="Enable multi-select",
            on_click=self._handler("toggle_selection"), icon_color=ft.Colors.GREY_700, icon_size=18,
            style=ft.ButtonStyle(padding=8))
        self.export_filtered_button = ft.IconButton(
            icon=ft.Icons.CLOUD_DOWNLOAD, tooltip="Export all filtered results",
            on_click=self._handler("export_filtered"), icon_color=ft.Colors.BLUE_800, icon_size=20,
            style=ft.ButtonStyle(padding=8))
        self.tiles_button = ft.TextButton("Tiles", on_click=lambda e: self._switch_view("tiles"))
        self.list_button = ft.TextButton("List", on_click=lambda e: self._switch_view("list"))
        self.set_view_mode(ctx.state.view_mode)
        self.root = ft.Container(
            content=ft.Row([
                self._small("Scan Drive", ft.Icons.REFRESH, ft.Colors.GREEN_700, "scan"),
                self._small("Refresh thumbnails", ft.Icons.IMAGE, ft.Colors.BLUE_700, "refresh_thumbnails"),
                self._small("Scan Drive Activity", ft.Icons.TIMELINE, ft.Colors.AMBER_700, "scan_activity"),
                self.queue_button,
                self.add_page_button,
                self.add_selected_button,
                self.selection_button,
                self._small("Export CSV", ft.Icons.TABLE_CHART, ft.Colors.BLUE_700, "export_csv"),
                self._small("Export JSON", ft.Icons.CODE, ft.Colors.PURPLE_700, "export_json"),
                self._small("Export XLSX", ft.Icons.GRID_ON, ft.Colors.GREEN_800, "export_xlsx"),
                self.export_filtered_button,
                ft.Text("View", size=12, color=ft.Colors.GREY_600),
                self.tiles_button,
                self.list_button,
            ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER, wrap=True),
            padding=ft.Padding.symmetric(vertical=6, horizontal=10),
            bgcolor=ft.Colors.WHITE,
            border=ft.Border.only(bottom=ft.BorderSide(1, ft.Colors.GREY_200)))
        ctx.events.subscribe(EV_QUEUE_CHANGED, lambda **kw: self.set_queue_count(len(self.ctx.state.queue_ids)))
        ctx.events.subscribe(EV_SELECTION_CHANGED, lambda **kw: self._sync_selection())

    def build(self) -> ft.Control:
        return self.root

    # ------------------------------------------------------------ state
    def set_queue_count(self, n: int) -> None:
        self.queue_badge.label = str(n)
        self.ctx.safe_update(self.queue_button)

    def set_selection_state(self, selection_mode: bool, selected_count: int, page_has_files: bool) -> None:
        self.add_page_button.disabled = not page_has_files
        self.add_selected_button.disabled = selected_count <= 0
        if selection_mode:
            self.selection_button.icon = ft.Icons.CHECK_BOX
            self.selection_button.tooltip = "Disable multi-select"
        else:
            self.selection_button.icon = ft.Icons.CHECK_BOX_OUTLINE_BLANK
            self.selection_button.tooltip = "Enable multi-select"
        self.ctx.safe_update(self.add_page_button, self.add_selected_button, self.selection_button)

    def set_view_mode(self, mode: str) -> None:
        self.tiles_button.style = _view_style(mode == "tiles")
        self.list_button.style = _view_style(mode == "list")
        self.ctx.safe_update(self.tiles_button, self.list_button)

    def _sync_selection(self) -> None:
        state = self.ctx.state
        self.set_selection_state(state.selection_mode, len(state.selected_ids), bool(state.current_file_ids))
        self.set_view_mode(state.view_mode)

    # ---------------------------------------------------------- actions
    def _small(self, tooltip: str, icon, color, action: str) -> ft.IconButton:
        return ft.IconButton(icon=icon, tooltip=tooltip, on_click=self._handler(action), icon_color=color,
                             icon_size=18, style=ft.ButtonStyle(padding=0))

    def _handler(self, action: str) -> Callable:
        return lambda e: self._invoke(action)

    def _switch_view(self, mode: str) -> None:
        if self._invoke("set_view_mode", mode):
            self.set_view_mode(mode)

    def _invoke(self, action: str, *args) -> bool:
        fn = getattr(self.actions, action)
        if fn is None:
            self.ctx.toast(NOT_AVAILABLE)
            return False
        try:
            result = fn(*args)
        except Exception as exc:
            self._failed(action, exc)
            return False
        if inspect.isawaitable(result):   # coroutine function, or a lambda returning a coroutine
            async def _run() -> None:
                try:
                    await result
                except Exception as exc:
                    self._failed(action, exc)
            self.ctx.dispatcher.spawn(_run)
        return True

    def _failed(self, action: str, exc: Exception) -> None:
        logger.exception("Toolbar action %s failed", action)
        self.ctx.error(f"Action failed: {exc}")

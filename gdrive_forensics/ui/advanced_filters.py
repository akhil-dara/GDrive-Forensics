"""Collapsible "Advanced Filters" panel of the Files tab: browse scope and file/service types."""
from __future__ import annotations

import flet as ft

from ..core.filters import SCOPE_OPTIONS
from ..core.mime import TYPE_FILTERS
from .context import EV_FILTERS_CHANGED, AppContext

_SCOPE_NOUNS = {"folders": "folders", "files": "files"}


class AdvancedFiltersPanel:
    """Edits `ctx.state.filters.scope/types`; every change resets to page 1 and emits EV_FILTERS_CHANGED."""

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.expanded = False
        filters = ctx.state.filters
        self.header_icon = ft.Icon(ft.Icons.ADD, color=ft.Colors.BLUE_700, size=18)
        self.scope_group = ft.RadioGroup(
            value=filters.scope, on_change=self._on_scope,
            content=ft.Column([ft.Radio(value=key, label=label) for key, label in SCOPE_OPTIONS], spacing=6))
        self.type_checkboxes: dict[str, ft.Checkbox] = {
            key: ft.Checkbox(label=label, value=key in filters.types,
                             on_change=lambda e, k=key: self._on_type(k, bool(e.control.value)))
            for key, (label, _sql, _params) in TYPE_FILTERS.items()
        }
        self.body = ft.Container(
            content=ft.Column([
                ft.Text("Browse scope", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                self.scope_group,
                ft.Divider(height=8),
                ft.Text("File / service type", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                ft.ResponsiveRow([ft.Container(content=cb, col={"xs": 12, "sm": 6, "md": 4})
                                  for cb in self.type_checkboxes.values()], spacing=8, run_spacing=4),
            ], spacing=10),
            padding=ft.Padding.only(top=4, bottom=4),
            visible=self.expanded)
        header = ft.Row([
            ft.GestureDetector(
                content=ft.Row([self.header_icon,
                                ft.Text("Advanced Filters", weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_800)],
                               spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                on_tap=lambda e: self.toggle(), mouse_cursor=ft.MouseCursor.CLICK, expand=True),
            ft.TextButton("Clear", icon=ft.Icons.CLEAR_ALL, on_click=lambda e: self.clear()),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        self.root = ft.Container(
            content=ft.Column([header, self.body], spacing=6),
            bgcolor=ft.Colors.WHITE, border=ft.Border.all(1, ft.Colors.GREY_200), border_radius=10,
            padding=ft.Padding.all(12))
        # Other views reset filters too (sidebar "Clear All Filters", drill-downs): mirror them.
        ctx.events.subscribe(EV_FILTERS_CHANGED, lambda **kw: self.sync_from_state())

    def toggle(self) -> None:
        self.expanded = not self.expanded
        self.body.visible = self.expanded
        self.header_icon.icon = ft.Icons.REMOVE if self.expanded else ft.Icons.ADD
        self.ctx.safe_update(self.root)

    def sync_from_state(self) -> None:
        filters = self.ctx.state.filters
        self.scope_group.value = filters.scope
        for key, checkbox in self.type_checkboxes.items():
            checkbox.value = key in filters.types
        self.ctx.safe_update(self.root)

    def clear(self) -> None:
        filters = self.ctx.state.filters
        filters.scope = "all"
        filters.types.clear()
        filters.mime_types.clear()      # an Analytics type drill-down is a type filter too
        self.sync_from_state()
        self._changed("Clearing advanced filters…")
        self.ctx.toast("Advanced filters reset")

    def _changed(self, message: str) -> None:
        self.ctx.state.page = 1
        self.ctx.events.emit(EV_FILTERS_CHANGED, message=message)

    def _on_scope(self, e) -> None:
        value = e.control.value or "all"
        filters = self.ctx.state.filters
        if value == filters.scope:
            return
        filters.scope = value
        self._changed(f"Showing {_SCOPE_NOUNS.get(value, 'items')}…")

    def _on_type(self, key: str, checked: bool) -> None:
        types = self.ctx.state.filters.types
        if checked == (key in types):
            return
        if checked:
            types.add(key)
        else:
            types.discard(key)
        self._changed("Updating file type filter…")

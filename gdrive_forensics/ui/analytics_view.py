"""Analytics tab: stat cards, top files, type distribution (drill-down), storage by owner, trash, activity."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import flet as ft

from .analytics_sections import (
    SORT_COLUMNS,
    TOP_FILES_LIMIT,
    AnalyticsData,
    activity_controls,
    analytics_csv,
    owners_table,
    panel,
    query_analytics,
    row_text,
    section_title,
    select_top,
    stat_cards,
    top_columns,
    top_rows,
    trashed_panel,
    type_chips,
)
from .context import EV_ACTIVITY_CHANGED, EV_DATA_CHANGED, EV_FILTERS_CHANGED, EV_NAVIGATE_FILES, AppContext

logger = logging.getLogger(__name__)

ANALYTICS_TAB = 2
LIMIT_CHOICES = (10, 25, 50, 100)
DEFAULT_LIMIT = 10


class AnalyticsView:
    """Plain object (Flet 1.0 controls have their own build()); MainView mounts `root`.

    Section builders live in `analytics_sections` (kept stateless); this class owns the loaded data,
    the top-files table state and the events.
    """

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self._session = ctx.state         # identity marker: drop results that land after a logout
        self._generation = 0
        self._data: Optional[AnalyticsData] = None
        self._top_search = ""
        self._top_limit = DEFAULT_LIMIT
        self._sort_col, self._sort_asc = "size", False

        # Persistent top-files controls: sortable from the first render, re-filtered in place.
        self.top_search_field = ft.TextField(label="Search files", prefix_icon=ft.Icons.SEARCH, width=250,
                                             dense=True, on_change=self._on_top_search)
        self.top_limit_dropdown = ft.Dropdown(
            label="Show", options=[ft.dropdown.Option(str(n), str(n)) for n in LIMIT_CHOICES],
            value=str(DEFAULT_LIMIT), width=100, dense=True, on_select=self._on_top_limit)
        self.top_table = ft.DataTable(
            columns=top_columns(self.sort_top), rows=[], sort_column_index=SORT_COLUMNS[self._sort_col],
            sort_ascending=self._sort_asc, border=ft.Border.all(1, ft.Colors.GREY_300), border_radius=8,
            heading_row_color=ft.Colors.BLUE_50)
        self.top_caption = ft.Text("", size=11, color=ft.Colors.GREY_600)
        self.top_section = panel(ft.Column([
            ft.Row([self.top_search_field, self.top_limit_dropdown], spacing=10),
            ft.Row([self.top_table], scroll=ft.ScrollMode.AUTO),
            self.top_caption,
        ], spacing=10))
        self.stats_row = ft.Row([], wrap=True, spacing=15)

        self.progress = ft.ProgressBar(visible=False, height=3)
        self.body = ft.Column([self._message("Loading analytics…", spinner=True)],
                              spacing=20, expand=True, scroll=ft.ScrollMode.AUTO)
        self.root = ft.Column([self.progress, self.body], spacing=0, expand=True)
        ctx.events.subscribe(EV_DATA_CHANGED, self._on_data_changed)
        ctx.events.subscribe(EV_ACTIVITY_CHANGED, self._on_data_changed)   # the Activity Summary section

    # ----------------------------------------------------------- reloads
    def _owns_session(self) -> bool:
        return self.ctx.state is self._session

    def _refresh(self, *controls) -> None:
        """Repaint only while shown (see UsersView._refresh); MainView re-sends the root on show."""
        if self._owns_session() and self.ctx.state.active_tab == ANALYTICS_TAB:
            self.ctx.safe_update(*controls)

    def _current(self, generation: int) -> bool:
        return generation == self._generation and self._owns_session()

    async def activate(self) -> None:
        await self.reload()   # every visit: scans/exports may have changed the numbers

    async def reload(self) -> None:
        self._generation += 1
        generation = self._generation
        self._set_busy(True)
        try:
            data = await asyncio.to_thread(query_analytics, self.ctx.repo)
        except Exception as exc:
            if self._current(generation):
                logger.exception("Loading analytics failed")
                self._set_busy(False)
                self._data = None             # nothing stale for copy_csv()
                self.body.controls = [self._message("Could not load analytics.", color=ft.Colors.RED_700)]
                self._refresh(self.body)
                self.ctx.error(f"Failed to load analytics: {exc}")
            return
        if self._current(generation):
            self._set_busy(False)
            self._apply(data)

    def _on_data_changed(self, **_) -> None:
        if self.ctx.state.active_tab == ANALYTICS_TAB:
            self.ctx.dispatcher.spawn(self.reload)

    def _set_busy(self, busy: bool) -> None:
        self.progress.visible = busy
        self._refresh(self.progress)

    # ---------------------------------------------------------- rendering
    @staticmethod
    def _message(text: str, color=ft.Colors.GREY_600, spinner: bool = False) -> ft.Control:
        items: list[ft.Control] = [ft.ProgressRing(width=18, height=18, stroke_width=2)] if spinner else []
        return ft.Container(content=ft.Row([*items, ft.Text(text, size=13, color=color)], spacing=8),
                            padding=ft.Padding.symmetric(vertical=12, horizontal=4))

    def _apply(self, data: AnalyticsData) -> None:
        self._data = data
        self.stats_row.controls = stat_cards(data.summary, self._copy_value)
        self._render_top(update=False)
        self.body.controls = [
            ft.Text("📊 Analytics Dashboard", size=28, weight=ft.FontWeight.BOLD),
            ft.Divider(height=20),
            self.stats_row,
            ft.Divider(height=30),
            section_title("🏆 Top Largest Files"),
            self.top_section,
            ft.Divider(height=30),
            section_title("📦 File Type Distribution"),
            ft.Text("Click a type to filter the Files tab", size=11, italic=True, color=ft.Colors.GREY_500),
            panel(ft.Row(type_chips(data.types, self.filter_by_mime), wrap=True, spacing=10), padding=20),
            ft.Divider(height=30),
            section_title("👥 Storage by Owner"),
            panel(ft.Row([owners_table(data.owners)], scroll=ft.ScrollMode.AUTO)),
            ft.Divider(height=30),
            section_title("🗑️ Trashed Files Summary"),
            trashed_panel(data.summary),
            *activity_controls(data.activity),
            ft.Divider(height=30),
            ft.Row([ft.Button("Copy as CSV", icon=ft.Icons.COPY_ALL, bgcolor=ft.Colors.TEAL_700,
                              color=ft.Colors.WHITE, on_click=lambda e: self.copy_csv())],
                   alignment=ft.MainAxisAlignment.END),
        ]
        self._refresh(self.body)

    # --------------------------------------------------------- top files
    def _render_top(self, update: bool = True) -> None:
        records = self._data.top_files if self._data is not None else []
        matching = select_top(records, self._top_search, self._sort_col, self._sort_asc, len(records))
        shown = matching[:self._top_limit]
        self.top_table.rows = top_rows(shown, self._copy_row)
        self.top_table.sort_column_index = SORT_COLUMNS[self._sort_col]
        self.top_table.sort_ascending = self._sort_asc
        self.top_caption.value = (f"Showing {len(shown)} of {len(matching)} matching files"
                                  f" (the {TOP_FILES_LIMIT} largest are loaded)" if records else "No sized files")
        if update:
            self._refresh(self.top_table, self.top_caption)

    def sort_top(self, column: str) -> None:
        """Same column toggles; a new one starts A→Z (name/owner) or largest-first (size)."""
        if column == self._sort_col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col, self._sort_asc = column, column != "size"
        self._render_top()

    def _on_top_search(self, e) -> None:
        self._top_search = (e.control.value or "").strip()
        self._render_top()

    def _on_top_limit(self, e) -> None:
        try:
            self._top_limit = int(e.control.value)
        except (TypeError, ValueError):
            self._top_limit = DEFAULT_LIMIT
        self._render_top()

    # ----------------------------------------------------------- actions
    def filter_by_mime(self, mime: str) -> None:
        """Drill-down: the Files tab showing exactly this MIME type, across the whole Drive.

        The chip counts every folder and item kind, so the open folder and the browse scope are
        reset too - otherwise the results would not match the chip's count.
        """
        state = self.ctx.state
        state.filters.mime_types = {mime}
        state.filters.types = set()
        state.filters.scope = "all"
        state.filters.folder_id = None
        state.folder_stack = []
        state.page = 1
        self.ctx.events.emit(EV_FILTERS_CHANGED, message=f"Filtering by {mime}…", navigate=True)
        self.ctx.events.emit(EV_NAVIGATE_FILES)

    def _copy_value(self, value: str) -> None:
        self.ctx.copy(value, f"Copied: {value}")

    def _copy_row(self, record: dict) -> None:
        self.ctx.copy(row_text(record), "Row copied")

    def copy_csv(self) -> None:
        text = analytics_csv(self._data) if self._data is not None else None
        self.ctx.copy(text, "Analytics copied as CSV")

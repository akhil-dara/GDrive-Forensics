"""Left filter rail: source/owner/user/search, quick toggles, sort and date range."""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import flet as ft

from ..core.filters import OWNER_OPTIONS, SORT_OPTIONS, SOURCE_OPTIONS
from .context import EV_DATA_CHANGED, EV_FILTERS_CHANGED, AppContext
from .dialogs import date_filter

logger = logging.getLogger(__name__)

SIDEBAR_WIDTH = 220
SEARCH_DEBOUNCE = 0.3
ALL_USERS = "all"


def user_option_label(name: Optional[str], email: str) -> str:
    return f"👤 {name or email} ({email})"


def date_button_label(date_from, date_to) -> str:
    if date_from and date_to:
        return f"📅 {date_from.strftime('%Y-%m-%d')} → {date_to.strftime('%Y-%m-%d')}"
    if date_from:
        return f"📅 From {date_from.strftime('%Y-%m-%d')}"
    if date_to:
        return f"📅 Until {date_to.strftime('%Y-%m-%d')}"
    return "📅 Date Filter"


def _caption(text: str) -> ft.Text:
    return ft.Text(text, size=12, color=ft.Colors.GREY_600)


class Sidebar:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.collapsed = False
        self._search_handle: Optional[asyncio.TimerHandle] = None
        self._users_generation = 0
        self._user_labels: dict[str, str] = {}
        filters = ctx.state.filters

        self.summary_text = ft.Text(filters.summary(), size=11, color=ft.Colors.GREY_600)
        self.source_dropdown = ft.Dropdown(
            label="Source", options=[ft.dropdown.Option(k, t) for k, t in SOURCE_OPTIONS], value=filters.source,
            on_select=self._on_source, width=180, dense=True)
        self.owner_dropdown = ft.Dropdown(
            label="Owner", options=[ft.dropdown.Option(k, t) for k, t in OWNER_OPTIONS], value=filters.owner,
            on_select=self._on_owner, width=170, dense=True)
        self.user_dropdown = ft.Dropdown(
            label="User", options=[ft.dropdown.Option(ALL_USERS, "All Users")],
            value=filters.user_email or ALL_USERS, on_select=self._on_user, width=240, dense=True)
        self.search_field = ft.TextField(
            label="Search", hint_text="Type to search...", value=filters.search, on_change=self._on_search,
            width=260, dense=True, prefix_icon=ft.Icons.SEARCH)
        self.starred_checkbox = ft.Checkbox(label="⭐ Starred Only", value=filters.starred_only,
                                            on_change=self._on_starred)
        self.trashed_checkbox = ft.Checkbox(label="🗑️ Include Trashed", value=filters.include_trashed,
                                            on_change=self._on_trashed)
        self.public_checkbox = ft.Checkbox(label="🌐 Public Files Only", value=filters.public_only,
                                           on_change=self._on_public)
        self.sort_dropdown = ft.Dropdown(
            label="Sort By", options=[ft.dropdown.Option(k, label) for k, (label, _) in SORT_OPTIONS.items()],
            value=filters.sort, on_select=self._on_sort, width=180, dense=True)
        self.date_button = ft.Button(date_button_label(filters.date_from, filters.date_to),
                                     icon=ft.Icons.DATE_RANGE, on_click=self._open_date_filter)

        self.root = ft.Container(
            width=SIDEBAR_WIDTH,
            bgcolor=ft.Colors.GREY_50,
            padding=ft.Padding(12, 12, 12, 12),
            content=ft.Column([
                ft.Text("Filters", weight=ft.FontWeight.BOLD, size=14),
                self.summary_text,
                ft.TextButton("Clear All Filters", icon=ft.Icons.CLOSE, on_click=self._clear_all),
                ft.Divider(height=8),
                ft.Column([
                    _caption("Source"), self.source_dropdown,
                    _caption("Owner"), self.owner_dropdown,
                    _caption("User"), self.user_dropdown,
                    _caption("Search"), self.search_field,
                ], spacing=6),
                ft.Divider(height=12),
                ft.Column([
                    _caption("Quick Filters"),
                    ft.Row([self.starred_checkbox, self.trashed_checkbox, self.public_checkbox],
                           wrap=True, spacing=8),
                    ft.Divider(height=10),
                    _caption("Sort & Date"),
                    self.sort_dropdown,
                    self.date_button,
                ], spacing=8),
            ], spacing=10, scroll=ft.ScrollMode.AUTO))

        ctx.events.subscribe(EV_DATA_CHANGED, lambda **kw: self.populate_users())
        ctx.events.subscribe(EV_FILTERS_CHANGED, lambda **kw: self._on_filters_changed())

    def build(self) -> ft.Control:
        return self.root

    def toggle(self) -> None:
        self.collapsed = not self.collapsed
        self.root.visible = not self.collapsed
        self.root.width = 0 if self.collapsed else SIDEBAR_WIDTH
        self.ctx.safe_update(self.root)

    # ------------------------------------------------------------ users
    def populate_users(self) -> None:
        """Reload the User dropdown from the evidence DB (read off the loop)."""
        self._users_generation += 1
        self.ctx.dispatcher.spawn(self._load_users, self._users_generation)

    async def _load_users(self, generation: int) -> None:
        owners = await asyncio.to_thread(self.ctx.repo.list_owners)
        if generation != self._users_generation:
            return  # a newer reload is in flight
        options = [ft.dropdown.Option(ALL_USERS, "All Users")]
        labels: dict[str, str] = {}
        for owner in owners:
            email = owner.get("email")
            if not email:
                continue
            options.append(ft.dropdown.Option(email, user_option_label(owner.get("name"), email)))
            labels[email] = owner.get("name") or email
        self._user_labels = labels
        self.user_dropdown.options = options
        filters = self.ctx.state.filters
        if filters.user_email:
            self._ensure_user_option(filters.user_email, filters.user_label)
        self.user_dropdown.value = filters.user_email or ALL_USERS
        self.ctx.safe_update(self.user_dropdown)

    def _ensure_user_option(self, email: str, label: Optional[str]) -> None:
        """Drill-downs can select a collaborator who owns nothing (so is not in list_owners)."""
        if any(option.key == email for option in self.user_dropdown.options):
            return
        self.user_dropdown.options.append(ft.dropdown.Option(email, user_option_label(label, email)))
        self._user_labels.setdefault(email, label or email)

    # ------------------------------------------------------- state sync
    def refresh_summary(self) -> None:
        self.summary_text.value = self.ctx.state.filters.summary()
        self.ctx.safe_update(self.summary_text)

    def sync_from_state(self) -> None:
        """Push `ctx.state.filters` into the controls (other views change filters too)."""
        filters = self.ctx.state.filters
        self.source_dropdown.value = filters.source
        self.owner_dropdown.value = filters.owner
        if filters.user_email:
            self._ensure_user_option(filters.user_email, filters.user_label)
        self.user_dropdown.value = filters.user_email or ALL_USERS
        # Never clobber what the user is typing while the debounced search is still pending.
        if self._search_handle is None and (self.search_field.value or "").strip() != filters.search:
            self.search_field.value = filters.search
        self.starred_checkbox.value = filters.starred_only
        self.trashed_checkbox.value = filters.include_trashed
        self.public_checkbox.value = filters.public_only
        self.sort_dropdown.value = filters.sort
        self.date_button.content = date_button_label(filters.date_from, filters.date_to)
        self.ctx.safe_update(self.root)

    def _on_filters_changed(self) -> None:
        self.refresh_summary()
        self.sync_from_state()

    def _changed(self, message: str) -> None:
        self.ctx.state.page = 1
        self.ctx.events.emit(EV_FILTERS_CHANGED, message=message)

    # --------------------------------------------------------- handlers
    def _on_source(self, e) -> None:
        self.ctx.state.filters.source = e.control.value or "all"
        self._changed("Changing source filter…")

    def _on_owner(self, e) -> None:
        self.ctx.state.filters.owner = e.control.value or "all"
        self._changed("Changing owner filter…")

    def _on_user(self, e) -> None:
        filters = self.ctx.state.filters
        email = e.control.value
        if not email or email == ALL_USERS:
            filters.user_email = filters.user_label = None
            self._changed("Clearing user filter…")
            return
        label = self._user_labels.get(email, email)
        filters.user_email, filters.user_label = email, label
        self._changed(f"Filtering by {label}…")

    def _on_search(self, e) -> None:
        value = (e.control.value or "").strip()
        self._cancel_search()
        self._search_handle = self.ctx.dispatcher.later(SEARCH_DEBOUNCE, lambda: self._apply_search(value))

    def _apply_search(self, value: str) -> None:
        self._search_handle = None
        if value == self.ctx.state.filters.search:
            return
        self.ctx.state.filters.search = value
        self._changed("Searching files…")

    def _cancel_search(self) -> None:
        if self._search_handle is not None:
            self._search_handle.cancel()
            self._search_handle = None

    def _on_starred(self, e) -> None:
        self.ctx.state.filters.starred_only = bool(e.control.value)
        self._changed("Applying starred filter…")

    def _on_trashed(self, e) -> None:
        self.ctx.state.filters.include_trashed = bool(e.control.value)
        self._changed("Updating trashed filter…")

    def _on_public(self, e) -> None:
        self.ctx.state.filters.public_only = bool(e.control.value)
        self._changed("Updating public filter…")

    def _on_sort(self, e) -> None:
        self.ctx.state.filters.sort = e.control.value or "name_asc"
        self._changed("Loading files…")

    def _open_date_filter(self, e) -> None:
        date_filter.show(self.ctx, on_apply=self._dates_applied, on_clear=self._dates_cleared)

    def _dates_applied(self) -> None:
        self._changed("Applying date filter…")   # the filters event relabels the date button
        self.ctx.toast(self.ctx.state.filters.summary())

    def _dates_cleared(self) -> None:
        self._changed("Clearing date filter…")

    def _clear_all(self, e) -> None:
        self._cancel_search()
        self.ctx.state.filters.reset()
        self.ctx.state.user_search = ""          # v1 also cleared the Users-tab search
        self.search_field.value = ""
        self.sync_from_state()
        self._changed("Clearing all filters…")
        self.ctx.toast("All filters cleared")

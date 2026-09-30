"""Users tab: people found in the evidence DB, with search and a per-user "Filter files" drill-down."""
from __future__ import annotations

import asyncio
import logging
import re
import webbrowser
from typing import Optional

import flet as ft

from .context import EV_DATA_CHANGED, EV_FILTERS_CHANGED, EV_NAVIGATE_FILES, AppContext

logger = logging.getLogger(__name__)

USERS_TAB = 1
USER_LIMIT = 200
SEARCH_DEBOUNCE = 0.25
AVATAR_RADIUS = 28


def high_res_avatar(url: str) -> str:
    """Google profile photo URLs carry their size as `=s<px>`: ask for the largest one."""
    return re.sub(r"=s\d+", "=s4096", url)


def _stat_chip(label: str, value: int, bgcolor, color) -> ft.Container:
    return ft.Container(
        bgcolor=bgcolor, border_radius=8, padding=ft.Padding.symmetric(vertical=6, horizontal=12),
        content=ft.Column([ft.Text(label, size=11, color=color),
                           ft.Text(f"{value:,}", size=18, weight=ft.FontWeight.BOLD, color=color)],
                          spacing=0, alignment=ft.MainAxisAlignment.CENTER))


class UsersView:
    """Plain object (Flet 1.0 controls have their own build()); MainView mounts `root`."""

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        # Identity marker only (never read through): work finishing after a logout must not touch the
        # next session's state. ctx.state/ctx.events are always used via ctx.
        self._session = ctx.state
        self._generation = 0
        self._search_handle: Optional[asyncio.TimerHandle] = None
        self.search_field = ft.TextField(
            hint_text="Search users...", prefix_icon=ft.Icons.SEARCH, width=260, dense=True,
            border=ft.OutlineInputBorder(border_radius=20), value=ctx.state.user_search, on_change=self._on_search)
        self.clear_search_button = ft.IconButton(icon=ft.Icons.CLEAR, tooltip="Clear search",
                                                 on_click=lambda e: self.clear_search())
        self.filter_button = ft.Button("Filter by user", icon=ft.Icons.FILTER_LIST, disabled=True,
                                       on_click=lambda e: self.clear_filter())
        self.filter_label = ft.Text("None", weight=ft.FontWeight.BOLD)
        self.active_filter_chip = ft.Chip(
            label=ft.Row([ft.Text("Filtering:"), self.filter_label], spacing=4, tight=True),
            bgcolor=ft.Colors.BLUE_50, visible=False)
        self.list = ft.Column([self._message_row("Loading users…", spinner=True)], spacing=8)
        header = ft.Row([
            ft.Text("👥 Users", size=26, weight=ft.FontWeight.BOLD),
            ft.Row([self.search_field, self.clear_search_button, self.filter_button],
                   spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, wrap=True)
        self.root = ft.Column([header, ft.Divider(height=10), self.active_filter_chip, ft.Divider(height=10),
                               self.list], spacing=12, expand=True, scroll=ft.ScrollMode.AUTO)
        self._sync_search_controls()
        self._sync_filter_controls()
        ctx.events.subscribe(EV_DATA_CHANGED, self._on_data_changed)
        ctx.events.subscribe(EV_FILTERS_CHANGED, self._on_filters_changed)

    # ----------------------------------------------------------- reloads
    def _owns_session(self) -> bool:
        return self.ctx.state is self._session

    def _visible(self) -> bool:
        return self.ctx.state.active_tab == USERS_TAB

    def _refresh(self, *controls) -> None:
        """Repaint only while shown: Flet keeps a removed control's parent, so update() on a hidden tab
        would patch ids the client already dropped. MainView re-sends the whole root when showing it."""
        if self._owns_session() and self._visible():
            self.ctx.safe_update(*controls)

    async def activate(self) -> None:
        await self.reload()   # every visit: a scan may have changed the people meanwhile

    async def reload(self) -> None:
        self._generation += 1
        generation = self._generation
        search = self.ctx.state.user_search
        try:
            users = await asyncio.to_thread(self.ctx.repo.user_analytics, search, USER_LIMIT)
        except Exception as exc:
            if generation == self._generation and self._owns_session():
                logger.exception("Loading users failed")
                self.list.controls = [self._message_row("Could not load users.", color=ft.Colors.RED_700)]
                self._refresh(self.list)
                self.ctx.error(f"Failed to load users: {exc}")
            return
        if generation == self._generation and self._owns_session():
            self._render(users)

    def _on_data_changed(self, **_) -> None:
        if self._visible():
            self.ctx.dispatcher.spawn(self.reload)

    def _on_filters_changed(self, **_) -> None:
        """Mirror the user filter (set here, in the sidebar or cleared by "Clear All Filters")."""
        self._sync_filter_controls()
        # "Clear All Filters" also clears the Users search; never clobber a pending (typed) search.
        wanted = self.ctx.state.user_search
        if self._search_handle is None and (self.search_field.value or "").strip() != wanted:
            self.search_field.value = wanted
            self._refresh(self.search_field)
            self._sync_search_controls()
            if self._visible():
                self.ctx.dispatcher.spawn(self.reload)

    # ------------------------------------------------------------- search
    def _on_search(self, e) -> None:
        value = (e.control.value or "").strip()
        self._cancel_search()
        self._search_handle = self.ctx.dispatcher.later(SEARCH_DEBOUNCE, lambda: self._apply_search(value))

    def _apply_search(self, value: str) -> None:
        self._search_handle = None
        if not self._owns_session():
            return   # typed before a logout: must not leak into the next session
        self.ctx.state.user_search = value
        self._sync_search_controls()
        if self._visible():   # otherwise the next visit's activate() queries with it
            self.ctx.dispatcher.spawn(self.reload)

    def _cancel_search(self) -> None:
        if self._search_handle is not None:
            self._search_handle.cancel()
            self._search_handle = None

    def clear_search(self) -> None:
        self._cancel_search()
        self.search_field.value = ""
        self.ctx.state.user_search = ""
        self._refresh(self.search_field)
        self._sync_search_controls()
        self.ctx.dispatcher.spawn(self.reload)

    def _sync_search_controls(self) -> None:
        # The field itself is only repainted when its value is set from code (never mid-typing).
        self.clear_search_button.visible = bool(self.ctx.state.user_search)
        self._refresh(self.clear_search_button)

    # ------------------------------------------------------------ filters
    def _sync_filter_controls(self) -> None:
        filters = self.ctx.state.filters
        active = bool(filters.user_email)
        self.filter_button.content = "Clear Filter" if active else "Filter by user"
        self.filter_button.icon = ft.Icons.FILTER_ALT_OFF if active else ft.Icons.FILTER_LIST
        self.filter_button.disabled = not active
        self.filter_label.value = (filters.user_label or filters.user_email) if active else "None"
        self.active_filter_chip.visible = active
        self._refresh(self.filter_button, self.active_filter_chip)

    def clear_filter(self) -> None:
        state = self.ctx.state
        if not state.filters.user_email:
            return
        state.filters.user_email = state.filters.user_label = None
        state.page = 1
        # Files is not visible: FilesView defers the reload and says so ("… (will apply on Files tab)").
        self.ctx.events.emit(EV_FILTERS_CHANGED, message="Clearing user filter…")

    def filter_files(self, email: Optional[str], label: Optional[str] = None) -> None:
        """Drill-down: show the files this person owns or has a permission on."""
        if not email:
            return
        state = self.ctx.state
        label = label or email
        state.filters.user_email, state.filters.user_label = email, label
        state.page = 1
        self.ctx.events.emit(EV_FILTERS_CHANGED, message=f"Filtering files involving {label}…", navigate=True)
        self.ctx.events.emit(EV_NAVIGATE_FILES)

    # ------------------------------------------------------------- avatar
    def open_avatar(self, photo_url: Optional[str]) -> None:
        if not photo_url:
            self.ctx.toast("No avatar available")
            return
        self.ctx.dispatcher.background(self._open_in_browser, high_res_avatar(photo_url), name="open-avatar")

    def _open_in_browser(self, url: str) -> None:
        """Worker thread (webbrowser.open can block)."""
        try:
            webbrowser.open(url)
        except Exception as exc:
            logger.error("Failed to open avatar: %s", exc)
            self.ctx.dispatcher.ui(self.ctx.error, "Could not open avatar in browser")

    # ---------------------------------------------------------- rendering
    @staticmethod
    def _message_row(text: str, color=ft.Colors.GREY_600, spinner: bool = False) -> ft.Control:
        items: list[ft.Control] = [ft.ProgressRing(width=18, height=18, stroke_width=2)] if spinner else []
        return ft.Container(content=ft.Row([*items, ft.Text(text, size=13, color=color)], spacing=8),
                            padding=ft.Padding.symmetric(vertical=12, horizontal=4))

    @staticmethod
    def _empty_state() -> ft.Control:
        return ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.SEARCH_OFF, size=80, color=ft.Colors.GREY_400),
                ft.Text("No users yet", size=18, color=ft.Colors.GREY_600),
                ft.Text("Try scanning drive or adjusting search", size=13, color=ft.Colors.GREY_500),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8),
            padding=40, alignment=ft.Alignment.CENTER)

    def _render(self, users: list[dict]) -> None:
        self.list.controls = [self._user_card(user) for user in users] or [self._empty_state()]
        self._refresh(self.list)

    def _avatar(self, name: str, photo: Optional[str]) -> ft.Control:
        # Plain public URL (no token): Flutter loads it; the initial shows until/unless it does.
        avatar = ft.CircleAvatar(radius=AVATAR_RADIUS, bgcolor=ft.Colors.BLUE_100, foreground_image_src=photo or None,
                                 content=ft.Text((name or "?")[:1].upper(), size=16))

        def on_image_error(e) -> None:
            # Broken/expired photo URL: drop it so the initial letter shows instead of an empty circle.
            avatar.foreground_image_src = None
            self._refresh(avatar)

        avatar.on_image_error = on_image_error
        return ft.GestureDetector(content=avatar, on_tap=lambda e: self.open_avatar(photo),
                                  mouse_cursor=ft.MouseCursor.CLICK if photo else None)

    def _user_card(self, user: dict) -> ft.Control:
        email = user.get("email_address") or ""
        name = user.get("display_name") or email or "Unknown"
        info = ft.Row([
            self._avatar(name, user.get("photo_link")),
            ft.Column([
                ft.Text(name, size=15, weight=ft.FontWeight.BOLD, overflow=ft.TextOverflow.ELLIPSIS, max_lines=1),
                ft.Text(email, size=12, color=ft.Colors.GREY_600, overflow=ft.TextOverflow.ELLIPSIS, max_lines=1),
            ], spacing=2, expand=True),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        stats = ft.Row([
            _stat_chip("Shared with", user.get("files_shared_with_count") or 0, ft.Colors.BLUE_50, ft.Colors.BLUE_900),
            _stat_chip("Shared by", user.get("files_shared_by_count") or 0, ft.Colors.GREEN_50, ft.Colors.GREEN_900),
        ], spacing=10, run_spacing=6, wrap=True)
        actions = ft.Row([
            ft.TextButton("Filter files", icon=ft.Icons.FILTER_ALT, disabled=not email,
                          on_click=lambda e: self.filter_files(email, name)),
        ], spacing=6, alignment=ft.MainAxisAlignment.END)
        return ft.Container(
            bgcolor=ft.Colors.WHITE, border_radius=10, border=ft.Border.all(1, ft.Colors.GREY_200),
            padding=ft.Padding.symmetric(vertical=10, horizontal=14),
            content=ft.ResponsiveRow([
                ft.Container(content=info, col={"xs": 12, "md": 5, "lg": 4}),
                ft.Container(content=stats, col={"xs": 12, "md": 4, "lg": 4}),
                ft.Container(content=actions, col={"xs": 12, "md": 3, "lg": 2}, alignment=ft.Alignment.CENTER_RIGHT),
            ], run_spacing=8, alignment=ft.MainAxisAlignment.SPACE_BETWEEN))

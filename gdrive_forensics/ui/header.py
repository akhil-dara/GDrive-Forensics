"""Blue title bar: logo, interface guide, sidebar toggle, timezone, signed-in account, logout."""
from __future__ import annotations

from typing import Callable, Optional

import flet as ft

from ..core.formatting import TIMEZONE_OPTIONS
from .context import EV_FILTERS_CHANGED, EV_JOBS_CHANGED, EV_TIMEZONE_CHANGED, AppContext

INTERFACE_GUIDE = "\n".join([
    "🧠 GDrive Forensics Suite — files, users, analytics in one screen.",
    "🧭 Header: switch timezone, view signed-in account, logout.",
    "🎛️ Left rail: stacked filters & quick toggles for scope, owners, dates.",
    "📚 Tabs: Files / Users / Analytics switch the center canvas.",
    "📂 Results grid: tiles or list with badges for public, duplicates, shortcuts.",
    "🗃️ Queue bar: add selections, export filtered sets, refresh thumbnails.",
    "📉 Footer: live status, active download/ export progress, pagination controls.",
])


class HeaderBar:
    def __init__(self, ctx: AppContext, on_toggle_sidebar: Callable[[], None],
                 on_logout: Callable[[], None]) -> None:
        self.ctx = ctx
        self._on_toggle_sidebar = on_toggle_sidebar
        self._on_logout = on_logout
        self.toggle_button = ft.IconButton(
            icon=ft.Icons.MENU_OPEN, tooltip="Toggle filters", icon_size=18, icon_color=ft.Colors.WHITE,
            on_click=lambda e: self._on_toggle_sidebar(), style=ft.ButtonStyle(padding=0))
        self.timezone_dropdown = ft.Dropdown(
            options=[ft.dropdown.Option(key, text) for key, text in TIMEZONE_OPTIONS],
            value=ctx.state.timezone, width=150, dense=True, bgcolor=ft.Colors.WHITE,
            on_select=self._on_timezone, content_padding=ft.Padding.symmetric(vertical=4, horizontal=0))
        self.user_text = ft.Text(ctx.state.viewer_email or "User", size=11, color=ft.Colors.WHITE)
        self.logout_button = ft.IconButton(
            icon=ft.Icons.LOGOUT, tooltip="Logout", on_click=lambda e: self._on_logout(),
            icon_color=ft.Colors.WHITE, disabled_color=ft.Colors.WHITE_38, icon_size=16,
            style=ft.ButtonStyle(padding=0), disabled=bool(ctx.active_jobs))
        self.root = ft.Container(
            content=ft.Row([
                ft.Row([
                    ft.Image(src="logo.png", width=24, height=24, fit=ft.BoxFit.CONTAIN),
                    ft.Text("GDrive Forensics", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    ft.IconButton(icon=ft.Icons.INFO_OUTLINE, icon_color=ft.Colors.WHITE, tooltip=INTERFACE_GUIDE,
                                  icon_size=16, style=ft.ButtonStyle(padding=0)),
                ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Row([self.toggle_button, self.timezone_dropdown, self.user_text, self.logout_button],
                       spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=ft.Colors.BLUE_700,
            padding=ft.Padding.symmetric(vertical=6, horizontal=12))
        ctx.events.subscribe(EV_JOBS_CHANGED, lambda **kw: self.set_logout_enabled(not self.ctx.active_jobs))

    def build(self) -> ft.Control:
        return self.root

    def set_user(self, email: Optional[str]) -> None:
        self.user_text.value = email or "User"
        self.ctx.safe_update(self.user_text)

    def set_logout_enabled(self, enabled: bool) -> None:
        """Logging out mid-job would pull the client from under a running worker."""
        self.logout_button.disabled = not enabled
        self.ctx.safe_update(self.logout_button)

    def set_sidebar_collapsed(self, collapsed: bool) -> None:
        self.toggle_button.icon = ft.Icons.MENU if collapsed else ft.Icons.MENU_OPEN
        self.ctx.safe_update(self.toggle_button)

    def _on_timezone(self, e) -> None:
        value = e.control.value or "UTC"
        if value == self.ctx.state.timezone:
            return
        self.ctx.state.timezone = value
        self.ctx.events.emit(EV_TIMEZONE_CHANGED, timezone=value)
        # Listings render timestamps in the selected zone, so they must be rebuilt.
        self.ctx.events.emit(EV_FILTERS_CHANGED, message="Updating timezone…")

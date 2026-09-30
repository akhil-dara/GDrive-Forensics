"""OAuth landing screen."""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

import flet as ft

from ..config import APP_TITLE
from ..drive.auth import AUTH_REASON_MESSAGES, OAuthCancelled
from ..logging_setup import AUTH_LOGGER

logger = logging.getLogger(AUTH_LOGGER)

# Deliberately does not repeat the button label, so the label identifies exactly one control.
IDLE_STATUS = "Click the sign-in button above to begin authentication"


class LoginView:
    def __init__(self, ctx, on_authenticated: Callable, reason: Optional[str] = None) -> None:
        self.ctx = ctx
        self.on_authenticated = on_authenticated
        self._cancel: Optional[threading.Event] = None
        self.banner_text = ft.Text("", size=13, color=ft.Colors.ORANGE_900)
        self.banner = ft.Container(
            content=ft.Row([ft.Icon(ft.Icons.WARNING_AMBER, color=ft.Colors.ORANGE_800), self.banner_text],
                           spacing=10),
            bgcolor=ft.Colors.ORANGE_50, border=ft.Border.all(1, ft.Colors.ORANGE_200), border_radius=8,
            padding=12, visible=False, width=800)
        self.status = ft.Text(IDLE_STATUS, size=14, selectable=True, color=ft.Colors.GREY_700)
        self.login_button = ft.Button(
            "Start OAuth Login", icon=ft.Icons.LOGIN, on_click=self.start_oauth, height=60, width=250,
            style=ft.ButtonStyle(color=ft.Colors.WHITE, bgcolor=ft.Colors.BLUE_700, padding=20))
        self.cancel_button = ft.TextButton("Cancel sign-in", icon=ft.Icons.CLOSE, on_click=self.cancel_oauth,
                                           visible=False)
        if reason:
            self.show_banner(AUTH_REASON_MESSAGES.get(reason, reason))

    def build(self) -> ft.Control:
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.FOLDER_SPECIAL, size=64, color=ft.Colors.BLUE_700),
                    ft.Column([
                        ft.Text(APP_TITLE, size=36, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_900),
                        ft.Text("Professional Digital Forensics Tool - read-only access", size=18,
                                color=ft.Colors.GREY_700),
                    ], spacing=5),
                ], spacing=20, alignment=ft.MainAxisAlignment.CENTER),
                ft.Divider(height=40, color=ft.Colors.TRANSPARENT),
                self.banner,
                ft.Row([self.login_button, self.cancel_button], alignment=ft.MainAxisAlignment.CENTER),
                ft.Container(content=self.status, padding=25, bgcolor=ft.Colors.BLUE_50, border_radius=10,
                             width=800, border=ft.Border.all(2, ft.Colors.BLUE_200)),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=25),
            padding=50, alignment=ft.Alignment.CENTER, expand=True)

    def show_banner(self, message: str) -> None:
        self.banner_text.value = message
        self.banner.visible = True
        self.ctx.safe_update(self.banner)

    def _set_waiting(self, waiting: bool) -> None:
        self.login_button.disabled = waiting
        self.cancel_button.visible = waiting
        self.ctx.safe_update(self.login_button, self.cancel_button)

    def start_oauth(self, e=None) -> None:
        if self.login_button.disabled:
            return   # a flow is already waiting (double-click / queued click): never start a second one
        if not self.ctx.paths.credentials_file.exists():
            self.show_banner(AUTH_REASON_MESSAGES["missing_client_secrets"])
            return
        self._cancel = threading.Event()
        self._set_waiting(True)
        self.status.value = "Opening Google sign-in in your browser…"
        self.ctx.safe_update(self.status)
        cancel = self._cancel

        def show_url(url: str) -> None:
            def apply() -> None:
                self.status.value = ("Waiting for Google sign-in (listening on 127.0.0.1 only).\n\n"
                                     "If the browser did not open, copy this URL into it:\n" + url)
                self.ctx.safe_update(self.status)
            self.ctx.dispatcher.ui(apply)

        def worker() -> None:
            try:
                creds = self.ctx.auth.run_oauth_flow(show_url, cancel=cancel)
            except OAuthCancelled:
                self.ctx.dispatcher.ui(self._reset, "Sign-in cancelled.")
                return
            except FileNotFoundError:
                # credentials.json disappeared between the pre-check and the flow.
                self.ctx.dispatcher.ui(self._reset, IDLE_STATUS, AUTH_REASON_MESSAGES["missing_client_secrets"])
                return
            except Exception as exc:
                logger.exception("Sign-in failed")
                self.ctx.dispatcher.ui(self._reset, IDLE_STATUS, f"Sign-in failed: {exc}")
                return
            self.ctx.dispatcher.ui(self.on_authenticated, creds)

        self.ctx.dispatcher.background(worker, name="oauth")

    def _reset(self, status: Optional[str], banner: Optional[str] = None) -> None:
        self._set_waiting(False)
        if status:
            self.status.value = status
            self.ctx.safe_update(self.status)
        if banner:
            self.show_banner(banner)

    def cancel_oauth(self, e=None) -> None:
        if self._cancel is not None:
            self._cancel.set()

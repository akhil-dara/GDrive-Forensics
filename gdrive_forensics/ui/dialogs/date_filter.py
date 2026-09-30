"""Date range filter dialog (modified-time range, inclusive)."""
from __future__ import annotations

from datetime import date, datetime, tzinfo
from typing import Callable, Optional

import flet as ft

FIRST_DATE = date(2000, 1, 1)
LAST_DATE = date(2035, 12, 31)


def as_date(value, tz: Optional[tzinfo] = None) -> Optional[date]:
    """The calendar date the user picked.

    Flet 1.0.1's client sends a DatePicker pick (Flutter local midnight) as `toUtc()`, which Python
    decodes as an AWARE UTC datetime: 2025-01-02 picked in IST arrives as 2025-01-01 18:30 UTC.
    Aware values are therefore converted to `tz` (default: the system zone the desktop client
    picked in) before taking the date. Naive datetimes and plain dates are taken as-is.
    """
    if isinstance(value, str):
        if not value:
            return None
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(tz)
        return value.date()
    if isinstance(value, date):
        return value
    return None


def _selected(value: Optional[date]) -> str:
    return f"Selected: {value.strftime('%Y-%m-%d') if value else 'Not set'}"


def show(ctx, on_apply: Callable[[], None], on_clear: Optional[Callable[[], None]] = None) -> ft.AlertDialog:
    """Edit `ctx.state.filters.date_from/date_to`.

    Picks are held locally until Apply (Cancel discards them). Apply commits and calls `on_apply`;
    "Clear Dates" clears both and calls `on_clear` (or `on_apply` when not given).
    """
    pending = {"from": ctx.state.filters.date_from, "to": ctx.state.filters.date_to}
    labels = {key: ft.Text(_selected(pending[key]), size=12, color=ft.Colors.GREY_700) for key in pending}

    def open_picker(key: str) -> None:
        def on_change(e) -> None:
            pending[key] = as_date(e.control.value)
            labels[key].value = _selected(pending[key])
            ctx.safe_update(labels[key])

        # A DatePicker is its own dialog stacked above this one: show it directly on the page
        # (ctx.show_dialog would close the date filter dialog). A fresh picker per click avoids
        # "already opened" errors while a previous one is still being dismissed.
        ctx.page.show_dialog(ft.DatePicker(first_date=FIRST_DATE, last_date=LAST_DATE, value=pending[key],
                                           on_change=on_change))

    def apply(e) -> None:
        filters = ctx.state.filters
        filters.date_from, filters.date_to = pending["from"], pending["to"]
        ctx.close_dialog(dialog)
        on_apply()

    def clear(e) -> None:
        ctx.state.filters.date_from = ctx.state.filters.date_to = None
        ctx.close_dialog(dialog)
        (on_clear or on_apply)()

    dialog = ft.AlertDialog(
        title=ft.Text("📅 Date Range Filter"),
        content=ft.Container(
            content=ft.Column([
                ft.Text("From Date", weight=ft.FontWeight.BOLD),
                ft.Button("Pick From Date", icon=ft.Icons.CALENDAR_TODAY, on_click=lambda e: open_picker("from")),
                labels["from"],
                ft.Divider(),
                ft.Text("To Date", weight=ft.FontWeight.BOLD),
                ft.Button("Pick To Date", icon=ft.Icons.CALENDAR_TODAY, on_click=lambda e: open_picker("to")),
                labels["to"],
            ], tight=True, spacing=12),
            width=350, padding=20),
        actions=[
            ft.TextButton("Clear Dates", on_click=clear),
            ft.TextButton("Cancel", on_click=lambda e: ctx.close_dialog(dialog)),
            ft.Button("Apply", on_click=apply),
        ])
    ctx.show_dialog(dialog)
    return dialog

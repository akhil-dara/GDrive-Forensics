"""Prompt shown when downloading a Drive shortcut: skip it (or all shortcuts) or export its target."""
from __future__ import annotations

from typing import Callable

import flet as ft


def show(ctx, record: dict, *, on_export: Callable[[str], None]) -> None:
    ctx.show_dialog(build(ctx, record, on_export=on_export))


def build(ctx, record: dict, *, on_export: Callable[[str], None]) -> ft.AlertDialog:
    name = record.get("name") or record.get("id") or "This file"

    def choose(export_target: bool, skip_all: bool = False) -> Callable:
        def handler(e) -> None:
            if skip_all:
                ctx.state.skip_all_shortcuts = True
            ctx.close_dialog(dialog)
            if not export_target:
                return
            target = record.get("shortcut_target_id")
            if target:
                on_export(target)
            else:
                ctx.error("Shortcut target not found")
        return handler

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("🔗 Shortcut Detected"),
        content=ft.Text(f"'{name}' is a shortcut. Do you want to export the target file?"),
        actions=[
            ft.TextButton("Skip", on_click=choose(False)),
            ft.TextButton("Skip All Shortcuts", on_click=choose(False, skip_all=True)),
            ft.Button("Export Target", on_click=choose(True)),
        ])
    return dialog

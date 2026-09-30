"""Right-click menu for a file: info, download, queue and copy ID / path / link."""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

import flet as ft

from ...core.mime import is_folder

logger = logging.getLogger(__name__)


def drive_link(record: dict) -> str:
    return record.get("web_view_link") or f"https://drive.google.com/file/d/{record['id']}/view"


def show(ctx, file_id: str, *, on_info: Callable[[str], None], on_download: Callable[[str], None],
         on_queue: Callable[[str], None]) -> None:
    """Look the file up off the loop, then open the menu."""
    ctx.dispatcher.spawn(_show, ctx, file_id, on_info, on_download, on_queue)


async def _show(ctx, file_id, on_info, on_download, on_queue) -> None:
    try:
        record = await asyncio.to_thread(ctx.repo.get_file, file_id)
    except Exception as exc:
        logger.exception("Context menu lookup for %s failed", file_id)
        ctx.error(f"Failed to open context menu: {exc}")
        return
    if record is None:
        ctx.error("File not found")
        return
    ctx.show_dialog(build(ctx, record, on_info=on_info, on_download=on_download, on_queue=on_queue))


def build(ctx, record: dict, *, on_info, on_download, on_queue) -> ft.AlertDialog:
    file_id = record["id"]
    name = record.get("name") or ""
    full_path = record.get("full_path") or "/"

    def close() -> None:
        ctx.close_dialog(dialog)

    def close_then(fn: Callable[[str], None]) -> Callable:
        def run(e) -> None:
            close()
            fn(file_id)
        return run

    def copy(text: str, toast: str) -> Callable:
        def run(e) -> None:
            ctx.copy(text, toast)
            close()
        return run

    def queue(e) -> None:
        on_queue(file_id)
        close()

    actions = [ft.TextButton("Info", icon=ft.Icons.INFO_OUTLINE, on_click=close_then(on_info))]
    if not is_folder(record.get("mime_type")):
        actions.append(ft.TextButton("Download", icon=ft.Icons.DOWNLOAD, on_click=close_then(on_download)))
    actions += [
        ft.TextButton("Add to Queue", icon=ft.Icons.PLAYLIST_ADD, on_click=queue),
        ft.TextButton("Copy ID", icon=ft.Icons.BADGE, on_click=copy(file_id, "File ID copied")),
        ft.TextButton("Copy Path", icon=ft.Icons.FOLDER_COPY, on_click=copy(full_path, "Path copied")),
        ft.TextButton("Copy Link", icon=ft.Icons.LINK, on_click=copy(drive_link(record), "Link copied")),
        ft.TextButton("Close", icon=ft.Icons.CLOSE, on_click=lambda e: close()),
    ]
    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text(name[:40] or "File", max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
        content=ft.Text(full_path, size=12, color=ft.Colors.GREY_600, selectable=True),
        actions=actions)
    return dialog

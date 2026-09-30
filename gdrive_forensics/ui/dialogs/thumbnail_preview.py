"""Large thumbnail preview (fetched off the loop; the token never goes into a URL)."""
from __future__ import annotations

import asyncio
import logging
import re
import webbrowser
from typing import Optional

import flet as ft

from .context_menu import drive_link

logger = logging.getLogger(__name__)

PREVIEW_SIZE = 2048


def scaled_link(link: str, size: int = PREVIEW_SIZE) -> str:
    return re.sub(r"=s\d+", f"=s{size}", link)


def show(ctx, file_id: str) -> ft.AlertDialog:
    """Open the preview at once with a spinner; the image arrives when the worker has it."""
    body = ft.Container(
        content=ft.Column([ft.ProgressRing(), ft.Text("Loading preview…", size=12, color=ft.Colors.GREY_600)],
                          horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
        width=640, height=640, alignment=ft.Alignment.CENTER)
    open_button = ft.TextButton("Open in Browser", icon=ft.Icons.OPEN_IN_NEW, disabled=True)
    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("🖼️ Thumbnail Preview"),
        content=body,
        actions=[open_button, ft.TextButton("Close", on_click=lambda e: ctx.close_dialog(dialog))])
    ctx.show_dialog(dialog)
    ctx.dispatcher.spawn(_load, ctx, file_id, dialog, body, open_button)
    return dialog


def _fetch(repo, client, file_id: str) -> tuple[Optional[dict], Optional[bytes]]:
    """Worker thread: refresh a missing thumbnail link from Drive, then download the large image."""
    record = repo.get_file(file_id)
    if record is None:
        return None, None
    if not record.get("thumbnail_link") and client is not None:
        meta = client.thumbnail_metadata(file_id)
        if meta and meta.get("thumbnail_link"):
            owner_photo = meta.get("owner_photo") or record.get("owner_photo")   # never clobber with None
            repo.update_thumbnail_metadata(file_id, thumbnail_link=meta["thumbnail_link"], owner_photo=owner_photo,
                                           owner_name=meta.get("owner_name"), owner_email=meta.get("owner_email"))
            record = {**record, "thumbnail_link": meta["thumbnail_link"], "owner_photo": owner_photo}
    link = record.get("thumbnail_link")
    if not link or client is None:
        return record, None
    return record, client.fetch_image(scaled_link(link))


async def _load(ctx, file_id: str, dialog: ft.AlertDialog, body: ft.Container, open_button: ft.TextButton) -> None:
    try:
        record, data = await asyncio.to_thread(_fetch, ctx.repo, ctx.client, file_id)
    except Exception as exc:
        logger.exception("Thumbnail preview for %s failed", file_id)
        if dialog.open:
            ctx.close_dialog(dialog)
            ctx.error(f"Failed to preview thumbnail: {exc}")
        return
    if not dialog.open:
        return   # closed while loading
    if record is None or not record.get("thumbnail_link"):
        ctx.close_dialog(dialog)
        ctx.error("File not found" if record is None else "No thumbnail available")
        return
    link = drive_link(record)   # the Drive page, never a tokenised image URL
    open_button.disabled = False
    open_button.on_click = lambda e: ctx.dispatcher.background(webbrowser.open, link, name="open-browser")
    body.content = (ft.Image(src=data, width=620, height=620, fit=ft.BoxFit.CONTAIN) if data else
                    ft.Text("Could not download the thumbnail image.", size=12, color=ft.Colors.GREY_600))
    ctx.safe_update(body, open_button)

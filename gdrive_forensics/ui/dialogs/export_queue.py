"""Export queue dialog: list queued files, remove one or all, start the queue export."""
from __future__ import annotations

import asyncio
import logging

import flet as ft

from ...core.mime import get_file_icon
from ..context import EV_QUEUE_CHANGED

logger = logging.getLogger(__name__)


def show(ctx) -> None:
    """Load the queue off the loop, then open the dialog."""
    ctx.dispatcher.spawn(_open, ctx)


async def _open(ctx) -> None:
    session = ctx.state
    try:
        records = await asyncio.to_thread(ctx.repo.queue_files)
    except Exception as exc:
        logger.exception("Loading the export queue failed")
        ctx.error(f"Failed to load export queue: {exc}")
        return
    if ctx.state is session:
        ctx.show_dialog(QueueDialog(ctx, records).dialog)


class QueueDialog:
    def __init__(self, ctx, records: list[dict]) -> None:
        self.ctx = ctx
        self._session = ctx.state          # identity marker only
        self.dialog = ft.AlertDialog()
        self.render(records)

    def render(self, records: list[dict]) -> None:
        items: list[ft.Control] = [ft.ListTile(
            leading=ft.Text(get_file_icon(r.get("mime_type")), size=20),
            title=ft.Text(r.get("name") or r["id"], size=13, overflow=ft.TextOverflow.ELLIPSIS),
            subtitle=ft.Text(r.get("full_path") or "/", size=11, color=ft.Colors.GREY_600,
                             overflow=ft.TextOverflow.ELLIPSIS),
            trailing=ft.IconButton(icon=ft.Icons.REMOVE_CIRCLE, icon_color=ft.Colors.RED_700, tooltip="Remove",
                                   on_click=lambda e, fid=r["id"]: self.ctx.dispatcher.spawn(self._remove, fid)),
        ) for r in records] or [ft.Text("Queue is empty", color=ft.Colors.GREY_600)]
        empty = not records
        self.dialog.title = ft.Text(f"📋 Export Queue ({len(records)} items)")
        self.dialog.content = ft.Container(width=600, height=400,
                                           content=ft.Column(items, scroll=ft.ScrollMode.AUTO, spacing=4))
        self.dialog.actions = [
            ft.TextButton("Clear All", on_click=lambda e: self.ctx.dispatcher.spawn(self._clear), disabled=empty),
            ft.TextButton("Close", on_click=lambda e: self.ctx.close_dialog(self.dialog)),
            ft.Button("Export Queue", icon=ft.Icons.DOWNLOAD, on_click=lambda e: self._export(), disabled=empty),
        ]
        self.ctx.safe_update(self.dialog)

    async def _remove(self, file_id: str) -> None:
        await self._change(self.ctx.repo.remove_from_queue, [file_id], failure="Failed to remove file")

    async def _clear(self) -> None:
        await self._change(self.ctx.repo.clear_queue, failure="Failed to clear queue")

    async def _change(self, mutate, *args, failure: str) -> None:
        repo = self.ctx.repo

        def run() -> tuple:
            mutate(*args)
            return repo.queue_ids(), repo.queue_files()

        try:
            queue_ids, records = await asyncio.to_thread(run)
        except Exception as exc:
            logger.exception(failure)
            self.ctx.error(f"{failure}: {exc}")
            return
        if self.ctx.state is not self._session:
            return
        self.ctx.state.queue_ids = queue_ids
        self.ctx.events.emit(EV_QUEUE_CHANGED)
        self.render(records)

    def _export(self) -> None:
        self.ctx.close_dialog(self.dialog)
        jobs = self.ctx.jobs
        if jobs is None:
            self.ctx.toast("Exports not available yet")
            return
        self.ctx.dispatcher.spawn(jobs.export_queue)

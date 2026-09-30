"""File details dialog: metadata, hashes, permissions, recent activity, revisions and raw JSON."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Optional

import flet as ft

from ...core.formatting import convert_timezone, format_size
from ...core.mime import get_file_icon, size_label

logger = logging.getLogger(__name__)

DEFAULT_SIZE = (550, 500)
ROLE_ICONS = {
    "owner": (ft.Icons.ADMIN_PANEL_SETTINGS, ft.Colors.GREEN_700),
    "writer": (ft.Icons.EDIT, ft.Colors.BLUE_700),
    "commenter": (ft.Icons.COMMENT, ft.Colors.ORANGE_700),
    "reader": (ft.Icons.VISIBILITY, ft.Colors.PURPLE_700),
}
ACTION_ICONS = {
    "create": (ft.Icons.ADD_CIRCLE, ft.Colors.GREEN_700),
    "edit": (ft.Icons.EDIT, ft.Colors.BLUE_700),
    "move": (ft.Icons.DRIVE_FILE_MOVE, ft.Colors.ORANGE_700),
    "rename": (ft.Icons.DRIVE_FILE_RENAME_OUTLINE, ft.Colors.TEAL_700),
    "delete": (ft.Icons.DELETE, ft.Colors.RED_700),
    "restore": (ft.Icons.RESTORE, ft.Colors.GREEN_600),
    "permission_change": (ft.Icons.LOCK, ft.Colors.PURPLE_700),
    "comment": (ft.Icons.COMMENT, ft.Colors.AMBER_700),
}


def dialog_size(page) -> tuple[float, float]:
    """70% x 80% of the window, capped at 650 x 600; 550 x 500 while the size is unknown."""
    width, height = getattr(page, "width", None), getattr(page, "height", None)
    if not width or not height:
        return DEFAULT_SIZE
    return min(width * 0.7, 650), min(height * 0.8, 600)


def show(ctx, file_id: str, *, on_download: Callable[[str], None], on_preview: Callable[[str], None],
         on_queue: Callable[[str], None]) -> None:
    """Load the file's evidence off the loop, then open the dialog."""
    ctx.dispatcher.spawn(_show, ctx, file_id, on_download, on_preview, on_queue)


def _load(repo, file_id: str) -> Optional[dict]:
    record = repo.get_file(file_id)
    if record is None:
        return None
    return {"file": record, "permissions": repo.get_permissions(file_id),
            "revisions": repo.list_revisions(file_id), "activity": repo.file_activity(file_id, 10)}


def _fetch_revisions(client, repo, file_id: str) -> list[dict]:
    repo.replace_revisions(file_id, client.list_revisions(file_id))
    return repo.list_revisions(file_id)


async def _show(ctx, file_id, on_download, on_preview, on_queue) -> None:
    try:
        data = await asyncio.to_thread(_load, ctx.repo, file_id)
    except Exception as exc:
        logger.exception("Loading file info for %s failed", file_id)
        ctx.error(f"Failed to load file info: {exc}")
        return
    if data is None:
        ctx.error("File not found in database")
        return
    ctx.show_dialog(_build(ctx, data, on_download, on_preview, on_queue))


def info_row(label: str, value, selectable: bool = False, color=None) -> ft.Row:
    return ft.Row([
        ft.Text(label, size=11, weight=ft.FontWeight.BOLD, width=110, color=ft.Colors.GREY_700),
        ft.Text(str(value), size=11, selectable=selectable, color=color or ft.Colors.GREY_800, expand=True),
    ], spacing=6)


def _heading(text: str) -> ft.Text:
    return ft.Text(text, size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700)


def _boxed(controls: list, height: int = 150) -> ft.Container:
    return ft.Container(content=ft.Column(controls, spacing=0, scroll=ft.ScrollMode.AUTO), height=height,
                        bgcolor=ft.Colors.GREY_50, border_radius=4, padding=5)


def _permission_tiles(ctx, permissions: list[dict]) -> list[ft.Control]:
    if not permissions:
        return [ft.Text("No permissions found", size=12, color=ft.Colors.GREY_600)]
    thumbs = ctx.thumbnails
    tiles = []
    for perm in permissions:
        role = perm.get("role") or "unknown"
        icon, color = ROLE_ICONS.get(role, (ft.Icons.PERSON, ft.Colors.GREY_700))
        email = perm.get("email_address")
        photo = thumbs.cached("avatar", email) if thumbs is not None else None   # memory only: safe on loop
        leading = (ft.CircleAvatar(radius=12, foreground_image_src=photo) if photo
                   else ft.Icon(icon, color=color, size=20))
        name = perm.get("display_name") or email or (
            "Anyone with the link" if perm.get("type") == "anyone" else "Unknown")
        tiles.append(ft.ListTile(leading=leading, dense=True,
                                 title=ft.Text(name, size=12, weight=ft.FontWeight.BOLD),
                                 subtitle=ft.Text(f"{email or 'N/A'} • {role.upper()}", size=10)))
    return tiles


def _activity_section(rows: list[dict], tz: str) -> list[ft.Control]:
    if not rows:
        return []
    tiles = []
    for row in rows:
        action = row.get("action_type") or "unknown"
        icon, color = ACTION_ICONS.get(action, (ft.Icons.INFO, ft.Colors.GREY_600))
        actor = row.get("actor_email") or row.get("actor_name") or "Unknown"
        when = convert_timezone(row.get("timestamp"), tz)
        tiles.append(ft.ListTile(leading=ft.Icon(icon, color=color, size=18), dense=True,
                                 title=ft.Text(action.replace("_", " ").title(), size=12, weight=ft.FontWeight.BOLD),
                                 subtitle=ft.Text(f"{actor} • {when}", size=10, color=ft.Colors.GREY_600)))
    return [ft.Divider(height=10), _heading(f"RECENT ACTIVITY ({len(rows)})"), _boxed(tiles)]


def _revision_tiles(revisions: list[dict], tz: str) -> list[ft.Control]:
    if not revisions:
        return [ft.Text("No revisions stored yet.", size=12, color=ft.Colors.GREY_600)]
    tiles = []
    for rev in revisions:
        size = format_size(rev["size"]) if rev.get("size") else "—"
        by = rev.get("modified_by_name") or rev.get("modified_by_email") or "Unknown"
        tiles.append(ft.ListTile(
            leading=ft.Icon(ft.Icons.HISTORY, color=ft.Colors.BLUE_GREY_500, size=18), dense=True,
            title=ft.Text(convert_timezone(rev.get("modified_time"), tz) or "Unknown time", size=12,
                          weight=ft.FontWeight.BOLD),
            subtitle=ft.Text(f"{size} • MD5: {rev.get('md5_checksum') or 'N/A'} • {by}", size=10,
                             color=ft.Colors.GREY_600, selectable=True)))
    return tiles


def _pretty_json(raw: Optional[str]) -> str:
    raw = raw or "{}"
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (TypeError, ValueError):
        return raw


def _build(ctx, data: dict, on_download, on_preview, on_queue) -> ft.AlertDialog:
    record, permissions = data["file"], data["permissions"]
    file_id = record["id"]
    tz = ctx.state.timezone
    width, height = dialog_size(ctx.page)
    metadata = _pretty_json(record.get("metadata_json"))

    revision_count = ft.Text(str(len(data["revisions"])), size=11, color=ft.Colors.GREY_800, expand=True)
    revision_list = ft.Column(_revision_tiles(data["revisions"], tz), spacing=0)
    fetch_button = ft.TextButton("Fetch revisions", icon=ft.Icons.HISTORY)

    async def fetch_revisions(e) -> None:
        client = ctx.client
        if client is None:
            ctx.error("Sign in to fetch revisions")
            return
        fetch_button.disabled, fetch_button.content = True, "Fetching revisions…"
        ctx.safe_update(fetch_button)
        try:
            revisions = await asyncio.to_thread(_fetch_revisions, client, ctx.repo, file_id)
        except Exception as exc:
            logger.exception("Fetching revisions for %s failed", file_id)
            revisions = None
            ctx.error(f"Could not fetch revisions: {exc}")
        finally:
            fetch_button.disabled, fetch_button.content = False, "Fetch revisions"
        if revisions is not None:
            revision_count.value = str(len(revisions))
            revision_list.controls = _revision_tiles(revisions, ctx.state.timezone)
        ctx.safe_update(fetch_button, revision_count, revision_list)

    fetch_button.on_click = fetch_revisions

    def close(e=None) -> None:
        ctx.close_dialog(dialog)

    def download(e) -> None:
        close()
        on_download(file_id)

    def queue(e) -> None:
        on_queue(file_id)
        close()

    content = ft.Column([
        ft.Row([
            ft.Text(get_file_icon(record.get("mime_type")), size=32),
            ft.Column([
                ft.Text(record.get("name") or "Unknown", size=16, weight=ft.FontWeight.BOLD, selectable=True),
                ft.Text(record.get("mime_type") or "Unknown", size=11, color=ft.Colors.GREY_600, selectable=True),
            ], spacing=2, expand=True),
        ], spacing=10),
        ft.Divider(height=10),
        _heading("DETAILS"),
        info_row("Size", size_label(record.get("mime_type"), record.get("size"))),
        info_row("Path", record.get("full_path") or "/", selectable=True),
        info_row("Created", convert_timezone(record.get("created_time"), tz) or "N/A"),
        info_row("Modified", convert_timezone(record.get("modified_time"), tz) or "N/A"),
        info_row("Owner", f"{record.get('owner_name') or 'Unknown'} ({record.get('owner_email') or 'N/A'})"),
        info_row("Web Link", record.get("web_view_link") or "N/A", selectable=True, color=ft.Colors.BLUE_600),
        info_row("MD5", record.get("md5_checksum") or "N/A", selectable=True),
        info_row("SHA1", record.get("sha1_checksum") or "N/A", selectable=True),
        info_row("SHA256", record.get("sha256_checksum") or "N/A", selectable=True),
        ft.Row([ft.Text("Revisions", size=11, weight=ft.FontWeight.BOLD, width=110, color=ft.Colors.GREY_700),
                revision_count, fetch_button], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        revision_list,
        ft.Divider(height=10),
        ft.Row([_heading("RAW METADATA (JSON)"),
                ft.TextButton("Copy", icon=ft.Icons.CONTENT_COPY,
                              on_click=lambda e: ctx.copy(metadata, "Metadata JSON copied"))],
               alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.TextField(value=metadata, multiline=True, read_only=True, text_size=12, height=200,
                     border=ft.OutlineInputBorder()),
        ft.Divider(height=10),
        _heading(f"SHARED WITH ({len(permissions)})"),
        _boxed(_permission_tiles(ctx, permissions)),
        *_activity_section(data["activity"], tz),
    ], spacing=8, scroll=ft.ScrollMode.AUTO, height=height,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH)   # full width, e.g. the raw-metadata field

    dialog = ft.AlertDialog(
        title=ft.Text("📄 File Details"),
        content=ft.Container(content=content, width=width),
        actions=[
            ft.TextButton("Download", icon=ft.Icons.DOWNLOAD, on_click=download),
            ft.TextButton("Preview Thumbnail", icon=ft.Icons.IMAGE, on_click=lambda e: on_preview(file_id),
                          disabled=not record.get("thumbnail_link")),
            ft.TextButton("Add to Queue", icon=ft.Icons.PLAYLIST_ADD, on_click=queue),
            ft.TextButton("Close", on_click=close),
        ])
    return dialog

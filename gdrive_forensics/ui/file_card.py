"""File cards for the Files tab: tile and list layouts, badges, thumbnail/avatar slots, actions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import flet as ft

from ..core.mime import get_file_icon, get_mime_label, is_folder, size_label

THUMB_SIZE = 36
AVATAR_SIZE = 22
TILE_WIDTH = 240

_HASHES = (("MD5", "md5_checksum", ft.Colors.ORANGE_700),
           ("SHA1", "sha1_checksum", ft.Colors.BLUE_700),
           ("SHA256", "sha256_checksum", ft.Colors.GREEN_700))


@dataclass
class CardActions:
    """Per-card callbacks; each takes the file id (`open_folder` takes `(file_id, name)`)."""
    info: Callable[[str], None]
    download: Callable[[str], None]
    queue: Callable[[str], None]
    open_folder: Callable[[str, str], None]
    context: Callable[[str], None]
    toggle_select: Callable[[str], None]


@dataclass
class CardMeta:
    is_duplicate: bool = False
    revision_count: int = 0
    modified_str: str = ""
    thumb: Optional[bytes] = None      # already-fetched image bytes (memory cache), else a slot job
    avatar: Optional[bytes] = None


def thumb_image(data: bytes) -> ft.Image:
    return ft.Image(src=data, width=THUMB_SIZE, height=THUMB_SIZE, fit=ft.BoxFit.COVER, border_radius=4)


def avatar_image(data: bytes) -> ft.Image:
    return ft.Image(src=data, width=AVATAR_SIZE, height=AVATAR_SIZE, fit=ft.BoxFit.COVER,
                    border_radius=AVATAR_SIZE // 2)


def selection_checkbox(card: ft.Control) -> Optional[ft.Checkbox]:
    """The selection checkbox of a card built in selection mode (kept in the card's `data`)."""
    return card.data if isinstance(card.data, ft.Checkbox) else None


def owner_label(record: dict) -> str:
    return record.get("owner_name") or record.get("owner_email") or "Unknown"


def hash_line(record: dict) -> tuple[str, str]:
    for label, key, color in _HASHES:
        if record.get(key):
            return f"{label}: {record[key]}", color
    return "No hash available", ft.Colors.GREY_500


def _chip(icon: str, label: str, color, label_color=None) -> ft.Chip:
    return ft.Chip(
        label=ft.Row([ft.Text(icon, size=12), ft.Text(label, size=10, weight=ft.FontWeight.BOLD, color=label_color)],
                     spacing=4, tight=True, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor=color, height=22, padding=ft.Padding.symmetric(vertical=2, horizontal=8))


def badges(record: dict, meta: CardMeta) -> list[ft.Control]:
    chips: list[ft.Control] = []
    if record.get("starred"):
        chips.append(_chip("⭐", "Starred", ft.Colors.YELLOW_100))
    if record.get("trashed"):
        chips.append(_chip("🗑️", "Trashed", ft.Colors.RED_100))
    if record.get("is_public"):
        chips.append(_chip("🌐", "Public", ft.Colors.PURPLE_100))
    if meta.is_duplicate:
        chips.append(_chip("⚠️", "Path conflict", ft.Colors.ORANGE_100, ft.Colors.ORANGE_900))
    if record.get("is_shortcut"):
        chips.append(_chip("🔗", "Shortcut", ft.Colors.CYAN_100))
    if meta.revision_count:
        plural = "s" if meta.revision_count != 1 else ""
        chips.append(_chip("🕘", f"{meta.revision_count} revision{plural}", ft.Colors.GREY_100))
    mime_label = get_mime_label(record.get("mime_type"))
    if mime_label:
        chips.append(ft.Chip(label=ft.Text(mime_label, size=10, weight=ft.FontWeight.BOLD), bgcolor=ft.Colors.BLUE_50,
                             height=20, padding=ft.Padding.symmetric(vertical=2, horizontal=8)))
    return chips


def _initial_avatar(record: dict) -> ft.CircleAvatar:
    initial = owner_label(record)[:1].upper() or "?"
    return ft.CircleAvatar(content=ft.Text(initial, size=9), bgcolor=ft.Colors.GREEN_200, radius=10)


def _action_buttons(fid: str, actions: CardActions, size: int, queue_icon) -> list[ft.Control]:
    style = ft.ButtonStyle(padding=4)
    return [
        ft.IconButton(icon=ft.Icons.INFO_OUTLINE, tooltip="Details", on_click=lambda e: actions.info(fid),
                      icon_color=ft.Colors.BLUE_700, icon_size=size, style=style),
        ft.IconButton(icon=ft.Icons.DOWNLOAD, tooltip="Download", on_click=lambda e: actions.download(fid),
                      icon_color=ft.Colors.GREEN_700, icon_size=size, style=style),
        ft.IconButton(icon=queue_icon, tooltip="Add to Queue", on_click=lambda e: actions.queue(fid),
                      icon_color=ft.Colors.PURPLE_700, icon_size=size, style=style),
    ]


def build_card(record: dict, *, view_mode: str, meta: CardMeta, actions: CardActions, selection_mode: bool,
               selected: bool) -> tuple[ft.Control, ft.Container, ft.Container]:
    """Return (card, thumbnail slot, avatar slot); slots get their content swapped when images arrive."""
    fid = record["id"]
    name = record.get("name") or "Untitled"
    mime = record.get("mime_type") or ""
    mime_label = get_mime_label(mime)
    size_display = size_label(mime, record.get("size"))
    hash_text, hash_color = hash_line(record)

    thumb_slot = ft.Container(
        content=thumb_image(meta.thumb) if meta.thumb else ft.Text(get_file_icon(mime), size=28),
        alignment=ft.Alignment.CENTER_LEFT)
    avatar_slot = ft.Container(content=avatar_image(meta.avatar) if meta.avatar else _initial_avatar(record))
    checkbox = (ft.Checkbox(value=selected, on_change=lambda e: actions.toggle_select(fid))
                if selection_mode else None)
    owner_row = ft.Row([avatar_slot, ft.Text(owner_label(record)[:40], size=11, color=ft.Colors.GREY_700, max_lines=1,
                                             overflow=ft.TextOverflow.ELLIPSIS, expand=True)],
                       spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
    hash_text_control = ft.Text(hash_text, size=10, color=hash_color, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS,
                                tooltip=hash_text)

    if view_mode == "list":
        body = _list_row(record, name, mime, mime_label, size_display, meta, actions, checkbox, thumb_slot,
                         owner_row, hash_text_control)
    else:
        body = _tile(record, name, mime, mime_label, size_display, meta, actions, checkbox, thumb_slot,
                     owner_row, hash_text_control)

    card = ft.GestureDetector(content=body, on_secondary_tap=lambda e: actions.context(fid), data=checkbox)
    if selection_mode:
        card.on_tap = lambda e: actions.toggle_select(fid)
        card.mouse_cursor = ft.MouseCursor.CLICK
    elif is_folder(mime):
        card.on_double_tap = lambda e: actions.open_folder(fid, name)
    return card, thumb_slot, avatar_slot


def _list_row(record, name, mime, mime_label, size_display, meta, actions, checkbox, thumb_slot, owner_row,
              hash_text_control) -> ft.Container:
    extension = record.get("file_extension") or (mime.split("/")[-1] if mime else "")
    meta_column = ft.Column([
        ft.Text(name, size=13, weight=ft.FontWeight.BOLD, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS,
                tooltip=record.get("full_path") or None),
        ft.Row([ft.Text(mime_label or mime, size=11, color=ft.Colors.GREY_600),
                ft.Text(size_display, size=11, color=ft.Colors.GREY_600)], spacing=8),
        ft.Row(badges(record, meta), spacing=4, wrap=True),
        hash_text_control,
    ], spacing=2, expand=True)
    size_column = ft.Column([ft.Text(size_display, size=12, weight=ft.FontWeight.BOLD),
                             ft.Text(extension, size=11, color=ft.Colors.GREY_600)],
                            alignment=ft.MainAxisAlignment.CENTER, spacing=2)
    thumb_slot.width = 44
    controls = [checkbox] if checkbox else []
    controls += [
        thumb_slot,
        meta_column,
        ft.Container(owner_row, width=170, alignment=ft.Alignment.CENTER_LEFT),
        ft.Container(ft.Text(meta.modified_str, size=11, color=ft.Colors.GREY_600), width=140,
                     alignment=ft.Alignment.CENTER_LEFT),
        ft.Container(size_column, width=110),
        ft.Row(_action_buttons(record["id"], actions, 16, ft.Icons.ADD_CIRCLE_OUTLINE), spacing=4),
    ]
    return ft.Container(
        content=ft.Row(controls, spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor=ft.Colors.WHITE, padding=ft.Padding.symmetric(vertical=8, horizontal=12),
        border=ft.Border.only(bottom=ft.BorderSide(1, ft.Colors.GREY_100)))


def _tile(record, name, mime, mime_label, size_display, meta, actions, checkbox, thumb_slot, owner_row,
          hash_text_control) -> ft.Container:
    name_text = ft.Text(name, size=13, weight=ft.FontWeight.BOLD, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS,
                        tooltip=record.get("full_path") or None)
    if checkbox:
        name_text.expand = True
        name_row: ft.Control = ft.Row([checkbox, name_text], spacing=6,
                                      vertical_alignment=ft.CrossAxisAlignment.CENTER)
    else:
        name_row = name_text
    tile = ft.Container(
        width=TILE_WIDTH,
        clip_behavior=ft.ClipBehavior.ANTI_ALIAS,   # no fixed height: long names/badges grow the tile
        bgcolor=ft.Colors.WHITE,
        border_radius=12,
        border=ft.Border.all(1, ft.Colors.GREY_200),
        padding=ft.Padding.all(14),
        content=ft.Column([
            ft.Container(content=thumb_slot, alignment=ft.Alignment.CENTER_LEFT, height=60),
            name_row,
            ft.Text(mime_label or mime, size=11, color=ft.Colors.GREY_600, max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS),
            ft.Row(badges(record, meta), spacing=4, wrap=True),
            hash_text_control,
            owner_row,
            ft.Text(f"Updated: {meta.modified_str}", size=11, color=ft.Colors.GREY_600, max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS),
            ft.Text(size_display, size=11, color=ft.Colors.GREY_700),
            ft.Row(_action_buttons(record["id"], actions, 18, ft.Icons.QUEUE), spacing=6,
                   alignment=ft.MainAxisAlignment.END),
        ], spacing=6))
    tile.on_hover = lambda e: set_hovered(tile, e.data is True)
    return tile


def set_hovered(tile: ft.Container, hovered: bool) -> None:
    """Flet 1.0 delivers Container hover state as a real bool in `e.data`."""
    tile.border = ft.Border.all(2 if hovered else 1, ft.Colors.BLUE_200 if hovered else ft.Colors.GREY_200)
    try:
        tile.update()
    except (RuntimeError, AssertionError):
        pass   # not mounted

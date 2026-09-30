"""MIME type knowledge: icons, labels, Workspace export formats, type filter presets."""
from __future__ import annotations

from typing import Optional

FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
GOOGLE_APPS_PREFIX = "application/vnd.google-apps."

MIME_TYPE_ICONS = {
    FOLDER_MIME: "📁",
    "application/vnd.google-apps.document": "📝",
    "application/vnd.google-apps.spreadsheet": "📊",
    "application/vnd.google-apps.presentation": "📽️",
    "application/vnd.google-apps.form": "📋",
    SHORTCUT_MIME: "🔗",
    "application/pdf": "📕",
    "application/zip": "📦",
    "image/jpeg": "🖼️",
    "image/png": "🖼️",
    "image/gif": "🖼️",
    "video/mp4": "🎬",
    "video/avi": "🎬",
    "audio/mpeg": "🎵",
    "text/plain": "📄",
    "application/msword": "📄",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "📄",
    "application/vnd.ms-excel": "📊",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "📊",
}

MIME_TYPE_LABELS = {
    "application/vnd.google-apps.document": "Google Docs",
    "application/vnd.google-apps.spreadsheet": "Google Sheets",
    "application/vnd.google-apps.presentation": "Google Slides",
    "application/vnd.google-apps.form": "Google Forms",
    FOLDER_MIME: "Folder",
    SHORTCUT_MIME: "Shortcut",
    "application/vnd.google-apps.script": "Apps Script",
    "application/vnd.google-apps.jam": "Jamboard",
    "application/vnd.google-apps.drive-sdk": "Drive App Data",
    "application/vnd.google-apps.site": "Google Sites",
    "application/vnd.google-apps.map": "Google My Maps",
    "application/vnd.google-apps.drawing": "Google Drawings",
}

# Google Workspace types that can be exported, mapped to (export MIME, file extension).
EXPORT_FORMATS: dict[str, tuple[str, str]] = {
    "application/vnd.google-apps.document": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"),
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
    "application/vnd.google-apps.presentation": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"),
}

# Browse "File / service type" presets: key -> (label, SQL fragment, params).
TYPE_FILTERS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "docs": ("Google Docs", "mime_type = ?", ("application/vnd.google-apps.document",)),
    "sheets": ("Google Sheets", "mime_type = ?", ("application/vnd.google-apps.spreadsheet",)),
    "slides": ("Google Slides", "mime_type = ?", ("application/vnd.google-apps.presentation",)),
    "forms": ("Google Forms", "mime_type = ?", ("application/vnd.google-apps.form",)),
    "shortcuts": ("Shortcuts", "mime_type = ?", (SHORTCUT_MIME,)),
    "pdf": ("PDF", "mime_type = ?", ("application/pdf",)),
    "images": ("Images", "mime_type LIKE ?", ("image/%",)),
    "videos": ("Videos", "mime_type LIKE ?", ("video/%",)),
    "audio": ("Audio", "mime_type LIKE ?", ("audio/%",)),
    "archives": ("Archives", "mime_type IN (?,?,?)",
                 ("application/zip", "application/x-zip-compressed", "application/x-rar-compressed")),
}


def get_file_icon(mime_type: Optional[str]) -> str:
    """Emoji icon for a MIME type."""
    if not mime_type:
        return "📎"
    if mime_type in MIME_TYPE_ICONS:
        return MIME_TYPE_ICONS[mime_type]
    for prefix, icon in (("image/", "🖼️"), ("video/", "🎬"), ("audio/", "🎵"), ("text/", "📄")):
        if mime_type.startswith(prefix):
            return icon
    return "📎"


def get_mime_label(mime_type: Optional[str]) -> Optional[str]:
    if not mime_type:
        return None
    return MIME_TYPE_LABELS.get(mime_type)


def is_folder(mime_type: Optional[str]) -> bool:
    return mime_type == FOLDER_MIME


def is_google_workspace(mime_type: Optional[str]) -> bool:
    return bool(mime_type) and mime_type.startswith(GOOGLE_APPS_PREFIX)


def size_label(mime_type: Optional[str], size) -> str:
    """Display size: 'Folder', 'Cloud doc' for size-less Workspace files, else human size."""
    from .formatting import format_size

    if is_folder(mime_type):
        return "Folder"
    if is_google_workspace(mime_type) and not size:
        return "Cloud doc"
    return format_size(size or 0)

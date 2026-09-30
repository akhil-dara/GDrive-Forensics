"""Analytics tab: the dashboard query and stateless section builders (the view owns state and events)."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Callable, Optional

import flet as ft

from ..core.formatting import format_size
from ..core.mime import get_file_icon, get_mime_label
from .file_card import owner_label

TOP_FILES_LIMIT = 100
TYPE_LIMIT = 15
OWNER_LIMIT = 20
TOP_ACTORS = 5
BAR_WIDTH = 160        # px, the storage-by-owner distribution bar
NAME_MAX = 50


@dataclass
class AnalyticsData:
    summary: dict
    top_files: list        # dicts: id, name, size, owner_name, owner_email, mime_type
    types: list            # (mime_type, count)
    owners: list           # dicts: owner_email, owner_name, total_size, file_count
    activity: dict         # {"total", "by_type": [(action, n)], "top_actors": [(actor, n)]}


def query_analytics(repo) -> AnalyticsData:
    """Worker thread: every dashboard query in one hop off the loop."""
    return AnalyticsData(summary=repo.analytics_summary(), top_files=repo.top_largest_files(TOP_FILES_LIMIT),
                         types=repo.type_distribution(TYPE_LIMIT), owners=repo.storage_by_owner(OWNER_LIMIT),
                         activity=repo.activity_stats(TOP_ACTORS))


# ------------------------------------------------------------------ helpers
def share(size: Optional[int], biggest: Optional[int]) -> float:
    """Fraction of the biggest value in [0, 1]; 0 for missing/zero sizes."""
    size, biggest = int(size or 0), int(biggest or 0)
    if size <= 0 or biggest <= 0:
        return 0.0
    return min(1.0, size / biggest)


def mime_short(mime: Optional[str]) -> str:
    if not mime:
        return "unknown"
    return get_mime_label(mime) or mime.split("/")[-1]


def plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def section_title(text: str) -> ft.Text:
    return ft.Text(text, size=22, weight=ft.FontWeight.BOLD)


def panel(content: ft.Control, bgcolor=ft.Colors.WHITE, border_color=ft.Colors.GREY_300,
          padding: int = 15) -> ft.Container:
    return ft.Container(content=content, bgcolor=bgcolor, padding=padding, border_radius=10,
                        border=ft.Border.all(2, border_color))


def _bold(text: str, size: Optional[int] = None) -> ft.Text:
    return ft.Text(text, weight=ft.FontWeight.BOLD, size=size)


# ------------------------------------------------------------- 1. stat cards
def stat_values(summary: dict) -> list[tuple[str, str, str, str]]:
    """(title, value, text colour, background) for the six headline cards."""
    return [
        ("📁 Total Files", str(summary.get("total_files", 0)), ft.Colors.BLUE_700, ft.Colors.BLUE_50),
        ("👤 Owned", str(summary.get("owned_files", 0)), ft.Colors.GREEN_700, ft.Colors.GREEN_50),
        ("🤝 Shared", str(summary.get("shared_files", 0)), ft.Colors.ORANGE_700, ft.Colors.ORANGE_50),
        ("💾 Total Size", format_size(summary.get("total_size", 0)), ft.Colors.PURPLE_700, ft.Colors.PURPLE_50),
        ("⭐ Starred", str(summary.get("starred", 0)), ft.Colors.YELLOW_700, ft.Colors.YELLOW_50),
        ("🌐 Public", str(summary.get("public", 0)), ft.Colors.PINK_700, ft.Colors.PINK_50),
    ]


def stat_card(title: str, value: str, text_color, bgcolor, on_copy: Callable[[str], None]) -> ft.Card:
    copy_button = ft.IconButton(icon=ft.Icons.COPY, icon_size=14, tooltip="Copy value",
                                style=ft.ButtonStyle(padding=2), on_click=lambda e: on_copy(value))
    return ft.Card(
        elevation=3,
        content=ft.Container(
            width=200, padding=25, bgcolor=bgcolor, border_radius=12,
            content=ft.Column([
                ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                ft.Row([ft.Text(value, size=32, weight=ft.FontWeight.BOLD, color=text_color), copy_button],
                       alignment=ft.MainAxisAlignment.CENTER, spacing=4),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12)))


def stat_cards(summary: dict, on_copy: Callable[[str], None]) -> list[ft.Control]:
    return [stat_card(title, value, color, bg, on_copy) for title, value, color, bg in stat_values(summary)]


# ---------------------------------------------------------- 2. top files
SORT_COLUMNS = {"name": 2, "size": 3, "owner": 4}   # DataTable column index per sortable key


def select_top(records: list[dict], search: str, sort_col: str, ascending: bool, limit: int) -> list[dict]:
    """Filter (name/owner, case-insensitive), sort and cut the loaded top-files rows."""
    term = (search or "").strip().lower()
    if term:
        records = [r for r in records if term in (r.get("name") or "").lower()
                   or term in owner_label(r).lower() or term in (r.get("owner_email") or "").lower()]
    if sort_col == "size":
        key = lambda r: int(r.get("size") or 0)                      # noqa: E731
    elif sort_col == "owner":
        key = lambda r: owner_label(r).lower()                       # noqa: E731
    else:
        key = lambda r: (r.get("name") or "").lower()                # noqa: E731
    return sorted(records, key=key, reverse=not ascending)[:max(0, limit)]


def row_text(record: dict) -> str:
    return f"{record.get('name') or ''}\t{format_size(record.get('size') or 0)}\t{owner_label(record)}"


def top_columns(on_sort: Callable[[str], None]) -> list[ft.DataColumn]:
    def sortable(key: str):
        return lambda e: on_sort(key)

    return [
        ft.DataColumn(_bold("#")),
        ft.DataColumn(_bold("Type")),
        ft.DataColumn(_bold("Name"), on_sort=sortable("name")),
        ft.DataColumn(_bold("Size"), numeric=True, on_sort=sortable("size")),
        ft.DataColumn(_bold("Owner"), on_sort=sortable("owner")),
        ft.DataColumn(_bold("")),
    ]


def top_rows(records: list[dict], on_copy: Callable[[dict], None]) -> list[ft.DataRow]:
    rows = []
    for index, record in enumerate(records, 1):
        name = record.get("name") or ""
        rows.append(ft.DataRow(cells=[
            ft.DataCell(_bold(str(index))),
            ft.DataCell(ft.Text(get_file_icon(record.get("mime_type")), size=20)),
            ft.DataCell(ft.Text(name[:NAME_MAX], size=12, tooltip=name if len(name) > NAME_MAX else None)),
            ft.DataCell(_bold(format_size(record.get("size") or 0))),
            ft.DataCell(ft.Text(owner_label(record), size=11, tooltip=record.get("owner_email"))),
            ft.DataCell(ft.IconButton(icon=ft.Icons.COPY, icon_size=14, tooltip="Copy row",
                                      style=ft.ButtonStyle(padding=2),
                                      on_click=lambda e, r=record: on_copy(r))),
        ]))
    return rows


# -------------------------------------------------------- 3. type chips
def type_chips(types: list, on_pick: Callable[[str], None]) -> list[ft.Control]:
    chips: list[ft.Control] = []
    for mime, count in types:
        chips.append(ft.Chip(
            label=ft.Text(f"{get_file_icon(mime)} {mime_short(mime)}: {count}", size=11),
            tooltip=mime or "Unknown type", bgcolor=ft.Colors.CYAN_50,
            # No MIME type recorded: nothing to filter on (mime_type IN (NULL) matches nothing).
            on_click=(lambda e, m=mime: on_pick(m)) if mime else None))
    return chips


# ---------------------------------------------------- 4. storage by owner
def owners_table(owners: list[dict]) -> ft.DataTable:
    biggest = max((int(o.get("total_size") or 0) for o in owners), default=0)
    rows = []
    for owner in owners:
        size = int(owner.get("total_size") or 0)
        rows.append(ft.DataRow(cells=[
            ft.DataCell(ft.Text(owner.get("owner_name") or owner.get("owner_email") or "Unknown", size=12,
                                tooltip=owner.get("owner_email"))),
            ft.DataCell(ft.Text(str(owner.get("file_count") or 0), size=12)),
            ft.DataCell(ft.Text(format_size(size), size=12, weight=ft.FontWeight.BOLD)),
            ft.DataCell(ft.ProgressBar(value=share(size, biggest), width=BAR_WIDTH, color=ft.Colors.BLUE_700,
                                       bgcolor=ft.Colors.BLUE_50)),
        ]))
    return ft.DataTable(
        columns=[ft.DataColumn(_bold("Owner")), ft.DataColumn(_bold("Files"), numeric=True),
                 ft.DataColumn(_bold("Size"), numeric=True), ft.DataColumn(_bold("Distribution"))],
        rows=rows, border=ft.Border.all(1, ft.Colors.GREY_300), border_radius=8, heading_row_color=ft.Colors.GREEN_50)


# ------------------------------------------------------- 5. trashed files
def trashed_panel(summary: dict) -> ft.Container:
    count = int(summary.get("trashed_count") or 0)
    size = int(summary.get("trashed_size") or 0)
    # Keyed on the count: trashed Google Docs have no size but still exist.
    note = f"Potential space recovery: {format_size(size)}" if count else "No trashed files found."
    return panel(ft.Column([
        ft.Row([ft.Icon(ft.Icons.DELETE_OUTLINE, color=ft.Colors.RED_400, size=24),
                ft.Text(f"{plural(count, 'trashed file')}  ({format_size(size)})", size=16,
                        weight=ft.FontWeight.BOLD, color=ft.Colors.RED_700)], spacing=8),
        ft.Text(note, size=13, color=ft.Colors.GREY_600, italic=True),
    ], spacing=6), bgcolor=ft.Colors.RED_50, border_color=ft.Colors.RED_100, padding=20)


# ------------------------------------------------------ 6. activity summary
def activity_controls(activity: dict) -> list[ft.Control]:
    """Nothing unless Drive Activity was scanned."""
    total = int(activity.get("total") or 0)
    if total <= 0:
        return []
    chips = [ft.Chip(label=ft.Text(f"{action or 'unknown'}: {n}", size=11), bgcolor=ft.Colors.AMBER_50)
             for action, n in activity.get("by_type", [])]
    tiles = [ft.ListTile(leading=ft.CircleAvatar(content=ft.Text(str(rank), size=12), radius=14,
                                                 bgcolor=ft.Colors.AMBER_200),
                         title=ft.Text(actor or "Unknown", size=13),
                         trailing=ft.Text(plural(n, "action"), size=12, weight=ft.FontWeight.BOLD))
             for rank, (actor, n) in enumerate(activity.get("top_actors", [])[:TOP_ACTORS], 1)]
    return [
        ft.Divider(height=30),
        section_title("📈 Activity Summary"),
        panel(ft.Column([
            ft.Text(f"Total activity records: {total}", size=14, weight=ft.FontWeight.BOLD),
            ft.Text("Actions by type:", size=13, color=ft.Colors.GREY_700),
            ft.Row(chips, wrap=True, spacing=8),
            ft.Divider(height=10),
            ft.Text(f"Top {TOP_ACTORS} most active users:", size=13, color=ft.Colors.GREY_700),
            *tiles,
        ], spacing=8), padding=20),
    ]


# ------------------------------------------------------------- 7. CSV
def analytics_csv(data: AnalyticsData) -> str:
    s = data.summary
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["Metric", "Value"])
    for label, key in (("Total Files", "total_files"), ("Owned Files", "owned_files"),
                       ("Shared Files", "shared_files")):
        writer.writerow([label, s.get(key, 0)])
    writer.writerow(["Total Size", format_size(s.get("total_size", 0))])
    writer.writerow(["Total Size (bytes)", s.get("total_size", 0)])
    writer.writerow(["Starred", s.get("starred", 0)])
    writer.writerow(["Public", s.get("public", 0)])
    writer.writerow(["Trashed Count", s.get("trashed_count", 0)])
    writer.writerow(["Trashed Size", format_size(s.get("trashed_size", 0))])
    writer.writerow([])
    writer.writerow(["Top Files"])
    writer.writerow(["#", "Name", "Size", "Size (bytes)", "Owner", "MIME Type"])
    for index, r in enumerate(data.top_files, 1):
        writer.writerow([index, r.get("name") or "", format_size(r.get("size") or 0), r.get("size") or 0,
                         owner_label(r), r.get("mime_type") or ""])
    writer.writerow([])
    writer.writerow(["File Type Distribution"])
    writer.writerow(["MIME Type", "Count"])
    for mime, count in data.types:
        writer.writerow([mime or "", count])
    writer.writerow([])
    writer.writerow(["Storage by Owner"])
    writer.writerow(["Owner Email", "Owner Name", "Total Size", "Total Size (bytes)", "File Count"])
    for o in data.owners:
        writer.writerow([o.get("owner_email") or "", o.get("owner_name") or "", format_size(o.get("total_size") or 0),
                         o.get("total_size") or 0, o.get("file_count") or 0])
    return buf.getvalue()

"""Mutable UI state shared by the views (single-threaded: mutate on the Flet loop only)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.filters import FilterState


@dataclass
class UIState:
    filters: FilterState = field(default_factory=FilterState)
    timezone: str = "UTC"
    page: int = 1
    per_page: int = 50
    total_items: int = 0
    total_pages: int = 1
    folder_stack: list = field(default_factory=list)        # [(folder_id, folder_name)]
    view_mode: str = "tiles"                                # tiles | list
    selection_mode: bool = False
    selected_ids: set = field(default_factory=set)
    current_file_ids: list = field(default_factory=list)
    queue_ids: list = field(default_factory=list)
    user_search: str = ""
    active_tab: int = 0                                     # 0 files, 1 users, 2 analytics
    skip_all_shortcuts: bool = False
    viewer_email: Optional[str] = None

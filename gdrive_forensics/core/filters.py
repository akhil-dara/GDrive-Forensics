"""Browse filter state and its translation to a parameterised SQL WHERE clause."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from .mime import FOLDER_MIME, TYPE_FILTERS

SOURCE_OPTIONS = [("all", "All Files"), ("my_drive", "My Drive"),
                  ("shared_with_me", "Shared With Me"), ("shared_by_me", "Shared By Me")]
OWNER_OPTIONS = [("all", "All Owners"), ("me", "Owned by Me"), ("others", "Owned by Others")]
SCOPE_OPTIONS = [("all", "All items"), ("folders", "Folders only"), ("files", "Files only")]
SORT_OPTIONS: dict[str, tuple[str, str]] = {
    "name_asc": ("Name (A→Z)", "name ASC"),
    "name_desc": ("Name (Z→A)", "name DESC"),
    "size_desc": ("Size (Largest)", "size DESC"),
    "size_asc": ("Size (Smallest)", "size ASC"),
    "modified_desc": ("Modified (Newest)", "modified_time DESC"),
    "modified_asc": ("Modified (Oldest)", "modified_time ASC"),
    "created_desc": ("Created (Newest)", "created_time DESC"),
    "created_asc": ("Created (Oldest)", "created_time ASC"),
    "owner_asc": ("Owner (A→Z)", "owner_name ASC"),
}


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass
class FilterState:
    source: str = "all"            # all | my_drive | shared_with_me | shared_by_me
    owner: str = "all"             # all | me | others
    user_email: Optional[str] = None
    user_label: Optional[str] = None
    search: str = ""
    starred_only: bool = False
    include_trashed: bool = False
    public_only: bool = False
    scope: str = "all"             # all | folders | files
    types: set = field(default_factory=set)        # keys of TYPE_FILTERS
    mime_types: set = field(default_factory=set)   # exact MIME types (analytics drill-down)
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    folder_id: Optional[str] = None
    sort: str = "name_asc"

    def where_clause(self) -> tuple[str, list]:
        conditions: list[str] = []
        params: list = []
        if not self.include_trashed:
            conditions.append("trashed = 0")
        if self.starred_only:
            conditions.append("starred = 1")
        if self.public_only:
            conditions.append("is_public = 1")
        if self.source == "my_drive":
            conditions.append("source = 'my_drive'")
        elif self.source == "shared_with_me":
            conditions.append("source = 'shared_with_me'")
        elif self.source == "shared_by_me":
            conditions.append(
                "owned_by_me = 1 AND EXISTS (SELECT 1 FROM permissions p WHERE p.file_id = files.id "
                "AND p.role != 'owner' AND COALESCE(p.deleted, 0) = 0)")
        if self.owner == "me":
            conditions.append("owned_by_me = 1")
        elif self.owner == "others":
            conditions.append("owned_by_me = 0")
        if self.user_email:
            conditions.append("(owner_email = ? OR EXISTS (SELECT 1 FROM permissions p "
                              "WHERE p.file_id = files.id AND p.email_address = ?))")
            params.extend([self.user_email, self.user_email])
        if self.search:
            conditions.append("name LIKE ? ESCAPE '\\'")
            params.append(f"%{_escape_like(self.search)}%")
        if self.scope == "folders":
            conditions.append("mime_type = ?")
            params.append(FOLDER_MIME)
        elif self.scope == "files":
            conditions.append("mime_type != ?")
            params.append(FOLDER_MIME)
        type_sql: list[str] = []
        for key in sorted(self.types):
            if key in TYPE_FILTERS:
                _, sql, values = TYPE_FILTERS[key]
                type_sql.append(sql)
                params.extend(values)
        if self.mime_types:
            ordered = sorted(self.mime_types)
            type_sql.append(f"mime_type IN ({','.join('?' * len(ordered))})")
            params.extend(ordered)
        if type_sql:
            conditions.append("(" + " OR ".join(type_sql) + ")")
        if self.date_from:
            conditions.append("DATE(modified_time) >= ?")
            params.append(self.date_from.strftime("%Y-%m-%d"))
        if self.date_to:
            conditions.append("DATE(modified_time) <= ?")
            params.append(self.date_to.strftime("%Y-%m-%d"))
        if self.folder_id:
            conditions.append("parent_id = ?")
            params.append(self.folder_id)
        return (" AND ".join(conditions) if conditions else "1=1"), params

    def order_by(self) -> str:
        return SORT_OPTIONS.get(self.sort, SORT_OPTIONS["name_asc"])[1] + ", id ASC"

    def summary(self) -> str:
        parts: list[str] = []
        if self.source != "all":
            parts.append(f"Source: {self.source}")
        if self.owner != "all":
            parts.append(f"Owner: {self.owner}")
        if self.user_email:
            parts.append(f"User: {self.user_label or self.user_email}")
        if self.search:
            parts.append(f"Search: '{self.search}'")
        if self.starred_only:
            parts.append("Starred only")
        if self.include_trashed:
            parts.append("Including trashed")
        if self.public_only:
            parts.append("Public only")
        if self.scope == "folders":
            parts.append("Folders only")
        elif self.scope == "files":
            parts.append("Files only")
        if self.types:
            parts.append("Types: " + ", ".join(TYPE_FILTERS[k][0] for k in sorted(self.types) if k in TYPE_FILTERS))
        if self.mime_types:
            parts.append("MIME: " + ", ".join(sorted(self.mime_types)))
        if self.date_from or self.date_to:
            parts.append(f"Date: {self.date_from or 'any'} to {self.date_to or 'any'}")
        return " | ".join(parts) if parts else "No filters active"

    def is_active(self) -> bool:
        return self.summary() != "No filters active"

    def reset(self) -> None:
        """Clear every filter; keeps sort order and current folder."""
        keep_sort, keep_folder = self.sort, self.folder_id
        self.__init__(sort=keep_sort, folder_id=keep_folder)

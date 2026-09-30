from datetime import date

from gdrive_forensics.core.filters import FilterState, SORT_OPTIONS
from gdrive_forensics.core.mime import FOLDER_MIME


def test_default_filter_excludes_trash_only():
    where, params = FilterState().where_clause()
    assert where == "trashed = 0" and params == []


def test_full_filter_clause_and_params():
    fs = FilterState(
        source="shared_by_me", owner="others", user_email="a@x.com", search="50%_off",
        starred_only=True, include_trashed=True, public_only=True, scope="files",
        types={"pdf", "images"}, mime_types={"text/csv"}, date_from=date(2025, 3, 1),
        date_to=date(2025, 3, 15), folder_id="F1",
    )
    where, params = fs.where_clause()
    assert "trashed = 0" not in where
    assert "starred = 1" in where and "is_public = 1" in where
    assert "owned_by_me = 1 AND EXISTS" in where
    assert "owned_by_me = 0" in where
    assert "name LIKE ? ESCAPE '\\'" in where
    assert "(mime_type LIKE ? OR mime_type = ? OR mime_type IN (?))" in where
    assert params == [
        "a@x.com", "a@x.com", "%50\\%\\_off%", FOLDER_MIME,
        "image/%", "application/pdf", "text/csv", "2025-03-01", "2025-03-15", "F1",
    ]


def test_order_by_is_stable_and_defaults():
    assert FilterState(sort="size_desc").order_by() == "size DESC, id ASC"
    assert FilterState(sort="bogus").order_by() == "name ASC, id ASC"
    assert "owner_asc" in SORT_OPTIONS


def test_summary_and_reset():
    fs = FilterState(search="inv", starred_only=True, types={"docs"}, user_email="a@x.com", user_label="Alice", sort="size_desc", folder_id="F")
    assert fs.summary() == "User: Alice | Search: 'inv' | Starred only | Types: Google Docs"
    assert fs.is_active()
    fs.reset()
    assert fs.summary() == "No filters active" and not fs.is_active()
    assert fs.sort == "size_desc" and fs.folder_id == "F"

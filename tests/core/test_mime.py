from gdrive_forensics.core import mime


def test_icons_and_labels():
    assert mime.get_file_icon(mime.FOLDER_MIME) == "📁"
    assert mime.get_file_icon("image/webp") == "🖼️"
    assert mime.get_file_icon("application/x-unknown") == "📎"
    assert mime.get_file_icon(None) == "📎"
    assert mime.get_mime_label("application/vnd.google-apps.spreadsheet") == "Google Sheets"
    assert mime.get_mime_label("application/vnd.google-apps.drawing") == "Google Drawings"
    assert mime.get_mime_label("application/pdf") is None
    assert mime.get_mime_label(None) is None


def test_workspace_and_size_label():
    assert mime.is_google_workspace("application/vnd.google-apps.document")
    assert not mime.is_google_workspace("application/pdf")
    assert mime.size_label(mime.FOLDER_MIME, 0) == "Folder"
    assert mime.size_label("application/vnd.google-apps.document", 0) == "Cloud doc"
    assert mime.size_label("application/pdf", 2048) == "2.00 KB"


def test_type_filters_cover_all_presets():
    assert set(mime.TYPE_FILTERS) == {
        "docs", "sheets", "slides", "forms", "shortcuts", "pdf", "images", "videos", "audio", "archives",
    }
    label, sql, params = mime.TYPE_FILTERS["images"]
    assert label == "Images" and sql == "mime_type LIKE ?" and params == ("image/%",)

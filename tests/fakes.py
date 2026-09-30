"""Fakes for Drive API access (no network)."""
from __future__ import annotations

from types import SimpleNamespace

PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63f8"
    "cfc0f01f0005000201d0a1b2b50000000049454e44ae426082")


class FakeRequest:
    def __init__(self, response=None, error=None, content=b""):
        self.response, self.error, self.content = response, error, content
        self.executed = 0

    def execute(self, num_retries=0):
        self.executed += 1
        if self.error:
            raise self.error
        return self.response


class FakeDownloader:
    """Mimics MediaIoBaseDownload: writes request.content to fd in 3 chunks."""

    def __init__(self, fd, request, chunksize=0):
        data = request.content
        step = max(1, len(data) // 3 or 1)
        self._chunks = [data[i:i + step] for i in range(0, len(data), step)] or [b""]
        self._fd, self._i = fd, 0

    def next_chunk(self, num_retries=0):
        self._fd.write(self._chunks[self._i])
        self._i += 1
        done = self._i >= len(self._chunks)
        return SimpleNamespace(progress=lambda: self._i / len(self._chunks)), done


class FakeDriveClient:
    """Stand-in for DriveClient used by scanner/exporter/UI tests."""

    def __init__(self, pages=None, contents=None, revisions=None, fail_on_page=None):
        self.pages = pages or [{"files": []}]
        self.contents = contents or {}
        self.revisions = revisions or {}
        self.fail_on_page = fail_on_page
        self.page_calls = 0
        self.images = []

    def about_user(self):
        return {"emailAddress": "me@x.com", "displayName": "Me", "permissionId": "999"}

    def root_folder_id(self):
        return "ROOT"

    def list_files_page(self, page_token, fields, page_size=1000):
        index = int(page_token or 0)
        self.page_calls += 1
        if self.fail_on_page is not None and index == self.fail_on_page:
            raise RuntimeError("API exploded")
        page = dict(self.pages[index])
        if index + 1 < len(self.pages):
            page["nextPageToken"] = str(index + 1)
        return page

    def list_revisions(self, file_id):
        return self.revisions.get(file_id, [])

    def thumbnail_metadata(self, file_id):
        return {"thumbnail_link": f"https://lh3.googleusercontent.com/{file_id}=s220", "owner_photo": None,
                "owner_name": None, "owner_email": None}

    def fetch_image(self, url, timeout=10):
        self.images.append(url)
        return PNG_1PX

    def media_request(self, file_id, mime_type):
        from gdrive_forensics.core.mime import EXPORT_FORMATS, is_google_workspace
        from gdrive_forensics.drive.client import UnsupportedExportError

        if is_google_workspace(mime_type):
            if mime_type not in EXPORT_FORMATS:
                raise UnsupportedExportError(mime_type)
            return FakeRequest(content=self.contents.get(file_id, b"exported")), EXPORT_FORMATS[mime_type][1]
        return FakeRequest(content=self.contents.get(file_id, b"")), None

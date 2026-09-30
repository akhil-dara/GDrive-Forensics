from types import SimpleNamespace

import pytest
from googleapiclient.errors import HttpError

from gdrive_forensics.drive.client import DriveClient, UnsupportedExportError
from tests.fakes import FakeRequest


class Recorder:
    def __init__(self):
        self.calls = []

    def log_api_call(self, **kw):
        self.calls.append(kw)


class FakeFiles:
    def __init__(self):
        self.kwargs = []

    def list(self, **kw):
        self.kwargs.append(("list", kw))
        return FakeRequest({"files": [{"id": "1"}], "nextPageToken": None})

    def get(self, **kw):
        self.kwargs.append(("get", kw))
        if kw.get("fileId") == "root":
            return FakeRequest({"id": "ROOTID"})
        return FakeRequest({"thumbnailLink": "t", "owners": [{"photoLink": "p", "displayName": "D",
                                                               "emailAddress": "e"}]})

    def export_media(self, **kw):
        return ("export", kw)

    def get_media(self, **kw):
        return ("media", kw)


class FakeService:
    def __init__(self):
        self.files_api = FakeFiles()
        self.revision_pages = iter([{"revisions": [{"id": "r1"}], "nextPageToken": "n"},
                                    {"revisions": [{"id": "r2"}]}])

    def files(self):
        return self.files_api

    def about(self):
        return SimpleNamespace(get=lambda **kw: FakeRequest({"user": {"emailAddress": "me@x.com"}}))

    def revisions(self):
        return SimpleNamespace(list=lambda **kw: FakeRequest(next(self.revision_pages)))


def make_client():
    service = FakeService()
    rec = Recorder()
    return DriveClient(object(), repository=rec, service_factory=lambda api, ver: service), service, rec


def test_execute_logs_success_and_errors():
    client, _, rec = make_client()
    assert client.execute(FakeRequest({"ok": 1}), "x.get", "u", {"a": 1}) == {"ok": 1}
    assert rec.calls[-1]["status"] == 200
    err = HttpError(SimpleNamespace(status=403, reason="Forbidden"), b"{}")
    with pytest.raises(HttpError):
        client.execute(FakeRequest(error=err), "x.get", "u")
    assert rec.calls[-1]["status"] == 403


def test_high_level_calls():
    client, service, _ = make_client()
    assert client.about_user()["emailAddress"] == "me@x.com"
    assert client.root_folder_id() == "ROOTID"
    assert client.list_files_page(None, "fields")["files"] == [{"id": "1"}]
    assert service.files_api.kwargs[-1][1]["pageSize"] == 1000
    assert [r["id"] for r in client.list_revisions("f")] == ["r1", "r2"]
    assert client.thumbnail_metadata("f") == {"thumbnail_link": "t", "owner_photo": "p", "owner_name": "D",
                                              "owner_email": "e"}


def test_media_request_routing():
    client, _, _ = make_client()
    req, ext = client.media_request("f", "application/vnd.google-apps.document")
    assert req[0] == "export" and ext == ".docx"
    req, ext = client.media_request("f", "application/pdf")
    assert req[0] == "media" and ext is None
    with pytest.raises(UnsupportedExportError):
        client.media_request("f", "application/vnd.google-apps.form")


def test_fetch_image_only_sends_token_to_google_hosts(monkeypatch):
    client, _, _ = make_client()
    client.credentials = SimpleNamespace(valid=True, token="TKN")
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append((url, headers))
        return SimpleNamespace(status_code=200, content=b"img")

    monkeypatch.setattr("gdrive_forensics.drive.client.requests.get", fake_get)
    assert client.fetch_image("https://lh3.googleusercontent.com/a=s220") == b"img"
    assert seen[-1][1] == {"Authorization": "Bearer TKN"}
    assert client.fetch_image("https://evil.example.com/x.png") == b"img"
    assert seen[-1][1] == {}
    assert client.fetch_image("") is None


@pytest.mark.parametrize("url", [
    "https://evil.net\\@lh3.googleusercontent.com/x",
    "http://lh3.googleusercontent.com/x",
    "https://google.com@evil.net/x",
    "https://evilgoogle.com/x",
    "https://google.com.evil.net/x",
])
def test_fetch_image_rejects_host_spoofing_and_cleartext(monkeypatch, url):
    client, _, _ = make_client()
    client.credentials = SimpleNamespace(valid=True, token="TKN")
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append((url, headers))
        return SimpleNamespace(status_code=200, content=b"img")

    monkeypatch.setattr("gdrive_forensics.drive.client.requests.get", fake_get)
    assert client.fetch_image(url) == b"img"
    assert seen[-1][1] == {}

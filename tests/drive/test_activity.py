import json
import threading
from types import SimpleNamespace

import pytest

from gdrive_forensics.drive.activity import ActivityScanner, extract_action_type, parse_activities
from gdrive_forensics.storage.repository import Repository
from tests.fakes import FakeRequest
from tests.fixtures.drive_samples import seed_database
from tests.helpers import make_db

CREATE = {"timestamp": "2025-03-05T10:00:00Z",
          "primaryActionDetail": {"create": {"new": {}}},
          "actors": [{"user": {"knownUser": {"personName": "people/222"}}}],
          "targets": [{"driveItem": {"name": "items/pdf1", "title": "invoice-001.pdf", "mimeType": "application/pdf"}},
                      {"driveItem": {"name": "items/doc1", "title": "Meeting notes", "driveFolder": {}}}]}
EDIT = {"timeRange": {"endTime": "2025-03-06T10:00:00Z"},
        "primaryActionDetail": {"edit": {}},
        "actors": [{"user": {"knownUser": {"personName": "people/999", "isCurrentUser": True}}}],
        "targets": [{"fileComment": {"parent": {"name": "items/doc1", "title": "Meeting notes"}}}]}


def test_extract_action_type():
    assert extract_action_type({"permissionChange": {}}) == "permission_change"
    assert extract_action_type({"dlpChange": {}}) == "dlp_change"
    assert extract_action_type({}) == "unknown"


def test_parse_activities_is_stable_and_crash_free():
    recs = parse_activities([CREATE, EDIT])
    assert len(recs) == 3
    assert recs[0]["target_id"] == "pdf1" and recs[0]["action_type"] == "create"
    assert recs[1]["target_mime_type"] == "application/vnd.google-apps.folder"
    assert recs[2]["target_id"] == "doc1" and recs[2]["timestamp"] == "2025-03-06T10:00:00Z"
    assert recs[0]["activity_id"] == recs[0]["activity_key"] and len(recs[0]["activity_key"]) == 40
    assert parse_activities([CREATE])[0]["activity_key"] == recs[0]["activity_key"]
    assert json.loads(recs[0]["details_json"])["primaryActionDetail"] == {"create": {"new": {}}}


class ActivityService:
    def __init__(self, pages):
        self.pages = pages
        self.bodies = []

    def activity(self):
        def query(body):
            self.bodies.append(dict(body))
            index = int(body.get("pageToken") or 0)
            page = dict(self.pages[index])
            if index + 1 < len(self.pages):
                page["nextPageToken"] = str(index + 1)
            return FakeRequest(page)
        return SimpleNamespace(query=query)


class Client:
    def __init__(self, service):
        self._service = service

    def service(self, api="drive", version="v3"):
        assert (api, version) == ("driveactivity", "v2")
        return self._service

    def execute(self, request, request_type, url, params=None, num_retries=3):
        return request.execute()


def test_scan_stores_resolved_deduplicated_rows(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    repo = Repository(db)
    service = ActivityService([{"activities": [CREATE]}, {"activities": [EDIT]}])
    scanner = ActivityScanner(Client(service), repo, "me@x.com")
    progress = []
    assert scanner.scan(days_back=7, progress=lambda fetched, stored: progress.append(fetched)) == (2, 3)
    assert scanner.scan(days_back=7) == (2, 0)
    assert service.bodies[0]["filter"].startswith("time >= ") and service.bodies[0]["pageSize"] == 100
    rows = {(r["target_id"], r["action_type"]): r for r in repo.file_activity("pdf1") + repo.file_activity("doc1")}
    assert rows[("pdf1", "create")]["actor_email"] == "bob@x.com"
    assert rows[("pdf1", "create")]["actor_name"] == "Bob"
    assert rows[("pdf1", "create")]["target_path"] == "/Case Files/Invoices/invoice-001.pdf"
    assert rows[("doc1", "edit")]["actor_email"] == "me@x.com"
    assert progress


def test_scan_cancel(tmp_path):
    db = make_db(tmp_path)
    cancel = threading.Event()
    cancel.set()
    scanner = ActivityScanner(Client(ActivityService([{"activities": [CREATE]}])), Repository(db), "me@x.com")
    with pytest.raises(Exception) as info:
        scanner.scan(cancel=cancel)
    assert info.type.__name__ == "ActivityCancelled"

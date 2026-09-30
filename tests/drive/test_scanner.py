import json
import threading

from gdrive_forensics.core.mime import FOLDER_MIME
from gdrive_forensics.drive import scanner
from gdrive_forensics.drive.scanner import DriveScanner, build_full_paths, file_row
from gdrive_forensics.storage.repository import Repository
from tests.fakes import FakeDriveClient
from tests.fixtures.drive_samples import SAMPLE_PAGES, seed_database
from tests.helpers import make_db


def test_build_full_paths_handles_nesting_orphans_and_cycles():
    files = [
        {"id": "A", "name": "A", "mimeType": FOLDER_MIME, "parents": ["ROOT"]},
        {"id": "B", "name": "B", "mimeType": FOLDER_MIME, "parents": ["A"]},
        {"id": "f", "name": "f.txt", "mimeType": "text/plain", "parents": ["B"]},
        {"id": "o", "name": "orphan", "mimeType": "text/plain", "parents": ["gone"]},
        {"id": "X", "name": "X", "mimeType": FOLDER_MIME, "parents": ["Y"]},
        {"id": "Y", "name": "Y", "mimeType": FOLDER_MIME, "parents": ["X"]},
        {"id": "n", "name": "noparent", "mimeType": "text/plain"},
    ]
    build_full_paths(files, {"root", "ROOT"})
    paths = {f["id"]: f["fullPath"] for f in files}
    assert paths["f"] == "/A/B/f.txt" and paths["o"] == "/orphan" and paths["n"] == "/noparent"
    assert paths["X"] in ("/Y/X", "/X") and paths["Y"] in ("/X/Y", "/Y")


def test_file_row_public_inference_and_permissions():
    shared = {"id": "s", "name": "s.pdf", "mimeType": "application/pdf", "ownedByMe": False,
              "owners": [{"emailAddress": "bob@x.com", "displayName": "Bob", "permissionId": "222"}],
              "permissions": [{"id": "222", "type": "user", "role": "owner", "emailAddress": "bob@x.com"}]}
    row, perms = file_row(shared, "me@x.com", "2025-01-01T00:00:00")
    assert row[-1] is True  # is_public inferred: owner-only permissions and viewer not listed
    meta = json.loads(row[20])
    assert meta["inferredPublicLink"] is True
    assert meta["inferredPublicReason"] == "owner_only_permissions_missing_viewer"
    assert [p[4] for p in perms] == ["bob@x.com"]
    owned = {"id": "o", "name": "o.txt", "mimeType": "text/plain", "ownedByMe": True, "size": "7",
             "owners": [{"emailAddress": "me@x.com", "permissionId": "999"}], "permissions": []}
    row, perms = file_row(owned, "me@x.com", "t")
    assert row[3] == 7 and row[-1] is False and row[12] == "my_drive" and row[23] == "txt"
    assert [(p[3], p[4]) for p in perms] == [("owner", "me@x.com")]


def test_scan_populates_database(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    repo = Repository(db)
    assert repo.total_file_count() == 10
    assert repo.get_file("pdf1")["full_path"] == "/Case Files/Invoices/invoice-001.pdf"
    assert repo.get_file("img1")["is_public"] == 1
    assert repo.get_file("cut1")["shortcut_target_id"] == "pdf1"
    assert json.loads(repo.get_file("dupA")["metadata_json"]).get("is_duplicate") == "true"
    users = {u["email_address"]: u for u in repo.user_analytics()}
    assert users["me@x.com"]["files_owned_count"] == 8 and users["bob@x.com"]["files_owned_count"] == 1
    with db.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM session_metadata").fetchone()[0] == 1


def test_failed_scan_keeps_existing_evidence(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    result = DriveScanner(FakeDriveClient(pages=SAMPLE_PAGES, fail_on_page=1), db, "me@x.com").scan()
    assert result.status == "error" and "API exploded" in result.message
    assert Repository(db).total_file_count() == 10


def test_cancelled_scan_keeps_existing_evidence(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    cancel = threading.Event()
    cancel.set()
    updates = []
    result = DriveScanner(FakeDriveClient(pages=[{"files": []}]), db, "me@x.com").scan(updates.append, cancel)
    assert result.status == "cancelled" and Repository(db).total_file_count() == 10
    assert updates and updates[-1].status == "cancelled"
    assert updates[0] is not updates[-1]  # snapshots, not one shared mutable object


def _evidence_counts(db):
    with db.session() as conn:
        return (conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM permissions").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM session_metadata").fetchone()[0])


def test_failure_after_delete_inside_the_transaction_keeps_existing_evidence(tmp_path, monkeypatch):
    db = make_db(tmp_path)
    seed_database(db)
    before = _evidence_counts(db)
    assert before[0] == 10

    def boom(conn):
        raise RuntimeError("duplicate detection exploded")

    # detect_duplicates runs after DELETE FROM files/permissions and the re-inserts, in the same transaction.
    monkeypatch.setattr(scanner, "detect_duplicates", boom)
    result = DriveScanner(FakeDriveClient(pages=[{"files": []}]), db, "me@x.com").scan()
    assert result.status == "error" and "duplicate detection exploded" in result.message
    assert _evidence_counts(db) == before                      # rolled back: nothing deleted, no new session row
    assert Repository(db).get_file("pdf1")["name"] == "invoice-001.pdf"


def test_cancel_during_first_page_progress_stops_after_one_page(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    client = FakeDriveClient(pages=SAMPLE_PAGES)
    assert len(SAMPLE_PAGES) > 1
    cancel = threading.Event()
    updates = []

    def progress(p):
        updates.append(p)
        if p.current and not cancel.is_set():   # first callback reporting a fetched page
            cancel.set()

    result = DriveScanner(client, db, "me@x.com").scan(progress, cancel)
    assert result.status == "cancelled" and client.page_calls == 1
    assert Repository(db).total_file_count() == 10

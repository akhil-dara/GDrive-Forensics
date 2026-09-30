from gdrive_forensics.core.filters import FilterState
from gdrive_forensics.core.mime import FOLDER_MIME
from gdrive_forensics.storage.repository import Repository
from tests.helpers import insert_file, insert_permission, make_db


def seeded(tmp_path):
    db = make_db(tmp_path)
    insert_file(db, id="root", name="Case", mime_type=FOLDER_MIME, full_path="/Case", size=0)
    insert_file(db, id="a", name="alpha.pdf", mime_type="application/pdf", parent_id="root",
                full_path="/Case/alpha.pdf", size=300, starred=1)
    insert_file(db, id="b", name="beta.png", mime_type="image/png", parent_id="root",
                full_path="/Case/beta.png", size=200, owned_by_me=0, source="shared_with_me",
                owner_email="bob@x.com", owner_name="Bob", is_public=1)
    insert_file(db, id="c", name="alpha.pdf", mime_type="application/pdf", parent_id="root",
                full_path="/Case/alpha.pdf", size=100, trashed=1)
    insert_file(db, id="d", name="dup.txt", full_path="/dup.txt")
    insert_file(db, id="e", name="dup.txt", full_path="/dup.txt")
    insert_permission(db, file_id="a", permission_id="111", email_address="alice@x.com", display_name="Alice")
    insert_permission(db, file_id="a", permission_id="999", role="owner", email_address="me@x.com", display_name="Me")
    insert_permission(db, file_id="b", permission_id="222", type="anyone", role="reader",
                      email_address="anyone", display_name="anyone")
    return db, Repository(db)


def test_listing_counts_and_paging(tmp_path):
    _, repo = seeded(tmp_path)
    fs = FilterState(sort="size_desc")
    assert repo.count_files(fs) == 5
    page = repo.list_files(fs, limit=2, offset=0)
    assert [r["id"] for r in page] == ["a", "b"]
    assert isinstance(page[0], dict)
    assert repo.total_file_count() == 6
    assert repo.count_files(FilterState(folder_id="root")) == 2
    assert repo.count_files(FilterState(source="shared_by_me")) == 1


def test_lookup_helpers(tmp_path):
    _, repo = seeded(tmp_path)
    assert repo.get_file("a")["name"] == "alpha.pdf" and repo.get_file("zzz") is None
    assert [r["id"] for r in repo.get_files(["b", "a", "b", "missing"])] == ["b", "a"]
    assert {r["id"] for r in repo.list_children("root")} == {"a", "b", "c"}
    assert repo.get_parent_link("a") == ("a", "alpha.pdf", "root")
    assert repo.duplicate_keys(["dup.txt", "alpha.pdf"]) == {("/dup.txt", "dup.txt")}
    assert repo.file_paths(["a", "b"]) == {"a": "/Case/alpha.pdf", "b": "/Case/beta.png"}
    perms = repo.permissions_map(["a", "b", "d"])
    assert perms["d"] == [] and {p["email"] for p in perms["a"]} == {"alice@x.com", "me@x.com"}
    assert repo.get_permissions("a")[0]["role"] in {"reader", "owner"}
    owners = repo.list_owners()
    assert [o["email"] for o in owners] == ["bob@x.com", "me@x.com"]


def test_queue_roundtrip(tmp_path):
    _, repo = seeded(tmp_path)
    assert repo.add_to_queue(["a", "b", "a"]) == 2
    assert repo.add_to_queue(["a"]) == 0
    assert repo.queue_ids() == ["a", "b"]
    assert [f["id"] for f in repo.queue_files()] == ["a", "b"]
    repo.remove_from_queue(["a"])
    assert repo.queue_ids() == ["b"]
    repo.clear_queue()
    assert repo.queue_ids() == []


def test_history_revisions_thumbnail_updates(tmp_path):
    db, repo = seeded(tmp_path)
    repo.record_export(file_id="a", local_path="/x/alpha.pdf", status="success", original_hash="h",
                       exported_hash="h", hash_verified=True, hash_algorithm="md5", md5_local="h",
                       sha256_local="s", source="queue")
    with db.session() as conn:
        row = conn.execute("SELECT * FROM export_history").fetchone()
    assert row["hash_verified"] == 1 and row["source"] == "queue"
    repo.replace_revisions("a", [{"id": "r1", "modifiedTime": "2025-01-01T00:00:00Z", "size": "5",
                                  "lastModifyingUser": {"emailAddress": "e@x", "displayName": "E"}}])
    assert repo.revision_counts(["a", "b"]) == {"a": 1, "b": 0}
    assert repo.list_revisions("a")[0]["modified_by_email"] == "e@x"
    repo.update_thumbnail_metadata("b", thumbnail_link="http://t", owner_photo="http://p",
                                   owner_name="Other", owner_email="other@x.com")
    b = repo.get_file("b")
    assert b["thumbnail_link"] == "http://t" and b["owner_name"] == "Bob"


def test_analytics_queries(tmp_path):
    _, repo = seeded(tmp_path)
    summary = repo.analytics_summary()
    assert summary["total_files"] == 5 and summary["trashed_count"] == 1 and summary["trashed_size"] == 100
    assert summary["public"] == 1 and summary["starred"] == 1 and summary["shared_files"] == 1
    assert repo.top_largest_files(2)[0]["id"] == "a"
    assert ("application/pdf", 1) in repo.type_distribution()
    owners = {o["owner_email"]: o for o in repo.storage_by_owner()}
    assert owners["bob@x.com"]["total_size"] == 200


def test_api_log_and_activity(tmp_path):
    db, repo = seeded(tmp_path)
    repo.log_api_call(request_type="files.list", url="drive/v3/files", params={"pageSize": 1},
                      status=200, response={"files": []}, elapsed=0.1)
    with db.session() as conn:
        assert conn.execute("SELECT response_status FROM api_logs").fetchone()[0] == 200
    rec = {"activity_key": "k1", "activity_id": "k1", "timestamp": "2025-03-02T00:00:00Z",
           "actor_person": "people/111", "actor_email": "alice@x.com", "actor_name": "Alice",
           "action_type": "edit", "target_id": "a", "target_name": "alpha.pdf",
           "target_mime_type": "application/pdf", "target_path": "/Case/alpha.pdf", "details_json": "{}"}
    assert repo.store_activities([rec, dict(rec)]) == 1
    assert repo.store_activities([rec]) == 0
    assert repo.activity_count() == 1
    assert repo.file_activity("a")[0]["action_type"] == "edit"
    stats = repo.activity_stats()
    assert stats["total"] == 1 and stats["by_type"] == [("edit", 1)] and stats["top_actors"] == [("alice@x.com", 1)]
    assert repo.resolve_people(["people/111", "people/404", "bad"]) == {"people/111": ("Alice", "alice@x.com")}


def test_user_analytics_search(tmp_path):
    db, repo = seeded(tmp_path)
    with db.session() as conn:
        conn.execute("INSERT INTO user_analytics (email_address, display_name, files_owned_count, "
                     "files_shared_with_count, files_shared_by_count) VALUES ('bob@x.com','Bob',1,0,0), "
                     "('me@x.com','Me',5,1,1)")
    assert [u["email_address"] for u in repo.user_analytics()] == ["me@x.com", "bob@x.com"]
    assert [u["email_address"] for u in repo.user_analytics("bob")] == ["bob@x.com"]
    assert len(repo.user_analytics(limit=1)) == 1

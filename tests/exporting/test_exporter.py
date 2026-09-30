import csv
import json
import os
import threading
from datetime import datetime

from gdrive_forensics.core.mime import FOLDER_MIME
from gdrive_forensics.core.paths import unique_file_path
from gdrive_forensics.drive.downloads import DownloadCancelled, DownloadResult
from gdrive_forensics.exporting import exporter as exporter_module
from gdrive_forensics.exporting.exporter import (
    PathResolver, QueueExporter, build_local_path, export_metadata_report, gather_export_records,
)
from gdrive_forensics.storage.repository import Repository
from tests.fixtures.drive_samples import seed_database
from tests.helpers import insert_file, make_db


def setup(tmp_path):
    db = make_db(tmp_path)
    seed_database(db)
    return Repository(db)


def fake_download(fail_ids=(), mismatch_ids=(), cancel_after=None):
    calls = []

    def download(client, record, dest_dir, progress=None, cancel=None):
        calls.append(record["id"])
        if cancel_after is not None and len(calls) > cancel_after:
            raise DownloadCancelled()
        if record["id"] in fail_ids:
            raise RuntimeError("HTTP 403")
        os.makedirs(dest_dir, exist_ok=True)
        path = unique_file_path(os.path.join(dest_dir, record["name"]))  # like the real downloader: never overwrite
        with open(path, "wb") as fh:
            fh.write(b"x")
        if progress:
            progress(0.5)
            progress(1.0)
        verified = False if record["id"] in mismatch_ids else (True if record.get("md5_checksum") else None)
        return DownloadResult(path=path, size=1, md5="m", sha1="s", sha256="h", algorithm="md5" if verified is not None else None,
                              expected_hash=record.get("md5_checksum"), verified=verified)
    download.calls = calls
    return download


def test_paths_and_gathering(tmp_path):
    repo = setup(tmp_path)
    resolver = PathResolver(repo)
    pdf = repo.get_file("pdf1")
    assert resolver.segments(pdf) == ["Case Files", "Invoices", "invoice-001.pdf"]
    assert resolver.drive_path(pdf) == "Case Files / Invoices / invoice-001.pdf"
    ids = [r["id"] for r in gather_export_records(repo, [repo.get_file("fold1")])]
    assert ids[0] == "fold1" and set(ids) == {"fold1", "sub1", "pdf1", "doc1", "cut1"}
    assert build_local_path("/out/Case Files", ["Case Files", "Invoices"]) == os.path.join("/out/Case Files", "Invoices")
    assert build_local_path("/out/Export", []) == "/out/Export"


def test_queue_export_records_everything(tmp_path):
    repo = setup(tmp_path)
    out = tmp_path / "out"
    download = fake_download(fail_ids={"doc1"}, mismatch_ids={"img1"})
    progress = []
    result = QueueExporter(repo, client=None, tz_name="UTC", download=download).run(
        str(out), [repo.get_file("fold1"), repo.get_file("img1")], progress=progress.append)
    assert not result.cancelled and result.total_files == 4
    # the shortcut is skipped, not failed; only doc1 really failed
    assert (result.downloaded, result.failed, result.skipped, result.verified, result.mismatched) == (2, 1, 1, 1, 1)
    assert result.failed_root_ids == {"fold1"}          # doc1 lives under fold1; img1's mismatch was exported
    assert os.path.isdir(out / "Export" / "Case Files" / "Invoices")
    assert os.path.isfile(out / "Export" / "Case Files" / "Invoices" / "invoice-001.pdf")
    with open(result.csv_path, encoding="utf-8") as fh:
        rows = {r["File_ID"]: r for r in csv.DictReader(fh)}
    assert rows["pdf1"]["Hash_Verified"] == "Yes" and rows["img1"]["Hash_Verified"] == "No"
    assert rows["doc1"]["Local_Path"] == "Not downloaded" and rows["cut1"]["Downloaded"] == "No"
    assert os.path.isfile(result.json_path) and progress[-1].fraction == 1.0
    with open(result.json_path, encoding="utf-8") as fh:
        meta = json.load(fh)["metadata"]
    assert (meta["failed_files"], meta["skipped_files"], meta["hash_mismatches"]) == (1, 1, 1)
    with repo.db.session() as conn:
        statuses = dict(conn.execute("SELECT file_id, status FROM export_history").fetchall())
    assert statuses == {"pdf1": "success", "img1": "hash_mismatch", "doc1": "failed", "cut1": "skipped"}


def test_queue_export_cancel(tmp_path):
    repo = setup(tmp_path)
    cancel = threading.Event()
    result = QueueExporter(repo, None, "UTC", download=fake_download(cancel_after=1)).run(
        str(tmp_path / "out"), [repo.get_file("fold1")], cancel=cancel)
    assert result.cancelled and result.csv_path is None


def test_folder_export_is_relative_to_the_folder(tmp_path):
    repo = setup(tmp_path)
    result = QueueExporter(repo, None, "UTC", download=fake_download()).run(
        str(tmp_path / "out"), [repo.get_file("sub1")], export_root_name="Invoices", include_reports=False,
        source="folder", relative_to_root=True)
    # nested folder: no duplicated "Case Files/Invoices" chain under the chosen root
    assert result.csv_path is None and os.path.isfile(tmp_path / "out" / "Invoices" / "invoice-001.pdf")
    assert not os.path.exists(tmp_path / "out" / "Invoices" / "Case Files")


def test_metadata_report(tmp_path):
    repo = setup(tmp_path)
    records = [repo.get_file("pdf1"), repo.get_file("doc1")]
    for fmt in ("csv", "json", "xlsx"):
        path = export_metadata_report(repo, records, fmt, str(tmp_path / "rep"), "UTC", "No filters active")
        assert path.endswith(f".{fmt}") and os.path.getsize(path) > 0
    cancel = threading.Event()
    cancel.set()
    assert export_metadata_report(repo, records, "csv", str(tmp_path / "rep"), "UTC", "", cancel=cancel) is None


def _tree_db(tmp_path):
    """Case > Photos > {a.jpg, Photos > b.jpg, a *file* named Photos}; plus a top-level file named Export."""
    db = make_db(tmp_path)
    insert_file(db, id="case", name="Case", mime_type=FOLDER_MIME, full_path="/Case")
    insert_file(db, id="ph1", name="Photos", mime_type=FOLDER_MIME, parent_id="case", full_path="/Case/Photos")
    insert_file(db, id="a", name="a.jpg", mime_type="image/jpeg", parent_id="ph1", full_path="/Case/Photos/a.jpg")
    insert_file(db, id="ph2", name="Photos", mime_type=FOLDER_MIME, parent_id="ph1", full_path="/Case/Photos/Photos")
    insert_file(db, id="b", name="b.jpg", mime_type="image/jpeg", parent_id="ph2",
                full_path="/Case/Photos/Photos/b.jpg")
    insert_file(db, id="phf", name="Photos", mime_type="text/plain", parent_id="ph1", full_path="/Case/Photos/Photos")
    insert_file(db, id="exp", name="Export", mime_type="text/plain", parent_id=None, full_path="/Export")
    return Repository(db)


def test_folder_export_keeps_same_named_subfolder_and_stays_inside_export_dir(tmp_path):
    repo = _tree_db(tmp_path)
    out = tmp_path / "out"
    result = QueueExporter(repo, None, "UTC", download=fake_download()).run(
        str(out), [repo.get_file("ph1")], export_root_name="Photos", include_reports=False,
        source="folder", relative_to_root=True)
    assert (result.downloaded, result.failed) == (3, 0)
    root = out / "Photos"
    assert os.listdir(out) == ["Photos"]  # nothing escaped next to the export folder
    assert os.path.isfile(root / "a.jpg")
    assert os.path.isfile(root / "Photos" / "b.jpg")  # the nested same-named folder is not collapsed
    assert os.path.isdir(root / "Photos")
    # the *file* named "Photos" lives in the export dir (renamed, never overwriting the "Photos" folder)
    assert os.path.isfile(root / "Photos_1")
    assert sorted(os.listdir(root)) == ["Photos", "Photos_1", "a.jpg"]


def test_queue_export_of_top_level_file_named_like_the_export_root(tmp_path):
    repo = _tree_db(tmp_path)
    out = tmp_path / "out"
    result = QueueExporter(repo, None, "UTC", download=fake_download()).run(
        str(out), [repo.get_file("exp")], include_reports=False)
    assert (result.downloaded, result.failed) == (1, 0)
    assert os.listdir(out) == ["Export"]
    assert os.path.isfile(out / "Export" / "Export")


def run_queue(repo, tmp_path, roots, **download_kw):
    return QueueExporter(repo, None, "UTC", download=fake_download(**download_kw)).run(
        str(tmp_path / "out"), [repo.get_file(r) for r in roots], include_reports=False)


def test_failed_root_ids_keep_only_roots_whose_subtree_failed(tmp_path):
    repo = setup(tmp_path)
    # doc1 (inside fold1) fails, img1 is a hash mismatch, cut1 is a shortcut root, shared1 succeeds
    result = run_queue(repo, tmp_path, ["fold1", "cut1", "img1", "shared1"], fail_ids={"doc1"}, mismatch_ids={"img1"})
    assert result.failed_root_ids == {"fold1"}
    assert (result.failed, result.skipped, result.mismatched) == (1, 1, 1)


def test_failed_root_ids_cover_every_root_containing_the_failure(tmp_path):
    repo = setup(tmp_path)
    # pdf1 is queued on its own *and* sits under fold1: both roots keep it
    result = run_queue(repo, tmp_path, ["fold1", "pdf1", "img1"], fail_ids={"pdf1"})
    assert result.failed_root_ids == {"fold1", "pdf1"}


def test_shortcut_root_is_skipped_not_failed(tmp_path):
    repo = setup(tmp_path)
    result = run_queue(repo, tmp_path, ["cut1"])
    assert (result.downloaded, result.failed, result.skipped) == (0, 0, 1)
    assert result.failed_root_ids == set()
    with repo.db.session() as conn:
        assert conn.execute("SELECT status FROM export_history WHERE file_id = 'cut1'").fetchone()[0] == "skipped"


def test_all_success_has_no_failed_roots(tmp_path):
    repo = setup(tmp_path)
    result = run_queue(repo, tmp_path, ["fold1", "img1"], mismatch_ids={"img1"})
    assert result.failed_root_ids == set() and result.failed == 0 and result.skipped == 1


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2025, 3, 1, 10, 20, 30)


def test_reports_never_overwrite_an_existing_report(tmp_path, monkeypatch):
    monkeypatch.setattr(exporter_module, "datetime", FrozenDatetime)   # every report lands in the same second
    repo = setup(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    earlier_csv, earlier_json = out / "ExportReport_20250301_102030.csv", out / "ExportReport_20250301_102030.json"
    earlier_csv.write_text("earlier evidence", encoding="utf-8")
    earlier_json.write_text("{}", encoding="utf-8")
    result = QueueExporter(repo, None, "UTC", download=fake_download()).run(str(out), [repo.get_file("img1")])
    assert os.path.basename(result.csv_path) == "ExportReport_20250301_102030_1.csv"
    assert os.path.basename(result.json_path) == "ExportReport_20250301_102030_1.json"
    assert earlier_csv.read_text(encoding="utf-8") == "earlier evidence" and earlier_json.read_text(encoding="utf-8") == "{}"

    records = [repo.get_file("pdf1")]
    first = export_metadata_report(repo, records, "csv", str(out), "UTC", "No filters active")
    second = export_metadata_report(repo, records, "csv", str(out), "UTC", "No filters active")
    assert os.path.basename(first) == "FilteredReport_20250301_102030.csv"
    assert os.path.basename(second) == "FilteredReport_20250301_102030_1.csv"
    assert os.path.getsize(first) > 0 and os.path.getsize(second) > 0

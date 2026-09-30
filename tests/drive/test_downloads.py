import hashlib
import os
import threading
from types import SimpleNamespace

import pytest

from gdrive_forensics.drive.downloads import DownloadCancelled, download_file, reference_hash
from tests.fakes import FakeDownloader, FakeDriveClient

DATA = b"evidence-bytes" * 100


class _RaisingDownloader:
    """Writes the first chunk successfully, then raises mid-stream on the second chunk."""

    def __init__(self, fd, request, chunksize=0):
        self._fd = fd
        self._calls = 0

    def next_chunk(self, num_retries=0):
        self._calls += 1
        if self._calls == 1:
            self._fd.write(b"partial-bytes")
            return SimpleNamespace(progress=lambda: 0.5), False
        raise RuntimeError("boom mid-stream")


def read_bytes(path):
    with open(path, "rb") as fh:   # closed explicitly: a leaked handle is a ResourceWarning under -W error
        return fh.read()


def record(**kw):
    base = {"id": "f1", "name": "report:final.pdf", "mime_type": "application/pdf",
            "md5_checksum": hashlib.md5(DATA).hexdigest(), "sha1_checksum": None, "sha256_checksum": None}
    base.update(kw)
    return base


def test_reference_hash_prefers_strongest():
    assert reference_hash({"md5_checksum": "m", "sha1_checksum": "s1", "sha256_checksum": "s2"}) == ("sha256", "s2")
    assert reference_hash({"md5_checksum": "m"}) == ("md5", "m")
    assert reference_hash({}) == (None, None)


def test_download_verifies_hash_and_never_overwrites(tmp_path):
    client = FakeDriveClient(contents={"f1": DATA})
    progress = []
    result = download_file(client, record(), str(tmp_path), progress=progress.append,
                           downloader_factory=FakeDownloader)
    assert result.path.endswith("report꞉final.pdf") and read_bytes(result.path) == DATA
    assert result.verified is True and result.algorithm == "md5"
    assert result.sha256 == hashlib.sha256(DATA).hexdigest() and result.size == len(DATA)
    assert progress[-1] == 1.0
    second = download_file(client, record(), str(tmp_path), downloader_factory=FakeDownloader)
    assert second.path.endswith("report꞉final_1.pdf")


def test_hash_mismatch_is_reported(tmp_path):
    client = FakeDriveClient(contents={"f1": DATA})
    result = download_file(client, record(md5_checksum="0" * 32), str(tmp_path), downloader_factory=FakeDownloader)
    assert result.verified is False and result.expected_hash == "0" * 32


def test_workspace_export_has_no_reference_hash(tmp_path):
    client = FakeDriveClient(contents={"d1": b"docx"})
    rec = record(id="d1", name="Notes", mime_type="application/vnd.google-apps.document", md5_checksum=None)
    result = download_file(client, rec, str(tmp_path), downloader_factory=FakeDownloader)
    assert result.path.endswith("Notes.docx") and result.verified is None and result.algorithm is None


def test_cancel_removes_partial_file(tmp_path):
    client = FakeDriveClient(contents={"f1": DATA})
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(DownloadCancelled):
        download_file(client, record(), str(tmp_path), cancel=cancel, downloader_factory=FakeDownloader)
    assert list(tmp_path.iterdir()) == []


def test_download_never_touches_a_preexisting_part_file(tmp_path):
    stray = tmp_path / "notes.txt.part"
    stray.write_bytes(b"unrelated-evidence-already-on-disk")
    client = FakeDriveClient(contents={"f1": DATA})
    result = download_file(client, record(name="notes.txt"), str(tmp_path), downloader_factory=FakeDownloader)
    assert result.path.endswith("notes.txt") and not result.path.endswith(".part")
    assert stray.read_bytes() == b"unrelated-evidence-already-on-disk"
    assert read_bytes(result.path) == DATA


def test_download_cleans_up_on_mid_stream_error(tmp_path):
    client = FakeDriveClient(contents={"f1": DATA})
    before = set(os.listdir(tmp_path))
    with pytest.raises(RuntimeError, match="boom mid-stream"):
        download_file(client, record(), str(tmp_path), downloader_factory=_RaisingDownloader)
    assert set(os.listdir(tmp_path)) == before


def test_download_next_to_a_dangling_symlink_does_not_loop(tmp_path):
    link = tmp_path / "notes.txt"
    try:
        os.symlink(str(tmp_path / "gone.txt"), str(link))
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")
    client = FakeDriveClient(contents={"f1": DATA})
    result = download_file(client, record(name="notes.txt"), str(tmp_path), downloader_factory=FakeDownloader)
    assert os.path.basename(result.path) == "notes_1.txt" and read_bytes(result.path) == DATA
    assert os.path.islink(link)                                  # the symlink itself is left alone


def test_workspace_export_appends_the_extension_without_eating_dotted_names(tmp_path):
    client = FakeDriveClient(contents={"d1": b"docx"})
    doc = "application/vnd.google-apps.document"
    dotted = download_file(client, record(id="d1", name="Minutes 12.03.2024", mime_type=doc, md5_checksum=None),
                           str(tmp_path), downloader_factory=FakeDownloader)
    assert os.path.basename(dotted.path) == "Minutes 12.03.2024.docx"
    named = download_file(client, record(id="d1", name="Report.docx", mime_type=doc, md5_checksum=None),
                          str(tmp_path), downloader_factory=FakeDownloader)
    assert os.path.basename(named.path) == "Report.docx"
    upper = download_file(client, record(id="d1", name="Plan.DOCX", mime_type=doc, md5_checksum=None),
                          str(tmp_path), downloader_factory=FakeDownloader)
    assert os.path.basename(upper.path) == "Plan.DOCX"
    long_doc = download_file(client, record(id="d1", name="n" * 250, mime_type=doc, md5_checksum=None),
                             str(tmp_path), downloader_factory=FakeDownloader)
    assert len(os.path.basename(long_doc.path)) == 200 and long_doc.path.endswith(".docx")


def test_leftover_temp_file_does_not_fail_a_verified_download(tmp_path, monkeypatch, caplog):
    real_remove = os.remove

    def remove(path):
        if os.path.basename(path).startswith(".gdf-"):
            raise PermissionError("file is locked by an antivirus scanner")
        real_remove(path)

    monkeypatch.setattr(os, "remove", remove)
    client = FakeDriveClient(contents={"f1": DATA})
    with caplog.at_level("WARNING", logger="gdrive_forensics.drive.downloads"):
        result = download_file(client, record(), str(tmp_path), downloader_factory=FakeDownloader)
    assert result.verified is True and read_bytes(result.path) == DATA
    assert any("could not be removed" in r.getMessage() for r in caplog.records)
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith(".gdf-")]
    assert len(leftovers) == 1                                   # the temp file stays; the evidence is complete

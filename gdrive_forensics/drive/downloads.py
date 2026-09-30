"""Streaming downloads that hash while writing and verify against Drive checksums."""
from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from googleapiclient.http import MediaIoBaseDownload

from ..core.paths import MAX_UNIQUE_ATTEMPTS, ensure_directory, sanitize_filename, unique_file_path

logger = logging.getLogger(__name__)
CHUNK_SIZE = 8 * 1024 * 1024


class DownloadCancelled(Exception):
    """Download aborted by the user; the partial file was removed."""


@dataclass
class DownloadResult:
    path: str
    size: int
    md5: str
    sha1: str
    sha256: str
    algorithm: Optional[str]       # which Drive checksum was compared (sha256 > sha1 > md5)
    expected_hash: Optional[str]
    verified: Optional[bool]       # None when Drive has no checksum (e.g. Workspace exports)

    @property
    def local_hash(self) -> Optional[str]:
        return {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}.get(self.algorithm or "")


class _HashingWriter:
    def __init__(self, fh) -> None:
        self.fh = fh
        self.size = 0
        self.md5, self.sha1, self.sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.fh.write(data)
        self.md5.update(data)
        self.sha1.update(data)
        self.sha256.update(data)
        self.size += len(data)
        return len(data)


def reference_hash(record: dict) -> tuple[Optional[str], Optional[str]]:
    for algorithm in ("sha256", "sha1", "md5"):
        value = record.get(f"{algorithm}_checksum")
        if value:
            return algorithm, value
    return None, None


def _finalize_never_overwrite(tmp_path: str, desired_path: str) -> str:
    """Move tmp_path into place under a unique name derived from desired_path, without ever
    overwriting an existing file. Prefers os.link (exclusive: fails with FileExistsError instead
    of overwriting) so two concurrent downloads of the same name can never race onto one file;
    falls back to os.rename (which refuses to overwrite on Windows, and is checked immediately
    before on POSIX where rename overwrites silently) when hard links are not supported at all.
    """
    for _attempt in range(MAX_UNIQUE_ATTEMPTS):
        final_path = unique_file_path(desired_path)
        try:
            os.link(tmp_path, final_path)
        except FileExistsError:
            continue  # someone else just took this name - ask unique_file_path for the next one
        except OSError:
            # os.link itself unsupported (e.g. cross-device, or a filesystem without hard links).
            if os.name != "nt" and os.path.lexists(final_path):
                continue
            try:
                os.rename(tmp_path, final_path)
            except FileExistsError:
                continue
            return final_path
        else:
            try:
                os.remove(tmp_path)
            except OSError as exc:
                # The evidence file is complete and verified under final_path; a leftover temp file
                # (e.g. locked by an antivirus scanner) must not turn a good download into a failure.
                logger.warning("Saved %s, but the temporary file %s could not be removed: %s",
                               final_path, tmp_path, exc)
            return final_path
    raise RuntimeError(f"Could not find a free file name for {desired_path} after {MAX_UNIQUE_ATTEMPTS} attempts")


def download_file(client, record: dict, dest_dir: str, *,
                  progress: Optional[Callable[[float], None]] = None,
                  cancel: Optional[threading.Event] = None,
                  downloader_factory=MediaIoBaseDownload) -> DownloadResult:
    request, export_ext = client.media_request(record["id"], record["mime_type"])
    name = sanitize_filename(record.get("name"))
    if export_ext and not name.lower().endswith(export_ext.lower()):
        # Append, never replace: "Minutes 12.03.2024" must not lose ".2024" to splitext.
        name = sanitize_filename(name + export_ext)   # re-applies the length cap, keeping the extension
    ensure_directory(dest_dir)
    desired_path = os.path.join(dest_dir, name)
    # Created exclusively under a random name so it can never collide with - or truncate - an
    # existing "<name>.part" evidence file, and so two same-named downloads never share one temp file.
    fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix=".gdf-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as fh:
            writer = _HashingWriter(fh)
            downloader = downloader_factory(writer, request, chunksize=CHUNK_SIZE)
            done = False
            while not done:
                if cancel is not None and cancel.is_set():
                    raise DownloadCancelled()
                status, done = downloader.next_chunk(num_retries=3)
                if progress and status:
                    progress(max(0.0, min(1.0, status.progress() or 0.0)))
        final_path = _finalize_never_overwrite(tmp_path, desired_path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    if progress:
        progress(1.0)
    algorithm, expected = (None, None) if export_ext else reference_hash(record)
    digests = {"md5": writer.md5.hexdigest(), "sha1": writer.sha1.hexdigest(), "sha256": writer.sha256.hexdigest()}
    verified = (digests[algorithm].lower() == expected.lower()) if expected else None
    logger.info("Downloaded %s -> %s (verified=%s)", record.get("id"), final_path, verified)
    return DownloadResult(path=final_path, size=writer.size, algorithm=algorithm, expected_hash=expected,
                          verified=verified, **digests)

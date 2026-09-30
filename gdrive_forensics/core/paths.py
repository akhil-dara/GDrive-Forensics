"""Filesystem-safe naming helpers."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional

SAFE_CHAR_MAP = str.maketrans({
    "<": "﹤", ">": "﹥", ":": "꞉", '"': "″", "/": "／",
    "\\": "＼", "|": "｜", "?": "？", "*": "﹡",
})
MAX_NAME_LENGTH = 200          # characters; leaves room for the export folder path on Windows
MAX_UNIQUE_ATTEMPTS = 10_000
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Windows device names are reserved with or without an extension ("NUL.txt" and "nul.tar.gz" are NUL).
_RESERVED_NAME = re.compile(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", re.IGNORECASE)


def sanitize_filename(name: Optional[str]) -> str:
    """Make a Drive name safe for Windows/macOS/Linux while staying readable.

    Control characters become spaces, a reserved Windows device name gets "_" after its stem
    ("nul" -> "nul_", "NUL.txt" -> "NUL_.txt") and the name is capped at MAX_NAME_LENGTH
    characters, keeping its extension.
    """
    if not name:
        return "untitled"
    cleaned = _CONTROL_CHARS.sub(" ", name)
    cleaned = cleaned.translate(SAFE_CHAR_MAP)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = cleaned.rstrip(". ")
    if not cleaned:
        return "untitled"
    stem, dot, rest = cleaned.partition(".")
    if _RESERVED_NAME.fullmatch(stem.rstrip(" ")):
        cleaned = f"{stem}_{dot}{rest}"
    if len(cleaned) > MAX_NAME_LENGTH:
        base, ext = os.path.splitext(cleaned)
        if len(ext) >= MAX_NAME_LENGTH // 2:     # no real extension to keep: cut the whole name
            base, ext = cleaned, ""
        cleaned = base[:MAX_NAME_LENGTH - len(ext)].rstrip(". ") + ext
    return cleaned or "untitled"


def safe_path_join(base_path: str, *segments: str) -> str:
    safe_segments = [sanitize_filename(seg) for seg in segments if seg]
    if not safe_segments:
        return base_path
    return os.path.join(base_path, *safe_segments)


def ensure_directory(path: str) -> None:
    if path:
        os.makedirs(path, exist_ok=True)


def build_unique_path(
    base_dir: str,
    desired_name: str,
    existing_paths: Optional[set] = None,
    reference_timestamp: Optional[str] = None,
) -> tuple[str, bool]:
    """Return (path, was_renamed); duplicates get a ' (Duplicate_<name>_<ts> UTC)' suffix."""
    safe_name = sanitize_filename(desired_name) or "file"
    base_dir = base_dir or "."
    existing_paths = existing_paths if existing_paths is not None else set()
    candidate = os.path.join(base_dir, safe_name)
    if candidate not in existing_paths and not os.path.lexists(candidate):
        existing_paths.add(candidate)
        return candidate, False
    stamp = None
    if reference_timestamp:
        try:
            stamp = datetime.fromisoformat(reference_timestamp.replace("Z", "+00:00")).strftime("%Y%m%d_%H%M%S")
        except ValueError:
            stamp = None
    if not stamp:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name, ext = os.path.splitext(safe_name)
    token = f" (Duplicate_{name or 'file'}_{stamp} UTC)"
    candidate = os.path.join(base_dir, f"{name}{token}{ext}")
    for counter in range(1, MAX_UNIQUE_ATTEMPTS + 1):
        if candidate not in existing_paths and not os.path.lexists(candidate):
            existing_paths.add(candidate)
            return candidate, True
        candidate = os.path.join(base_dir, f"{name}{token}_{counter}{ext}")
    raise RuntimeError(f"No free file name for {safe_name!r} in {base_dir} after {MAX_UNIQUE_ATTEMPTS} attempts")


def unique_file_path(path: str) -> str:
    """Never overwrite evidence: 'a.txt' -> 'a_1.txt' -> 'a_2.txt' ...

    Uses lexists: a dangling symlink occupies its name too (exists() says it is free, but creating
    a file or hard link there fails, which would make a retrying caller loop forever).
    """
    if not os.path.lexists(path):
        return path
    base, ext = os.path.splitext(path)
    for counter in range(1, MAX_UNIQUE_ATTEMPTS + 1):
        candidate = f"{base}_{counter}{ext}"
        if not os.path.lexists(candidate):
            return candidate
    raise RuntimeError(f"No free file name for {path} after {MAX_UNIQUE_ATTEMPTS} attempts")

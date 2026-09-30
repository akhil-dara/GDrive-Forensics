"""Application constants and data-file locations (working-directory based, like v1)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

APP_TITLE = "Google Drive Forensics Suite"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
ACTIVITY_SCOPE = "https://www.googleapis.com/auth/drive.activity.readonly"
SCOPES = [DRIVE_SCOPE, ACTIVITY_SCOPE]

PACKAGE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = PACKAGE_DIR / "assets"


@dataclass(frozen=True)
class AppPaths:
    base_dir: Path

    @classmethod
    def from_cwd(cls) -> "AppPaths":
        return cls(Path.cwd())

    @property
    def credentials_file(self) -> Path:
        return self.base_dir / "credentials.json"

    @property
    def token_file(self) -> Path:
        return self.base_dir / "token.json"

    @property
    def database_file(self) -> Path:
        return self.base_dir / "gdrive_forensics.db"

    @property
    def thumbnail_cache_file(self) -> Path:
        return self.base_dir / "thumbnail_cache.db"

    @property
    def log_dir(self) -> Path:
        return self.base_dir / "logs"

    @property
    def export_dir(self) -> Path:
        return self.base_dir / "exports"

    @property
    def download_dir(self) -> Path:
        return self.base_dir / "downloads"

    def ensure_dirs(self) -> None:
        for directory in (self.log_dir, self.export_dir, self.download_dir):
            directory.mkdir(parents=True, exist_ok=True)

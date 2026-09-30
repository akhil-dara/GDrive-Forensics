import logging

from gdrive_forensics import config
from gdrive_forensics.logging_setup import API_LOGGER, APP_LOGGER, setup_logging


def test_app_paths(tmp_path):
    paths = config.AppPaths(tmp_path)
    assert paths.database_file == tmp_path / "gdrive_forensics.db"
    assert paths.token_file.name == "token.json" and paths.credentials_file.name == "credentials.json"
    assert paths.thumbnail_cache_file.name == "thumbnail_cache.db"
    assert not paths.log_dir.exists()
    paths.ensure_dirs()
    assert paths.log_dir.is_dir() and paths.export_dir.is_dir() and paths.download_dir.is_dir()
    assert config.SCOPES == [config.DRIVE_SCOPE, config.ACTIVITY_SCOPE]
    assert (config.ASSETS_DIR / "logo.png").exists()


def test_setup_logging_is_idempotent(tmp_path):
    setup_logging(tmp_path, console=False)
    setup_logging(tmp_path, console=False)
    app = logging.getLogger(APP_LOGGER)
    ours = [h for h in app.handlers if getattr(h, "_gdf_handler", False)]
    assert len(ours) == 1
    logging.getLogger(API_LOGGER).info("API_REQUEST test")
    logging.getLogger("gdrive_forensics.drive.scanner").info("child message")
    for h in logging.getLogger(API_LOGGER).handlers + app.handlers:
        h.flush()
    assert "API_REQUEST test" in (tmp_path / "api_requests.log").read_text(encoding="utf-8")
    main_log = (tmp_path / "gdrive_forensics.log").read_text(encoding="utf-8")
    assert "child message" in main_log and "API_REQUEST test" not in main_log

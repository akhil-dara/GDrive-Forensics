"""Rotating log files: app, API requests, auth and exports."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_LOGGER = "gdrive_forensics"
API_LOGGER = "gdrive_forensics.api"
AUTH_LOGGER = "gdrive_forensics.auth"
EXPORT_LOGGER = "gdrive_forensics.exports"

_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] %(message)s"
_MAX_BYTES = 5 * 1024 * 1024
_BACKUPS = 3


def _file_handler(path: Path, fmt: str) -> RotatingFileHandler:
    handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8")
    handler.setFormatter(logging.Formatter(fmt))
    handler._gdf_handler = True  # marker so setup_logging can be re-run safely
    return handler


def _reset(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        if getattr(handler, "_gdf_handler", False):
            logger.removeHandler(handler)
            handler.close()


def setup_logging(log_dir: Path, level: int = logging.INFO, console: bool = True) -> None:
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    app = logging.getLogger(APP_LOGGER)
    _reset(app)
    app.setLevel(level)
    app.addHandler(_file_handler(log_dir / "gdrive_forensics.log", _FORMAT))
    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(_FORMAT))
        stream._gdf_handler = True
        app.addHandler(stream)

    api = logging.getLogger(API_LOGGER)
    _reset(api)
    api.setLevel(logging.INFO)
    api.propagate = False
    api.addHandler(_file_handler(log_dir / "api_requests.log", "%(asctime)s - %(message)s"))

    for name, filename in ((AUTH_LOGGER, "auth.log"), (EXPORT_LOGGER, "exports.log")):
        logger = logging.getLogger(name)
        _reset(logger)
        logger.setLevel(logging.INFO)
        logger.addHandler(_file_handler(log_dir / filename, _FORMAT))

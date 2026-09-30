"""Entry point: `python gdrive-flet.py` or `python -m gdrive_forensics`."""
from __future__ import annotations

import logging
from typing import Optional

import flet as ft

from .config import ASSETS_DIR, AppPaths
from .logging_setup import setup_logging
from .ui.shell import ForensicsApp, shutdown_all

logger = logging.getLogger(__name__)


def main(page: ft.Page, paths: Optional[AppPaths] = None) -> ForensicsApp:
    app = ForensicsApp(page, paths or AppPaths.from_cwd())
    app.start()
    return app


def run() -> None:
    paths = AppPaths.from_cwd()
    paths.ensure_dirs()
    setup_logging(paths.log_dir)
    logger.info("Starting Google Drive Forensics Suite in %s", paths.base_dir)
    started: list[ForensicsApp] = []   # the shell's registry is weak: keep each window's app until shut down
    try:
        ft.run(lambda page: started.append(main(page, paths)), view=ft.AppView.FLET_APP,
               assets_dir=str(ASSETS_DIR))
    finally:
        # page.on_close does this too, but it is not guaranteed to fire (e.g. the client process
        # dies): nothing may keep the process alive once the window is gone.
        shutdown_all()
        started.clear()

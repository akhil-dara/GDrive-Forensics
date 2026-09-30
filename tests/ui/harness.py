"""Headless Flet session: real controls, real msgpack encoding, no Flutter client."""
from __future__ import annotations

import asyncio
import dataclasses
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Awaitable, Callable, Optional

import flet as ft
import msgpack
from flet.controls.base_control import BaseControl
from flet.controls.context import _context_page, context
from flet.messaging.connection import Connection
from flet.messaging.protocol import MessageAction, configure_encode_object_for_msgpack
from flet.messaging.session import Session
from flet.pubsub.pubsub_hub import PubSubHub


class FakeConnection(Connection):
    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        self.executor = ThreadPoolExecutor()
        self.pubsubhub = PubSubHub(loop=loop, executor=self.executor)
        self.sent = []
        self.crashes: list[str] = []   # SESSION_CRASHED texts (unhandled errors in event handlers)

    def send_message(self, message):
        # Encoding here proves every control/prop we send is serialisable by Flet 1.0.
        msgpack.packb([message.action, message.body], default=configure_encode_object_for_msgpack(BaseControl))
        self.sent.append(message)
        if message.action == MessageAction.SESSION_CRASHED:
            self.crashes.append(message.body.message)


def new_session():
    conn = FakeConnection(asyncio.get_running_loop())
    session = Session(conn)
    msgpack.packb(session.get_page_patch(), default=configure_encode_object_for_msgpack(BaseControl))
    # Mirror flet.app's on_session_created: `main` runs with the page bound as the current
    # context, so services (FilePicker, Clipboard) constructed there auto-register with it.
    _context_page.set(session.page)
    context.reset_auto_update()
    return session, conn


def run_ui(test_body: Callable[[], Awaitable[None]]) -> None:
    asyncio.run(test_body())


async def settle(n: int = 5, delay: float = 0.02) -> None:
    for _ in range(n):
        await asyncio.sleep(delay)


async def wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


def iter_controls(root):
    stack, seen = [root], set()
    while stack:
        control = stack.pop()
        if id(control) in seen:
            continue
        seen.add(id(control))
        yield control
        for field in dataclasses.fields(control):
            if field.name in ("parent", "_parent", "page"):
                continue
            try:
                value = getattr(control, field.name)
            except Exception:
                continue
            if isinstance(value, BaseControl):
                stack.append(value)
            elif isinstance(value, (list, tuple)):
                stack.extend(v for v in value if isinstance(v, BaseControl))


def find(root, predicate) -> list:
    return [c for c in iter_controls(root) if predicate(c)]


def texts(root) -> list[str]:
    out = []
    for c in iter_controls(root):
        if isinstance(c, ft.Text) and isinstance(c.value, str):
            out.append(c.value)
        content = getattr(c, "content", None)
        if isinstance(content, str):
            out.append(content)
        tooltip = getattr(c, "tooltip", None)
        if isinstance(tooltip, str):
            out.append(tooltip)
    return out


def find_text(root, text: str):
    """First control whose Text value, string content, tooltip or label contains `text`."""
    for c in iter_controls(root):
        for attr in ("value", "content", "tooltip", "label"):
            if attr == "value" and not isinstance(c, ft.Text):
                continue  # TextField/Dropdown values are user data, not labels
            v = getattr(c, attr, None)
            if isinstance(v, str) and text in v:
                return c
    return None


async def click(session, control, event: str = "click", data=None) -> None:
    """Dispatch an event; raise if its handler crashed.

    Session.dispatch_event swallows handler exceptions (logs them and sends SESSION_CRASHED to the
    client), so without this check a crashing handler would look like a successful click.
    """
    sent = session.connection.sent
    start = len(sent)
    await session.dispatch_event(control._i, event, data)
    await settle(2)
    crashes = [m.body.message for m in sent[start:] if m.action == MessageAction.SESSION_CRASHED]
    if crashes:
        raise AssertionError(f"on_{event} handler crashed:\n" + "\n".join(crashes))


async def make_app(tmp_path, seeded: bool = True, client=None):
    """Signed-in app with main view on a headless session."""
    from gdrive_forensics.config import AppPaths
    from gdrive_forensics.ui.shell import ForensicsApp
    from tests.fakes import FakeDriveClient
    from tests.fixtures.drive_samples import seed_database

    session, conn = new_session()
    paths = AppPaths(tmp_path)
    paths.ensure_dirs()
    app = ForensicsApp(session.page, paths)
    if seeded:
        seed_database(app.ctx.db)
    app.on_authenticated(credentials=object(), client=client or FakeDriveClient())
    await settle(10)
    return app, session, conn

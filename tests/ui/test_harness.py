import flet as ft
import pytest

from tests.ui.harness import click, new_session, run_ui


def test_click_surfaces_handler_crash_once():
    async def body():
        session, conn = new_session()
        state = {}

        def explode(e):
            state["clicked"] = True
            raise ValueError("handler exploded")

        boom = ft.Button("Boom", on_click=explode)
        fine = ft.Button("Fine", on_click=lambda e: state.update(fine=True))
        session.page.add(boom, fine)

        with pytest.raises(AssertionError, match="ValueError"):
            await click(session, boom)
        assert state["clicked"] is True
        assert len(conn.crashes) == 1 and "handler exploded" in conn.crashes[0]

        # The earlier crash is not re-reported by a later, clean dispatch.
        await click(session, fine)
        assert state["fine"] is True
        assert len(conn.crashes) == 1
    run_ui(body)

"""Signed-in window: header, filter sidebar, toolbar, tabbed content area and footer."""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional, Protocol

import flet as ft

from .context import EV_NAVIGATE_FILES, EV_QUEUE_CHANGED, AppContext
from .footer import Footer
from .header import HeaderBar
from .sidebar import Sidebar
from .toolbar import ActionToolbar, ToolbarActions

logger = logging.getLogger(__name__)

TAB_LABELS = ("Files", "Users", "Analytics")


class ContentView(Protocol):
    root: ft.Control

    async def activate(self) -> None: ...


class PlaceholderView:
    def __init__(self, title: str) -> None:
        self.root = ft.Container(content=ft.Text(f"{title} view"), expand=True)

    async def activate(self) -> None:
        return None


def files_toolbar_actions(files_view, base: Optional[ToolbarActions] = None) -> ToolbarActions:
    """Wire the toolbar buttons that act on the Files tab (queue page/selection, multi-select, view mode).

    Fields already set on `base` are kept; the others stay None ("Not available yet").
    """
    actions = base or ToolbarActions()
    wiring = {
        "add_page": files_view.add_current_page_to_queue,
        "add_selected": files_view.add_selected_to_queue,
        "toggle_selection": files_view.toggle_selection_mode,
        "set_view_mode": files_view.set_view_mode,
    }
    for name, method in wiring.items():
        if getattr(actions, name) is None:
            setattr(actions, name, method)
    return actions


class MainView:
    """Plain object (not a Flet control): the shell mounts `build()`'s result."""

    def __init__(self, ctx: AppContext, views: Optional[list] = None,
                 actions: Optional[ToolbarActions] = None) -> None:
        self.ctx = ctx
        self.views = views or [PlaceholderView(t) for t in TAB_LABELS]
        if len(self.views) != len(TAB_LABELS):
            raise ValueError(f"MainView needs {len(TAB_LABELS)} views, got {len(self.views)}")
        self.on_logout: Callable[[], None] = lambda: None
        self.header = HeaderBar(ctx, on_toggle_sidebar=self._toggle_sidebar, on_logout=lambda: self.on_logout())
        self.sidebar = Sidebar(ctx)
        self.toolbar = ActionToolbar(ctx, actions or ToolbarActions())
        self.footer = Footer(ctx)
        self.content_host = ft.Container(content=self.views[0].root, expand=True, bgcolor=ft.Colors.WHITE,
                                         padding=ft.Padding(12, 8, 12, 8))
        self.tabs = ft.Tabs(
            length=len(TAB_LABELS), selected_index=0, on_change=self._on_tab_change, height=40,
            content=ft.TabBar(tabs=[ft.Tab(label=t) for t in TAB_LABELS], indicator_color=ft.Colors.BLUE_700,
                              tab_alignment=ft.TabAlignment.START))
        ctx.events.subscribe(EV_NAVIGATE_FILES, lambda **kw: self.ctx.dispatcher.spawn(self.select_tab, 0))

    def build(self) -> ft.Control:
        main_stack = ft.Column([
            self.toolbar.build(),
            ft.Container(content=self.tabs, bgcolor=ft.Colors.WHITE,
                         padding=ft.Padding.symmetric(vertical=12, horizontal=0)),
            self.content_host,
            self.footer.build(),
        ], spacing=0, expand=True)
        workspace = ft.Row([self.sidebar.build(), ft.Container(content=main_stack, expand=True)],
                           expand=True, spacing=0)
        return ft.Column([self.header.build(), workspace], spacing=0, expand=True)

    def set_user(self, email: Optional[str]) -> None:
        self.header.set_user(email)

    def _toggle_sidebar(self) -> None:
        self.sidebar.toggle()
        self.header.set_sidebar_collapsed(self.sidebar.collapsed)

    # -------------------------------------------------------------- tabs
    async def _on_tab_change(self, e) -> None:
        try:
            index = int(e.data)
        except (TypeError, ValueError):
            index = self.tabs.selected_index
        if not self._valid(index):
            return
        if index == self.ctx.state.active_tab and self.content_host.content is self.views[index].root:
            return  # e.g. the client echoing a programmatic select_tab()
        self.tabs.selected_index = index
        await self._show(index)

    async def select_tab(self, index: int) -> None:
        if not self._valid(index):
            return
        self.tabs.selected_index = index
        self.ctx.safe_update(self.tabs)
        await self._show(index)

    def _valid(self, index: int) -> bool:
        if 0 <= index < len(self.views):
            return True
        logger.warning("Ignoring unknown tab index %r", index)
        return False

    async def _show(self, index: int) -> None:
        self.ctx.state.active_tab = index
        self.content_host.content = self.views[index].root
        self.ctx.safe_update(self.content_host)
        await self._activate_view(index)

    async def _activate_view(self, index: int) -> None:
        # A failing view must not escape into Flet's event dispatch (that reports a session crash).
        try:
            await self.views[index].activate()
        except Exception as exc:
            logger.exception("Activating the %s tab failed", TAB_LABELS[index])
            self.ctx.error(f"Could not load the {TAB_LABELS[index]} tab: {exc}")

    # ---------------------------------------------------------- lifecycle
    async def activate(self) -> None:
        """First paint after sign-in: queue badge, user filter options, current tab."""
        try:
            self.ctx.state.queue_ids = await asyncio.to_thread(self.ctx.repo.queue_ids)
        except Exception:
            logger.exception("Could not load the export queue")
        self.ctx.events.emit(EV_QUEUE_CHANGED)
        self.sidebar.populate_users()
        index = self.ctx.state.active_tab if self._valid(self.ctx.state.active_tab) else 0
        await self._activate_view(index)

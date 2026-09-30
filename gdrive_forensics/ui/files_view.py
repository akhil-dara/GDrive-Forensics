"""Files tab: breadcrumbs, advanced filters and the paged card listing with progressive thumbnails."""
from __future__ import annotations

import asyncio
import copy
import logging
import math
from dataclasses import dataclass
from typing import Callable, Optional

import flet as ft

from ..core.formatting import convert_timezone
from .advanced_filters import AdvancedFiltersPanel
from .context import (
    EV_DATA_CHANGED,
    EV_FILTERS_CHANGED,
    EV_LISTING,
    EV_QUEUE_CHANGED,
    EV_SELECTION_CHANGED,
    AppContext,
)
from .dialogs import context_menu, file_details, thumbnail_preview
from .file_card import CardActions, CardMeta, avatar_image, build_card, selection_checkbox, thumb_image
from .thumbnails import ImageJob

logger = logging.getLogger(__name__)

DEFAULT_MESSAGE = "Loading files…"
CRUMB_MAX = 30
TILE_COLUMNS = {"xs": 12, "sm": 6, "md": 3, "lg": 3}


@dataclass
class Listing:
    records: list
    total: int
    page: int
    pages: int
    duplicates: set
    revisions: dict


def query_listing(repo, filters, per_page: int, page: int) -> Listing:
    """Worker thread: one page of files plus the per-card facts (path conflicts, revision counts)."""
    total = repo.count_files(filters)
    pages = max(1, math.ceil(total / per_page)) if per_page > 0 else 1
    page = min(max(1, page), pages)
    records = repo.list_files(filters, per_page, (page - 1) * per_page)
    return Listing(records=records, total=total, page=page, pages=pages,
                   duplicates=repo.duplicate_keys([r["name"] for r in records]),
                   revisions=repo.revision_counts([r["id"] for r in records]))


class FilesView:
    """Plain object (Flet 1.0 controls have their own build()); MainView mounts `root`."""

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        # Identity marker only (never read through): async work that finishes after a logout must
        # not write into the next session's state or bus. ctx.state/ctx.events are always used via ctx.
        self._session = ctx.state
        self._generation = 0                 # bumped whenever a reload is requested
        self._inflight: Optional[int] = None  # generation of the reload queued/running, if any
        self._pending: Optional[str] = None  # reload message deferred while another tab is shown
        self._listing: Optional[Listing] = None
        self.last_listing: list[dict] = []
        self._cards: dict[str, ft.Control] = {}
        self._slots: dict[tuple[str, str], list[ft.Container]] = {}
        self._card_actions = CardActions(info=self.show_info, download=self.download, queue=self.add_to_queue,
                                         open_folder=self.enter_folder, context=self.show_context_menu,
                                         toggle_select=self._toggle_selected)
        self.breadcrumbs = ft.Row(spacing=0, wrap=True, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        self.advanced_filters = AdvancedFiltersPanel(ctx)
        self.advanced_panel = self.advanced_filters.root
        self.results = ft.Column([], spacing=12, expand=True, scroll=ft.ScrollMode.AUTO)
        self.root = ft.Column([self.breadcrumbs, self.advanced_panel, self.results], spacing=8, expand=True)
        self._render_breadcrumbs()
        # EV_TIMEZONE_CHANGED is deliberately not handled: the header emits EV_FILTERS_CHANGED too.
        ctx.events.subscribe(EV_FILTERS_CHANGED, self._on_filters_changed)
        ctx.events.subscribe(EV_DATA_CHANGED, self._on_data_changed)

    # ----------------------------------------------------------- reloads
    def _owns_session(self) -> bool:
        return self.ctx.state is self._session

    def _visible(self) -> bool:
        return self.ctx.state.active_tab == 0

    def _on_filters_changed(self, message: Optional[str] = None, navigate: bool = False, **_) -> None:
        message = message or DEFAULT_MESSAGE
        if self._visible():
            self._request_reload(message)
        else:
            self._pending = message
            if not navigate:   # a drill-down switches to this tab right away (EV_NAVIGATE_FILES)
                self.ctx.toast(f"{message} (will apply on Files tab)")

    def _on_data_changed(self, **_) -> None:
        state = self.ctx.state
        state.folder_stack = []
        state.filters.folder_id = None
        self._render_breadcrumbs()
        self._reload_or_defer("Refreshing files…")

    def _reload_or_defer(self, message: str) -> None:
        if self._visible():
            self._request_reload(message)
        else:
            self._pending = self._pending or message

    def _claim(self) -> int:
        self._generation += 1
        self._inflight = self._generation
        return self._generation

    def _request_reload(self, message: str) -> None:
        self._pending = None
        self.ctx.dispatcher.spawn(self._run_reload, self._claim(), message)

    async def activate(self) -> None:
        """Reload on every visit (data may have changed meanwhile), using any deferred filter message.

        Coalesced: a drill-down emits EV_FILTERS_CHANGED (reload requested) and then
        EV_NAVIGATE_FILES, whose select_tab(0) activates this view again - that must not query twice.
        """
        message, self._pending = self._pending, None
        if message is None and self._inflight is not None and self._inflight == self._generation:
            return
        await self.reload(message or DEFAULT_MESSAGE)

    async def reload(self, message: str = DEFAULT_MESSAGE) -> None:
        await self._run_reload(self._claim(), message)

    async def _run_reload(self, generation: int, message: str) -> None:
        try:
            if generation != self._generation:
                return   # superseded before it started
            self._show_transition(message)
            state = self.ctx.state
            filters = copy.deepcopy(state.filters)   # the loop may mutate filters while we query
            try:
                listing = await asyncio.to_thread(query_listing, self.ctx.repo, filters, state.per_page, state.page)
            except Exception as exc:
                if generation == self._generation and self._owns_session():
                    logger.exception("Loading files failed")
                    self._show_failure(exc)
                return
            if generation == self._generation and self._owns_session():
                self._apply(listing)
        finally:
            if self._inflight == generation:
                self._inflight = None

    def _apply(self, listing: Listing) -> None:
        state = self.ctx.state
        self._listing = listing
        self.last_listing = listing.records
        state.page = listing.page
        state.total_items = listing.total
        state.total_pages = listing.pages
        state.current_file_ids = [r["id"] for r in listing.records]
        self._render()
        self._render_breadcrumbs()
        self.ctx.events.emit(EV_LISTING, shown=len(listing.records), total=listing.total, page=listing.page,
                             pages=listing.pages, folder_path=" / ".join(name for _, name in state.folder_stack))
        self.ctx.events.emit(EV_SELECTION_CHANGED)

    def _show_failure(self, exc: Exception) -> None:
        self.ctx.state.current_file_ids = []
        self._listing = None          # nothing to re-render until a reload succeeds
        self.last_listing = []
        self.results.controls = [ft.Text("Could not load files.", color=ft.Colors.RED_700)]
        self.ctx.safe_update(self.results)
        self.ctx.events.emit(EV_SELECTION_CHANGED)
        self.ctx.error(f"Failed to load files: {exc}")

    # ---------------------------------------------------------- rendering
    def _show_transition(self, message: str) -> None:
        self.results.controls = [ft.Container(
            content=ft.Column([
                ft.ProgressRing(width=54, height=54, stroke_width=4, color=ft.Colors.BLUE_500),
                ft.Text(message, size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_GREY_800),
                ft.Text("Please wait while we refresh the view", size=11, color=ft.Colors.BLUE_GREY_500),
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
            alignment=ft.Alignment.CENTER, padding=ft.Padding.symmetric(vertical=30, horizontal=60),
            bgcolor=ft.Colors.WHITE, border=ft.Border.all(1, ft.Colors.BLUE_100), border_radius=18)]
        self.ctx.safe_update(self.results)

    @staticmethod
    def _empty_state() -> ft.Control:
        return ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.FOLDER_OFF, size=80, color=ft.Colors.GREY_400),
                ft.Text("No files found", size=20, color=ft.Colors.GREY_600, weight=ft.FontWeight.BOLD),
                ft.Text("Try adjusting your filters or running a scan", size=14, color=ft.Colors.GREY_500),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
            padding=80, alignment=ft.Alignment.CENTER)

    def _render(self) -> None:
        """(Re)build the cards of the current listing on the loop; images come later, per batch."""
        listing = self._listing
        if listing is None:
            return
        state = self.ctx.state
        thumbs = self.ctx.thumbnails
        self._cards, self._slots = {}, {}
        jobs: dict[tuple[str, str], ImageJob] = {}
        cards = [self._build_card(record, listing, thumbs, jobs) for record in listing.records]
        if not cards:
            layout = self._empty_state()
        elif state.view_mode == "list":
            layout = ft.Column(cards, spacing=0)
        else:
            layout = ft.ResponsiveRow([ft.Container(content=card, col=TILE_COLUMNS, padding=6) for card in cards],
                                      alignment=ft.MainAxisAlignment.START, spacing=12, run_spacing=12)
        self.results.controls = [layout]
        self.ctx.safe_update(self.results)
        if thumbs is not None:
            generation = thumbs.new_generation()   # stop fetching for cards that no longer exist
            thumbs.request(list(jobs.values()), self._apply_images, generation)

    def _rerender(self) -> None:
        """Selection/view-mode change: rebuild from the cached listing (no query). While a reload is
        running its transition card stays up; the reload renders with the new state anyway."""
        if self._inflight is None:
            self._render()

    def _build_card(self, record: dict, listing: Listing, thumbs, jobs: dict) -> ft.Control:
        state = self.ctx.state
        fid = record["id"]
        email = record.get("owner_email")
        want_thumb = bool(thumbs is not None and record.get("thumbnail_link"))
        want_avatar = bool(thumbs is not None and record.get("owner_photo") and email)
        meta = CardMeta(
            is_duplicate=(record.get("full_path"), record.get("name")) in listing.duplicates,
            revision_count=listing.revisions.get(fid, 0),
            modified_str=convert_timezone(record.get("modified_time"), state.timezone),
            thumb=thumbs.cached("thumb", fid) if want_thumb else None,
            avatar=thumbs.cached("avatar", email) if want_avatar else None)
        card, thumb_slot, avatar_slot = build_card(
            record, view_mode=state.view_mode, meta=meta, actions=self._card_actions,
            selection_mode=state.selection_mode, selected=fid in state.selected_ids)
        self._cards[fid] = card
        if want_thumb and meta.thumb is None:
            self._want(jobs, ImageJob("thumb", fid, record["thumbnail_link"], thumb_slot))
        if want_avatar and meta.avatar is None:
            self._want(jobs, ImageJob("avatar", email, record["owner_photo"], avatar_slot))
        return card

    def _want(self, jobs: dict, job: ImageJob) -> None:
        """One fetch per image; every slot showing it (e.g. an owner's avatar) is filled on arrival."""
        self._slots.setdefault((job.kind, job.key), []).append(job.slot)
        jobs.setdefault((job.kind, job.key), job)

    def _apply_images(self, ready: list) -> None:
        if not self._owns_session():
            return
        updated = []
        for job, data in ready:
            for slot in self._slots.get((job.kind, job.key), []):
                slot.content = thumb_image(data) if job.kind == "thumb" else avatar_image(data)
                updated.append(slot)
        self.ctx.safe_update(*updated)

    def _render_breadcrumbs(self) -> None:
        crumbs: list[ft.Control] = [ft.TextButton("📁 Drive Home", on_click=lambda e: self.navigate_to(None),
                                                  style=ft.ButtonStyle(padding=4))]
        for folder_id, name in self.ctx.state.folder_stack:
            crumbs.append(ft.Text(" / ", size=12, color=ft.Colors.GREY_600))
            crumbs.append(ft.TextButton(name[:CRUMB_MAX], tooltip=name if len(name) > CRUMB_MAX else None,
                                        on_click=lambda e, fid=folder_id: self.navigate_to(fid),
                                        style=ft.ButtonStyle(padding=4)))
        self.breadcrumbs.controls = crumbs
        self.ctx.safe_update(self.breadcrumbs)

    # --------------------------------------------------------- navigation
    def enter_folder(self, folder_id: str, name: str) -> None:
        state = self.ctx.state
        state.folder_stack = [*state.folder_stack, (folder_id, name)]
        self._open(folder_id, f"Opening {name}…")

    def navigate_to(self, folder_id: Optional[str]) -> None:
        state = self.ctx.state
        if folder_id is None:
            state.folder_stack = []
        else:
            ids = [fid for fid, _ in state.folder_stack]
            if folder_id in ids:
                state.folder_stack = state.folder_stack[:ids.index(folder_id) + 1]
        self._open(folder_id, DEFAULT_MESSAGE if folder_id is None else "Loading folder…")

    def _open(self, folder_id: Optional[str], message: str) -> None:
        state = self.ctx.state
        state.filters.folder_id = folder_id
        state.page = 1
        self._render_breadcrumbs()
        self._reload_or_defer(message)

    # ---------------------------------------------------------- selection
    def toggle_selection_mode(self) -> None:
        state = self.ctx.state
        state.selection_mode = not state.selection_mode
        if not state.selection_mode:
            state.selected_ids = set()
        self._rerender()
        self.ctx.events.emit(EV_SELECTION_CHANGED)
        self.ctx.toast("Multi-select on" if state.selection_mode else "Multi-select off")

    def set_selected(self, file_id: str, selected: bool) -> None:
        state = self.ctx.state
        if selected:
            state.selected_ids.add(file_id)
        else:
            state.selected_ids.discard(file_id)
        card = self._cards.get(file_id)
        checkbox = selection_checkbox(card) if card is not None else None
        if checkbox is not None and checkbox.value != selected:
            checkbox.value = selected
            self.ctx.safe_update(checkbox)
        self.ctx.events.emit(EV_SELECTION_CHANGED)

    def _toggle_selected(self, file_id: str) -> None:
        if self.ctx.state.selection_mode:
            self.set_selected(file_id, file_id not in self.ctx.state.selected_ids)

    def set_view_mode(self, mode: str) -> None:
        if mode not in ("tiles", "list"):
            logger.warning("Ignoring unknown view mode %r", mode)
            return
        self.ctx.state.view_mode = mode
        self._rerender()
        self.ctx.events.emit(EV_SELECTION_CHANGED)   # the toolbar re-syncs its Tiles/List highlight

    # -------------------------------------------------------------- queue
    def add_to_queue(self, file_id: str) -> None:
        if file_id in self.ctx.state.queue_ids:
            self.ctx.toast("⚠️ File already in queue")
            return
        self.ctx.dispatcher.spawn(self._enqueue, [file_id], lambda added, size: (
            f"✅ Added to export queue ({size} items)" if added else "⚠️ File already in queue"))

    def add_selected_to_queue(self) -> None:
        state = self.ctx.state
        selected = set(state.selected_ids)
        if not selected:
            self.ctx.toast("Select files first")
            return
        ordered = [fid for fid in state.current_file_ids if fid in selected]
        ordered += sorted(selected.difference(ordered))
        state.selected_ids = set()
        state.selection_mode = False
        self._rerender()
        self.ctx.events.emit(EV_SELECTION_CHANGED)
        self.ctx.dispatcher.spawn(self._enqueue, ordered, lambda added, size: (
            f"✅ Added {added} files to queue" if added else "No new files added"))

    def add_current_page_to_queue(self) -> None:
        ids = list(self.ctx.state.current_file_ids)
        if not ids:
            self.ctx.toast("No files on this page")
            return
        self.ctx.dispatcher.spawn(self._enqueue, ids, lambda added, size: (
            f"✅ Added {added} files from this page to queue" if added
            else "All files on this page are already in queue"))

    async def _enqueue(self, ids: list, describe: Callable[[int, int], str]) -> None:
        repo = self.ctx.repo
        try:
            added = await asyncio.to_thread(repo.add_to_queue, ids)
            queue_ids = await asyncio.to_thread(repo.queue_ids)
        except Exception as exc:
            logger.exception("Adding %d file(s) to the export queue failed", len(ids))
            self.ctx.error(f"Failed to add to queue: {exc}")
            return
        if not self._owns_session():
            return   # logged out meanwhile: the next session reloads the queue itself
        self.ctx.state.queue_ids = queue_ids
        self.ctx.events.emit(EV_QUEUE_CHANGED)
        self.ctx.activity(f"Queue size: {len(queue_ids)} items", ft.Colors.ORANGE_700)
        self.ctx.toast(describe(added, len(queue_ids)))

    # ------------------------------------------------------- file actions
    def download(self, file_id: str) -> None:
        jobs = self.ctx.jobs
        if jobs is None:
            self.ctx.toast("Downloads not available yet")
            return
        self.ctx.dispatcher.spawn(jobs.download_file, file_id)

    def show_info(self, file_id: str) -> None:
        file_details.show(self.ctx, file_id, on_download=self.download,
                          on_preview=lambda fid: thumbnail_preview.show(self.ctx, fid), on_queue=self.add_to_queue)

    def show_context_menu(self, file_id: str) -> None:
        context_menu.show(self.ctx, file_id, on_info=self.show_info, on_download=self.download,
                          on_queue=self.add_to_queue)

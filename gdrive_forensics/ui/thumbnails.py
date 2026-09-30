"""Progressive thumbnail/avatar loading: worker-pool fetches, one batched UI update per batch."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class ImageJob:
    kind: str      # "thumb" | "avatar"
    key: str       # file id / owner email
    url: str
    slot: Any      # ft.Container whose content is replaced


class ThumbnailService:
    """Fetches images off the loop (memory -> disk cache -> Drive) and hands them back via the dispatcher.

    Every listing calls `new_generation()`; batches of an older generation are dropped, so a fast
    page flip never paints stale images. The OAuth token never travels in a URL: `fetch_image`
    sends it in a header, and only to Google hosts.
    """

    def __init__(self, client_getter: Callable[[], Any], cache, dispatcher, max_workers: int = 8) -> None:
        self._client_getter = client_getter
        self.cache = cache
        self.dispatcher = dispatcher
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="thumb")
        self._generation = 0
        self._lock = threading.Lock()
        self._memory: dict[tuple[str, str], bytes] = {}

    def new_generation(self) -> int:
        with self._lock:
            self._generation += 1
            return self._generation

    def cached(self, kind: str, key: Optional[str]) -> Optional[bytes]:
        """Memory-only lookup: safe to call on the loop thread."""
        return self._memory.get((kind, key)) if key else None

    def request(self, jobs: list, on_ready: Callable[[list], None], generation: int) -> None:
        """Fetch in up to 8 parallel batches; each batch delivers one UI update via the dispatcher."""
        if not jobs:
            return
        chunk = max(1, -(-len(jobs) // 8))
        for start in range(0, len(jobs), chunk):
            try:
                self._pool.submit(self._run, jobs[start:start + chunk], on_ready, generation)
            except RuntimeError:   # shut down (logout) while a listing was still rendering
                return

    def _run(self, jobs: list, on_ready, generation: int) -> None:
        ready: list = []
        for job in jobs:
            if generation != self._generation:
                return
            try:
                data = self._memory.get((job.kind, job.key)) or self.cache.get(job.kind, job.key)
                if data is None:
                    client = self._client_getter()
                    data = client.fetch_image(job.url) if client else None
                    if data:
                        self.cache.put(job.kind, job.key, data)
            except Exception:
                logger.exception("Thumbnail fetch failed for %s", job.key)
                data = None
            if data:
                self._memory[(job.kind, job.key)] = data
                ready.append((job, data))
        self._deliver(on_ready, ready, generation)

    def _deliver(self, on_ready, ready: list, generation: int) -> None:
        if ready and generation == self._generation:
            self.dispatcher.ui(on_ready, list(ready))

    def invalidate(self, kind: str, keys) -> None:
        """Forget cached images (memory and disk). Touches SQLite: call from a worker thread."""
        keys = list(keys)
        for key in keys:
            self._memory.pop((kind, key), None)
        self.cache.delete(kind, keys)

    def clear(self, kind: Optional[str] = None) -> None:
        """Drop every cached image (of `kind`). Touches SQLite: call from a worker thread."""
        if kind is None:
            self._memory.clear()
        else:
            # list() snapshots the keys: pool threads may be adding images meanwhile.
            for mk in [mk for mk in list(self._memory) if mk[0] == kind]:
                self._memory.pop(mk, None)
        self.cache.clear(kind)

    def shutdown(self) -> None:
        """Non-blocking (called on the loop during logout): stale batches stop at their next job."""
        self.new_generation()
        self._pool.shutdown(wait=False, cancel_futures=True)

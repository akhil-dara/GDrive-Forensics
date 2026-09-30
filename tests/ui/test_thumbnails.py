import threading
import time

from gdrive_forensics.ui.thumbnails import ImageJob, ThumbnailService
from tests.fakes import PNG_1PX, FakeDriveClient


class FakeCache:
    def __init__(self):
        self.data, self.deleted, self.cleared = {}, [], []

    def get(self, kind, key):
        return self.data.get((kind, key))

    def put(self, kind, key, data):
        self.data[(kind, key)] = data

    def delete(self, kind, keys):
        self.deleted.append((kind, list(keys)))
        for key in keys:
            self.data.pop((kind, key), None)

    def clear(self, kind=None):
        self.cleared.append(kind)
        self.data = {k: v for k, v in self.data.items() if kind is not None and k[0] != kind}


class InlineDispatcher:
    """Runs UI callbacks right away on the worker (the real one marshals them onto the loop)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.batches = []

    def ui(self, fn, *args):
        with self.lock:
            self.batches.append(args[0])
            fn(*args)


def jobs(n, kind="thumb"):
    return [ImageJob(kind, f"f{i}", f"https://lh3.googleusercontent.com/f{i}=s220", slot=None) for i in range(n)]


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.01)


def test_batches_cache_and_memory():
    client, cache, dispatcher = FakeDriveClient(), FakeCache(), InlineDispatcher()
    service = ThumbnailService(lambda: client, cache, dispatcher)
    got = []
    service.request(jobs(20), got.extend, service.new_generation())
    wait_for(lambda: len(got) == 20)
    assert 1 <= len(dispatcher.batches) <= 8                 # one UI update per batch, not per image
    assert all(data == PNG_1PX for _, data in got) and len(client.images) == 20
    assert cache.get("thumb", "f3") == PNG_1PX and service.cached("thumb", "f3") == PNG_1PX
    assert service.cached("thumb", None) is None

    again = []
    service.request(jobs(20), again.extend, service.new_generation())
    wait_for(lambda: len(again) == 20)
    assert len(client.images) == 20                           # served from memory, no refetch

    service.invalidate("thumb", ["f1", "f2"])
    assert service.cached("thumb", "f1") is None and cache.deleted == [("thumb", ["f1", "f2"])]
    service.clear("thumb")
    assert service.cached("thumb", "f5") is None and cache.cleared == ["thumb"]
    service.shutdown()


def test_stale_generation_is_dropped_and_shutdown_does_not_block():
    gate = threading.Event()

    class SlowClient(FakeDriveClient):
        def fetch_image(self, url, timeout=10):
            gate.wait(5)
            return super().fetch_image(url, timeout)

    dispatcher = InlineDispatcher()
    service = ThumbnailService(lambda: SlowClient(), FakeCache(), dispatcher, max_workers=2)
    got = []
    service.request(jobs(4), got.extend, service.new_generation())
    service.new_generation()                                   # a newer listing replaced those cards
    gate.set()
    time.sleep(0.3)
    assert got == [] and dispatcher.batches == []
    service.shutdown()

    # A fresh service: phase 1 left f0/f1 in the old service's memory cache, and a memory hit never
    # waits on the gate - it could be delivered before shutdown() and make this phase timing-dependent.
    gate.clear()
    service = ThumbnailService(lambda: SlowClient(), FakeCache(), dispatcher, max_workers=2)
    service.request(jobs(4), got.extend, service.new_generation())
    started = time.monotonic()
    service.shutdown()                                         # called on the loop at logout
    assert time.monotonic() - started < 1
    gate.set()
    service.request(jobs(2), got.extend, 99)                   # after shutdown: ignored, no exception
    time.sleep(0.3)
    assert got == [] and dispatcher.batches == []


def test_no_client_means_no_fetch():
    dispatcher = InlineDispatcher()
    service = ThumbnailService(lambda: None, FakeCache(), dispatcher)
    service.request(jobs(3), lambda ready: None, service.new_generation())
    time.sleep(0.2)
    assert dispatcher.batches == []
    service.shutdown()

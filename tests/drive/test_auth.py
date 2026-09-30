import json
import socket
import threading
import urllib.request
from types import SimpleNamespace

import pytest
from google.auth.exceptions import RefreshError, TransportError

from gdrive_forensics.config import ACTIVITY_SCOPE, DRIVE_SCOPE, AppPaths
from gdrive_forensics.drive import auth as auth_mod
from gdrive_forensics.drive.auth import CredentialManager, OAuthCancelled


class FakeCreds:
    def __init__(self, valid=False, expired=True, refresh_token="r", refresh_exc=None, scopes=None):
        self.valid, self.expired, self.refresh_token = valid, expired, refresh_token
        self._exc, self.scopes, self.granted_scopes = refresh_exc, scopes or [], None

    def refresh(self, request):
        if self._exc:
            raise self._exc
        self.valid = True

    def to_json(self):
        return json.dumps({"token": "t", "scopes": self.scopes})


def paths(tmp_path, token=True):
    p = AppPaths(tmp_path)
    if token:
        p.token_file.write_text("{}")
    return p


def patch_load(monkeypatch, creds):
    monkeypatch.setattr(auth_mod.Credentials, "from_authorized_user_file", staticmethod(lambda f: creds))


def test_no_token(tmp_path):
    assert CredentialManager(paths(tmp_path, token=False)).load_saved() == (None, None)


def test_valid_token(tmp_path, monkeypatch):
    creds = FakeCreds(valid=True, expired=False, scopes=["https://www.googleapis.com/auth/drive.readonly"])
    patch_load(monkeypatch, creds)
    mgr = CredentialManager(paths(tmp_path))
    assert mgr.load_saved() == (creds, None)
    assert mgr.has_scope("https://www.googleapis.com/auth/drive.readonly")
    assert not mgr.has_scope("https://www.googleapis.com/auth/drive.activity.readonly")


def test_corrupt_token(tmp_path, monkeypatch):
    def boom(f):
        raise ValueError("bad json")
    monkeypatch.setattr(auth_mod.Credentials, "from_authorized_user_file", staticmethod(boom))
    assert CredentialManager(paths(tmp_path)).load_saved() == (None, "token_invalid")


def test_revoked_refresh_deletes_token(tmp_path, monkeypatch):
    patch_load(monkeypatch, FakeCreds(refresh_exc=RefreshError(
        "invalid_grant: Token has been expired or revoked.", {"error": "invalid_grant"})))
    p = paths(tmp_path)
    assert CredentialManager(p).load_saved() == (None, "token_refresh_failed")
    assert not p.token_file.exists()


def test_network_errors_keep_token(tmp_path, monkeypatch):
    for exc in (
        TransportError("offline"),
        RefreshError("temporary", retryable=True),
        RefreshError("<html>Service Unavailable</html>", "<html>Service Unavailable</html>"),
    ):
        patch_load(monkeypatch, FakeCreds(refresh_exc=exc))
        p = paths(tmp_path)
        assert CredentialManager(p).load_saved() == (None, "network_error")
        assert p.token_file.exists()


def test_successful_refresh_saves(tmp_path, monkeypatch):
    creds = FakeCreds()
    patch_load(monkeypatch, creds)
    p = paths(tmp_path)
    mgr = CredentialManager(p)
    assert mgr.load_saved() == (creds, None)
    assert json.loads(p.token_file.read_text())["token"] == "t"


def test_save_persists_granted_scopes_not_requested(tmp_path):
    p = paths(tmp_path, token=False)
    mgr = CredentialManager(p)
    creds = FakeCreds(scopes=[DRIVE_SCOPE, ACTIVITY_SCOPE])
    creds.granted_scopes = [DRIVE_SCOPE]
    mgr.save(creds)
    assert json.loads(p.token_file.read_text())["scopes"] == [DRIVE_SCOPE]


class FakeFlow:
    instances = []

    def __init__(self):
        self.redirect_uri = None
        self.fetched = None
        self.credentials = FakeCreds(valid=True, expired=False)
        FakeFlow.instances.append(self)

    def authorization_url(self, **kwargs):
        return f"https://accounts.example/auth?redirect={self.redirect_uri}", "STATE"

    def fetch_token(self, authorization_response):
        self.fetched = authorization_response


def test_oauth_flow_loopback(tmp_path, monkeypatch):
    p = paths(tmp_path, token=False)
    p.credentials_file.write_text("{}")
    monkeypatch.setattr(auth_mod.InstalledAppFlow, "from_client_secrets_file",
                        staticmethod(lambda *a, **k: FakeFlow()))
    urls = []
    mgr = CredentialManager(p)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault(
        "creds", mgr.run_oauth_flow(urls.append, open_browser=False, timeout_seconds=10)))
    t.start()
    for _ in range(100):
        if urls:
            break
        threading.Event().wait(0.05)
    flow = FakeFlow.instances[-1]
    assert flow.redirect_uri.startswith("http://127.0.0.1:")
    body = urllib.request.urlopen(flow.redirect_uri + "?state=STATE&code=abc", timeout=5).read()
    t.join(5)
    assert b"Authentication Successful" in body
    assert flow.fetched.startswith("https://127.0.0.1:") and "code=abc" in flow.fetched
    assert result["creds"] is flow.credentials and p.token_file.exists()


def test_oauth_flow_denied_serves_a_failure_page(tmp_path, monkeypatch):
    p = paths(tmp_path, token=False)
    p.credentials_file.write_text("{}")
    monkeypatch.setattr(auth_mod.InstalledAppFlow, "from_client_secrets_file",
                        staticmethod(lambda *a, **k: FakeFlow()))
    urls = []
    mgr = CredentialManager(p)
    result = {}

    def run():
        try:
            mgr.run_oauth_flow(urls.append, open_browser=False, timeout_seconds=10)
        except Exception as exc:  # noqa: BLE001 - capture for assertion in the main thread
            result["exc"] = exc

    t = threading.Thread(target=run)
    t.start()
    for _ in range(100):
        if urls:
            break
        threading.Event().wait(0.05)
    flow = FakeFlow.instances[-1]
    body = urllib.request.urlopen(flow.redirect_uri + "?error=access_denied&state=STATE", timeout=5).read()
    t.join(5)
    assert b"Sign-in was cancelled or failed" in body and b"return to the app" in body
    assert b"Authentication Successful" not in body
    assert isinstance(result.get("exc"), PermissionError) and "access_denied" in str(result["exc"])
    assert flow.fetched is None and not p.token_file.exists()


def test_oauth_flow_cancel_with_stalled_connection(tmp_path, monkeypatch):
    p = paths(tmp_path, token=False)
    p.credentials_file.write_text("{}")
    monkeypatch.setattr(auth_mod.InstalledAppFlow, "from_client_secrets_file",
                        staticmethod(lambda *a, **k: FakeFlow()))
    urls = []
    mgr = CredentialManager(p)
    result = {}

    def run():
        try:
            mgr.run_oauth_flow(urls.append, cancel=cancel, open_browser=False, timeout_seconds=30)
        except Exception as exc:  # noqa: BLE001 - capture for assertion in the main thread
            result["exc"] = exc

    cancel = threading.Event()
    t = threading.Thread(target=run)
    t.start()
    for _ in range(100):
        if urls:
            break
        threading.Event().wait(0.05)
    flow = FakeFlow.instances[-1]
    port = int(flow.redirect_uri.rstrip("/").rsplit(":", 1)[1])
    # Open a raw TCP connection and never send a request, simulating a stray/probing
    # connect that would otherwise block the WSGI handler's blocking read forever.
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        cancel.set()
        t.join(8)
        assert not t.is_alive()
        assert isinstance(result.get("exc"), OAuthCancelled)
    finally:
        sock.close()


def test_oauth_flow_cancel_and_missing_secrets(tmp_path, monkeypatch):
    p = paths(tmp_path, token=False)
    with pytest.raises(FileNotFoundError):
        CredentialManager(p).run_oauth_flow(lambda u: None, open_browser=False)
    p.credentials_file.write_text("{}")
    monkeypatch.setattr(auth_mod.InstalledAppFlow, "from_client_secrets_file",
                        staticmethod(lambda *a, **k: FakeFlow()))
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(OAuthCancelled):
        CredentialManager(p).run_oauth_flow(lambda u: None, cancel=cancel, open_browser=False)


def test_logout(tmp_path):
    p = paths(tmp_path)
    mgr = CredentialManager(p)
    mgr.credentials, mgr.user_email = object(), "a@x.com"
    mgr.logout()
    assert not p.token_file.exists() and mgr.credentials is None and mgr.user_email is None

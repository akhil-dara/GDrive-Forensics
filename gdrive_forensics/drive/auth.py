"""Token persistence and a localhost-only, cancellable OAuth loopback flow."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import webbrowser
import wsgiref.simple_server
import wsgiref.util
from typing import Callable, Optional, Sequence
from urllib.parse import parse_qs, urlparse

from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from ..config import SCOPES, AppPaths
from ..logging_setup import AUTH_LOGGER

logger = logging.getLogger(AUTH_LOGGER)

AUTH_REASON_MESSAGES = {
    "token_refresh_failed": "Your saved Google session expired or was revoked. Please sign in again.",
    "token_invalid": "The saved token.json could not be read. Please sign in again.",
    "network_error": "Could not reach Google to refresh your saved session. Check the connection, "
                     "or sign in again.",
    "missing_client_secrets": "credentials.json was not found in the app folder. See README → "
                              "'Getting credentials.json'.",
}

_SUCCESS_HTML = (b"<html><head><title>Authentication Successful</title></head>"
                 b"<body style='font-family: Arial; text-align: center; padding: 50px;'>"
                 b"<h1 style='color: #4CAF50;'>Authentication Successful!</h1>"
                 b"<p style='font-size: 18px;'>You can close this window and return to the app.</p>"
                 b"</body></html>")
_FAILURE_HTML = ("<html><head><title>Sign-in not completed</title></head>"
                 "<body style='font-family: Arial; text-align: center; padding: 50px;'>"
                 "<h1 style='color: #C62828;'>Sign-in was cancelled or failed — return to the app</h1>"
                 "<p style='font-size: 18px;'>No access was granted. You can close this window and try "
                 "again from the app.</p></body></html>").encode("utf-8")


class OAuthCancelled(Exception):
    """The user cancelled the sign-in."""


class _CallbackApp:
    """WSGI app that captures the first redirect carrying ?code= or ?error=."""

    def __init__(self) -> None:
        self.last_request_uri: Optional[str] = None

    def __call__(self, environ, start_response):
        query = parse_qs(environ.get("QUERY_STRING", ""))
        if "code" in query or "error" in query:
            self.last_request_uri = wsgiref.util.request_uri(environ)
            start_response("200 OK", [("Content-type", "text/html; charset=utf-8")])
            # Google redirects with ?error=access_denied when consent is refused.
            return [_FAILURE_HTML if "error" in query else _SUCCESS_HTML]
        start_response("404 Not Found", [("Content-type", "text/plain")])
        return [b"Not found"]


class _QuietHandler(wsgiref.simple_server.WSGIRequestHandler):
    # StreamRequestHandler.setup() applies this as the accepted socket's timeout, so a
    # connection that never sends a request (e.g. a stray/probing TCP connect) can't
    # block handle_request() forever and starve the cancel/timeout checks below.
    timeout = 5

    def log_message(self, format, *args):  # noqa: A002 - signature defined by base class
        logger.debug("OAuth callback: " + format, *args)


class CredentialManager:
    def __init__(self, paths: AppPaths, scopes: Sequence[str] = SCOPES) -> None:
        self.paths = paths
        self.scopes = list(scopes)
        self.credentials: Optional[Credentials] = None
        self.user_email: Optional[str] = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- tokens
    def load_saved(self) -> tuple[Optional[Credentials], Optional[str]]:
        token = self.paths.token_file
        if not token.exists():
            return None, None
        try:
            creds = Credentials.from_authorized_user_file(str(token))
        except (ValueError, OSError) as exc:
            logger.error("Could not read %s: %s", token, exc)
            return None, "token_invalid"
        if creds.valid:
            self.credentials = creds
            return creds, None
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError as exc:
                # google-auth raises RefreshError(error_details, response_data, retryable=...).
                # Only delete token.json when Google's response explicitly names the token as
                # rejected (invalid_grant); any other RefreshError (5xx, HTML error page, etc.)
                # is treated as transient so the saved token survives for a later retry.
                details = exc.args[1] if len(exc.args) > 1 else None
                if isinstance(details, dict) and details.get("error") == "invalid_grant":
                    logger.error("Saved token rejected by Google (%s); removing token.json", exc)
                    self._remove_token()
                    return None, "token_refresh_failed"
                logger.warning("Transient token refresh failure: %s", exc)
                return None, "network_error"
            except TransportError as exc:
                logger.warning("Network error refreshing token: %s", exc)
                return None, "network_error"
            self.save(creds)
            self.credentials = creds
            return creds, None
        return None, "token_invalid"

    def has_scope(self, scope: str) -> bool:
        creds = self.credentials
        if not creds:
            return False
        granted = getattr(creds, "granted_scopes", None) or getattr(creds, "scopes", None) or []
        return scope in granted

    def save(self, creds: Credentials) -> None:
        # Credentials.to_json() persists the REQUESTED scopes (creds.scopes), not what
        # Google actually granted under granular consent. Overwrite "scopes" with
        # granted_scopes when available so a reload's has_scope() reflects reality.
        data = json.loads(creds.to_json())
        granted = getattr(creds, "granted_scopes", None)
        if granted:
            data["scopes"] = list(granted)
        self.paths.token_file.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(self.paths.token_file, 0o600)
        except OSError:
            pass
        logger.info("Credentials saved to %s", self.paths.token_file)

    def _remove_token(self) -> None:
        try:
            self.paths.token_file.unlink()
        except FileNotFoundError:
            pass

    def logout(self) -> None:
        self._remove_token()
        self.credentials = None
        self.user_email = None
        logger.info("Logged out; token.json removed")

    # ----------------------------------------------------------------- OAuth
    def run_oauth_flow(self, on_auth_url: Callable[[str], None], cancel: Optional[threading.Event] = None,
                       timeout_seconds: int = 300, open_browser: bool = True) -> Credentials:
        """Blocking loopback flow bound to 127.0.0.1 on a random port. Call from a worker thread."""
        if not self.paths.credentials_file.exists():
            raise FileNotFoundError(str(self.paths.credentials_file))
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("A sign-in is already in progress")
        try:
            # Google may grant a subset (granular consent); has_scope() checks what we got.
            os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")
            flow = InstalledAppFlow.from_client_secrets_file(
                str(self.paths.credentials_file), scopes=self.scopes, autogenerate_code_verifier=True)
            app = _CallbackApp()
            server = wsgiref.simple_server.make_server("127.0.0.1", 0, app, handler_class=_QuietHandler)
            try:
                flow.redirect_uri = f"http://127.0.0.1:{server.server_port}/"
                auth_url, _state = flow.authorization_url(
                    access_type="offline", prompt="consent", include_granted_scopes="true")
                logger.info("OAuth loopback listening on %s", flow.redirect_uri)
                on_auth_url(auth_url)
                if open_browser:
                    webbrowser.open(auth_url, new=1)
                server.timeout = 0.5
                deadline = time.monotonic() + timeout_seconds
                while app.last_request_uri is None:
                    if cancel is not None and cancel.is_set():
                        raise OAuthCancelled()
                    if time.monotonic() > deadline:
                        raise TimeoutError("Timed out waiting for Google sign-in")
                    server.handle_request()
            finally:
                server.server_close()
            query = parse_qs(urlparse(app.last_request_uri).query)
            if "error" in query:
                raise PermissionError(f"Google sign-in was denied: {query['error'][0]}")
            # oauthlib requires https; the loopback redirect is plain http by design (same as google's own helper).
            flow.fetch_token(authorization_response=app.last_request_uri.replace("http://", "https://", 1))
            creds = flow.credentials
            self.save(creds)
            self.credentials = creds
            return creds
        finally:
            self._lock.release()

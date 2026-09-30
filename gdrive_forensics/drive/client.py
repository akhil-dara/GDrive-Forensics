"""Drive API access: per-thread services, retried + logged calls, media requests, images."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httplib2
import requests
import urllib3
from google.auth.transport.requests import Request
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..core.mime import EXPORT_FORMATS, is_google_workspace
from ..logging_setup import API_LOGGER

logger = logging.getLogger(__name__)
api_logger = logging.getLogger(API_LOGGER)

_GOOGLE_IMAGE_HOSTS = ("googleusercontent.com", "google.com", "googleapis.com")


class UnsupportedExportError(Exception):
    """Google Workspace type that Drive cannot export to a file (e.g. Forms)."""


class DriveClient:
    def __init__(self, credentials, repository=None,
                 service_factory: Optional[Callable[[str, str], Any]] = None, timeout: int = 60) -> None:
        self.credentials = credentials
        self.repository = repository
        self.timeout = timeout
        self._factory = service_factory or self._build_service
        self._local = threading.local()
        self._refresh_lock = threading.Lock()

    def _build_service(self, api: str, version: str):
        http = AuthorizedHttp(self.credentials, http=httplib2.Http(timeout=self.timeout))
        return build(api, version, http=http, cache_discovery=False)

    def service(self, api: str = "drive", version: str = "v3"):
        """googleapiclient/httplib2 are not thread-safe: one service object per thread."""
        services = getattr(self._local, "services", None)
        if services is None:
            services = self._local.services = {}
        key = f"{api}:{version}"
        if key not in services:
            services[key] = self._factory(api, version)
        return services[key]

    def execute(self, request, request_type: str, url: str, params: Optional[dict] = None,
                num_retries: int = 3) -> dict:
        started = time.monotonic()
        try:
            response = request.execute(num_retries=num_retries)
        except HttpError as exc:
            elapsed = time.monotonic() - started
            status = getattr(exc.resp, "status", 0)
            api_logger.error("API_ERROR: %s %s - Status: %s", request_type, url, status)
            self._record(request_type, url, params, status, {"error": str(exc)}, elapsed)
            raise
        elapsed = time.monotonic() - started
        api_logger.info("API_REQUEST: %s %s - Status: 200 - Time: %.2fs", request_type, url, elapsed)
        self._record(request_type, url, params, 200, response, elapsed)
        return response

    def _record(self, request_type, url, params, status, response, elapsed) -> None:
        if self.repository is None:
            return
        try:
            self.repository.log_api_call(request_type=request_type, url=url, params=params, status=status,
                                         response=response, elapsed=elapsed)
        except Exception:  # an audit-log write must never break the API call itself
            logger.exception("Failed to write api_logs row for %s", request_type)

    # ------------------------------------------------------------- endpoints
    def about_user(self) -> dict:
        fields = "user(emailAddress,displayName,permissionId)"
        return self.execute(self.service().about().get(fields=fields), "about.get", "drive/v3/about",
                            {"fields": fields}).get("user", {})

    def root_folder_id(self) -> Optional[str]:
        try:
            return self.execute(self.service().files().get(fileId="root", fields="id"), "files.get",
                                "drive/v3/files/root", {"fields": "id"}).get("id")
        except HttpError:
            logger.warning("Could not resolve My Drive root id")
            return None

    def list_files_page(self, page_token: Optional[str], fields: str, page_size: int = 1000) -> dict:
        params = {"q": "", "pageSize": page_size, "fields": fields, "pageToken": page_token}
        return self.execute(self.service().files().list(**params), "files.list", "drive/v3/files", params)

    def list_revisions(self, file_id: str) -> list[dict]:
        fields = ("nextPageToken, revisions(id, modifiedTime, size, md5Checksum, originalFilename, mimeType, "
                  "lastModifyingUser, keepForever, published)")
        revisions: list[dict] = []
        token = None
        while True:
            params = {"fileId": file_id, "fields": fields, "pageToken": token}
            page = self.execute(self.service().revisions().list(**params), "revisions.list",
                                f"drive/v3/files/{file_id}/revisions", params)
            revisions.extend(page.get("revisions", []))
            token = page.get("nextPageToken")
            if not token:
                return revisions

    def thumbnail_metadata(self, file_id: str) -> Optional[dict]:
        fields = "thumbnailLink, owners(photoLink, displayName, emailAddress)"
        try:
            meta = self.execute(self.service().files().get(fileId=file_id, fields=fields), "files.get",
                                f"drive/v3/files/{file_id}", {"fields": fields})
        except HttpError as exc:
            logger.warning("Failed to fetch thumbnail metadata for %s: %s", file_id, exc)
            return None
        owner = (meta.get("owners") or [{}])[0]
        return {"thumbnail_link": meta.get("thumbnailLink"), "owner_photo": owner.get("photoLink"),
                "owner_name": owner.get("displayName"), "owner_email": owner.get("emailAddress")}

    def media_request(self, file_id: str, mime_type: str):
        """Return (request, export_extension|None). Workspace docs are exported to Office formats."""
        files = self.service().files()
        if is_google_workspace(mime_type):
            if mime_type not in EXPORT_FORMATS:
                raise UnsupportedExportError(f"Unsupported Google Workspace file type: {mime_type}")
            export_mime, ext = EXPORT_FORMATS[mime_type]
            return files.export_media(fileId=file_id, mimeType=export_mime), ext
        return files.get_media(fileId=file_id), None

    # ---------------------------------------------------------------- images
    def _access_token(self) -> Optional[str]:
        creds = self.credentials
        if creds is None:
            return None
        with self._refresh_lock:
            if not getattr(creds, "valid", False) and getattr(creds, "refresh_token", None):
                try:
                    creds.refresh(Request())
                except Exception as exc:
                    logger.warning("Token refresh for image fetch failed: %s", exc)
                    return None
        return getattr(creds, "token", None)

    @staticmethod
    def _is_safe_google_url(url: str) -> bool:
        """True only when requests/urllib3 will actually connect to an allow-listed Google host
        over https. urlparse().hostname alone is not trustworthy: it and the host requests
        connects to can disagree on malformed netlocs (backslashes, stray '@'), which is how a
        naive hostname check can be tricked into sending the token to an attacker-controlled host.
        """
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        netloc = parsed.netloc or ""
        if "@" in netloc or "\\" in netloc:
            return False
        try:
            prepared_url = requests.Request("GET", url).prepare().url
            connect_host = (urllib3.util.parse_url(prepared_url).host or "").lower()
        except Exception:
            return False
        return any(connect_host == h or connect_host.endswith("." + h) for h in _GOOGLE_IMAGE_HOSTS)

    def fetch_image(self, url: Optional[str], timeout: float = 10) -> Optional[bytes]:
        """Download a thumbnail/avatar. The OAuth token is sent only to Google hosts, over https,
        in a header - never in cleartext and never to a host a malformed URL merely claims to be."""
        if not url:
            return None
        headers = {}
        if self._is_safe_google_url(url):
            token = self._access_token()
            if token:
                headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            logger.debug("Image fetch failed for %s: %s", url, exc)
            return None
        if response.status_code == 200 and response.content:
            return response.content
        logger.debug("Image fetch HTTP %s for %s", response.status_code, url)
        return None

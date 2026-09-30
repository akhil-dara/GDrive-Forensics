"""Drive Activity API v2: fetch, normalise, de-duplicate and resolve actors."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from googleapiclient.errors import HttpError

from ..core.mime import FOLDER_MIME

logger = logging.getLogger(__name__)

_ACTION_KEYS = [("create", "create"), ("edit", "edit"), ("move", "move"), ("rename", "rename"),
                ("delete", "delete"), ("restore", "restore"), ("permissionChange", "permission_change"),
                ("comment", "comment"), ("dlpChange", "dlp_change"), ("reference", "reference"),
                ("settingsChange", "settings_change")]


class ActivityUnavailable(Exception):
    """Drive Activity API not enabled for the project, or token lacks the activity scope."""


class ActivityCancelled(Exception):
    pass


def extract_action_type(detail: dict) -> str:
    for key, label in _ACTION_KEYS:
        if key in (detail or {}):
            return label
    return "unknown"


def _actor(activity: dict) -> tuple[Optional[str], Optional[str], bool]:
    """(people/ID or None, fallback label, is_current_user)."""
    actor = (activity.get("actors") or [{}])[0]
    user = actor.get("user") or {}
    known = user.get("knownUser") or {}
    if known:
        return known.get("personName"), None, bool(known.get("isCurrentUser"))
    if "deletedUser" in user:
        return None, "Deleted user", False
    if "unknownUser" in user:
        return None, "Unknown user", False
    for key, label in (("administrator", "Administrator"), ("system", "System"),
                       ("anonymous", "Anonymous"), ("impersonation", "Impersonation")):
        if key in actor:
            return None, label, False
    return None, "Unknown", False


def _target(target: dict) -> tuple[str, Optional[str], Optional[str]]:
    item = target.get("driveItem") or (target.get("fileComment") or {}).get("parent") or {}
    if not item and target.get("drive"):
        drive = target["drive"]
        return (drive.get("name") or "").replace("drives/", "", 1), drive.get("title"), None
    target_id = (item.get("name") or "").replace("items/", "", 1)
    mime = item.get("mimeType")
    if not mime and ("driveFolder" in item or "folder" in item):
        mime = FOLDER_MIME
    return target_id, item.get("title"), mime


def parse_activities(activities: list[dict]) -> list[dict]:
    records: list[dict] = []
    for activity in activities:
        timestamp = activity.get("timestamp") or (activity.get("timeRange") or {}).get("endTime")
        action_type = extract_action_type(activity.get("primaryActionDetail") or {})
        person, label, is_current = _actor(activity)
        raw = json.dumps(activity, sort_keys=True, default=str)
        for target in activity.get("targets") or [{}]:
            target_id, target_name, mime = _target(target)
            key = hashlib.sha1(
                f"{timestamp}|{person or label}|{action_type}|{target_id}|{target_name}".encode("utf-8")).hexdigest()
            records.append({
                "activity_key": key, "activity_id": key, "timestamp": timestamp, "actor_person": person,
                "actor_email": None, "actor_name": label, "is_current_user": is_current,
                "action_type": action_type, "target_id": target_id, "target_name": target_name,
                "target_mime_type": mime, "target_path": "", "details_json": raw,
            })
    return records


class ActivityScanner:
    def __init__(self, client, repository, viewer_email: Optional[str]) -> None:
        self.client = client
        self.repository = repository
        self.viewer_email = viewer_email

    def scan(self, days_back: int = 30, progress: Optional[Callable[[int, int], None]] = None,
             cancel: Optional[threading.Event] = None) -> tuple[int, int]:
        since_ms = int((datetime.now(timezone.utc) - timedelta(days=days_back)).timestamp() * 1000)
        body: dict = {"pageSize": 100, "filter": f"time >= {since_ms}"}
        fetched = stored = 0
        while True:
            if cancel is not None and cancel.is_set():
                raise ActivityCancelled()
            try:
                service = self.client.service("driveactivity", "v2")
                page = self.client.execute(service.activity().query(body=body), "activity.query",
                                           "driveactivity/v2/activity:query", dict(body))
            except HttpError as exc:
                status = getattr(exc.resp, "status", 0)
                if status in (403, 404):
                    raise ActivityUnavailable(str(exc)) from exc
                raise
            records = parse_activities(page.get("activities", []))
            fetched += len(page.get("activities", []))
            self._resolve(records)
            stored += self.repository.store_activities(records)
            if progress:
                progress(fetched, stored)
            token = page.get("nextPageToken")
            if not token:
                return fetched, stored
            body["pageToken"] = token

    def _resolve(self, records: list[dict]) -> None:
        people = self.repository.resolve_people(r["actor_person"] for r in records if r["actor_person"])
        paths = self.repository.file_paths(r["target_id"] for r in records if r["target_id"])
        for record in records:
            name, email = people.get(record["actor_person"], (None, None))
            if record.pop("is_current_user", False):
                email = email or self.viewer_email
            record["actor_email"] = email
            record["actor_name"] = name or record["actor_name"] or email
            record["target_path"] = paths.get(record["target_id"], "")

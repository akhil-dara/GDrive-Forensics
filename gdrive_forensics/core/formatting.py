"""Human-readable sizes, speeds, durations and timezone rendering."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytz

TIMEZONE_OPTIONS: list[tuple[str, str]] = [
    ("UTC", "UTC"),
    ("Asia/Kolkata", "IST (Asia/Kolkata)"),
    ("America/New_York", "EST (America/New_York)"),
    ("America/Los_Angeles", "PST (America/Los_Angeles)"),
    ("Europe/London", "GMT (Europe/London)"),
]


def now_iso() -> str:
    """Local-time ISO timestamp (the format already stored in existing databases)."""
    return datetime.now().isoformat()


def format_size(size_bytes) -> str:
    try:
        value = float(int(size_bytes or 0))
    except (TypeError, ValueError):
        return "Unknown"
    if value == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} PB"


def format_speed(bytes_per_second: float) -> str:
    if not bytes_per_second or bytes_per_second <= 0:
        return "Measuring…"
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    index = 0
    while bytes_per_second >= 1024 and index < len(units) - 1:
        bytes_per_second /= 1024
        index += 1
    precision = 0 if index == 0 else 1
    return f"{bytes_per_second:.{precision}f} {units[index]}"


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds <= 0:
        return "Calculating…"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def eta_text(processed: float, total: int, elapsed: float) -> str:
    if processed <= 0 or elapsed <= 0 or not total:
        return "ETA: Calculating…"
    rate = processed / elapsed
    if rate <= 0:
        return "ETA: ∞"
    remaining = max(total - processed, 0) / rate
    return f"ETA: {int(remaining // 60)}m {int(remaining % 60)}s"


def parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse a Drive API timestamp (UTC or with an explicit offset) into an aware datetime.

    Naive input is interpreted as UTC. Do not use this on `now_iso()` values, which are
    naive local time, not UTC.
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _tz(tz_name: Optional[str]):
    try:
        return pytz.timezone(tz_name or "UTC")
    except pytz.UnknownTimeZoneError:
        return pytz.UTC


def convert_timezone(iso: Optional[str], tz_name: Optional[str]) -> str:
    """'YYYY-mm-dd HH:MM:SS' in tz; '' for empty input; original string if unparsable.

    For Drive API timestamps (UTC or carrying an offset); naive input is interpreted as
    UTC. Do not pass `now_iso()` values here, which are naive local time, not UTC.
    """
    if not iso:
        return ""
    dt = parse_iso(iso)
    if dt is None:
        return iso
    return dt.astimezone(_tz(tz_name)).strftime("%Y-%m-%d %H:%M:%S")


def _offset_label(offset: Optional[timedelta]) -> str:
    total_minutes = int((offset or timedelta(0)).total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    return f"UTC{sign}{total_minutes // 60:02d}:{total_minutes % 60:02d}"


def format_with_offset(iso: Optional[str], tz_name: Optional[str]) -> Optional[str]:
    """'YYYY-mm-dd HH:MM:SS (UTC+05:30)'; None for empty input; original if unparsable.

    For Drive API timestamps (UTC or carrying an offset); naive input is interpreted as
    UTC. Do not pass `now_iso()` values here, which are naive local time, not UTC.
    """
    if not iso:
        return None
    dt = parse_iso(iso)
    if dt is None:
        return iso
    local = dt.astimezone(_tz(tz_name))
    return f"{local.strftime('%Y-%m-%d %H:%M:%S')} ({_offset_label(local.utcoffset())})"


def utc_offset_label(tz_name: Optional[str], at: Optional[datetime] = None) -> str:
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return _offset_label(moment.astimezone(_tz(tz_name)).utcoffset())


def timezone_display(tz_name: Optional[str]) -> str:
    name = tz_name if tz_name and _tz(tz_name).zone == tz_name else "UTC"
    return f"{name} ({utc_offset_label(name)})"

from datetime import datetime, timedelta, timezone

from gdrive_forensics.core import formatting as f


def test_format_size():
    assert f.format_size(0) == "0 B"
    assert f.format_size(None) == "0 B"
    assert f.format_size(1023) == "1023.00 B"
    assert f.format_size(1024) == "1.00 KB"
    assert f.format_size("1536") == "1.50 KB"
    assert f.format_size(1024 ** 5) == "1.00 PB"
    assert f.format_size("abc") == "Unknown"


def test_speed_duration_eta():
    assert f.format_speed(0) == "Measuring…"
    assert f.format_speed(512) == "512 B/s"
    assert f.format_speed(1536) == "1.5 KB/s"
    assert f.format_duration(None) == "Calculating…"
    assert f.format_duration(42) == "42s"
    assert f.format_duration(125) == "2m 5s"
    assert f.format_duration(3725) == "1h 2m"
    assert f.eta_text(0, 10, 5) == "ETA: Calculating…"
    assert f.eta_text(5, 10, 10) == "ETA: 0m 10s"


def test_timezone_conversion():
    assert f.convert_timezone("2025-01-01T00:00:00.000Z", "Asia/Kolkata") == "2025-01-01 05:30:00"
    assert f.convert_timezone("", "UTC") == ""
    assert f.convert_timezone("garbage", "UTC") == "garbage"
    assert f.format_with_offset("2025-01-01T00:00:00Z", "Asia/Kolkata") == "2025-01-01 05:30:00 (UTC+05:30)"
    assert f.format_with_offset(None, "UTC") is None
    assert f.format_with_offset("2025-01-01T00:00:00Z", "Not/AZone") == "2025-01-01 00:00:00 (UTC+00:00)"
    at = datetime(2025, 1, 15, tzinfo=timezone.utc)
    assert f.utc_offset_label("America/New_York", at) == "UTC-05:00"
    assert f.timezone_display("UTC") == "UTC (UTC+00:00)"
    assert ("Asia/Kolkata", "IST (Asia/Kolkata)") in f.TIMEZONE_OPTIONS


def test_naive_timestamps_are_treated_as_utc():
    dt = f.parse_iso("2025-01-01T00:00:00")
    assert dt is not None and dt.tzinfo is not None and dt.utcoffset() == timedelta(0)
    assert f.convert_timezone("2025-01-01T00:00:00", "Asia/Kolkata") == "2025-01-01 05:30:00"
    assert f.utc_offset_label("America/New_York", datetime(2025, 1, 15)) == "UTC-05:00"

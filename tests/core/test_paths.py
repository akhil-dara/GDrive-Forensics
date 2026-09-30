import os

import pytest

from gdrive_forensics.core import paths as paths_module
from gdrive_forensics.core.paths import (
    build_unique_path, sanitize_filename, safe_path_join, unique_file_path,
)


def test_sanitize_filename_replaces_reserved_characters():
    assert sanitize_filename('a<b>c:d"e/f\\g|h?i*j') == "a﹤b﹥c꞉d″e／f＼g｜h？i﹡j"
    assert sanitize_filename("  name\twith\nbreaks. ") == "name with breaks"
    assert sanitize_filename("") == "untitled"
    assert sanitize_filename("...") == "untitled"


def test_safe_path_join(tmp_path):
    assert safe_path_join(str(tmp_path), "a:b", "", "c") == os.path.join(str(tmp_path), "a꞉b", "c")
    assert safe_path_join(str(tmp_path)) == str(tmp_path)


def test_build_unique_path(tmp_path):
    first, dup = build_unique_path(str(tmp_path), "report.csv")
    assert not dup and first == os.path.join(str(tmp_path), "report.csv")
    open(first, "w").close()
    second, dup = build_unique_path(str(tmp_path), "report.csv", reference_timestamp="2025-03-01T10:20:30Z")
    assert dup and os.path.basename(second) == "report (Duplicate_report_20250301_102030 UTC).csv"


def test_unique_file_path(tmp_path):
    target = tmp_path / "a.txt"
    assert unique_file_path(str(target)) == str(target)
    target.write_text("x")
    assert unique_file_path(str(target)) == str(tmp_path / "a_1.txt")
    (tmp_path / "a_1.txt").write_text("x")
    assert unique_file_path(str(target)) == str(tmp_path / "a_2.txt")


def test_sanitize_filename_replaces_every_control_character():
    assert sanitize_filename("a\x00b\x07c\x1fd\x7fe") == "a b c d e"
    assert sanitize_filename("x\x01\x02\x03y") == "x y"                  # runs collapse to one space
    assert sanitize_filename("\x1b[31mred\x7f") == "[31mred"
    assert sanitize_filename("\x00\x01") == "untitled"


def test_sanitize_filename_defuses_windows_device_names():
    assert sanitize_filename("nul") == "nul_"
    assert sanitize_filename("NUL.txt") == "NUL_.txt"
    assert sanitize_filename("com1.log") == "com1_.log"
    assert sanitize_filename("Lpt9") == "Lpt9_"
    assert sanitize_filename("aux ") == "aux_"                           # trailing space stripped first
    assert sanitize_filename("con.tar.gz") == "con_.tar.gz"              # Windows looks at the first dot
    assert sanitize_filename("PRN.") == "PRN_"
    for fine in ("console.txt", "com10.log", "lpt0", "nul_.txt", "my con.txt", "com.txt"):
        assert sanitize_filename(fine) == fine


def test_sanitize_filename_caps_length_and_keeps_the_extension():
    long_name = "x" * 300 + ".pdf"
    capped = sanitize_filename(long_name)
    assert len(capped) == 200 and capped.endswith(".pdf") and capped.startswith("x" * 196)
    assert sanitize_filename("y" * 250) == "y" * 200
    assert sanitize_filename("z" * 200) == "z" * 200                     # at the limit: unchanged
    odd = sanitize_filename("a." + "e" * 300)                            # an absurd "extension": plain cut
    assert len(odd) == 200 and odd.startswith("a.e")
    # the cut never leaves a stem ending in a space or dot
    assert sanitize_filename("w" * 195 + " " + "v" * 10 + ".pdf") == "w" * 195 + ".pdf"


def _dangling_symlink(path):
    try:
        os.symlink(str(path) + ".missing-target", str(path))
    except (OSError, NotImplementedError) as exc:   # Windows without Developer Mode / privilege
        pytest.skip(f"cannot create symlinks here: {exc}")


def test_unique_file_path_treats_a_dangling_symlink_as_taken(tmp_path):
    link = tmp_path / "a.txt"
    _dangling_symlink(link)
    assert not os.path.exists(link) and os.path.lexists(link)
    assert unique_file_path(str(link)) == str(tmp_path / "a_1.txt")
    _dangling_symlink(tmp_path / "a_1.txt")
    assert unique_file_path(str(link)) == str(tmp_path / "a_2.txt")
    path, renamed = build_unique_path(str(tmp_path), "a.txt", reference_timestamp="2025-03-01T10:20:30Z")
    assert renamed and os.path.basename(path) == "a (Duplicate_a_20250301_102030 UTC).txt"


def test_unique_file_path_gives_up_after_a_hard_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(paths_module.os.path, "lexists", lambda p: True)
    with pytest.raises(RuntimeError, match="10000"):
        unique_file_path(str(tmp_path / "a.txt"))

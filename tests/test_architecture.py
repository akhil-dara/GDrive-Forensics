import ast
import pathlib

PKG = pathlib.Path(__file__).resolve().parents[1] / "gdrive_forensics"


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_backend_layers_do_not_import_flet():
    for layer in ("core", "storage", "drive", "exporting"):
        for file in (PKG / layer).rglob("*.py"):
            assert "flet" not in imports(file), file


def test_ui_does_not_touch_sqlite():
    for file in (PKG / "ui").rglob("*.py"):
        assert "sqlite3" not in imports(file), file
        assert "execute(" not in file.read_text(encoding="utf-8"), file


def test_launcher_is_thin():
    text = (PKG.parent / "gdrive-flet.py").read_text(encoding="utf-8")
    assert len(text.splitlines()) < 20 and "from gdrive_forensics.app import run" in text

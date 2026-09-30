import importlib


def test_package_imports():
    pkg = importlib.import_module("gdrive_forensics")
    assert pkg.__version__ == "2.0.0"


def test_pinned_flet_version():
    import flet
    from importlib.metadata import version

    assert version("flet") == "1.0.1"
    assert hasattr(flet, "Button") and not hasattr(flet, "ElevatedButton")


def test_directly_imported_libraries_are_pinned_to_the_tested_versions():
    import pathlib
    from importlib.metadata import version

    root = pathlib.Path(__file__).resolve().parents[1]
    pins = dict(line.split("==", 1) for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
                if "==" in line and not line.lstrip().startswith("#"))
    for package in ("httplib2", "urllib3"):          # imported directly by gdrive_forensics.drive.client
        assert pins.get(package) == version(package), package
    readme = (root / "README.md").read_text(encoding="utf-8")
    for package, pinned in pins.items():               # the README's requirements block matches the file
        assert f"{package}=={pinned}" in readme, package

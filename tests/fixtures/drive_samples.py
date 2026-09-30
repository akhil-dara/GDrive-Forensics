"""Realistic Drive API files.list pages for tests and UI smoke tests."""
from __future__ import annotations

from gdrive_forensics.core.mime import FOLDER_MIME

ME = {"emailAddress": "me@x.com", "displayName": "Me", "permissionId": "999", "photoLink": "https://lh3.googleusercontent.com/me=s64"}
BOB = {"emailAddress": "bob@x.com", "displayName": "Bob", "permissionId": "222", "photoLink": None}


def _owner_perm(owner):
    return {"id": owner["permissionId"], "type": "user", "role": "owner", "emailAddress": owner["emailAddress"],
            "displayName": owner["displayName"]}


def _f(id_, name, mime, parents=("ROOT",), owner=ME, **extra):
    data = {"id": id_, "name": name, "mimeType": mime, "parents": list(parents), "owners": [owner],
            "ownedByMe": owner is ME, "createdTime": "2025-03-01T10:00:00.000Z",
            "modifiedTime": "2025-03-05T10:00:00.000Z", "trashed": False, "shared": False, "starred": False,
            "permissions": [_owner_perm(owner)], "capabilities": {"canDownload": True},
            "webViewLink": f"https://drive.google.com/file/d/{id_}/view"}
    data.update(extra)
    return data


SAMPLE_PAGES = [
    {"files": [
        _f("fold1", "Case Files", FOLDER_MIME),
        _f("sub1", "Invoices", FOLDER_MIME, parents=("fold1",)),
        _f("pdf1", "invoice-001.pdf", "application/pdf", parents=("sub1",), size="2048",
           md5Checksum="5d41402abc4b2a76b9719d911017c592", starred=True,
           thumbnailLink="https://lh3.googleusercontent.com/pdf1=s220"),
        _f("doc1", "Meeting notes", "application/vnd.google-apps.document", parents=("fold1",), shared=True,
           permissions=[_owner_perm(ME), {"id": "222", "type": "user", "role": "writer",
                                          "emailAddress": "bob@x.com", "displayName": "Bob"}]),
    ]},
    {"files": [
        _f("img1", "photo.png", "image/png", size="4096", md5Checksum="aa" * 16,
           permissions=[_owner_perm(ME), {"id": "anyoneWithLink", "type": "anyone", "role": "reader"}],
           thumbnailLink="https://lh3.googleusercontent.com/img1=s220"),
        _f("shared1", "bob-plan.xlsx",
           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
           parents=("bobsfolder",), owner=BOB, size="512"),
        _f("trash1", "old.txt", "text/plain", size="10", trashed=True),
        _f("cut1", "shortcut to pdf", "application/vnd.google-apps.shortcut", parents=("fold1",),
           shortcutDetails={"targetId": "pdf1"}),
        _f("dupA", "same.txt", "text/plain", size="1", md5Checksum="11" * 16),
        _f("dupB", "same.txt", "text/plain", size="2", md5Checksum="22" * 16),
    ]},
]


def seed_database(db, viewer_email: str = "me@x.com") -> None:
    """Run the real scanner against the sample pages (no network)."""
    from gdrive_forensics.drive.scanner import DriveScanner
    from tests.fakes import FakeDriveClient

    DriveScanner(FakeDriveClient(pages=SAMPLE_PAGES), db, viewer_email).scan()

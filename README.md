<h1 align="center">Google Drive Forensics Suite</h1>

<p align="center">
  <img src="https://github.com/user-attachments/assets/cb302c02-13b0-4d2b-8b0e-8c2d89e53ea3" width="500" height="500" />
</p>
**Professional evidence intelligence for Google Drive** — built for DFIR teams, internal audit, and DLP responders who need fast, read-only insight into massive Drive estates.

---

## Why Investigators Love It

- **No-download triage** → enumerate every file’s metadata (paths, owners, sharing, MD5/SHA1/SHA256) without touching the payload.
- **Never-before-seen UI** → tiles, badges, queues, inline loaders, per-user analytics, and buttery-smooth transitions built with Flet.
- **Trustworthy chain of custody** → SQLite evidence lake (`gdrive_forensics.db`) + API request logs (`logs/api_requests.log`).
- **Safe bulk exports** → live ETA, speed, cancel + background buttons, and CSV/JSON reporting with timezone stamps.

> **Mission:** Make Google Drive forensic investigations faster, easier, and accessible.

---

## Visual Walkthrough (DFIR / DLP How-To)

### 1. Launch → OAuth landing
![OAuth landing](assets/OAuth-Screen-Google%20Drive%20Forensics%20Suite.png)

Open the desktop app and click **Start OAuth Login**. This locked-down landing screen reminds investigators the session is read-only and prepares them for Google consent.

### 2. Approve in your browser
![OAuth start](assets/OAuth-Start%20screen-2025-11-22%2021_21_46-Google%20Drive%20Forensics%20Suite.png)

The app opens Google's consent page in your browser and waits for the callback on `127.0.0.1` only (loopback, nothing is exposed to your LAN). Desktop OAuth clients need no redirect-URI configuration.

### 3. Files workspace (primary triage)
![Files grid](assets/Files-2025-11-22%2020_56_01-.png)

Use filters (starred, public, owners, MIME presets) as needed. Add required items or entire result pages to the export queue from here. Entire Metadata export with hashes also can be done without downloading of the files.

### 4. Users intelligence
![Users tab](assets/Users-Google%20Drive%20Forensics%20Suite.png)

Pivot into user-centric DLP views. Ispect per-user volume, and jump back into file listings scoped to a single account with one click.

### 5. Analytics pulse
![Analytics tab](assets/Analytics-Screenshot-Google%20Drive%20Forensics%20Suite.png)


### 6. File detail window
![File detail window](assets/File-detail-window-Google%20Drive%20Forensics%20Suite.png)

When you need case-ready metadata, open the detail drawer to copy Drive path, owners, permissions, hashes, and timestamps—everything required for DFIR chain-of-custody notes.

### 7. Export queue oversight
![Export queue](assets/export-queue-Google%20Drive%20Forensics%20Suite.png)

Queue view shows each batch with background/run-now controls. Investigators can park long-running exports while still continuing other triage work.

### 8. Export progress + backgrounding
![Export dialog](assets/export-start-Gdrive%20suite.png)

The progress dialog exposes ETA, throughput, and “Run in background” plus “Cancel” buttons. This prevents UI freezes while keeping an auditable trail of what was generated.

*(Runs as a native Flet desktop.)*

---

## Feature Highlights

| 🔍 Evidence Discovery | 🧠 Analyst Experience | 📦 Export & Reporting |
| --- | --- | --- |
| Full-text search, owner filters, date slices, MIME presets, folder breadcrumbs | Inline transition overlays, per-user analytics, tooltip help, keyboard focus, background tasks | CSV/JSON reports w/ timezone & hash fields, queue-based downloads|

- **User Analytics:** “Shared with” vs “Shared by” heatmaps, avatar previews, one-click user filters.
- **Queue Intelligence:** Add entire pages, merge selections, watch live ETA + transfer speed.
- **Safe Controls:** Cancel exports gracefully, run tasks headless, refresh thumbnails with progress bars.
- **Drive Activity timeline:** Optional Activity scan (Drive Activity API) records who did what and when; recent activity shows up in the file details window.
- **XLSX export:** Metadata-only reports can be written as `.xlsx` in addition to CSV/JSON.
- **Hash verification on every export:** Binary files are hashed while streaming and verified against the strongest checksum Drive reports for them (SHA-256, else SHA-1, else MD5; the one used is in `Hash_Algorithm`). Google Workspace files (Docs/Sheets/Slides) are converted to Office formats on export and have no Drive checksum, so their `Hash_Verified` is `N/A`; their `Local_MD5` / `Local_SHA256` are still recorded.
- **Transactional scans:** A failed or cancelled scan never destroys existing evidence; the previous data is replaced only when a scan succeeds.

---

## What changed in v2

- **Flet 1.0.1 migration** with exact, pinned requirements (`requirements.txt`); the single 5,000-line script is now the modular `gdrive_forensics` package (see Project Structure). `python gdrive-flet.py` still works.
- **Localhost-only OAuth with PKCE:** the sign-in callback listens on `127.0.0.1` only (no LAN-exposed callback) and Desktop clients need no redirect-URI setup.
- **Transactional scans:** a failed or cancelled scan never destroys existing evidence.
- **Streaming downloads with hash verification on every export** (binary files against Drive's MD5/SHA-1/SHA-256; Workspace exports have no Drive checksum, so `Hash_Verified` is `N/A`). New report columns are appended after the v1 columns, so existing column positions are unchanged: `Downloaded`, `Local_MD5`, `Local_SHA256`, `Hash_Verified`, `Hash_Algorithm`, `Error`, plus time columns (`Created_Time`, `Modified_Time`, `Created_Time_Local`, `Modified_Time_Local`) in the export report.
- **`metadata.downloaded_files` in the ExportReport JSON now counts files actually downloaded** (v1 counted all files in the export).
- **Drive Activity scan** (optional): needs the Google Drive Activity API enabled in your project and a re-consent for the new `drive.activity.readonly` scope. The app works without it.
- **XLSX metadata export** and an **analytics dashboard** (stat cards, top files, type distribution with drill-down, storage by owner, trash, activity).
- **Spreadsheet safety:** formula-looking names (starting with `=`, `+`, `-` or `@`) are stored as text in XLSX. CSV reports keep names verbatim, so spreadsheet apps may interpret such names as formulas; use the JSON report as the canonical record.

---

## Quick Start

```bash
# 1. Clone or download this repo
git clone https://github.com/akhil-dara/GDrive-Forensics.git
cd GDrive-Forensics

# 2. Install deps (Python 3.10+)
pip install -r requirements.txt

# 3. Drop your OAuth desktop client credentials
default: credentials.json

# 4. Launch the app (native desktop window only)
python gdrive-flet.py
# or, equivalently:
python -m gdrive_forensics
```

### requirements.txt
```
flet[desktop]==1.0.1
google-api-python-client==2.200.0
google-auth==2.58.1
google-auth-httplib2==0.4.2
google-auth-oauthlib==1.4.1
requests==2.34.2
pytz==2026.4
openpyxl==3.1.5
# imported directly by gdrive_forensics.drive.client
httplib2==0.32.0
urllib3==2.8.0
```

---

## Getting `credentials.json`

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project → **APIs & Services → Enable APIs** → search “Google Drive API” → Enable
   - Optional: enable **Google Drive Activity API** for the Activity scan (the app works without it)
3. **OAuth consent screen** → External → fill app info
4. **Credentials → Create Credentials → OAuth client ID → Desktop App**
5. Download the JSON → rename to `credentials.json` → place it in the folder you run the app from (normally the repo folder, next to `gdrive-flet.py`)
6. First launch opens Google login. Approve the read-only scopes: `https://www.googleapis.com/auth/drive.readonly` and `https://www.googleapis.com/auth/drive.activity.readonly` (the second is only used by the Activity scan). The app listens on `127.0.0.1` only, so no redirect URL needs to be configured for a Desktop client.
---
## How to generate Credentials.json
[Generate Credentials.json](https://github.com/user-attachments/assets/2ef98b7c-7709-4454-9550-8701be0314de) 

## Investigation Scenario: Data Exfiltration Case

**Objective:** Investigate suspected unauthorized data sharing by employee during March 1-15, 2025.

**Steps:**
1. **Setup OAuth:** Create Google Cloud project on any google account→ Enable Drive API → Configure OAuth consent  → Generate desktop credentials → Download as `credentials.json`
2. **Authenticate Suspect Account:** Run `python gdrive-flet.py` → Browser opens → Sign in with **suspect's Google account**  → Grant read-only access → App creates `token.json`
3. **Apply Forensic Filters:** Files tab → Toggle "Shared by Me" + "Public only" → Set date range (March 1-15) → Filter by file type (PDF/Sheets/Archives for sensitive documents)
4. **Review & Queue Evidence:** Examine results with visual badges (🔒 public) → Select suspicious files → Add to export queue → Review sharing permissions and external recipients
5. **Export Evidence Package:** Click the **Export Queue** toolbar button (the queue icon with the count badge) → review the queue dialog → **Export Queue** → pick a destination folder → files are downloaded with hash verification and `ExportReport_<timestamp>.csv/.json` are written (file metadata, Drive and local hashes, permissions, timestamps) → close the app, then attach `gdrive_forensics.db` + `logs/` (including `logs/api_requests.log`) for chain of custody

**Result:** Complete evidence package with cryptographic hashes, sharing timelines, and audit trail ready for legal proceedings.

---

## Example CSV Row

| Column | Example |
| --- | --- |
| `File_ID` | `1a2B3cXyZ` |
| `Name` | `Finance_2024_Q2.xlsx` |
| `Item_Type` | `file` |
| `Drive_Path` | `/Shared drives/Finance/Reports` |
| `Owner_Email` | `cfo@example.com` |
| `Is_Public` | `Yes` |
| `MD5 / SHA1 / SHA256` | `d41d8cd9... / ... / ...` |
| `Timezone` | `Asia/Kolkata (UTC+05:30)` |

---

## Data Residency & Artifacts

Every data file lives in the folder you **run the app from** (the current working directory - normally the repo folder): `credentials.json` is read from there, and the app creates the files below there (plus empty `exports/` and `downloads/` folders).

| Artifact | Description |
| --- | --- |
| `token.json` | OAuth tokens of the signed-in (examined) account, including its **refresh token** - treat it as a secret |
| `gdrive_forensics.db` | SQLite evidence database (files, permissions, hashes, paths, export history) |
| `gdrive_forensics.db-wal`, `gdrive_forensics.db-shm` | SQLite WAL-mode sidecar files; while the app runs they can hold the most recent evidence writes |
| `thumbnail_cache.db` (+ `-wal` / `-shm`) | SQLite cache of thumbnails and avatars (can be deleted; it is refilled on demand) |
| `logs/gdrive_forensics.log` | App status + errors |
| `logs/api_requests.log` | Each Google API call w/ timestamp |
| `logs/auth.log` | Sign-in, token refresh and logout events |
| `logs/exports.log` | Export runs (start, cancel, finish) and metadata report output |

- **Close the app before copying the evidence database**, so every write is in `gdrive_forensics.db` itself; if a `-wal` / `-shm` file is still next to it, copy it together with the `.db`.
- **Do not run the app from a cloud-synced folder** (OneDrive, Dropbox, Google Drive for desktop, iCloud Drive): `token.json` - the examined account's refresh token - and the evidence database would be uploaded to that cloud. Use a local, access-controlled case folder instead.

All of the artifacts above (`token.json`, `*.db`, `*.db-wal`, `*.db-shm`, `logs/`) are git-ignored, as are `credentials.json`, `exports/` and `downloads/`, so evidence and secrets never land in a commit by accident.

---

## Project Structure

```
assets/                   README screenshots and media (not used by the app)
requirements.txt          Pinned runtime dependencies
requirements-dev.txt      Test dependencies (adds pytest to requirements.txt)
pytest.ini                pytest configuration (test paths, import path)
gdrive-flet.py            Thin launcher (python gdrive-flet.py)
gdrive_forensics/
  __main__.py             python -m gdrive_forensics
  app.py                  Entry point: data paths, logging, ft.run
  config.py               App constants, OAuth scopes, data-file locations
  logging_setup.py        Rotating app / API / auth / export logs
  core/                   Pure helpers (no UI, no network)
    filters.py            Browse filter state -> parameterised SQL WHERE
    formatting.py         Sizes, speeds, durations, timezone rendering
    mime.py               MIME icons, labels, Workspace export formats
    paths.py              Filesystem-safe naming
  storage/                SQLite + repository + thumbnail cache
    database.py           Schema, connections, additive migrations
    repository.py         All SQL used by the UI and background jobs
    thumbnail_cache.py    Persistent thumbnail/avatar cache
  drive/                  Everything that talks to Google
    auth.py               Token storage, localhost-only OAuth (PKCE)
    client.py             Drive API client (retries, request logging)
    scanner.py            Full metadata scan (transactional)
    activity.py           Drive Activity API scan
    downloads.py          Streaming downloads with hash verification
  exporting/              Report writers + export jobs
    reports.py            CSV / JSON / XLSX report rows and writers
    exporter.py           Queue, folder, filtered-set and metadata exports
  ui/                     Flet views, dialogs and background jobs
    shell.py              ForensicsApp: builds services, routes login <-> main
    context.py, state.py  Shared services, thread-safe UI dispatch, UI state
    jobs.py               Background scan, activity, download, export jobs
    login_view.py         OAuth landing screen
    main_view.py          Signed-in window (header, sidebar, toolbar, tabs, footer)
    header.py, sidebar.py, toolbar.py, footer.py
    files_view.py         Files tab (breadcrumbs, filters, paged cards)
    advanced_filters.py, file_card.py, thumbnails.py
    users_view.py         Users tab
    analytics_view.py, analytics_sections.py   Analytics tab
    dialogs/              Context menu, date filter, export queue, file details,
                          progress, shortcut prompt, thumbnail preview
  assets/                 Bundled UI assets (logo)
tests/                    pytest suite (architecture guard + per-layer tests)
```

Layering rules (enforced by `tests/test_architecture.py`): `core`, `storage`, `drive` and `exporting` never import Flet, and `ui` never imports `sqlite3` or runs SQL (it goes through `storage.repository`).

### Running tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

---

FAQ

**Q: Does it download every file for generating the metadata summary with hashes?**  
A: No. Metadata collection uses Drive API list calls. Only when you explicitly export/download does it fetch file bytes.

**Q: Are hashes reliable?**  
A: The `MD5` / `SHA1` / `SHA256` columns are Drive's own checksums, recorded by the metadata scan. Drive only has them for binary (uploaded) files; Google Docs/Sheets/Slides have none. When you download or export, every binary file is hashed while streaming and compared with the strongest Drive checksum available (SHA-256, else SHA-1, else MD5 - see `Hash_Algorithm`), giving `Hash_Verified` = `Yes` or `No`. Google Workspace files are converted to Office formats (e.g. `.docx`, `.xlsx`) on export, so there is no Drive checksum to compare: `Hash_Verified` is `N/A`, while `Local_MD5` / `Local_SHA256` still record the hashes of the exported file.

**Q: Can I cancel exports?**  
A: Yes. The progress dialog has “Cancel” and “Run in background”. Cancelling aborts the file that is downloading and removes its partial copy; files that already completed stay on disk with their export-history rows. Failed and cancelled items stay in the export queue: a cancelled queue export leaves the queue untouched, and a finished queue export removes every queued item except those with a failed download (which stay queued for retry); skipped shortcuts and hash-mismatched files count as processed and are removed from the queue, with their verdicts recorded in the report and export history.

**Q: Does it work offline?**  
A: Partly. Browsing, filtering and metadata-only reports (CSV/JSON/XLSX) read the local evidence database, but the main window only opens with a valid saved session: if the saved token has expired and Google cannot be reached to refresh it, the app shows the login screen instead. Downloads, file exports, Drive and Activity scans, revision fetches and thumbnail refresh always need network access.

**Q: Any license?**  
A: This repo is provided as-is for investigative workflows. Adapt as your policy allows.

---





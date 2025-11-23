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

### 2. Capture redirect URLs
![OAuth start](assets/OAuth-Start%20screen-2025-11-22%2021_21_46-Google%20Drive%20Forensics%20Suite.png)

The OAuth helper lists local + internal callback URLs.

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

The progress dialog exposes ETA, throughput, and “Run in background” plus “Cancel export” buttons. This prevents UI freezes while keeping an auditable trail of what was generated.

*(Runs as a native Flet desktop.)*

---

## Feature Highlights

| 🔍 Evidence Discovery | 🧠 Analyst Experience | 📦 Export & Reporting |
| --- | --- | --- |
| Full-text search, owner filters, date slices, MIME presets, folder breadcrumbs | Inline transition overlays, per-user analytics, tooltip help, keyboard focus, background tasks | CSV/JSON reports w/ timezone & hash fields, queue-based downloads|

- **User Analytics:** “Shared with” vs “Shared by” heatmaps, avatar previews, one-click user filters.
- **Queue Intelligence:** Add entire pages, merge selections, watch live ETA + transfer speed.
- **Safe Controls:** Cancel exports gracefully, run tasks headless, refresh thumbnails with progress bars.

---

## Quick Start

```bash
# 1. Clone or download this repo
cd gdrive-flet

# 2. Install deps (Python 3.11+)
pip install -r requirements.txt

# 3. Drop your OAuth desktop client credentials
default: credentials.json

# 4. Launch the app (native desktop window only)
python gdrive-flet.py
```

### requirements.txt
```
requests
pytz
google-auth
google-auth-oauthlib
google-auth-httplib2
google-api-python-client
flet
```

---

## Getting `credentials.json`

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project → **APIs & Services → Enable APIs** → search “Google Drive API” → Enable
3. **OAuth consent screen** → External → fill app info
4. **Credentials → Create Credentials → OAuth client ID → Desktop App**
5. Download the JSON → rename to `credentials.json` → place next to `gdrive-flet.py`
6. First launch opens Google login. Approve read-only scope: `https://www.googleapis.com/auth/drive.readonly`
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
5. **Export Evidence Package:** Export Queue tab → Generate CSV/JSON reports (includes file metadata, hashes, permissions, sharing history, timestamps) → Attach `gdrive_forensics.db` + `logs/api_requests.log` for chain of custody

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

| Artifact | Description |
| --- | --- |
| `gdrive_forensics.db` | SQLite evidence database (files, permissions, hashes, paths) |
| `logs/gdrive_forensics.log` | App status + errors |
| `logs/api_requests.log` | Each Google API call w/ timestamp |


All directories and DB is created automatically at launch.

---

FAQ

**Q: Does it download every file for generating the metadata summary with hashes?**  
A: No. Metadata collection uses Drive API list calls. Only when you explicitly export/download does it fetch file bytes.

**Q: Are hashes reliable?**  
A: MD5 always comes from Drive metadata. SHA1/SHA256 fields are filled when available from ingestion or verified during download.

**Q: Can I cancel exports?**  
A: Yes. The dialog has “Cancel export” (finishes current file safely) and “Run in background.”

**Q: Does it work offline?**  
A: Once the database is populated, you can browse/filter/export offline. Live thumbnail refresh and new scans need network access.

**Q: Any license?**  
A: This repo is provided as-is for investigative workflows. Adapt as your policy allows.

---




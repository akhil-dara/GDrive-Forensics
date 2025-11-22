"""
Google Drive Forensics Suite - FINAL PRODUCTION VERSION
Professional Digital Forensics Tool with Complete Feature Set
"""

import os
import json
import sqlite3
import hashlib
import threading
import time
from datetime import datetime, timezone, date, timedelta
from pathlib import Path
import io
import csv
import zipfile
import shutil
import base64
from collections import defaultdict
import logging
import traceback
import socket
import webbrowser
import re
from math import ceil
from urllib.parse import quote, urlencode
import requests
import pytz
from typing import Optional, List, Dict, Tuple, Callable

# Google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

# Flet imports
import flet as ft
from flet import Page, Column, Row, Container, Text, TextField, Dropdown, ElevatedButton, IconButton
from flet import Card, Tabs, Tab, ProgressBar, ProgressRing, AlertDialog, Checkbox, Icon, Image
from flet import FilePicker, FilePickerResultEvent, GestureDetector, PopupMenuButton, PopupMenuItem
from flet import Chip, Badge, Tooltip, ExpansionPanel, ExpansionPanelList, ListTile, Divider

# Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'
DATABASE_FILE = 'gdrive_forensics.db'
EXPORT_DIR = 'exports'
LOG_DIR = 'logs'
DOWNLOAD_DIR = 'downloads'
TOKEN_FILE = 'token.json'

# Create directories
for directory in [EXPORT_DIR, LOG_DIR, DOWNLOAD_DIR]:
    os.makedirs(directory, exist_ok=True)

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'gdrive_forensics.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API Request Logger
api_logger = logging.getLogger('api_requests')
api_handler = logging.FileHandler(os.path.join(LOG_DIR, 'api_requests.log'))
api_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
api_logger.addHandler(api_handler)
api_logger.setLevel(logging.INFO)

# MIME Type Icons
FOLDER_MIME = 'application/vnd.google-apps.folder'

MIME_TYPE_ICONS = {
    FOLDER_MIME: '📁',
    'application/vnd.google-apps.document': '📝',
    'application/vnd.google-apps.spreadsheet': '📊',
    'application/vnd.google-apps.presentation': '📽️',
    'application/vnd.google-apps.form': '📋',
    'application/vnd.google-apps.shortcut': '🔗',
    'application/pdf': '📕',
    'application/zip': '📦',
    'image/jpeg': '🖼️',
    'image/png': '🖼️',
    'image/gif': '🖼️',
    'video/mp4': '🎬',
    'video/avi': '🎬',
    'audio/mpeg': '🎵',
    'text/plain': '📄',
    'application/msword': '📄',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '📄',
    'application/vnd.ms-excel': '📊',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '📊',
}

MIME_TYPE_LABELS = {
    'application/vnd.google-apps.document': 'Google Docs',
    'application/vnd.google-apps.spreadsheet': 'Google Sheets',
    'application/vnd.google-apps.presentation': 'Google Slides',
    'application/vnd.google-apps.form': 'Google Forms',
    'application/vnd.google-apps.folder': 'Folder',
    'application/vnd.google-apps.shortcut': 'Shortcut',
    'application/vnd.google-apps.script': 'Apps Script',
    'application/vnd.google-apps.jam': 'Jamboard',
    'application/vnd.google-apps.drive-sdk': 'Drive App Data',
}


def get_file_icon(mime_type: str) -> str:
    """Get emoji icon for file type"""
    if mime_type in MIME_TYPE_ICONS:
        return MIME_TYPE_ICONS[mime_type]
    
    if mime_type.startswith('image/'):
        return '🖼️'
    elif mime_type.startswith('video/'):
        return '🎬'
    elif mime_type.startswith('audio/'):
        return '🎵'
    elif mime_type.startswith('text/'):
        return '📄'
    return '📎'


def get_mime_label(mime_type: Optional[str]) -> Optional[str]:
    if not mime_type:
        return None
    return MIME_TYPE_LABELS.get(mime_type)


SAFE_CHAR_MAP = str.maketrans({
    '<': '﹤',
    '>': '﹥',
    ':': '꞉',
    '"': '″',
    '/': '／',
    '\\': '＼',
    '|': '｜',
    '?': '？',
    '*': '﹡'
})


def sanitize_filename(name: str) -> str:
    if not name:
        return 'untitled'
    cleaned = re.sub(r'[\n\r\t]', ' ', name)
    cleaned = cleaned.translate(SAFE_CHAR_MAP)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    cleaned = cleaned.rstrip('. ')
    return cleaned or 'untitled'


def safe_path_join(base_path: str, *segments: str) -> str:
    safe_segments = [sanitize_filename(seg) for seg in segments if seg]
    if not safe_segments:
        return base_path
    return os.path.join(base_path, *safe_segments)


def ensure_directory(path: str):
    os.makedirs(path, exist_ok=True)


def build_unique_path(
    base_dir: str,
    desired_name: str,
    existing_paths: Optional[set] = None,
    reference_timestamp: Optional[str] = None
) -> Tuple[str, bool]:
    safe_name = sanitize_filename(desired_name) or 'file'
    base_dir = base_dir or '.'
    existing_paths = existing_paths if existing_paths is not None else set()
    candidate = os.path.join(base_dir, safe_name)
    if candidate not in existing_paths and not os.path.exists(candidate):
        existing_paths.add(candidate)
        return candidate, False
    timestamp = None
    if reference_timestamp:
        try:
            dt = datetime.fromisoformat(reference_timestamp.replace('Z', '+00:00'))
            timestamp = dt.strftime('%Y%m%d_%H%M%S')
        except Exception:
            pass
    if not timestamp:
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    name, ext = os.path.splitext(safe_name)
    token = f" (Duplicate_{name or 'file'}_{timestamp} UTC)"
    new_name = f"{name}{token}{ext}"
    candidate = os.path.join(base_dir, new_name)
    counter = 1
    while candidate in existing_paths or os.path.exists(candidate):
        new_name = f"{name}{token}_{counter}{ext}"
        candidate = os.path.join(base_dir, new_name)
        counter += 1
    existing_paths.add(candidate)
    return candidate, True


def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if not size_bytes or size_bytes == 0:
        return "0 B"
    
    try:
        size_bytes = int(size_bytes)
    except (ValueError, TypeError):
        return "Unknown"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


class DatabaseManager:
    """Manages SQLite database operations"""
    
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Files table with comprehensive fields
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                name TEXT,
                mime_type TEXT,
                size INTEGER,
                created_time TEXT,
                modified_time TEXT,
                trashed BOOLEAN,
                shared BOOLEAN,
                starred BOOLEAN,
                owned_by_me BOOLEAN,
                parent_id TEXT,
                full_path TEXT,
                source TEXT,
                md5_checksum TEXT,
                sha1_checksum TEXT,
                sha256_checksum TEXT,
                web_view_link TEXT,
                thumbnail_link TEXT,
                version INTEGER,
                viewed_by_me BOOLEAN,
                metadata_json TEXT,
                last_scan TEXT,
                file_category TEXT,
                file_extension TEXT,
                can_download BOOLEAN,
                owner_email TEXT,
                owner_name TEXT,
                owner_photo TEXT,
                is_shortcut BOOLEAN,
                shortcut_target_id TEXT,
                is_public BOOLEAN
            )
        """)
        
        # Permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                permission_id TEXT,
                type TEXT,
                role TEXT,
                email_address TEXT,
                display_name TEXT,
                photo_link TEXT,
                deleted BOOLEAN,
                pending_owner BOOLEAN,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        """)
        
        # User analytics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_address TEXT UNIQUE,
                display_name TEXT,
                photo_link TEXT,
                files_owned_count INTEGER,
                files_shared_with_count INTEGER,
                files_shared_by_count INTEGER,
                last_updated TEXT
            )
        """)
        
        # Revisions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS revisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                revision_id TEXT,
                modified_time TEXT,
                size INTEGER,
                md5_checksum TEXT,
                original_filename TEXT,
                mime_type TEXT,
                modified_by_email TEXT,
                modified_by_name TEXT,
                keep_forever BOOLEAN,
                published BOOLEAN,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        """)
        
        # Session metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS session_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                session_start TEXT,
                session_end TEXT,
                total_files_scanned INTEGER,
                scan_duration_seconds REAL
            )
        """)
        
        # API logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                request_type TEXT,
                request_url TEXT,
                request_params TEXT,
                response_status INTEGER,
                response_data TEXT,
                processing_time REAL
            )
        """)
        
        # Export queue table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS export_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE,
                added_time TEXT,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        """)
        
        # Export history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT,
                export_time TEXT,
                local_path TEXT,
                original_hash TEXT,
                exported_hash TEXT,
                hash_verified BOOLEAN,
                status TEXT,
                FOREIGN KEY (file_id) REFERENCES files (id)
            )
        """)
        
        self._migrate_legacy_files_table(cursor)
        self._ensure_indexes(cursor)
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    def _migrate_legacy_files_table(self, cursor):
        cursor.execute("PRAGMA table_info(files)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'folder_size' not in columns:
            return

        logger.info("Migrating files table to drop folder_size column")
        cursor.execute("ALTER TABLE files RENAME TO files_legacy")
        cursor.execute("""
            CREATE TABLE files (
                id TEXT PRIMARY KEY,
                name TEXT,
                mime_type TEXT,
                size INTEGER,
                created_time TEXT,
                modified_time TEXT,
                trashed BOOLEAN,
                shared BOOLEAN,
                starred BOOLEAN,
                owned_by_me BOOLEAN,
                parent_id TEXT,
                full_path TEXT,
                source TEXT,
                md5_checksum TEXT,
                sha1_checksum TEXT,
                sha256_checksum TEXT,
                web_view_link TEXT,
                thumbnail_link TEXT,
                version INTEGER,
                viewed_by_me BOOLEAN,
                metadata_json TEXT,
                last_scan TEXT,
                file_category TEXT,
                file_extension TEXT,
                can_download BOOLEAN,
                owner_email TEXT,
                owner_name TEXT,
                owner_photo TEXT,
                is_shortcut BOOLEAN,
                shortcut_target_id TEXT,
                is_public BOOLEAN
            )
        """)
        cursor.execute("""
            INSERT INTO files (
                id, name, mime_type, size, created_time, modified_time, trashed,
                shared, starred, owned_by_me, parent_id, full_path, source,
                md5_checksum, sha1_checksum, sha256_checksum, web_view_link,
                thumbnail_link, version, viewed_by_me, metadata_json, last_scan,
                file_category, file_extension, can_download, owner_email,
                owner_name, owner_photo, is_shortcut, shortcut_target_id, is_public
            )
            SELECT
                id, name, mime_type, size, created_time, modified_time, trashed,
                shared, starred, owned_by_me, parent_id, full_path, source,
                md5_checksum, sha1_checksum, sha256_checksum, web_view_link,
                thumbnail_link, version, viewed_by_me, metadata_json, last_scan,
                file_category, file_extension, can_download, owner_email,
                owner_name, owner_photo, is_shortcut, shortcut_target_id, is_public
            FROM files_legacy
        """)
        cursor.execute("DROP TABLE files_legacy")

    def _ensure_indexes(self, cursor):
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_files_owner_email ON files(owner_email)",
            "CREATE INDEX IF NOT EXISTS idx_files_parent_id ON files(parent_id)",
            "CREATE INDEX IF NOT EXISTS idx_files_mime_type ON files(mime_type)",
            "CREATE INDEX IF NOT EXISTS idx_files_full_path ON files(full_path)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_file_id ON permissions(file_id)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_email ON permissions(email_address)",
        ]
        for statement in indexes:
            cursor.execute(statement)


class GoogleDriveForensics:
    """Main forensics class handling Google Drive API operations"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.service = None
        self.credentials = None
        self.user_email = None
        self.timezone = 'UTC'
        self.scan_progress = {
            'status': 'idle',
            'current': 0,
            'total': 0,
            'message': '',
            'files_processed': 0,
            'folders_processed': 0,
            'errors': 0,
            'speed': 0,
            'eta': 'Calculating...'
        }
        self.total_files_cached = 0
    
    def get_credentials(self):
        """Get or refresh Google credentials"""
        creds = None
        
        if os.path.exists(TOKEN_FILE):
            try:
                creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
                logger.info("Loaded credentials from token.json")
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
        
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Refreshed expired credentials")
                self.save_credentials(creds)
            except Exception as e:
                logger.error(f"Failed to refresh credentials: {e}")
                return None
        
        if creds and creds.valid:
            self.credentials = creds
            self.service = build('drive', 'v3', credentials=creds)
            
            try:
                about = self.service.about().get(fields='user').execute()
                self.user_email = about['user']['emailAddress']
                logger.info(f"Authenticated as: {self.user_email}")
            except Exception as e:
                logger.error(f"Failed to get user email: {e}")
            
            return creds
        
        return None
    
    def save_credentials(self, creds):
        """Save credentials to token.json"""
        try:
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
            logger.info("Credentials saved to token.json")
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
    
    def convert_timezone(self, dt_str: str, to_timezone: str = None) -> str:
        """Convert datetime string to specified timezone"""
        if not dt_str:
            return ""
        
        try:
            # Parse ISO format datetime
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            
            # Convert to target timezone
            tz = pytz.timezone(to_timezone or self.timezone)
            dt_local = dt.astimezone(tz)
            
            return dt_local.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            logger.error(f"Timezone conversion error: {e}")
            return dt_str
    
    def get_timezone_offset(self, tz_name: str = None) -> str:
        """Get timezone offset like +05:30"""
        try:
            tz = pytz.timezone(tz_name or self.timezone)
            now = datetime.now(tz)
            offset = now.strftime('%z')
            return f"{offset[:3]}:{offset[3:]}"
        except:
            return "+00:00"
    
    def api_request_with_logging(self, request_func, request_type, url_info, **kwargs):
        """Execute API request with comprehensive logging"""
        start_time = time.time()
        
        try:
            response = request_func(**kwargs).execute()
            processing_time = time.time() - start_time
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            response_str = json.dumps(response, default=str)
            
            cursor.execute("""
                INSERT INTO api_logs (timestamp, request_type, request_url, request_params,
                                     response_status, response_data, processing_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                request_type,
                url_info,
                json.dumps(kwargs) if kwargs else None,
                200,
                response_str,
                processing_time
            ))
            conn.commit()
            conn.close()
            
            api_logger.info(f"API_REQUEST: {request_type} {url_info} - Status: 200 - Time: {processing_time:.2f}s")
            
            return response
            
        except HttpError as e:
            processing_time = time.time() - start_time
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_logs (timestamp, request_type, request_url, request_params,
                                     response_status, response_data, processing_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                request_type,
                url_info,
                json.dumps(kwargs) if kwargs else None,
                e.resp.status,
                json.dumps({'error': str(e)}, default=str),
                processing_time
            ))
            conn.commit()
            conn.close()
            
            api_logger.error(f"API_ERROR: {request_type} {url_info} - Status: {e.resp.status}")
            raise e
    
    def scan_drive(self, progress_callback=None):
        """OPTIMIZED: Comprehensive Drive scan"""
        self.scan_progress = {
            'status': 'running',
            'current': 0,
            'total': 0,
            'message': 'Initializing scan...',
            'files_processed': 0,
            'folders_processed': 0,
            'errors': 0,
            'speed': 0,
            'eta': 'Calculating...'
        }
        
        scan_start_time = time.time()
        
        try:
            if not self.service:
                raise Exception("Not authenticated")
            
            all_files = []
            page_token = None
            
            fields = ('nextPageToken, files(id, name, mimeType, parents, size, createdTime, '
                     'modifiedTime, trashed, shared, ownedByMe, starred, owners, permissions, '
                     'webViewLink, thumbnailLink, version, md5Checksum, sha1Checksum, '
                     'sha256Checksum, viewedByMe, capabilities, quotaBytesUsed, shortcutDetails)')
            
            self.scan_progress['message'] = 'Fetching file list from Google Drive...'
            if progress_callback:
                progress_callback(self.scan_progress)
            
            while True:
                try:
                    results = self.api_request_with_logging(
                        self.service.files().list,
                        'files.list',
                        'drive/v3/files',
                        q="",  # Get ALL files including trashed
                        pageSize=1000,
                        fields=fields,
                        pageToken=page_token
                    )
                    
                    items = results.get('files', [])
                    all_files.extend(items)
                    
                    # Calculate speed and ETA
                    elapsed = time.time() - scan_start_time
                    if elapsed > 0:
                        speed = len(all_files) / elapsed
                        self.scan_progress['speed'] = f"{speed:.1f} files/sec"
                    
                    self.scan_progress['current'] = len(all_files)
                    self.scan_progress['message'] = f'📥 Fetched {len(all_files)} files... ({self.scan_progress["speed"]})'
                    
                    if progress_callback:
                        progress_callback(self.scan_progress)
                    
                    page_token = results.get('nextPageToken')
                    if not page_token:
                        break
                        
                except HttpError as e:
                    logger.error(f"Error fetching files: {e}")
                    self.scan_progress['errors'] += 1
                    break
            
            self.scan_progress['total'] = len(all_files)
            self.scan_progress['message'] = '🔗 Building folder hierarchy...'
            if progress_callback:
                progress_callback(self.scan_progress)
            
            self.build_folder_tree(all_files)
            
            self.scan_progress['message'] = '💾 Processing files and permissions...'
            if progress_callback:
                progress_callback(self.scan_progress)
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM files")
            cursor.execute("DELETE FROM permissions")
            
            batch_size = 50
            for i, file_data in enumerate(all_files):
                try:
                    self.process_file_data(file_data, cursor)
                    
                    if file_data.get('mimeType') == 'application/vnd.google-apps.folder':
                        self.scan_progress['folders_processed'] += 1
                    else:
                        self.scan_progress['files_processed'] += 1
                    
                    self.scan_progress['current'] = i + 1
                    
                    # Calculate ETA
                    elapsed = time.time() - scan_start_time
                    if i > 0 and elapsed > 0:
                        speed = i / elapsed
                        remaining = len(all_files) - i
                        eta_seconds = remaining / speed if speed > 0 else 0
                        eta_minutes = int(eta_seconds / 60)
                        self.scan_progress['eta'] = f"{eta_minutes}m {int(eta_seconds % 60)}s"
                        self.scan_progress['speed'] = f"{speed:.1f} files/sec"
                    
                    self.scan_progress['message'] = (f'⚙️ Processing {i + 1}/{len(all_files)} | '
                                                    f'ETA: {self.scan_progress["eta"]} | '
                                                    f'Speed: {self.scan_progress["speed"]}')
                    
                    if progress_callback and i % 5 == 0:
                        progress_callback(self.scan_progress)
                    
                    if i % batch_size == 0:
                        conn.commit()
                        
                except Exception as e:
                    logger.error(f"Error processing file: {e}")
                    self.scan_progress['errors'] += 1
            
            # Update user analytics
            self.scan_progress['message'] = '👥 Updating user analytics...'
            if progress_callback:
                progress_callback(self.scan_progress)
            
            self.update_user_analytics(cursor)
            
            # Detect duplicates
            self.scan_progress['message'] = '🔄 Detecting duplicate files...'
            if progress_callback:
                progress_callback(self.scan_progress)
            
            self.detect_duplicates(cursor)
            
            scan_duration = time.time() - scan_start_time
            cursor.execute("""
                INSERT INTO session_metadata (user_email, session_start, total_files_scanned, scan_duration_seconds)
                VALUES (?, ?, ?, ?)
            """, (self.user_email, datetime.now().isoformat(), len(all_files), scan_duration))
            
            conn.commit()
            conn.close()
            
            self.scan_progress.update({
                'status': 'completed',
                'message': (f'✅ Scan Complete! {self.scan_progress["files_processed"]} files, '
                          f'{self.scan_progress["folders_processed"]} folders, '
                          f'{self.scan_progress["errors"]} errors in {int(scan_duration)}s')
            })
            
            if progress_callback:
                progress_callback(self.scan_progress)
            
            logger.info(f"Scan completed in {scan_duration:.2f}s")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            traceback.print_exc()
            self.scan_progress.update({
                'status': 'error',
                'message': f'❌ Scan failed: {str(e)}'
            })
            if progress_callback:
                progress_callback(self.scan_progress)
    
    def build_folder_tree(self, files_data):
        """Build folder hierarchy and full paths"""
        folder_map = {}
        path_cache = {}
        
        for file_data in files_data:
            if file_data.get('mimeType') == 'application/vnd.google-apps.folder':
                folder_map[file_data['id']] = {
                    'name': file_data['name'],
                    'parents': file_data.get('parents', [])
                }
        
        def get_full_path(file_id, file_name, parents):
            if file_id in path_cache:
                return path_cache[file_id]
            
            if not parents or len(parents) == 0:
                path_cache[file_id] = f"/{file_name}"
                return f"/{file_name}"
            
            parent_id = parents[0]
            if parent_id in ['root', '0AD9i_UAYhq_-Uk9PVA']:
                path_cache[file_id] = f"/{file_name}"
                return f"/{file_name}"
            
            if parent_id in folder_map:
                parent_path = get_full_path(
                    parent_id,
                    folder_map[parent_id]['name'],
                    folder_map[parent_id]['parents']
                )
                full_path = f"{parent_path}/{file_name}"
                path_cache[file_id] = full_path
                return full_path
            
            path_cache[file_id] = f"/{file_name}"
            return f"/{file_name}"
        
        for file_data in files_data:
            file_id = file_data['id']
            file_name = file_data['name']
            parents = file_data.get('parents', [])
            full_path = get_full_path(file_id, file_name, parents)
            file_data['fullPath'] = full_path
    
    def process_file_data(self, file_data, cursor):
        """Process and store file data with all metadata"""
        try:
            source = 'my_drive' if file_data.get('ownedByMe', False) else 'shared_with_me'
            
            size = file_data.get('size') or file_data.get('quotaBytesUsed') or 0
            
            # Extract ALL hash fields
            md5_hash = file_data.get('md5Checksum')
            sha1_hash = file_data.get('sha1Checksum')
            sha256_hash = file_data.get('sha256Checksum')
            
            parent_id = file_data.get('parents', [None])[0] if file_data.get('parents') else None
            
            # Get owner info
            owner_email = None
            owner_name = None
            owner_photo = None
            owners = file_data.get('owners', [])
            owner_emails_set = set()
            owner_permission_ids = set()
            if owners:
                owner_email = owners[0].get('emailAddress')
                owner_name = owners[0].get('displayName')
                owner_photo = owners[0].get('photoLink')
                for owner in owners:
                    email_val = (owner.get('emailAddress') or '').lower()
                    if email_val:
                        owner_emails_set.add(email_val)
                    perm_id = owner.get('permissionId')
                    if perm_id:
                        owner_permission_ids.add(perm_id)
            
            # Check if shortcut
            is_shortcut = file_data.get('mimeType') == 'application/vnd.google-apps.shortcut'
            shortcut_target_id = None
            if is_shortcut:
                shortcut_details = file_data.get('shortcutDetails', {})
                shortcut_target_id = shortcut_details.get('targetId')
            
            permissions = [dict(p) for p in (file_data.get('permissions') or [])]

            is_public = any(
                perm.get('type') == 'anyone' and not perm.get('deleted', False)
                for perm in permissions
            )

            viewer_email = (self.user_email or '').lower() if self.user_email else None
            viewer_has_explicit_permission = False
            if viewer_email:
                for perm in permissions:
                    perm_email = (perm.get('emailAddress') or '').lower()
                    if perm_email and perm_email == viewer_email:
                        viewer_has_explicit_permission = True
                        break

            def _perm_matches_owner(perm: Dict) -> bool:
                perm_role = (perm.get('role') or '').lower()
                perm_email = (perm.get('emailAddress') or '').lower()
                perm_id = perm.get('id')
                if perm_role != 'owner':
                    return False
                if perm_email and perm_email in owner_emails_set:
                    return True
                if perm_id and perm_id in owner_permission_ids:
                    return True
                return False

            owner_only_permissions = (
                not permissions or all(_perm_matches_owner(perm) for perm in permissions)
            )

            inferred_public = (
                not is_public
                and not file_data.get('ownedByMe', False)
                and owner_only_permissions
                and (not viewer_email or not viewer_has_explicit_permission)
            )

            if inferred_public:
                is_public = True
                file_data['inferredPublicLink'] = True
                file_data['inferredPublicReason'] = 'owner_only_permissions_missing_viewer'
            
            mime_type = file_data.get('mimeType', '')
            category = 'folder' if 'folder' in mime_type else 'file'
            
            cursor.execute("""
                INSERT OR REPLACE INTO files (
                    id, name, mime_type, size, created_time, modified_time, trashed, shared,
                    starred, owned_by_me, parent_id, full_path, source, md5_checksum, sha1_checksum,
                    sha256_checksum, web_view_link, thumbnail_link, version, viewed_by_me,
                    metadata_json, last_scan, file_category, file_extension, can_download,
                    owner_email, owner_name, owner_photo, is_shortcut, shortcut_target_id, is_public
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_data['id'],
                file_data['name'],
                file_data.get('mimeType'),
                int(size) if size else 0,
                file_data.get('createdTime'),
                file_data.get('modifiedTime'),
                file_data.get('trashed', False),
                file_data.get('shared', False),
                file_data.get('starred', False),
                file_data.get('ownedByMe', False),
                parent_id,
                file_data.get('fullPath', ''),
                source,
                md5_hash,
                sha1_hash,
                sha256_hash,
                file_data.get('webViewLink'),
                file_data.get('thumbnailLink'),
                file_data.get('version'),
                file_data.get('viewedByMe', False),
                json.dumps(file_data, default=str),
                datetime.now().isoformat(),
                category,
                os.path.splitext(file_data.get('name', ''))[1].lower().lstrip('.'),
                file_data.get('capabilities', {}).get('canDownload', False),
                owner_email,
                owner_name,
                owner_photo,
                is_shortcut,
                shortcut_target_id,
                is_public
            ))
            
            # Store permissions
            seen_emails = set()

            for perm in permissions:
                email = perm.get('emailAddress', '')
                if not email:
                    email = perm.get('id', '')  # Use permission ID for anyone/domain
                
                if email and email not in seen_emails:
                    seen_emails.add(email)
                    cursor.execute("""
                        INSERT OR REPLACE INTO permissions (
                            file_id, permission_id, type, role, email_address, display_name,
                            photo_link, deleted, pending_owner
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        file_data['id'],
                        perm.get('id'),
                        perm.get('type'),
                        perm.get('role'),
                        perm.get('emailAddress') or perm.get('type', 'unknown'),
                        perm.get('displayName') or perm.get('type', 'Unknown'),
                        perm.get('photoLink'),
                        perm.get('deleted', False),
                        perm.get('pendingOwner', False)
                    ))
            
            # Add owners to permissions if not already there
            for owner in owners:
                email = owner.get('emailAddress', '')
                if email and email not in seen_emails:
                    seen_emails.add(email)
                    cursor.execute("""
                        INSERT OR REPLACE INTO permissions (
                            file_id, permission_id, type, role, email_address, display_name,
                            photo_link, deleted, pending_owner
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        file_data['id'],
                        owner.get('permissionId'),
                        'user',
                        'owner',
                        owner.get('emailAddress'),
                        owner.get('displayName'),
                        owner.get('photoLink'),
                        False,
                        False
                    ))
            
        except Exception as e:
            logger.error(f"Error processing file data: {e}")
            traceback.print_exc()
            raise

    def _combine_permissions(self, file_data: Dict) -> List[Dict]:
        """Ensure we capture public link permissions even for files we don't own."""
        permissions = [dict(p) for p in (file_data.get('permissions') or [])]
        has_public = any(p.get('type') == 'anyone' for p in permissions)
        owned_by_me = file_data.get('ownedByMe', False)

        if owned_by_me or has_public or not self.service:
            return permissions

        try:
            response = self.api_request_with_logging(
                self.service.permissions().list,
                'permissions.list',
                f"drive/v3/files/{file_data['id']}/permissions",
                fileId=file_data['id'],
                fields='permissions(id,type,role,emailAddress,displayName,photoLink,deleted,pendingOwner,allowFileDiscovery)',
                supportsAllDrives=True
            )
            extra_permissions = response.get('permissions', [])
            merged: Dict[str, Dict] = {perm.get('id') or perm.get('emailAddress') or str(idx): perm for idx, perm in enumerate(permissions)}
            for idx, perm in enumerate(extra_permissions, start=len(merged)):
                key = perm.get('id') or perm.get('emailAddress') or f"extra_{idx}"
                merged[key] = perm
            return list(merged.values())
        except Exception as exc:
            logger.debug(f"Permission fetch fallback failed for {file_data.get('id')}: {exc}")
            return permissions
    
    
    def detect_duplicates(self, cursor):
        """Detect duplicate files (same name + same path + different hash)"""
        try:
            # Find files with same name and path
            cursor.execute("""
                SELECT full_path, name, COUNT(*) as count
                FROM files
                WHERE trashed = 0 AND mime_type != 'application/vnd.google-apps.folder'
                GROUP BY full_path, name
                HAVING count > 1
            """)
            
            duplicates = cursor.fetchall()
            
            for full_path, name, count in duplicates:
                # Get all files with this path/name
                cursor.execute("""
                    SELECT id, md5_checksum, sha1_checksum, sha256_checksum
                    FROM files
                    WHERE full_path = ? AND name = ? AND trashed = 0
                """, (full_path, name))
                
                files = cursor.fetchall()
                hashes = set()
                
                # Check if they have different hashes
                for file_id, md5, sha1, sha256 in files:
                    hash_val = sha256 or sha1 or md5
                    if hash_val:
                        hashes.add(hash_val)
                
                # If multiple different hashes, mark as duplicates
                if len(hashes) > 1:
                    # Mark all files in this group as duplicates
                    for file_id, _, _, _ in files:
                        cursor.execute("""
                            UPDATE files SET metadata_json = json_set(metadata_json, '$.is_duplicate', 'true')
                            WHERE id = ?
                        """, (file_id,))
            
        except Exception as e:
            logger.error(f"Error detecting duplicates: {e}")
    
    def update_user_analytics(self, cursor):
        """Update user analytics"""
        try:
            cursor.execute("DELETE FROM user_analytics")
            
            cursor.execute("""
                SELECT DISTINCT owner_email, owner_name, owner_photo
                FROM files
                WHERE owner_email IS NOT NULL
            """)
            
            users = cursor.fetchall()
            
            for email, name, photo in users:
                cursor.execute("""
                    SELECT COUNT(*) FROM files
                    WHERE owner_email = ? AND trashed = 0
                """, (email,))
                owned_count = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(DISTINCT p.file_id)
                    FROM permissions p
                    JOIN files f ON p.file_id = f.id
                    WHERE p.email_address = ? AND p.role != 'owner' AND f.owned_by_me = 0 AND f.trashed = 0
                """, (email,))
                shared_with_count = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(DISTINCT f.id)
                    FROM files f
                    WHERE f.owner_email = ? AND f.shared = 1 AND f.trashed = 0
                """, (email,))
                shared_by_count = cursor.fetchone()[0]
                
                cursor.execute("""
                    INSERT INTO user_analytics
                    (email_address, display_name, photo_link, files_owned_count,
                     files_shared_with_count, files_shared_by_count, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    email, name, photo,
                    owned_count, shared_with_count, shared_by_count,
                    datetime.now().isoformat()
                ))
            
        except Exception as e:
            logger.error(f"Error updating user analytics: {e}")
            traceback.print_exc()

    def get_user_analytics(self, search_query: str = '', limit: Optional[int] = None) -> List[Dict[str, object]]:
        """Fetch cached user analytics rows."""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            params: List[object] = []
            where_clause = ""
            if search_query:
                like_term = f"%{search_query}%"
                where_clause = "WHERE display_name LIKE ? OR email_address LIKE ?"
                params.extend([like_term, like_term])
            order_clause = "ORDER BY (files_owned_count + files_shared_with_count + files_shared_by_count) DESC"
            limit_clause = f" LIMIT {int(limit)}" if limit else ""
            query = f"SELECT * FROM user_analytics {where_clause} {order_clause} {limit_clause}".strip()
            cursor.execute(query, params)
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as exc:
            logger.error(f"Error fetching user analytics: {exc}")
            return []
    
    def get_file_revisions(self, file_id):
        """Fetch all file revisions"""
        try:
            if not self.service:
                raise Exception("Not authenticated")
            
            revisions = self.api_request_with_logging(
                self.service.revisions().list,
                'revisions.list',
                f'drive/v3/files/{file_id}/revisions',
                fileId=file_id,
                fields='revisions(id, modifiedTime, size, md5Checksum, originalFilename, '
                      'mimeType, lastModifyingUser, keepForever, published)'
            )
            
            # Store revisions in DB
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM revisions WHERE file_id = ?", (file_id,))
            
            for rev in revisions.get('revisions', []):
                cursor.execute("""
                    INSERT INTO revisions (
                        file_id, revision_id, modified_time, size, md5_checksum,
                        original_filename, mime_type, modified_by_email, modified_by_name,
                        keep_forever, published
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    file_id,
                    rev.get('id'),
                    rev.get('modifiedTime'),
                    rev.get('size'),
                    rev.get('md5Checksum'),
                    rev.get('originalFilename'),
                    rev.get('mimeType'),
                    rev.get('lastModifyingUser', {}).get('emailAddress'),
                    rev.get('lastModifyingUser', {}).get('displayName'),
                    rev.get('keepForever', False),
                    rev.get('published', False)
                ))
            
            conn.commit()
            conn.close()
            
            return revisions.get('revisions', [])
            
        except HttpError as e:
            logger.error(f"Error fetching revisions: {e}")
            return []
    
    def download_file(self, file_id, file_name, mime_type, save_path=None, progress_callback: Optional[Callable[[float], None]] = None):
        """Download file with hash verification"""
        try:
            if not self.service:
                raise Exception("Not authenticated")
            
            file_name = sanitize_filename(file_name)
            export_ext = None
            if mime_type.startswith('application/vnd.google-apps'):
                export_formats = {
                    'application/vnd.google-apps.document': ('application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.docx'),
                    'application/vnd.google-apps.spreadsheet': ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.xlsx'),
                    'application/vnd.google-apps.presentation': ('application/vnd.openxmlformats-officedocument.presentationml.presentation', '.pptx'),
                }
                
                if mime_type in export_formats:
                    export_mime, ext = export_formats[mime_type]
                    request_obj = self.service.files().export_media(
                        fileId=file_id,
                        mimeType=export_mime
                    )
                    export_ext = ext
                    file_name = os.path.splitext(file_name)[0] + ext
                else:
                    raise Exception(f'Unsupported Google Workspace file type: {mime_type}')
            else:
                request_obj = self.service.files().get_media(fileId=file_id)
            
            file_buffer = io.BytesIO()
            downloader = MediaIoBaseDownload(file_buffer, request_obj)
            
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status and progress_callback:
                    try:
                        progress_callback(max(0.0, min(1.0, status.progress() or 0.0)))
                    except Exception:
                        pass
            
            file_buffer.seek(0)
            if progress_callback:
                try:
                    progress_callback(1.0)
                except Exception:
                    pass
            
            # Determine save path
            if not save_path:
                save_path = os.path.join(DOWNLOAD_DIR, file_name)
            elif os.path.isdir(save_path):
                save_path = os.path.join(save_path, file_name)
            else:
                # Caller supplied a full file path; ensure exported apps end with correct extension
                if export_ext:
                    base_no_ext = os.path.splitext(save_path)[0]
                    save_path = base_no_ext + export_ext
            ensure_directory(os.path.dirname(save_path))
            
            # Handle existing files (don't overwrite)
            base, ext = os.path.splitext(save_path)
            counter = 1
            final_path = save_path
            while os.path.exists(final_path):
                final_path = f"{base}_{counter}{ext}"
                counter += 1
            
            ensure_directory(os.path.dirname(final_path))
            with open(final_path, 'wb') as f:
                f.write(file_buffer.read())
            
            logger.info(f"Downloaded: {file_name} to {final_path}")
            return final_path
            
        except Exception as e:
            logger.error(f"Error downloading file: {e}")
            raise
    
    def get_all_users(self):
        """Get list of all users from DB"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT DISTINCT owner_email, owner_name, owner_photo
                FROM files 
                WHERE owner_email IS NOT NULL
                ORDER BY owner_name
            """)
            
            users = cursor.fetchall()
            conn.close()
            
            return users
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []


# Due to character limits, I'll continue in the next part...
"""
PART 2: ForensicsApp UI Class - Professional Interface
Complete with all filters, export queue, context menu, and more
"""

class ForensicsApp:
    """Main Flet application with complete professional UI"""
    
    def __init__(self, page: ft.Page):
        self.page = page
        self.forensics = GoogleDriveForensics()
        self.current_folder_id = None
        self.current_filter = 'all'
        self.search_query = ''
        self.selected_user_filter = None
        self.user_filter_label = None
        self.user_filter_labels: Dict[str, str] = {"all": "All Users"}
        self.user_search_query = ''
        self.owner_filter = 'all'
        self.show_starred_only = False
        self.include_trashed = False
        self.show_public_only = False
        self.sort_by = 'name_asc'
        self.date_from = None
        self.date_to = None
        self.selected_timezone = 'UTC'
        self.export_queue = []
        self.skip_all_shortcuts = False
        self.thumbnail_cache: Dict[str, Optional[str]] = {}
        self.avatar_cache: Dict[str, Optional[str]] = {}
        self.current_page = 1
        self.total_pages = 1
        self.total_items = 0
        self.per_page = 50
        self.folder_stack: List[Tuple[str, str]] = []
        self.pending_file_picker_action: Optional[Callable[[Optional[str]], None]] = None
        self.queue_badge: Optional[ft.Badge] = None
        self.status_summary_text: Optional[ft.Text] = None
        self.pagination_text: Optional[ft.Text] = None
        self.prev_page_button: Optional[ft.IconButton] = None
        self.next_page_button: Optional[ft.IconButton] = None
        self.per_page_dropdown: Optional[ft.Dropdown] = None
        self.breadcrumb_row: Optional[ft.Row] = None
        self.view_mode = "tiles"
        self.filter_summary_text: Optional[ft.Text] = None
        self.tile_view_button: Optional[ft.TextButton] = None
        self.list_view_button: Optional[ft.TextButton] = None
        self._date_dialog_from_label: Optional[ft.Text] = None
        self._date_dialog_to_label: Optional[ft.Text] = None
        self.sidebar_collapsed = False
        self.side_panel: Optional[ft.Container] = None
        self.sidebar_toggle_button: Optional[ft.IconButton] = None
        self.results_container: Optional[ft.Column] = None
        self.browse_filters_panel: Optional[ft.Container] = None
        self.advanced_filters_header_icon: Optional[ft.Icon] = None
        self.advanced_filters_body: Optional[ft.Container] = None
        self.advanced_filters_expanded = False
        self.browse_scope_filter = 'all'
        self.browse_type_filter: set[str] = set()
        self.scope_radio_group: Optional[ft.RadioGroup] = None
        self.type_checkboxes: Dict[str, ft.Checkbox] = {}
        self._overlay_controls: set[str] = set()
        self.active_dialog: Optional[ft.AlertDialog] = None
        self.current_file_ids: List[str] = []
        self.scan_dialog: Optional[ft.AlertDialog] = None
        self.scan_status_text: Optional[ft.Text] = None
        self.scan_detail_text: Optional[ft.Text] = None
        self.scan_progress_bar: Optional[ft.ProgressBar] = None
        self.scan_running = False
        self.pending_files_reload = False
        self.loading_overlay: Optional[ft.Container] = None
        self.loading_text: Optional[ft.Text] = None
        self.user_search_field: Optional[ft.TextField] = None
        self.user_search_focus_pending = False
        self.pending_files_message: Optional[str] = None
        self._user_search_debounce: Optional[threading.Timer] = None
        self._file_search_debounce: Optional[threading.Timer] = None
        self.file_search_field: Optional[ft.TextField] = None
        self._path_cache: Dict[str, List[str]] = {}
        self.selection_mode = False
        self.selected_file_ids: set[str] = set()
        self.add_selected_button: Optional[ft.IconButton] = None
        self._active_export_cancel_event: Optional[threading.Event] = None
        
        # File picker
        self.file_picker = ft.FilePicker(on_result=self.on_file_picker_result)
        self._add_overlay(self.file_picker)
        self.date_from_picker = ft.DatePicker(
            first_date=datetime(2000, 1, 1),
            last_date=datetime(2035, 12, 31),
            on_change=self._handle_date_from_change
        )
        self.date_to_picker = ft.DatePicker(
            first_date=datetime(2000, 1, 1),
            last_date=datetime(2035, 12, 31),
            on_change=self._handle_date_to_change
        )
        self._add_overlay(self.date_from_picker)
        self._add_overlay(self.date_to_picker)
        
        self.setup_page()
        self.check_authentication()

    def _add_overlay(self, control: ft.Control):
        """Add overlay control once"""
        key = getattr(control, "__hash__", None)
        identifier = str(id(control)) if key is None else str(hash(control))
        if identifier not in self._overlay_controls:
            self.page.overlay.append(control)
            self._overlay_controls.add(identifier)

    def _ensure_loading_overlay(self):
        if self.loading_overlay:
            return
        self.loading_text = ft.Text("", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)
        overlay_body = ft.Container(
            content=ft.Column([
                ft.ProgressRing(width=48, height=48, stroke_width=4, color=ft.Colors.WHITE),
                self.loading_text,
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=14),
            alignment=ft.alignment.center,
            expand=True
        )
        self.loading_overlay = ft.Container(
            content=ft.GestureDetector(on_tap=lambda e: None, content=overlay_body),
            bgcolor=ft.Colors.BLACK54,
            expand=True,
            visible=False
        )
        self.page.overlay.append(self.loading_overlay)
        self._overlay_controls.add(str(id(self.loading_overlay)))

    def _set_loading(self, active: bool, message: str = "Loading..."):
        self._ensure_loading_overlay()
        if not self.loading_overlay or not self.loading_text:
            return
        if active:
            self.loading_text.value = message
            self.loading_overlay.visible = True
        else:
            self.loading_overlay.visible = False
        try:
            self.loading_text.update()
            self.loading_overlay.update()
        except Exception:
            pass

    def _show_results_transition(self, message: str = "Loading…"):
        if not self.results_container:
            return
        transition = ft.Container(
            content=ft.Column([
                ft.ProgressRing(width=54, height=54, stroke_width=4, color=ft.Colors.BLUE_500),
                ft.Text(message, size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_GREY_800),
                ft.Text("Please wait while we refresh the view", size=11, color=ft.Colors.BLUE_GREY_500)
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
            alignment=ft.alignment.center,
            padding=ft.padding.symmetric(vertical=30, horizontal=60),
            bgcolor=ft.Colors.WHITE,
            border=ft.border.all(1, ft.Colors.BLUE_100),
            border_radius=18
        )
        self.results_container.controls = [transition]
        try:
            self.results_container.update()
        except Exception:
            pass

    def _run_with_loading(self, message: str, action: Callable[[], None], show_transition: bool = True):
        if show_transition:
            self._show_results_transition(message)
        self._set_loading(True, message)
        try:
            action()
        finally:
            self._set_loading(False)

    def _is_on_files_tab(self) -> bool:
        return not self.tabs or self.tabs.selected_index == 0

    def _is_on_users_tab(self) -> bool:
        return bool(self.tabs) and self.tabs.selected_index == 1

    def _reload_files_if_visible(self, message: Optional[str] = None, force: bool = False):
        display_message = message or "Loading files…"
        if force or self._is_on_files_tab():
            self.pending_files_reload = False
            self.pending_files_message = None
            self._run_with_loading(display_message, self.load_files)
        else:
            self.pending_files_reload = True
            self.pending_files_message = display_message
            if message:
                self.show_snackbar(f"{message} (will apply on Files tab)")
            else:
                self.show_snackbar("Updates queued. Switch to Files tab to view results.")

    def _update_files_tab_visibility(self):
        on_files = self._is_on_files_tab()
        if self.browse_filters_panel:
            self.browse_filters_panel.visible = on_files
            try:
                self.browse_filters_panel.update()
            except Exception:
                pass
        if self.breadcrumb_row:
            self.breadcrumb_row.visible = on_files
            try:
                self.breadcrumb_row.update()
            except Exception:
                pass
        self._update_advanced_filters_display()

    def _update_advanced_filters_display(self):
        if self.advanced_filters_body:
            self.advanced_filters_body.visible = self.advanced_filters_expanded and self._is_on_files_tab()
            try:
                self.advanced_filters_body.update()
            except Exception:
                pass
        if not self.advanced_filters_header_icon:
            return
        self.advanced_filters_header_icon.name = ft.Icons.REMOVE if self.advanced_filters_expanded else ft.Icons.ADD
        try:
            self.advanced_filters_header_icon.update()
        except Exception:
            pass

    def toggle_advanced_filters(self, e=None):
        self.advanced_filters_expanded = not self.advanced_filters_expanded
        self._update_advanced_filters_display()

    def _handle_scope_radio_change(self, e: ft.ControlEvent):
        value = e.control.value or 'all'
        self._apply_scope_filter(value)

    def _apply_scope_filter(self, value: str):
        if value == self.browse_scope_filter:
            return
        self.browse_scope_filter = value
        if self.scope_radio_group and self.scope_radio_group.value != value:
            self.scope_radio_group.value = value
            try:
                self.scope_radio_group.update()
            except Exception:
                pass
        self.reset_to_first_page()
        label = "folders" if value == 'folders' else "files" if value == 'files' else "items"
        self._reload_files_if_visible(f"Showing {label}…")

    def _handle_type_checkbox_change(self, value: str, checked: bool):
        if checked:
            if value in self.browse_type_filter:
                return
            self.browse_type_filter.add(value)
        else:
            if value not in self.browse_type_filter:
                return
            self.browse_type_filter.remove(value)
        self.reset_to_first_page()
        self._reload_files_if_visible("Updating file type filter…")

    def clear_advanced_filters(self, e=None):
        self.browse_scope_filter = 'all'
        self.browse_type_filter.clear()
        self._refresh_advanced_filter_controls()
        self.reset_to_first_page()
        self._reload_files_if_visible("Clearing advanced filters…")
        if e is not None:
            self.show_snackbar("Advanced filters reset")

    def _refresh_advanced_filter_controls(self):
        if self.scope_radio_group and self.scope_radio_group.value != self.browse_scope_filter:
            self.scope_radio_group.value = self.browse_scope_filter
            try:
                self.scope_radio_group.update()
            except Exception:
                pass
        for value, checkbox in self.type_checkboxes.items():
            desired = value in self.browse_type_filter
            if checkbox.value != desired:
                checkbox.value = desired
                try:
                    checkbox.update()
                except Exception:
                    pass

    def _get_type_filter_clause(self) -> Tuple[str, List[str]]:
        if not self.browse_type_filter:
            return "", []
        clauses = []
        params: List[str] = []

        def add_clause(sql: str, values: List[str]):
            clauses.append(sql)
            params.extend(values)

        for value in sorted(self.browse_type_filter):
            if value == 'docs':
                add_clause("mime_type = ?", ['application/vnd.google-apps.document'])
            elif value == 'sheets':
                add_clause("mime_type = ?", ['application/vnd.google-apps.spreadsheet'])
            elif value == 'slides':
                add_clause("mime_type = ?", ['application/vnd.google-apps.presentation'])
            elif value == 'forms':
                add_clause("mime_type = ?", ['application/vnd.google-apps.form'])
            elif value == 'shortcuts':
                add_clause("mime_type = ?", ['application/vnd.google-apps.shortcut'])
            elif value == 'pdf':
                add_clause("mime_type = ?", ['application/pdf'])
            elif value == 'images':
                add_clause("mime_type LIKE ?", ['image/%'])
            elif value == 'videos':
                add_clause("mime_type LIKE ?", ['video/%'])
            elif value == 'audio':
                add_clause("mime_type LIKE ?", ['audio/%'])
            elif value == 'archives':
                add_clause("mime_type IN (?,?,?)", ['application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed'])

        if not clauses:
            return "", []
        joined = "(" + " OR ".join(clauses) + ")"
        return joined, params

    def copy_to_clipboard(self, text: str, toast: str = "Copied to clipboard"):
        if not text:
            self.show_snackbar("Nothing to copy")
            return
        try:
            if hasattr(self.page, "set_clipboard"):
                self.page.set_clipboard(text)
                self.show_snackbar(toast)
            else:
                raise RuntimeError("Clipboard not supported in this environment")
        except Exception as exc:
            logger.error(f"Clipboard copy failed: {exc}")
            self.show_error(f"Could not copy text: {exc}")

    def _dispatch_ui(self, func: Callable, *args, **kwargs):
        """Run UI mutations on the main Flet thread"""
        def runner():
            try:
                func(*args, **kwargs)
            except Exception as exc:
                logger.debug(f"UI dispatch error: {exc}")

        try:
            if hasattr(self.page, "invoke_later"):
                self.page.invoke_later(runner)
            else:
                runner()
        except Exception as exc:
            logger.debug(f"invoke_later unavailable: {exc}")
            runner()

    def _focus_first_control(self, container: ft.Control):
        try:
            if hasattr(container, "controls") and container.controls:
                first = container.controls[0]
                if hasattr(first, "focus"):
                    first.focus()
        except Exception:
            pass

    def _show_dialog(self, dialog: ft.AlertDialog):
        """Present dialog via overlay"""
        self.close_dialog()
        self.active_dialog = dialog
        if dialog not in self.page.overlay:
            self.page.overlay.append(dialog)
        dialog.open = True
        try:
            self.page.update()
        except Exception:
            pass

    def setup_page(self):
        """Configure page settings"""
        self.page.title = "Google Drive Forensics Suite"
        self.page.window_icon = "assets/logo.png"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 0
        self.page.window_width = 1600
        self.page.window_height = 950
        self.page.window_resizable = True
        self.page.bgcolor = ft.Colors.GREY_50
    
    def check_authentication(self):
        """Check authentication status"""
        creds = self.forensics.get_credentials()
        
        if not creds:
            self.show_login_screen()
        else:
            self.show_main_ui()
    
    def show_login_screen(self):
        """Display OAuth login screen"""
        
        def start_oauth(e):
            flow = Flow.from_client_secrets_file(
                CLIENT_SECRETS_FILE,
                scopes=SCOPES,
                redirect_uri='http://localhost:8080/oauth2callback'
            )
            
            auth_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'
            )
            
            local_ip = self.get_local_ip()
            
            url_text.value = f"""
🔗 OAuth Redirect URLs (Copy one to Google Cloud Console):

• Local: http://localhost:8080/oauth2callback
• Internal IP: http://{local_ip}:8080/oauth2callback  

📋 Authorization URL (Opens automatically):
{auth_url}
            """
            url_text.update()
            
            threading.Thread(target=self.run_oauth_server, args=(flow, state), daemon=True).start()
            webbrowser.open(auth_url)
        
        url_text = ft.Text(
            "Click 'Start OAuth Login' to begin authentication",
            size=14,
            selectable=True,
            color=ft.Colors.GREY_700
        )
        
        login_container = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.FOLDER_SPECIAL, size=64, color=ft.Colors.BLUE_700),
                    ft.Column([
                        ft.Text("Google Drive Forensics Suite", size=36, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_900),
                        ft.Text("Professional Digital Forensics Tool", size=18, color=ft.Colors.GREY_700),
                    ], spacing=5)
                ], spacing=20),
                ft.Divider(height=40, color=ft.Colors.TRANSPARENT),
                ft.ElevatedButton(
                    "Start OAuth Login",
                    icon=ft.Icons.LOGIN,
                    on_click=start_oauth,
                    style=ft.ButtonStyle(
                        color=ft.Colors.WHITE,
                        bgcolor=ft.Colors.BLUE_700,
                        padding=20,
                    ),
                    height=60,
                    width=250
                ),
                ft.Container(
                    content=url_text,
                    padding=25,
                    bgcolor=ft.Colors.BLUE_50,
                    border_radius=10,
                    width=800,
                    border=ft.border.all(2, ft.Colors.BLUE_200)
                ),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=25),
            padding=50,
            alignment=ft.alignment.center,
            expand=True
        )
        
        self.page.add(login_container)
        self.page.update()
    
    def get_local_ip(self):
        """Get local IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def run_oauth_server(self, flow, state):
        """Run OAuth callback server"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class OAuthHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(handler_self):
                if '/oauth2callback' in handler_self.path:
                    from urllib.parse import parse_qs, urlparse
                    query_params = parse_qs(urlparse(handler_self.path).query)
                    
                    if 'code' in query_params:
                        code = query_params['code'][0]
                        
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        
                        self.forensics.save_credentials(creds)
                        self.forensics.credentials = creds
                        self.forensics.service = build('drive', 'v3', credentials=creds)
                        
                        try:
                            about = self.forensics.service.about().get(fields='user').execute()
                            self.forensics.user_email = about['user']['emailAddress']
                        except:
                            pass
                        
                        handler_self.send_response(200)
                        handler_self.send_header('Content-type', 'text/html; charset=utf-8')
                        handler_self.end_headers()
                        html_content = '''
<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: Arial; text-align: center; padding: 50px;">
    <h1 style="color: #4CAF50;">Authentication Successful!</h1>
    <p style="font-size: 18px;">You can close this window and return to the app.</p>
</body>
</html>
                        '''
                        handler_self.wfile.write(html_content.encode('utf-8'))
                        
                        self.page.clean()
                        self.show_main_ui()
                        
                        threading.Thread(target=server.shutdown, daemon=True).start()
        
        server = HTTPServer(('', 8080), OAuthHandler)
        server.serve_forever()
    
    def show_main_ui(self):
        """Display main UI with all features"""
        
        self.sidebar_toggle_button = ft.IconButton(
            icon=ft.Icons.MENU_OPEN,
            tooltip="Toggle filters",
            icon_size=18,
            icon_color=ft.Colors.WHITE,
            on_click=self.toggle_sidebar,
            style=ft.ButtonStyle(padding=0)
        )

        interface_guide = "\n".join([
            "🧠 GDrive Forensics Suite — files, users, analytics in one screen.",
            "🧭 Header: switch timezone, view signed-in account, logout.",
            "🎛️ Left rail: stacked filters & quick toggles for scope, owners, dates.",
            "📚 Tabs: Files / Users / Analytics switch the center canvas.",
            "📂 Results grid: tiles or list with badges for public, duplicates, shortcuts.",
            "🗃️ Queue bar: add selections, export filtered sets, refresh thumbnails.",
            "📉 Footer: live status, active download/ export progress, pagination controls."
        ])
        header_info = ft.IconButton(
            icon=ft.Icons.INFO_OUTLINE,
            icon_color=ft.Colors.WHITE,
            tooltip=interface_guide,
            icon_size=16,
            style=ft.ButtonStyle(padding=0)
        )

        logo_image = ft.Image(src="/logo.png", width=24, height=24, fit=ft.ImageFit.CONTAIN)

        header = ft.Container(
            content=ft.Row([
                ft.Row([
                    logo_image,
                    ft.Text("GDrive Forensics", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                    header_info
                ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Row([
                    self.sidebar_toggle_button,
                    ft.Dropdown(
                        options=[
                            ft.dropdown.Option("UTC", "UTC"),
                            ft.dropdown.Option("Asia/Kolkata", "IST (Asia/Kolkata)"),
                            ft.dropdown.Option("America/New_York", "EST (America/New_York)"),
                            ft.dropdown.Option("America/Los_Angeles", "PST (America/Los_Angeles)"),
                            ft.dropdown.Option("Europe/London", "GMT (Europe/London)"),
                        ],
                        value="UTC",
                        width=150,
                        dense=True,
                        bgcolor=ft.Colors.WHITE,
                        on_change=self.change_timezone,
                        content_padding=ft.padding.symmetric(4, 0)
                    ),
                    ft.Text(self.forensics.user_email or "User", size=11, color=ft.Colors.WHITE),
                    ft.IconButton(
                        icon=ft.Icons.LOGOUT,
                        tooltip="Logout",
                        on_click=self.logout,
                        icon_color=ft.Colors.WHITE,
                        icon_size=16,
                        style=ft.ButtonStyle(padding=0)
                    )
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=ft.Colors.BLUE_700,
            padding=ft.padding.symmetric(6, 12)
        )
        
        # FILTERS & QUICK TOGGLES
        self.filter_dropdown = ft.Dropdown(
            label="Source",
            options=[
                ft.dropdown.Option("all", "All Files"),
                ft.dropdown.Option("my_drive", "My Drive"),
                ft.dropdown.Option("shared_with_me", "Shared With Me"),
                ft.dropdown.Option("shared_by_me", "Shared By Me"),
            ],
            value="all",
            on_change=self.change_filter,
            width=180,
            dense=True
        )
        
        self.owner_filter_dropdown = ft.Dropdown(
            label="Owner",
            options=[
                ft.dropdown.Option("all", "All Owners"),
                ft.dropdown.Option("me", "Owned by Me"),
                ft.dropdown.Option("others", "Owned by Others"),
            ],
            value="all",
            on_change=self.change_owner_filter,
            width=170,
            dense=True
        )
        
        self.user_filter_dropdown = ft.Dropdown(
            label="User",
            options=[ft.dropdown.Option("all", "All Users")],
            value="all",
            on_change=self.change_user_filter,
            width=240,
            dense=True
        )
        
        self.search_field = ft.TextField(
            label="Search",
            hint_text="Type to search...",
            on_change=self.search_files,
            width=260,
            dense=True,
            prefix_icon=ft.Icons.SEARCH
        )
        self.file_search_field = self.search_field
        
        self.starred_checkbox = ft.Checkbox(
            label="⭐ Starred Only",
            value=False,
            on_change=self.toggle_starred
        )
        
        self.trashed_checkbox = ft.Checkbox(
            label="🗑️ Include Trashed",
            value=False,
            on_change=self.toggle_trashed
        )
        
        self.public_checkbox = ft.Checkbox(
            label="🌐 Public Files Only",
            value=False,
            on_change=self.toggle_public
        )
        
        self.sort_dropdown = ft.Dropdown(
            label="Sort By",
            options=[
                ft.dropdown.Option("name_asc", "Name (A→Z)"),
                ft.dropdown.Option("name_desc", "Name (Z→A)"),
                ft.dropdown.Option("size_desc", "Size (Largest)"),
                ft.dropdown.Option("size_asc", "Size (Smallest)"),
                ft.dropdown.Option("modified_desc", "Modified (Newest)"),
                ft.dropdown.Option("modified_asc", "Modified (Oldest)"),
                ft.dropdown.Option("created_desc", "Created (Newest)"),
                ft.dropdown.Option("created_asc", "Created (Oldest)"),
                ft.dropdown.Option("owner_asc", "Owner (A→Z)"),
            ],
            value="name_asc",
            width=180,
            dense=True,
            on_change=self.change_sort
        )
        
        self.date_filter_button = ft.ElevatedButton(
            "📅 Date Filter",
            icon=ft.Icons.DATE_RANGE,
            on_click=self.show_date_picker
        )
        self.update_date_button_label()

        filter_controls = ft.Column([
            ft.Text("Source", size=12, color=ft.Colors.GREY_600),
            self.filter_dropdown,
            ft.Text("Owner", size=12, color=ft.Colors.GREY_600),
            self.owner_filter_dropdown,
            ft.Text("User", size=12, color=ft.Colors.GREY_600),
            self.user_filter_dropdown,
            ft.Text("Search", size=12, color=ft.Colors.GREY_600),
            self.search_field,
        ], spacing=6)
        quick_filters_bar = ft.Column([
            ft.Text("Quick Filters", size=12, color=ft.Colors.GREY_600),
            ft.Row([
                self.starred_checkbox,
                self.trashed_checkbox,
                self.public_checkbox
            ], wrap=True, spacing=8),
            ft.Divider(height=10),
            ft.Text("Sort & Date", size=12, color=ft.Colors.GREY_600),
            self.sort_dropdown,
            self.date_filter_button
        ], spacing=8)
        
        self.filter_summary_text = ft.Text(self.build_filter_summary(), size=12, color=ft.Colors.GREY_600)
        self.tile_view_button = ft.TextButton(
            "Tiles",
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4)),
            on_click=lambda e: self.change_view_mode("tiles")
        )
        self.list_view_button = ft.TextButton(
            "List",
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4)),
            on_click=lambda e: self.change_view_mode("list")
        )
        self.update_view_mode_buttons()
        
        # ACTION ROW: Scan, Export Queue, Export buttons
        self.queue_badge = ft.Badge(text="0", bgcolor=ft.Colors.RED_700, text_color=ft.Colors.WHITE, small_size=10)
        self.queue_icon_button = ft.IconButton(
            icon=ft.Icons.PLAYLIST_ADD_CHECK,
            tooltip="Export Queue",
            on_click=self.show_export_queue,
            icon_color=ft.Colors.ORANGE_700,
            icon_size=20,
            badge=self.queue_badge,
            style=ft.ButtonStyle(padding=8)
        )

        self.add_page_button = ft.IconButton(
            icon=ft.Icons.SELECT_ALL,
            tooltip="Add current page to queue",
            on_click=self.add_current_page_to_queue,
            icon_color=ft.Colors.TEAL_700,
            icon_size=20,
            style=ft.ButtonStyle(padding=8),
            disabled=True
        )

        self.add_selected_button = ft.IconButton(
            icon=ft.Icons.LIBRARY_ADD,
            tooltip="Add selected files to queue",
            on_click=self.add_selected_to_queue,
            icon_color=ft.Colors.PURPLE_700,
            icon_size=20,
            style=ft.ButtonStyle(padding=8),
            disabled=True
        )

        self.export_filtered_button = ft.IconButton(
            icon=ft.Icons.CLOUD_DOWNLOAD,
            tooltip="Export all filtered results",
            on_click=self.export_filtered_results,
            icon_color=ft.Colors.BLUE_800,
            icon_size=20,
            style=ft.ButtonStyle(padding=8)
        )

        self.selection_toggle_button = ft.IconButton(
            icon=ft.Icons.CHECK_BOX_OUTLINE_BLANK,
            tooltip="Enable multi-select",
            on_click=self.toggle_selection_mode,
            icon_color=ft.Colors.GREY_700,
            icon_size=18,
            style=ft.ButtonStyle(padding=8)
        )

        self.status_summary_text = ft.Text("Ready", size=12, color=ft.Colors.GREY_600)
        self.pagination_text = ft.Text("Page 1/1", size=12, color=ft.Colors.GREY_600)
        self.prev_page_button = ft.IconButton(icon=ft.Icons.CHEVRON_LEFT, on_click=lambda e: self.change_page(-1), disabled=True, icon_size=18)
        self.next_page_button = ft.IconButton(icon=ft.Icons.CHEVRON_RIGHT, on_click=lambda e: self.change_page(1), disabled=True, icon_size=18)
        self.per_page_dropdown = ft.Dropdown(
            width=90,
            dense=True,
            value=str(self.per_page),
            options=[ft.dropdown.Option(str(x)) for x in (25, 50, 100, 250)],
            on_change=lambda e: self.update_per_page(int(e.control.value)),
            content_padding=ft.padding.symmetric(4, 0)
        )
        pagination_controls = ft.Row([
            self.prev_page_button,
            self.pagination_text,
            self.next_page_button,
            ft.Text("Per page", size=11, color=ft.Colors.GREY_600),
            self.per_page_dropdown,
        ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)

        action_toolbar = ft.Container(
            content=ft.Row([
                ft.IconButton(icon=ft.Icons.REFRESH, tooltip="Scan Drive", on_click=self.start_scan, icon_color=ft.Colors.GREEN_700, icon_size=18, style=ft.ButtonStyle(padding=0)),
                ft.IconButton(icon=ft.Icons.IMAGE, tooltip="Refresh thumbnails", on_click=self.refresh_thumbnails, icon_color=ft.Colors.BLUE_700, icon_size=18, style=ft.ButtonStyle(padding=0)),
                self.queue_icon_button,
                self.add_page_button,
                self.add_selected_button,
                self.selection_toggle_button,
                ft.IconButton(icon=ft.Icons.TABLE_CHART, tooltip="Export CSV", on_click=self.export_csv, icon_color=ft.Colors.BLUE_700, icon_size=18, style=ft.ButtonStyle(padding=0)),
                ft.IconButton(icon=ft.Icons.CODE, tooltip="Export JSON", on_click=self.export_json, icon_color=ft.Colors.PURPLE_700, icon_size=18, style=ft.ButtonStyle(padding=0)),
                self.export_filtered_button,
                ft.Text("View", size=12, color=ft.Colors.GREY_600),
                self.tile_view_button,
                self.list_view_button
            ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.padding.symmetric(6, 10),
            bgcolor=ft.Colors.WHITE,
            border=ft.border.only(bottom=ft.border.BorderSide(1, ft.Colors.GREY_200))
        )
        
        self.tabs = ft.Tabs(
            selected_index=0,
            on_change=self.tab_changed,
            tabs=[
                ft.Tab(text="Files"),
                ft.Tab(text="Users"),
                ft.Tab(text="Analytics"),
            ],
            expand=1,
            indicator_color=ft.Colors.BLUE_700,
            tab_alignment=ft.TabAlignment.START,
            height=40
        )
        
        self.breadcrumb_row = ft.Row(spacing=4, wrap=True)
        empty_state = ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.CLOUD_SYNC, size=80, color=ft.Colors.GREY_400),
                ft.Text("Click 'Scan Drive' to begin", size=20, color=ft.Colors.GREY_600, weight=ft.FontWeight.BOLD),
                ft.Text("This will fetch all files from your Google Drive", size=14, color=ft.Colors.GREY_500),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
            padding=80,
            alignment=ft.alignment.center
        )

        initial_state = ft.Container(
            content=ft.Column([
                ft.ProgressRing(width=60, height=60, stroke_width=5),
                ft.Text("Loading files…", size=16, color=ft.Colors.GREY_700)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
            padding=80,
            alignment=ft.alignment.center
        )

        self.results_container = ft.Column([
            initial_state
        ], spacing=12, expand=True)
        self._initial_state_container = initial_state

        scope_options = [
            ("all", "All items"),
            ("folders", "Folders only"),
            ("files", "Files only")
        ]

        scope_radios = [
            ft.Radio(value=value, label=label)
            for value, label in scope_options
        ]
        self.scope_radio_group = ft.RadioGroup(
            value=self.browse_scope_filter,
            content=ft.Column(controls=scope_radios, spacing=6),
            on_change=self._handle_scope_radio_change
        )

        type_options = [
            ("docs", "Google Docs"),
            ("sheets", "Google Sheets"),
            ("slides", "Google Slides"),
            ("forms", "Google Forms"),
            ("shortcuts", "Shortcuts"),
            ("pdf", "PDF"),
            ("images", "Images"),
            ("videos", "Videos"),
            ("audio", "Audio"),
            ("archives", "Archives")
        ]

        self.type_checkboxes = {}
        type_checkbox_controls = []
        for value, label in type_options:
            checkbox = ft.Checkbox(
                label=label,
                value=(value in self.browse_type_filter),
                on_change=lambda e, v=value: self._handle_type_checkbox_change(v, e.control.value)
            )
            self.type_checkboxes[value] = checkbox
            type_checkbox_controls.append(ft.Container(content=checkbox, width=160))

        type_wrap = ft.ResponsiveRow(
            controls=[ft.Container(content=checkbox, col={'xs': 12, 'sm': 6, 'md': 4}) for checkbox in type_checkbox_controls],
            spacing=8,
            run_spacing=4
        )

        self.advanced_filters_header_icon = ft.Icon(ft.Icons.ADD, color=ft.Colors.BLUE_700, size=18)
        header_label = ft.Row([
            self.advanced_filters_header_icon,
            ft.Text("Advanced Filters", weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_800)
        ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        header_toggle = ft.GestureDetector(content=header_label, on_tap=self.toggle_advanced_filters, expand=True)
        header_row = ft.Row([
            header_toggle,
            ft.TextButton("Clear", icon=ft.Icons.CLEAR_ALL, on_click=self.clear_advanced_filters)
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER)

        self.advanced_filters_body = ft.Container(
            content=ft.Column([
                ft.Text("Browse scope", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                self.scope_radio_group,
                ft.Divider(height=8),
                ft.Text("File / service type", size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                type_wrap
            ], spacing=10),
            padding=ft.padding.only(top=4, bottom=4),
            visible=self.advanced_filters_expanded
        )

        self.browse_filters_panel = ft.Container(
            content=ft.Column([
                header_row,
                self.advanced_filters_body
            ], spacing=6),
            bgcolor=ft.Colors.WHITE,
            border=ft.border.all(1, ft.Colors.GREY_200),
            border_radius=10,
            padding=ft.padding.all(12),
            visible=self._is_on_files_tab()
        )

        self.content_area = ft.Column(
            controls=[
                self.breadcrumb_row,
                self.browse_filters_panel,
                self.results_container
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=12
        )
        
        self.activity_status_text = ft.Text("No active downloads", size=11, color=ft.Colors.GREY_500)

        footer_bar = ft.Container(
            content=ft.Row([
                ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINED, size=14, color=ft.Colors.GREY_500),
                        self.status_summary_text
                    ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    self.activity_status_text
                ], spacing=4, expand=True),
                pagination_controls
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.padding.symmetric(6, 10),
            bgcolor=ft.Colors.WHITE,
            border=ft.border.only(top=ft.border.BorderSide(1, ft.Colors.GREY_200))
        )
        self.footer_bar = footer_bar

        tabs_container = ft.Container(content=self.tabs, bgcolor=ft.Colors.WHITE, padding=ft.padding.symmetric(12, 0))

        side_panel = ft.Container(
            width=220,
            bgcolor=ft.Colors.GREY_50,
            padding=ft.padding.Padding(12, 12, 12, 12),
            content=ft.Column([
                ft.Text("Filters", weight=ft.FontWeight.BOLD, size=14),
                ft.Text(self.build_filter_summary(), size=11, color=ft.Colors.GREY_600),
                ft.TextButton("Clear All Filters", icon=ft.Icons.CLOSE, on_click=self.clear_all_filters),
                ft.Divider(height=8),
                filter_controls,
                ft.Divider(height=12),
                quick_filters_bar,
            ], spacing=10, scroll=ft.ScrollMode.AUTO)
        )
        self.side_panel = side_panel

        main_stack = ft.Column([
            action_toolbar,
            tabs_container,
            ft.Container(content=self.content_area, expand=True, bgcolor=ft.Colors.WHITE, padding=ft.padding.Padding(12, 8, 12, 8)),
            footer_bar
        ], spacing=0, expand=True)

        workspace = ft.Row([
            side_panel,
            ft.Container(content=main_stack, expand=True)
        ], expand=True, spacing=0)

        main_content = ft.Column([
            header,
            workspace
        ], spacing=0, expand=True)
        
        self.page.add(main_content)
        self.page.update()
        self._update_files_tab_visibility()

        # Load existing data if available
        self._reload_files_if_visible(force=True)
        self.populate_user_filter()
        self.load_export_queue()
    
    def change_timezone(self, e):
        """Handle timezone change"""
        self.selected_timezone = e.control.value
        self.forensics.timezone = self.selected_timezone
        self._reload_files_if_visible("Updating timezone…")

    def _format_timestamp_for_timezone(self, iso_timestamp: Optional[str]) -> Optional[str]:
        if not iso_timestamp:
            return None
        tz_name = self.selected_timezone or 'UTC'
        try:
            tz = pytz.timezone(tz_name)
        except Exception:
            tz_name = 'UTC'
            tz = pytz.UTC
        try:
            dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00')).astimezone(tz)
        except Exception:
            return iso_timestamp
        offset = dt.utcoffset() or timedelta(0)
        total_minutes = int(offset.total_seconds() // 60)
        sign = '+' if total_minutes >= 0 else '-'
        abs_minutes = abs(total_minutes)
        offset_str = f"UTC{sign}{abs_minutes // 60:02d}:{abs_minutes % 60:02d}"
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({offset_str})"

    def toggle_sidebar(self, e=None):
        self.sidebar_collapsed = not self.sidebar_collapsed
        if self.side_panel:
            self.side_panel.visible = not self.sidebar_collapsed
            self.side_panel.width = 0 if self.sidebar_collapsed else 220
            self.side_panel.update()
        if self.sidebar_toggle_button:
            self.sidebar_toggle_button.icon = ft.Icons.MENU if self.sidebar_collapsed else ft.Icons.MENU_OPEN
            self.sidebar_toggle_button.update()
    
    def populate_user_filter(self):
        """Populate user filter dropdown with thumbnails"""
        users = self.forensics.get_all_users()
        
        options = [ft.dropdown.Option("all", "All Users")]
        self.user_filter_labels = {"all": "All Users"}
        for email, name, photo in users:
            # Format: John Doe (john@example.com)
            display_name = name if name else email
            display = f"👤 {display_name} ({email})"
            options.append(ft.dropdown.Option(email, display))
            if email:
                self.user_filter_labels[email] = display_name or email
        
        self.user_filter_dropdown.options = options
        self.user_filter_dropdown.update()

    def load_export_queue(self):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT file_id FROM export_queue ORDER BY added_time")
            self.export_queue = [row[0] for row in cursor.fetchall()]
            conn.close()
        except Exception as e:
            logger.error(f"Error loading export queue: {e}")
            self.export_queue = []
        self.refresh_queue_badge()

    def pick_directory(self, callback: Callable[[Optional[str]], None]):
        """Open directory picker and invoke callback with selected path"""
        self.pending_file_picker_action = callback
        self.file_picker.get_directory_path()

    def _handle_date_from_change(self, e):
        value = e.control.value
        parsed = value if isinstance(value, date) else None
        if parsed is None and isinstance(value, str) and value:
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d").date()
            except ValueError:
                parsed = None
        self.date_from = parsed
        if self._date_dialog_from_label:
            self._date_dialog_from_label.value = f"Selected: {self.date_from.strftime('%Y-%m-%d') if self.date_from else 'Not set'}"
            self._date_dialog_from_label.update()
        self.update_date_button_label()

    def _handle_date_to_change(self, e):
        value = e.control.value
        parsed = value if isinstance(value, date) else None
        if parsed is None and isinstance(value, str) and value:
            try:
                parsed = datetime.strptime(value, "%Y-%m-%d").date()
            except ValueError:
                parsed = None
        self.date_to = parsed
        if self._date_dialog_to_label:
            self._date_dialog_to_label.value = f"Selected: {self.date_to.strftime('%Y-%m-%d') if self.date_to else 'Not set'}"
            self._date_dialog_to_label.update()
        self.update_date_button_label()

    def refresh_queue_badge(self):
        if self.queue_badge:
            self.queue_badge.text = str(len(self.export_queue))
            try:
                self.queue_badge.update()
            except Exception:
                pass
        if getattr(self, 'queue_icon_button', None):
            self.queue_icon_button.update()

    def get_permissions_payload(self, cursor, file_id: str) -> List[Dict[str, Optional[str]]]:
        cursor.execute(
            """
            SELECT display_name, email_address, role, type, photo_link
            FROM permissions
            WHERE file_id = ?
            ORDER BY role DESC, display_name
            """,
            (file_id,)
        )
        rows = cursor.fetchall()
        payload: List[Dict[str, Optional[str]]] = []
        for display_name, email, role, perm_type, photo in rows:
            payload.append({
                "name": display_name or email or perm_type or "Unknown",
                "email": email,
                "role": role,
                "type": perm_type,
                "photo": photo
            })
        return payload

    def toggle_starred(self, e):
        """Toggle starred filter"""
        self.show_starred_only = e.control.value
        self.reset_to_first_page()
        self._reload_files_if_visible("Applying starred filter…")

    def toggle_trashed(self, e):
        """Toggle trashed filter"""
        self.include_trashed = e.control.value
        self.reset_to_first_page()
        self._reload_files_if_visible("Updating trashed filter…")
    
    def toggle_public(self, e):
        """Toggle public files filter"""
        self.show_public_only = e.control.value
        self.reset_to_first_page()
        self._reload_files_if_visible("Updating public filter…")
    
    def change_owner_filter(self, e):
        """Handle owner filter change"""
        self.owner_filter = e.control.value
        self.reset_to_first_page()
        self._reload_files_if_visible("Changing owner filter…")
    
    def change_user_filter(self, e):
        """Handle user filter change"""
        value = e.control.value
        if value == "all":
            self.clear_user_filter()
            return
        display = self.user_filter_labels.get(value, value)
        self.selected_user_filter = value
        self.user_filter_label = display
        self.reset_to_first_page()
        self._reload_files_if_visible(f"Filtering by {display}…")
        if not self._is_on_files_tab():
            self.show_snackbar("Filter queued. Switch to Files tab to view results.")
    
    def change_filter(self, e):
        """Change source filter"""
        self.current_filter = e.control.value
        self.reset_to_first_page()
        self._reload_files_if_visible("Changing source filter…")
    
    def change_sort(self, e):
        """Change sort order"""
        self.sort_by = e.control.value
        self._reload_files_if_visible()

    
    def search_files(self, e):
        """Search files"""
        value = (e.control.value or '').strip()
        if self._file_search_debounce:
            self._file_search_debounce.cancel()

        def apply_search():
            self.search_query = value
            self.reset_to_first_page()
            self._reload_files_if_visible("Searching files…")

        self._file_search_debounce = threading.Timer(0.3, lambda: self._dispatch_ui(apply_search))
        self._file_search_debounce.start()
    
    def handle_user_search(self, e):
        """Update user search query and refresh users tab"""
        value = (e.control.value or '').strip()
        self.user_search_query = value
        self.user_search_focus_pending = True
        if self._user_search_debounce:
            self._user_search_debounce.cancel()

        def _run():
            self.load_users()

        self._user_search_debounce = threading.Timer(0.25, _run)
        self._user_search_debounce.start()
    
    def clear_user_search(self, e=None):
        self.user_search_query = ''
        self.user_search_focus_pending = True
        if self._user_search_debounce:
            self._user_search_debounce.cancel()
        def _run():
            self.load_users()
        self._user_search_debounce = threading.Timer(0.1, _run)
        self._user_search_debounce.start()
    
    def clear_user_filter(self, e=None):
        self.selected_user_filter = None
        self.user_filter_label = None
        if self.user_filter_dropdown:
            self.user_filter_dropdown.value = "all"
            try:
                self.user_filter_dropdown.update()
            except Exception:
                pass
        self.reset_to_first_page()
        self._reload_files_if_visible("Clearing user filter…")
        if self._is_on_users_tab():
            self.load_users()
        if e is not None:
            self.show_snackbar("Cleared user filter")
    
    def apply_user_filter_from_card(self, email: Optional[str], display_name: Optional[str] = None):
        if not email:
            return
        self.selected_user_filter = email
        self.user_filter_label = display_name or self.user_filter_labels.get(email, email)
        if self.user_filter_dropdown:
            self.user_filter_dropdown.value = email
            try:
                self.user_filter_dropdown.update()
            except Exception:
                pass
        if self.tabs and self.tabs.selected_index != 0:
            self.tabs.selected_index = 0
            try:
                self.tabs.update()
            except Exception:
                pass
        self.reset_to_first_page()
        self._reload_files_if_visible(f"Filtering files involving {self.user_filter_label}…")
    
    def show_date_picker(self, e):
        """Show date range picker dialog"""
        
        def apply_date_filter(e):
            self.close_dialog()
            self.reset_to_first_page()
            self._reload_files_if_visible("Applying date filter…")
            self.show_snackbar(self.build_filter_summary())
        
        def clear_dates(e):
            self.date_from = None
            self.date_to = None
            if self.date_from_picker:
                self.date_from_picker.value = None
            if self.date_to_picker:
                self.date_to_picker.value = None
            self.update_date_button_label()
            self.close_dialog()
            self.reset_to_first_page()
            self._reload_files_if_visible("Clearing date filter…")
        
        def open_from_picker(e):
            self.date_from_picker.open = True
            self.page.update()

        def open_to_picker(e):
            self.date_to_picker.open = True
            self.page.update()
        
        self._date_dialog_from_label = ft.Text(
            f"Selected: {self.date_from.strftime('%Y-%m-%d') if self.date_from else 'Not set'}",
            size=12,
            color=ft.Colors.GREY_700
        )
        self._date_dialog_to_label = ft.Text(
            f"Selected: {self.date_to.strftime('%Y-%m-%d') if self.date_to else 'Not set'}",
            size=12,
            color=ft.Colors.GREY_700
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text("📅 Date Range Filter"),
            content=ft.Container(
                content=ft.Column([
                    ft.Text("From Date", weight=ft.FontWeight.BOLD),
                    ft.ElevatedButton(
                        "Pick From Date",
                        icon=ft.Icons.CALENDAR_TODAY,
                        on_click=open_from_picker
                    ),
                    self._date_dialog_from_label,
                    ft.Divider(),
                    ft.Text("To Date", weight=ft.FontWeight.BOLD),
                    ft.ElevatedButton(
                        "Pick To Date",
                        icon=ft.Icons.CALENDAR_TODAY,
                        on_click=open_to_picker
                    ),
                    self._date_dialog_to_label,
                ], tight=True, spacing=12),
                width=350,
                padding=20
            ),
            actions=[
                ft.TextButton("Clear Dates", on_click=clear_dates),
                ft.TextButton("Cancel", on_click=lambda e: self.close_dialog()),
                ft.ElevatedButton("Apply", on_click=apply_date_filter),
            ]
        )
        
        self._show_dialog(dialog)
    
    def clear_all_filters(self, e=None):
        self.current_filter = 'all'
        self.owner_filter = 'all'
        self.show_starred_only = False
        self.include_trashed = False
        self.show_public_only = False
        self.selected_user_filter = None
        self.user_filter_label = None
        self.search_query = ''
        self.user_search_query = ''
        self.date_from = None
        self.date_to = None
        self.browse_scope_filter = 'all'
        self.browse_type_filter = set()
        if self.date_from_picker:
            self.date_from_picker.value = None
        if self.date_to_picker:
            self.date_to_picker.value = None
        self.update_date_button_label()
        if self.filter_dropdown:
            self.filter_dropdown.value = 'all'
            self.filter_dropdown.update()
        if self.owner_filter_dropdown:
            self.owner_filter_dropdown.value = 'all'
            self.owner_filter_dropdown.update()
        if self.starred_checkbox:
            self.starred_checkbox.value = False
            self.starred_checkbox.update()
        if self.trashed_checkbox:
            self.trashed_checkbox.value = False
            self.trashed_checkbox.update()
        if self.public_checkbox:
            self.public_checkbox.value = False
            self.public_checkbox.update()
        if self.user_filter_dropdown:
            self.user_filter_dropdown.value = 'all'
            self.user_filter_dropdown.update()
        if self.file_search_field:
            self.file_search_field.value = ''
            self.file_search_field.update()
        if self.user_search_field:
            self.user_search_field.value = ''
            try:
                self.user_search_field.update()
            except AssertionError:
                # Field not mounted yet; it will refresh when Users tab renders
                pass
        if self._file_search_debounce:
            self._file_search_debounce.cancel()
            self._file_search_debounce = None
        self._path_cache.clear()
        self._refresh_advanced_filter_controls()
        self.user_search_focus_pending = self._is_on_users_tab()
        self.reset_to_first_page()
        self._reload_files_if_visible("Clearing all filters…")
        if self._is_on_users_tab():
            self.load_users()
        if e is not None:
            self.show_snackbar("All filters cleared")
    
    def _build_filter_clause(self) -> Tuple[str, List[str]]:
        conditions: List[str] = []
        params: List[str] = []

        if not self.include_trashed:
            conditions.append("trashed = 0")

        if self.show_starred_only:
            conditions.append("starred = 1")

        if self.show_public_only:
            conditions.append("is_public = 1")

        if self.current_filter == 'my_drive':
            conditions.append("source = 'my_drive'")
        elif self.current_filter == 'shared_with_me':
            conditions.append("source = 'shared_with_me'")
        elif self.current_filter == 'shared_by_me':
            conditions.append("EXISTS (SELECT 1 FROM permissions p WHERE p.file_id = files.id AND p.email_address != owner_email)")

        if self.owner_filter == 'me':
            conditions.append("owned_by_me = 1")
        elif self.owner_filter == 'others':
            conditions.append("owned_by_me = 0")

        if self.selected_user_filter:
            user_email = self.selected_user_filter
            conditions.append("(owner_email = ? OR EXISTS (SELECT 1 FROM permissions p WHERE p.file_id = files.id AND p.email_address = ?))")
            params.extend([user_email, user_email])

        if self.search_query:
            conditions.append("name LIKE ?")
            params.append(f"%{self.search_query}%")

        if self.browse_scope_filter == 'folders':
            conditions.append("mime_type = ?")
            params.append(FOLDER_MIME)
        elif self.browse_scope_filter == 'files':
            conditions.append("mime_type != ?")
            params.append(FOLDER_MIME)

        type_clause, type_params = self._get_type_filter_clause()
        if type_clause:
            conditions.append(type_clause)
            params.extend(type_params)

        if self.date_from:
            conditions.append("DATE(modified_time) >= ?")
            params.append(self.date_from.strftime('%Y-%m-%d'))

        if self.date_to:
            conditions.append("DATE(modified_time) <= ?")
            params.append(self.date_to.strftime('%Y-%m-%d'))

        if self.current_folder_id:
            conditions.append("parent_id = ?")
            params.append(self.current_folder_id)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        return where_clause, params

    def load_files(self):
        """Load files with pagination"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            where_clause, params = self._build_filter_clause()

            # Count total
            count_query = f"SELECT COUNT(*) FROM files WHERE {where_clause}"
            cursor.execute(count_query, params)
            self.total_items = cursor.fetchone()[0]
            self.total_pages = max(1, (self.total_items + self.per_page - 1) // self.per_page)

            # Get paginated results
            sort_map = {
                'name_asc': 'name ASC',
                'name_desc': 'name DESC',
                'size_desc': 'size DESC',
                'size_asc': 'size ASC',
                'modified_desc': 'modified_time DESC',
                'modified_asc': 'modified_time ASC',
                'created_desc': 'created_time DESC',
                'created_asc': 'created_time ASC',
                'owner_asc': 'owner_name ASC'
            }
            order_by = sort_map.get(self.sort_by, 'name ASC')

            offset = (self.current_page - 1) * self.per_page
            query = f"SELECT * FROM files WHERE {where_clause} ORDER BY {order_by} LIMIT ? OFFSET ?"
            cursor.execute(query, params + [self.per_page, offset])
            files = cursor.fetchall()
            
            # Get duplicate paths
            cursor.execute("""
                SELECT full_path, name, COUNT(*) as dup_count
                FROM files
                WHERE trashed = 0
                GROUP BY full_path, name
                HAVING dup_count > 1
            """)
            duplicate_paths = {(row[0], row[1]) for row in cursor.fetchall()}
            
            file_cards = []
            if len(files) == 0:
                layout = ft.Container(
                    content=ft.Column([
                        ft.Icon(ft.Icons.FOLDER_OFF, size=80, color=ft.Colors.GREY_400),
                        ft.Text("No files found", size=20, color=ft.Colors.GREY_600, weight=ft.FontWeight.BOLD),
                        ft.Text("Try adjusting your filters or running a scan", size=14, color=ft.Colors.GREY_500)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=15),
                    padding=80,
                    alignment=ft.alignment.center
                )
                self.current_file_ids = []
            else:
                for file in files:
                    file_cards.append(self.build_file_card(file, duplicate_paths, cursor))
                self.current_file_ids = [file['id'] for file in files]
                if self.view_mode == "tiles":
                    layout = self.build_tile_grid(file_cards)
                else:
                    layout = ft.Column(file_cards, spacing=0, expand=True)

            if self.results_container:
                self.results_container.controls = [layout]
                self._initial_state_container = None
                try:
                    self.results_container.update()
                except Exception:
                    pass
            self._update_page_toolbar_state()
            self.update_breadcrumbs()
            self.update_status_footer(len(files))
            self.update_filter_summary()
            self.update_pagination_controls()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error loading files: {e}")
            self.show_error(f"Failed to load files: {str(e)}")
            if not locals().get('files'):
                self.current_file_ids = []
            self._update_page_toolbar_state()

    def _update_page_toolbar_state(self):
        has_files = bool(self.current_file_ids)
        if self.add_page_button:
            self.add_page_button.disabled = not has_files
            try:
                self.add_page_button.update()
            except Exception:
                pass

    def update_breadcrumbs(self):
        if not self.breadcrumb_row:
            return
        
        crumbs = [
            ft.TextButton(
                "📁 Drive Home",
                on_click=lambda e: self.navigate_to_root(),
                style=ft.ButtonStyle(padding=4)
            )
        ]
        
        for folder_id, folder_name in self.folder_stack:
            crumbs.append(ft.Text(" / ", size=12, color=ft.Colors.GREY_600))
            crumbs.append(
                ft.TextButton(
                    folder_name[:30],
                    on_click=lambda e, fid=folder_id: self.navigate_to_folder(fid),
                    style=ft.ButtonStyle(padding=4)
                )
            )
        
        self.breadcrumb_row.controls = crumbs
        try:
            self.breadcrumb_row.update()
        except:
            pass

    def navigate_to_root(self):
        self.current_folder_id = None
        self.folder_stack = []
        self.current_page = 1
        self.load_files()

    def navigate_to_folder(self, folder_id):
        for i, (fid, _) in enumerate(self.folder_stack):
            if fid == folder_id:
                self.folder_stack = self.folder_stack[:i+1]
                break
        self.current_folder_id = folder_id
        self.current_page = 1
        self.load_files()

    def enter_subfolder(self, folder_id, folder_name):
        self.folder_stack.append((folder_id, folder_name))
        self.current_folder_id = folder_id
        self.current_page = 1
        self.load_files()

    def update_status_footer(self, count: int):
        if not self.status_summary_text:
            return
        path = " / ".join([name for _, name in self.folder_stack]) or "Root"
        self.status_summary_text.value = f"Showing {count} of {self.total_items} items | Folder: {path}"
        try:
            self.status_summary_text.update()
        except Exception:
            pass
        if self.activity_status_text and not self.selection_mode and not self.selected_file_ids:
            # keep idle text subtle when nothing active
            pass

    def _update_activity_status(self, message: Optional[str], color=ft.Colors.GREY_600):
        if not self.activity_status_text:
            return
        self.activity_status_text.value = message or "No active downloads"
        self.activity_status_text.color = color
        try:
            self.activity_status_text.update()
        except Exception:
            pass

    def update_filter_summary(self):
        if not self.filter_summary_text:
            return
        self.filter_summary_text.value = self.build_filter_summary()
        try:
            self.filter_summary_text.update()
        except:
            pass
    
    def _announce_filters(self, message: Optional[str] = None):
        text = message or self.build_filter_summary()
        self.show_snackbar(text)
    
    def update_pagination_controls(self):
        """Refresh pagination UI safely"""
        if not self.pagination_text:
            return
        total_pages = max(1, self.total_pages)
        current_page = min(max(1, self.current_page), total_pages)
        self.pagination_text.value = f"Page {current_page} of {total_pages}"
        try:
            self.pagination_text.update()
        except Exception:
            pass
        if self.prev_page_button:
            self.prev_page_button.disabled = (current_page <= 1)
            try:
                self.prev_page_button.update()
            except Exception:
                pass
        if self.next_page_button:
            self.next_page_button.disabled = (current_page >= total_pages)
            try:
                self.next_page_button.update()
            except Exception:
                pass
        if self.per_page_dropdown and self.per_page_dropdown.value != str(self.per_page):
            self.per_page_dropdown.value = str(self.per_page)
            try:
                self.per_page_dropdown.update()
            except Exception:
                pass
    
    def load_analytics(self):
        """Load analytics tab with comprehensive stats"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            # Get stats
            cursor.execute("SELECT COUNT(*) FROM files WHERE trashed = 0")
            total_files = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM files WHERE owned_by_me = 1 AND trashed = 0")
            owned_files = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM files WHERE owned_by_me = 0 AND trashed = 0")
            shared_files = cursor.fetchone()[0]
            
            cursor.execute("SELECT SUM(size) FROM files WHERE trashed = 0")
            total_size = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM files WHERE starred = 1 AND trashed = 0")
            starred_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM files WHERE is_public = 1 AND trashed = 0")
            public_count = cursor.fetchone()[0]
            
            # Get top 10 largest files
            cursor.execute("""
                SELECT name, size, owner_name, mime_type
                FROM files
                WHERE trashed = 0 AND size > 0
                ORDER BY size DESC
                LIMIT 10
            """)
            top_files = cursor.fetchall()
            
            # Get file type distribution
            cursor.execute("""
                SELECT mime_type, COUNT(*) as count
                FROM files
                WHERE trashed = 0
                GROUP BY mime_type
                ORDER BY count DESC
                LIMIT 10
            """)
            file_types = cursor.fetchall()
            
            conn.close()
            
            # Build analytics cards
            stat_cards = ft.Row([
                self._stat_card("📁 Total Files", str(total_files), ft.Colors.BLUE_700, ft.Colors.BLUE_50),
                self._stat_card("👤 Owned", str(owned_files), ft.Colors.GREEN_700, ft.Colors.GREEN_50),
                self._stat_card("🤝 Shared", str(shared_files), ft.Colors.ORANGE_700, ft.Colors.ORANGE_50),
                self._stat_card("💾 Total Size", format_size(total_size), ft.Colors.PURPLE_700, ft.Colors.PURPLE_50),
                self._stat_card("⭐ Starred", str(starred_count), ft.Colors.YELLOW_700, ft.Colors.YELLOW_50),
                self._stat_card("🌐 Public", str(public_count), ft.Colors.PINK_700, ft.Colors.PINK_50),
            ], wrap=True, spacing=15)
            
            # Top 10 largest files table
            top_files_rows = []
            for idx, (name, size, owner, mime) in enumerate(top_files, 1):
                top_files_rows.append(
                    ft.DataRow(cells=[
                        ft.DataCell(ft.Text(str(idx), weight=ft.FontWeight.BOLD)),
                        ft.DataCell(ft.Text(get_file_icon(mime), size=20)),
                        ft.DataCell(ft.Text(name[:40], size=12)),
                        ft.DataCell(ft.Text(format_size(size), weight=ft.FontWeight.BOLD)),
                        ft.DataCell(ft.Text(owner or 'Unknown', size=11)),
                    ])
                )
            
            top_files_table = ft.DataTable(
                columns=[
                    ft.DataColumn(ft.Text("#", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Type", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Name", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Size", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Owner", weight=ft.FontWeight.BOLD)),
                ],
                rows=top_files_rows,
                border=ft.border.all(1, ft.Colors.GREY_300),
                border_radius=8,
                heading_row_color=ft.Colors.BLUE_50,
            )
            
            # File type distribution
            type_chips = []
            for mime, count in file_types:
                type_chips.append(
                    ft.Chip(
                        label=ft.Text(f"{get_file_icon(mime)} {mime.split('/')[-1]}: {count}", size=11),
                        bgcolor=ft.Colors.CYAN_50,
                        height=28
                    )
                )
            
            analytics_content = ft.Column([
                ft.Text("📊 Analytics Dashboard", size=28, weight=ft.FontWeight.BOLD),
                ft.Divider(height=20),
                
                # Stat cards
                stat_cards,
                
                ft.Divider(height=30),
                
                # Top 10 files
                ft.Text("🏆 Top 10 Largest Files", size=22, weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=top_files_table,
                    bgcolor=ft.Colors.WHITE,
                    padding=15,
                    border_radius=10,
                    border=ft.border.all(2, ft.Colors.GREY_300)
                ),
                
                ft.Divider(height=30),
                
                # File types
                ft.Text("📦 File Type Distribution (Top 10)", size=22, weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=ft.Row(type_chips, wrap=True, spacing=10),
                    bgcolor=ft.Colors.WHITE,
                    padding=20,
                    border_radius=10,
                    border=ft.border.all(2, ft.Colors.GREY_300)
                ),
                
            ], scroll=ft.ScrollMode.AUTO, spacing=20)
            
            if self.results_container:
                self.results_container.controls = [analytics_content]
                self.results_container.update()
            
        except Exception as e:
            logger.error(f"Error loading analytics: {e}")
            self.show_error(f"Failed to load analytics: {str(e)}")
    
    def _stat_card(self, title, value, text_color, bg_color):
        """Create stat card"""
        return ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                    ft.Text(value, size=32, weight=ft.FontWeight.BOLD, color=text_color),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
                padding=25,
                width=200,
                bgcolor=bg_color,
                border_radius=12
            ),
            elevation=3
        )
    
    def logout(self, e):
        """Logout and clear credentials"""
        try:
            if os.path.exists(TOKEN_FILE):
                os.remove(TOKEN_FILE)
            self.forensics.credentials = None
            self.forensics.service = None
            self.page.clean()
            self.show_login_screen()
            self.show_snackbar("✅ Logged out successfully")
        except Exception as e:
            self.show_error(f"Logout failed: {str(e)}")
    
    def close_dialog(self):
        """Close any open dialog"""
        dialog = self.active_dialog or getattr(self.page, "dialog", None)
        if dialog:
            dialog.open = False
            try:
                self.page.update()
            except Exception:
                pass
            if dialog in self.page.overlay:
                self.page.overlay.remove(dialog)
        if getattr(self.page, "dialog", None) is dialog:
            self.page.dialog = None
        self.active_dialog = None
    
    def show_snackbar(self, message):
        """Show snackbar notification"""
        self.page.snack_bar = ft.SnackBar(
            content=ft.Text(message, size=14),
            bgcolor=ft.Colors.GREY_800
        )
        self.page.snack_bar.open = True
        self.page.update()
    
    def show_error(self, message):
        """Show error dialog"""
        dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.ERROR, color=ft.Colors.RED_700, size=32),
                ft.Text("Error", size=20, color=ft.Colors.RED_700)
            ], spacing=12),
            content=ft.Text(message, size=14),
            actions=[
                ft.ElevatedButton("OK", on_click=lambda e: self.close_dialog(), bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE)
            ]
        )
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    def _resolve_thumbnail_url(self, link: Optional[str]) -> Optional[str]:
        if not link:
            return None
        token = getattr(getattr(self.forensics, 'credentials', None), 'token', None)
        if not token:
            return link
        separator = '&' if '?' in link else '?'
        resolved = f"{link}{separator}access_token={token}"
        logger.debug(f"Resolved thumbnail URL: {resolved[:80]}...")
        return resolved

    def _fetch_image_base64(self, cache_store: Dict[str, Optional[str]], cache_key: Optional[str], url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        if cache_key and cache_key in cache_store:
            return cache_store[cache_key]

        token = getattr(getattr(self.forensics, 'credentials', None), 'token', None)
        if not token:
            return None

        try:
            response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if response.status_code == 200 and response.content:
                encoded = base64.b64encode(response.content).decode('utf-8')
                if cache_key:
                    cache_store[cache_key] = encoded
                return encoded
            logger.warning(f"Image fetch failed ({response.status_code}) for {url}")
        except Exception as exc:
            logger.debug(f"Image fetch failed for {url}: {exc}")

        return None

    def _get_thumbnail_base64(self, file_id: str, link: Optional[str]) -> Optional[str]:
        return self._fetch_image_base64(self.thumbnail_cache, file_id, link)

    def _get_avatar_base64(self, owner_key: Optional[str], link: Optional[str]) -> Optional[str]:
        cache_key = owner_key or link
        return self._fetch_image_base64(self.avatar_cache, cache_key, link)

    def _build_owner_avatar(self, file_dict: Dict) -> ft.CircleAvatar:
        photo = file_dict.get('owner_photo')
        if photo:
            avatar_b64 = self._get_avatar_base64(file_dict.get('owner_email'), photo)
            if avatar_b64:
                return ft.CircleAvatar(
                    radius=10,
                    content=ft.Image(src_base64=avatar_b64, width=22, height=22, fit=ft.ImageFit.COVER)
                )
        initials = (file_dict.get('owner_name') or file_dict.get('owner_email') or '?')[:1].upper()
        return ft.CircleAvatar(
            content=ft.Text(initials, size=9),
            bgcolor=ft.Colors.GREEN_200,
            radius=10
        )
    def on_file_picker_result(self, e: FilePickerResultEvent):
        """Handle file picker result"""
        if self.pending_file_picker_action:
            callback = self.pending_file_picker_action
            self.pending_file_picker_action = None
            selected_path = getattr(e, 'path', None) or getattr(e, 'directory', None)
            callback(selected_path)
    
    def build_file_card(self, file, duplicate_paths, cursor):
        """Build compact file card"""
        file_dict = dict(file) if not isinstance(file, dict) else file
        file_icon = get_file_icon(file_dict['mime_type'])
        mime_label = get_mime_label(file_dict['mime_type'])
        is_duplicate = (file_dict.get('full_path'), file_dict['name']) in duplicate_paths
        
        # Hash display
        hash_type, hash_value, hash_color = ("MD5", file_dict.get('md5_checksum'), ft.Colors.ORANGE_700) if file_dict.get('md5_checksum') else \
                                             ("SHA1", file_dict.get('sha1_checksum'), ft.Colors.BLUE_700) if file_dict.get('sha1_checksum') else \
                                             ("SHA256", file_dict.get('sha256_checksum'), ft.Colors.GREEN_700) if file_dict.get('sha256_checksum') else \
                                             (None, None, None)
        hash_display = f"{hash_type}: {hash_value}" if hash_value else "No hash available"
        
        # Format dates
        modified_str = self.forensics.convert_timezone(file_dict['modified_time'], self.selected_timezone)
        
        # Build badges
        badges = []
        def _build_icon_chip(icon_text: str, label_text: Optional[str] = None, color=ft.Colors.BLUE_100):
            if not label_text:
                return ft.Chip(label=ft.Text(icon_text, size=11), bgcolor=color, height=20)
            return ft.Chip(
                label=ft.Row([
                    ft.Text(icon_text, size=12),
                    ft.Text(label_text, size=10, weight=ft.FontWeight.BOLD)
                ], spacing=4, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=color,
                height=22,
                padding=ft.padding.symmetric(horizontal=8, vertical=2)
            )

        if file_dict['starred']:
            badges.append(_build_icon_chip("⭐", "Starred", ft.Colors.YELLOW_100))
        if file_dict['trashed']:
            badges.append(_build_icon_chip("🗑️", "Trashed", ft.Colors.RED_100))
        if file_dict['is_public']:
            badges.append(_build_icon_chip("🌐", "Public", ft.Colors.PURPLE_100))
        if is_duplicate:
            badges.append(
                ft.Chip(
                    label=ft.Row([
                        ft.Text("⚠️", size=10),
                        ft.Text("Path conflict", size=9, weight=ft.FontWeight.BOLD, color=ft.Colors.ORANGE_900)
                    ], spacing=4, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=ft.Colors.ORANGE_100,
                    height=22,
                    padding=ft.padding.symmetric(horizontal=8, vertical=2)
                )
            )
        if file_dict['is_shortcut']:
            badges.append(_build_icon_chip("🔗", "Shortcut", ft.Colors.CYAN_100))
        
        # Size display
        size_display = "Folder" if file_dict['mime_type'] == FOLDER_MIME else format_size(file_dict['size'] or 0)
        
        # Check revisions
        cursor.execute("SELECT COUNT(*) FROM revisions WHERE file_id = ?", (file_dict['id'],))
        revision_count = cursor.fetchone()[0]
        has_revisions = revision_count > 0
        
        # Thumbnail / icon
        thumb_content: ft.Control
        thumb_base64 = self._get_thumbnail_base64(file_dict['id'], file_dict.get('thumbnail_link'))
        if thumb_base64:
            thumb_content = ft.Image(src_base64=thumb_base64, width=36, height=36, border_radius=4, fit=ft.ImageFit.COVER)
        elif file_dict.get('thumbnail_link'):
            thumb_url = self._resolve_thumbnail_url(file_dict['thumbnail_link'])
            thumb_content = ft.Image(src=thumb_url, width=36, height=36, border_radius=4, fit=ft.ImageFit.COVER) if thumb_url else ft.Text(file_icon, size=28)
        else:
            thumb_content = ft.Text(file_icon, size=28)

        if mime_label:
            badges.append(ft.Chip(label=ft.Text(mime_label, size=10, weight=ft.FontWeight.BOLD), bgcolor=ft.Colors.BLUE_50, height=20, padding=ft.padding.symmetric(horizontal=8, vertical=2)))

        owner_avatar = self._build_owner_avatar(file_dict)

        selection_checkbox_state = {"control": None, "syncing": False}

        def sync_selection_checkbox():
            checkbox_ctrl = selection_checkbox_state["control"]
            if not checkbox_ctrl:
                return
            selection_checkbox_state["syncing"] = True
            checkbox_ctrl.value = file_dict['id'] in self.selected_file_ids
            try:
                checkbox_ctrl.update()
            except Exception:
                pass
            finally:
                selection_checkbox_state["syncing"] = False

        def handle_selection_toggle(_=None):
            if not self.selection_mode:
                return
            new_state = file_dict['id'] not in self.selected_file_ids
            self._toggle_file_selection(file_dict['id'], new_state, refresh_view=False)
            sync_selection_checkbox()

        def make_selection_checkbox():
            if not self.selection_mode:
                return None, None
            fid = file_dict['id']

            def _handle_checkbox_change(e, fid=fid):
                if selection_checkbox_state["syncing"]:
                    return
                self._toggle_file_selection(fid, e.control.value, refresh_view=False)

            checkbox = ft.Checkbox(
                value=(fid in self.selected_file_ids),
                on_change=_handle_checkbox_change,
                tristate=False,
                scale=1.1 if hasattr(ft.Checkbox, 'scale') else None
            )

            def _handle_container_click(e, fid=fid):
                new_state = fid not in self.selected_file_ids
                self._toggle_file_selection(fid, new_state, refresh_view=False)
                sync_selection_checkbox()

            container = ft.Container(
                content=checkbox,
                width=40,
                on_click=_handle_container_click,
                ink=True
            )
            return container, checkbox

        def _context_trigger(event, fid=file_dict['id']):
            self.show_context_menu(event, fid)

        name_text = ft.Text(
            file_dict['name'],
            size=13,
            weight=ft.FontWeight.BOLD,
            tooltip=file_dict['full_path'] or ''
        )

        name_wrapper = ft.GestureDetector(
            content=name_text,
            on_secondary_tap=_context_trigger,
            mouse_cursor=ft.MouseCursor.CONTEXT_MENU
        )

        meta_column = ft.Column([
            name_wrapper,
            ft.Row([
                ft.Text(mime_label, size=11, color=ft.Colors.GREY_600),
                ft.Text(format_size(file_dict['size'] or 0), size=11, color=ft.Colors.GREY_600)
            ], spacing=8),
            ft.Row(badges, spacing=4, wrap=True)
        ], spacing=2, expand=True)

        owner_column = ft.Row([
            owner_avatar,
            ft.Text(
                (file_dict.get('owner_name') or file_dict.get('owner_email') or 'Unknown')[:20],
                size=11,
                color=ft.Colors.GREY_700,
                overflow=ft.TextOverflow.ELLIPSIS
            )
        ], spacing=6, alignment=ft.MainAxisAlignment.START)

        size_column = ft.Column([
            ft.Text(size_display, size=12, weight=ft.FontWeight.BOLD),
            ft.Text(file_dict.get('file_extension') or file_dict['mime_type'].split('/')[-1], size=11, color=ft.Colors.GREY_600)
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=2)

        action_buttons_list = ft.Row([
            ft.IconButton(icon=ft.Icons.INFO_OUTLINE, tooltip="Details", on_click=lambda e, fid=file_dict['id']: self.show_file_info(fid), icon_color=ft.Colors.BLUE_700, icon_size=16, style=ft.ButtonStyle(padding=4)),
            ft.IconButton(icon=ft.Icons.DOWNLOAD, tooltip="Download", on_click=lambda e, fid=file_dict['id'], fname=file_dict['name'], mime=file_dict['mime_type']: self.download_file_with_picker(fid, fname, mime), icon_color=ft.Colors.GREEN_700, icon_size=16, style=ft.ButtonStyle(padding=4)),
            ft.IconButton(icon=ft.Icons.ADD_CIRCLE_OUTLINE, tooltip="Add to Queue", on_click=lambda e, fid=file_dict['id']: self.add_to_queue(fid), icon_color=ft.Colors.PURPLE_700, icon_size=16, style=ft.ButtonStyle(padding=4)),
        ], spacing=4)

        if self.view_mode == "list":
            selection_checkbox, checkbox_control = make_selection_checkbox()
            if checkbox_control:
                selection_checkbox_state["control"] = checkbox_control
            row_controls = []
            if selection_checkbox:
                row_controls.append(selection_checkbox)
            row_controls.extend([
                thumb_content,
                meta_column,
                ft.Container(owner_column, width=170, alignment=ft.alignment.center_left),
                ft.Container(ft.Text(modified_str, size=11, color=ft.Colors.GREY_600), width=140, alignment=ft.alignment.center_left),
                ft.Container(size_column, width=110),
                action_buttons_list
            ])
            row_content = ft.Row([
                *row_controls
            ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER)

            card = ft.Container(
                bgcolor=ft.Colors.WHITE,
                padding=ft.padding.symmetric(8, 12),
                border=ft.border.only(bottom=ft.border.BorderSide(1, ft.Colors.GREY_100)),
                content=row_content
            )

            gesture = ft.GestureDetector(
                content=card,
                on_secondary_tap=_context_trigger,
                on_tap=handle_selection_toggle if self.selection_mode else None
            )
            if file_dict['mime_type'] == FOLDER_MIME:
                if not self.selection_mode:
                    gesture.on_double_tap = lambda e, fid=file_dict['id'], name=file_dict['name']: self.enter_subfolder(fid, name)

            return gesture

        # Tile view configuration
        tile_selection_checkbox, tile_checkbox_control = make_selection_checkbox()
        if tile_checkbox_control:
            selection_checkbox_state["control"] = tile_checkbox_control

        tile_actions = ft.Row([
            ft.IconButton(icon=ft.Icons.INFO_OUTLINE, tooltip="Details", on_click=lambda e, fid=file_dict['id']: self.show_file_info(fid), icon_color=ft.Colors.BLUE_700, icon_size=18, style=ft.ButtonStyle(padding=4)),
            ft.IconButton(icon=ft.Icons.DOWNLOAD, tooltip="Download", on_click=lambda e, fid=file_dict['id'], fname=file_dict['name'], mime=file_dict['mime_type']: self.download_file_with_picker(fid, fname, mime), icon_color=ft.Colors.GREEN_700, icon_size=18, style=ft.ButtonStyle(padding=4)),
            ft.IconButton(icon=ft.Icons.QUEUE, tooltip="Add to Queue", on_click=lambda e, fid=file_dict['id']: self.add_to_queue(fid), icon_color=ft.Colors.PURPLE_700, icon_size=18, style=ft.ButtonStyle(padding=4)),
        ], spacing=6, alignment=ft.MainAxisAlignment.END)

        tile_badge_row = ft.Row(badges, spacing=4, wrap=True)

        name_control = ft.Text(file_dict['name'], size=13, weight=ft.FontWeight.BOLD, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS)
        if tile_selection_checkbox:
            name_row = ft.Row([tile_selection_checkbox, name_control], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        else:
            name_row = name_control

        tile_container = ft.Container(
            width=240,
            height=260,
            bgcolor=ft.Colors.WHITE,
            border_radius=12,
            border=ft.border.all(1, ft.Colors.GREY_200),
            padding=ft.padding.all(14),
            content=ft.Column([
                ft.Container(content=thumb_content, alignment=ft.alignment.center_left, height=60),
                name_row,
                ft.Text(mime_label or file_dict['mime_type'], size=11, color=ft.Colors.GREY_600),
                tile_badge_row,
                ft.Text(f"Owner: {file_dict.get('owner_name') or file_dict.get('owner_email') or 'Unknown'}", size=11, color=ft.Colors.GREY_700, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(f"Updated: {modified_str}", size=11, color=ft.Colors.GREY_600, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(f"{size_display}", size=11, color=ft.Colors.GREY_700),
                tile_actions
            ], spacing=6)
        )

        def _hover_tile(e, ctrl=tile_container):
            hovered = e.data == "true"
            ctrl.border = ft.border.all(2, ft.Colors.BLUE_200 if hovered else ft.Colors.GREY_200)
            try:
                ctrl.update()
            except Exception:
                pass

        tile = ft.GestureDetector(
            content=tile_container,
            on_secondary_tap=_context_trigger,
            on_hover=_hover_tile,
            on_tap=handle_selection_toggle if self.selection_mode else None
        )
        if file_dict['mime_type'] == FOLDER_MIME and not self.selection_mode:
            tile.on_double_tap = lambda e, fid=file_dict['id'], name=file_dict['name']: self.enter_subfolder(fid, name)

        return tile
    
    def build_tile_grid(self, cards):
        if not cards:
            return ft.Column()
        return ft.ResponsiveRow(
            [ft.Container(content=card, col={"xs": 12, "sm": 6, "md": 3, "lg": 3}, padding=6) for card in cards],
            alignment=ft.MainAxisAlignment.START,
            run_spacing=12,
            spacing=12
        )
    
       
    def show_file_info(self, file_id):
        """Show comprehensive file information dialog"""
        try:
            self.close_dialog()
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            file_data = cursor.fetchone()

            if not file_data:
                conn.close()
                self.show_error("File not found in database")
                return

            file = dict(file_data)

            # Get permissions
            cursor.execute("SELECT * FROM permissions WHERE file_id = ?", (file_id,))
            permissions = [dict(row) for row in cursor.fetchall()]

            # Get revision count
            cursor.execute("SELECT COUNT(*) FROM revisions WHERE file_id = ?", (file_id,))
            revision_count = cursor.fetchone()[0]

            conn.close()

            # Build permissions list
            perm_controls = []
            if permissions:
                for perm in permissions:
                    role_icon = ft.Icons.PERSON
                    role_color = ft.Colors.GREY_700

                    if perm['role'] == 'owner':
                        role_icon = ft.Icons.ADMIN_PANEL_SETTINGS
                        role_color = ft.Colors.GREEN_700
                    elif perm['role'] == 'writer':
                        role_icon = ft.Icons.EDIT
                        role_color = ft.Colors.BLUE_700
                    elif perm['role'] == 'commenter':
                        role_icon = ft.Icons.COMMENT
                        role_color = ft.Colors.ORANGE_700
                    elif perm['role'] == 'reader':
                        role_icon = ft.Icons.VISIBILITY
                        role_color = ft.Colors.PURPLE_700

                    avatar = None
                    photo = perm.get('photo_link')
                    if photo:
                        avatar = ft.CircleAvatar(radius=12, foreground_image_src=self._resolve_thumbnail_url(photo))

                    perm_controls.append(
                        ft.ListTile(
                            leading=avatar or ft.Icon(role_icon, color=role_color, size=20),
                            title=ft.Text(perm['display_name'] or perm['email_address'] or 'Unknown', size=12, weight=ft.FontWeight.BOLD),
                            subtitle=ft.Text(f"{perm['email_address'] or 'N/A'} • {(perm['role'] or 'unknown').upper()}", size=10),
                            dense=True,
                        )
                    )
            else:
                perm_controls.append(ft.Text("No permissions found", size=12, color=ft.Colors.GREY_600))

            # Format dates
            created = self.forensics.convert_timezone(file.get('created_time'), self.selected_timezone) if file.get('created_time') else 'N/A'
            modified = self.forensics.convert_timezone(file.get('modified_time'), self.selected_timezone) if file.get('modified_time') else 'N/A'

            metadata_raw = file.get('metadata_json') or '{}'
            metadata_pretty = metadata_raw
            try:
                metadata_pretty = json.dumps(json.loads(metadata_raw), indent=2)
            except Exception:
                pass

            metadata_field = ft.TextField(
                value=metadata_pretty,
                multiline=True,
                read_only=True,
                text_size=12,
                height=200,
                border=ft.InputBorder.OUTLINE
            )

            # Build info content
            content = ft.Column([
                ft.Row([
                    ft.Text(get_file_icon(file.get('mime_type', '')), size=32),
                    ft.Column([
                        ft.Text(file.get('name', 'Unknown'), size=16, weight=ft.FontWeight.BOLD, selectable=True),
                        ft.Text(file.get('mime_type', 'Unknown'), size=11, color=ft.Colors.GREY_600, selectable=True),
                    ], spacing=2, expand=True)
                ], spacing=10),

                ft.Divider(height=10),

                ft.Text("DETAILS", size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                self._info_row("Size", format_size(file.get('size') or 0)),
                self._info_row("Path", file.get('full_path', '/'), selectable=True),
                self._info_row("Created", created),
                self._info_row("Modified", modified),
                self._info_row("Owner", f"{file.get('owner_name') or 'Unknown'} ({file.get('owner_email') or 'N/A'})"),
                self._info_row("Web Link", file.get('web_view_link') or "N/A", selectable=True, color=ft.Colors.BLUE_600),
                self._info_row("MD5", file.get('md5_checksum') or "N/A", selectable=True),
                self._info_row("SHA1", file.get('sha1_checksum') or "N/A", selectable=True),
                self._info_row("SHA256", file.get('sha256_checksum') or "N/A", selectable=True),
                self._info_row("Revisions", str(revision_count)),

                ft.Divider(height=10),

                ft.Row([
                    ft.Text("RAW METADATA (JSON)", size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                    ft.TextButton(
                        "Copy",
                        icon=ft.Icons.CONTENT_COPY,
                        on_click=lambda e, payload=metadata_pretty: self.copy_to_clipboard(payload, "Metadata JSON copied")
                    )
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                metadata_field,

                ft.Divider(height=10),

                ft.Text(f"SHARED WITH ({len(permissions)})", size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                ft.Container(
                    content=ft.Column(perm_controls, spacing=0, scroll=ft.ScrollMode.AUTO),
                    height=150,
                    bgcolor=ft.Colors.GREY_50,
                    border_radius=4,
                    padding=5
                )
            ], spacing=8, scroll=ft.ScrollMode.AUTO, height=500)

            dialog = ft.AlertDialog(
                title=ft.Text("📄 File Details"),
                content=ft.Container(content=content, width=550),
                actions=[
                    ft.TextButton("Download", on_click=lambda e: [self.close_dialog(), self.download_file_with_picker(file['id'], file['name'], file['mime_type'])]),
                    ft.TextButton("Preview Thumbnail", on_click=lambda e, fid=file['id']: self.show_thumbnail_preview(fid), disabled=not file.get('thumbnail_link')),
                    ft.TextButton("Add to Queue", on_click=lambda e: [self.add_to_queue(file['id']), self.close_dialog()]),
                    ft.TextButton("Close", on_click=lambda e: self.close_dialog())
                ]
            )

            self._show_dialog(dialog)
            self._focus_first_control(content)
            return
        except Exception as e:
            logger.error(f"Error showing file info: {e}")
            traceback.print_exc()
            self.show_error(f"Failed to load file info: {str(e)}")

    def refresh_thumbnails(self, e=None):
        if not self.current_file_ids:
            self.show_snackbar("Load some files first")
            return
        service = getattr(self.forensics, 'service', None)
        if not service:
            self.show_error("Run Scan Drive first to refresh thumbnails")
            return

        progress = ft.ProgressBar(width=420)
        status = ft.Text("Refreshing thumbnails...", size=13)
        dialog = ft.AlertDialog(
            title=ft.Text("🔄 Refreshing Thumbnails"),
            content=ft.Container(
                width=450,
                content=ft.Column([status, progress], spacing=10)
            ),
            modal=True
        )
        self._show_dialog(dialog)

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            total = len(self.current_file_ids)
            refreshed = 0
            def update_status_bar(current_idx):
                def _update():
                    status.value = f"Updated {current_idx}/{total} files"
                    progress.value = current_idx / total if total else 1
                    self.page.update()
                self._dispatch_ui(_update)

            for idx, file_id in enumerate(self.current_file_ids, start=1):
                metadata = self._fetch_latest_thumbnail_metadata(file_id)
                if metadata:
                    thumbnail_link, owner_photo, owner_name, owner_email = metadata
                    cursor.execute(
                        """
                        UPDATE files
                        SET thumbnail_link = ?,
                            owner_photo = ?,
                            owner_name = COALESCE(owner_name, ?),
                            owner_email = COALESCE(owner_email, ?)
                        WHERE id = ?
                        """,
                        (thumbnail_link, owner_photo, owner_name, owner_email, file_id)
                    )
                    refreshed += 1
                update_status_bar(idx)
            conn.commit()
            conn.close()
            self.thumbnail_cache.clear()
            self.avatar_cache.clear()
            self._dispatch_ui(lambda: self._run_with_loading("Refreshing thumbnails…", self.load_files))
            self._dispatch_ui(self.close_dialog)
            self._dispatch_ui(lambda: self.show_snackbar(f"✅ Refreshed {refreshed} thumbnails"))
        except Exception as exc:
            logger.error(f"Thumbnail refresh failed: {exc}")
            self._dispatch_ui(self.close_dialog)
            self._dispatch_ui(lambda: self.show_error(f"Failed to refresh thumbnails: {exc}"))

    def _fetch_latest_thumbnail_metadata(self, file_id: str) -> Optional[Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]]:
        service = getattr(self.forensics, 'service', None)
        if not service:
            return None
        try:
            metadata = service.files().get(
                fileId=file_id,
                fields="thumbnailLink, owners(photoLink, displayName, emailAddress)"
            ).execute()
            owners = metadata.get('owners', [])
            owner = owners[0] if owners else {}
            return (
                metadata.get('thumbnailLink'),
                owner.get('photoLink'),
                owner.get('displayName'),
                owner.get('emailAddress')
            )
        except HttpError as exc:
            logger.warning(f"Failed to fetch thumbnail for {file_id}: {exc}")
            return None

    def _scale_thumbnail_url(self, url: Optional[str], size: int = 2048) -> Optional[str]:
        if not url:
            return None
        return re.sub(r"=s(\d+)", f"=s{size}", url)

    def show_thumbnail_preview(self, file_id):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            file = cursor.fetchone()
            if not file:
                self.show_error("File not found")
                return
            file = dict(file)
            if not file.get('thumbnail_link'):
                metadata = self._fetch_latest_thumbnail_metadata(file_id)
                if metadata:
                    thumbnail_link, owner_photo, _, _ = metadata
                    cursor.execute("UPDATE files SET thumbnail_link = ?, owner_photo = ? WHERE id = ?", (thumbnail_link, owner_photo, file_id))
                    conn.commit()
                    file['thumbnail_link'] = thumbnail_link
            conn.close()

            if not file.get('thumbnail_link'):
                self.show_error("No thumbnail available")
                return

            preview_url = self._scale_thumbnail_url(self._resolve_thumbnail_url(file['thumbnail_link']), 2048)
            image = ft.Image(src=preview_url, width=620, height=620, fit=ft.ImageFit.CONTAIN)
            dialog = ft.AlertDialog(
                title=ft.Text("🖼️ Thumbnail Preview"),
                content=ft.Container(content=image, width=640, height=640),
                actions=[
                    ft.TextButton("Open in Browser", on_click=lambda e: webbrowser.open(preview_url)),
                    ft.TextButton("Close", on_click=lambda e: self.close_dialog())
                ],
                modal=True
            )
            self._show_dialog(dialog)
        except Exception as exc:
            logger.error(f"Thumbnail preview failed: {exc}")
            self.show_error(f"Failed to preview thumbnail: {exc}")

    def _info_row(self, label: str, value: str, selectable: bool = False, color=None):
        return ft.Row(
            [
                ft.Text(label, size=11, weight=ft.FontWeight.BOLD, width=110, color=ft.Colors.GREY_700),
                ft.Text(str(value), size=11, selectable=selectable, color=color or ft.Colors.GREY_800, expand=True),
            ],
            spacing=6,
        )
    def download_file_with_picker(self, file_id, file_name, mime_type):
        """Download file with file picker dialog"""
        
        # Get file info to check if it's a folder or shortcut
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            file_info = dict(cursor.fetchone())
            conn.close()
        except Exception:
            file_info = {'is_shortcut': False, 'mime_type': mime_type}

        # Handle shortcuts
        if file_info.get('is_shortcut'):
            def handle_shortcut_choice(export_target):
                if export_target:
                    target_id = file_info.get('shortcut_target_id')
                    if target_id:
                        self.download_file_with_picker(target_id, file_name, mime_type)
                    else:
                        self.show_error("Shortcut target not found")
                self.close_dialog()
            
            if not self.skip_all_shortcuts:
                dialog = ft.AlertDialog(
                    title=ft.Text("🔗 Shortcut Detected"),
                    content=ft.Text(f"'{file_name}' is a shortcut. Do you want to export the target file?"),
                    actions=[
                        ft.TextButton("Skip", on_click=lambda e: handle_shortcut_choice(False)),
                        ft.TextButton("Skip All Shortcuts", on_click=lambda e: [setattr(self, 'skip_all_shortcuts', True), handle_shortcut_choice(False)]),
                        ft.ElevatedButton("Export Target", on_click=lambda e: handle_shortcut_choice(True)),
                    ]
                )
                self._show_dialog(dialog)
                return
            else:
                self.show_snackbar("⏭️ Skipped shortcut")
                return

        if mime_type == FOLDER_MIME:
             self.download_folder_with_picker(file_id, file_name)
             return

        # Show progress dialog
        progress_bar = ft.ProgressBar(width=500, value=0)
        status_text = ft.Text("Starting download...", size=14)
        
        dialog = ft.AlertDialog(
            title=ft.Text("⬇️ Downloading File"),
            content=ft.Container(
                content=ft.Column([
                    ft.Text(file_name[:60], size=13, weight=ft.FontWeight.BOLD),
                    ft.Container(height=10),
                    progress_bar,
                    status_text
                ]),
                width=550,
                padding=20
            ),
            modal=True
        )
        
        self.page.dialog = dialog
        dialog.open = True
        self.page.update()
        
        def update_progress(status: Optional[str] = None, progress: Optional[float] = None):
            def _update():
                if status is not None:
                    status_text.value = status
                    self._update_activity_status(status, ft.Colors.BLUE_700)
                if progress is not None:
                    progress_bar.value = max(0.0, min(1.0, progress))
                try:
                    self.page.update()
                except Exception:
                    pass
            self._dispatch_ui(_update)

        def on_dir_selected(save_path):
            if not save_path:
                self._dispatch_ui(self.close_dialog)
                self._dispatch_ui(lambda: self.show_snackbar("Download cancelled"))
                return

            def do_download():
                try:
                    final_path = os.path.join(save_path, sanitize_filename(file_name))
                    update_progress("Downloading from Google Drive...", 0.05)

                    def progress_cb(value: float):
                        update_progress(f"Downloading… {int(value * 100)}%", value)

                    downloaded_path = self.forensics.download_file(
                        file_id,
                        file_name,
                        mime_type,
                        final_path,
                        progress_callback=progress_cb
                    )
                    
                    update_progress("Verifying hash...", 0.95)
                    
                    # Verify hash
                    original_hash = file_info.get('sha256_checksum') or file_info.get('sha1_checksum') or file_info.get('md5_checksum')
                    hash_verified = False
                    file_hash = "N/A"
                    
                    if original_hash and os.path.exists(downloaded_path):
                        # Calculate hash of downloaded file
                        with open(downloaded_path, 'rb') as f:
                            if file_info.get('sha256_checksum'):
                                file_hash = hashlib.sha256(f.read()).hexdigest()
                            elif file_info.get('sha1_checksum'):
                                file_hash = hashlib.sha1(f.read()).hexdigest()
                            else:
                                file_hash = hashlib.md5(f.read()).hexdigest()
                        
                        hash_verified = (file_hash.lower() == original_hash.lower())
                        
                        # Save to history
                        conn = sqlite3.connect(DATABASE_FILE)
                        cursor = conn.cursor()
                        cursor.execute("""
                            INSERT INTO export_history (file_id, export_time, local_path, original_hash, 
                                                       exported_hash, hash_verified, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (file_id, datetime.now().isoformat(), downloaded_path, original_hash,
                             file_hash, hash_verified, 'success'))
                        conn.commit()
                        conn.close()
                        
                        if hash_verified:
                            update_progress("✅ Download complete! Hash verified.", 1.0)
                        else:
                            update_progress("⚠️ Download complete! Hash mismatch!", 1.0)
                    else:
                        update_progress("✅ Download complete! (No hash to verify)", 1.0)
                    
                    time.sleep(1)
                    self._dispatch_ui(self.close_dialog)
                    self._dispatch_ui(lambda: self.show_snackbar(f"✅ Downloaded: {os.path.basename(downloaded_path)}"))
                    self._update_activity_status(f"✅ Downloaded {file_name}", ft.Colors.GREEN_700)
                    
                except Exception as e:
                    logger.error(f"Download failed: {e}")
                    update_progress("❌ Download failed", None)
                    self._dispatch_ui(self.close_dialog)
                    self._dispatch_ui(lambda: self.show_error(f"Download failed: {str(e)}"))
                    self._update_activity_status("❌ Download failed", ft.Colors.RED_600)
            
            threading.Thread(target=do_download, daemon=True).start()

        self.pick_directory(on_dir_selected)

    def download_folder_with_picker(self, folder_id, folder_name):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (folder_id,))
            folder_record = cursor.fetchone()
            conn.close()
            if not folder_record:
                self.show_error("Folder not found in database")
                return
            folder_record = dict(folder_record)
        except Exception as exc:
            logger.error(f"Folder lookup failed: {exc}")
            self.show_error(f"Unable to load folder metadata: {exc}")
            return

        def on_dir_selected(save_path):
            if not save_path:
                self.show_snackbar("Folder download cancelled")
                return

            export_root = sanitize_filename(folder_name) or "Folder"
            self._handle_queue_export_directory(
                save_path,
                [folder_record],
                export_root_name=export_root,
                include_reports=False,
                clear_queue=False,
                completion_message=f"✅ Folder '{folder_name}' downloaded to {os.path.join(save_path, export_root)}"
            )

        self.pick_directory(on_dir_selected)

    def add_to_queue(self, file_id):
        """Add file to export queue"""
        if file_id in self.export_queue:
             self.show_snackbar("⚠️ File already in queue")
             return

        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO export_queue (file_id, added_time) VALUES (?, ?)", (file_id, datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            if file_id not in self.export_queue:
                self.export_queue.append(file_id)
            self.refresh_queue_badge()
            self.show_snackbar(f"✅ Added to export queue ({len(self.export_queue)} items)")
            self._update_activity_status(f"Queue size: {len(self.export_queue)} items", ft.Colors.ORANGE_700)
        except Exception as e:
            logger.error(f"Error adding to queue: {e}")
            self.show_error(f"Failed to add to queue: {str(e)}")
    
    def show_export_queue(self, e):
        """Display export queue contents with actions"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.*
                FROM export_queue eq
                JOIN files f ON f.id = eq.file_id
                ORDER BY eq.added_time
                """
            )
            queue_files = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as exc:
            logger.error(f"Queue load failed: {exc}")
            self.show_error(f"Failed to load export queue: {exc}")
            return

        def remove_from_queue(file_id):
            try:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM export_queue WHERE file_id = ?", (file_id,))
                conn.commit()
                conn.close()
                if file_id in self.export_queue:
                    self.export_queue.remove(file_id)
                self.refresh_queue_badge()
                self.show_export_queue(None)
            except Exception as exc:
                logger.error(f"Failed to remove queue item: {exc}")
                self.show_error(f"Failed to remove file: {exc}")

        def clear_queue(e=None):
            try:
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM export_queue")
                conn.commit()
                conn.close()
                self.export_queue.clear()
                self.refresh_queue_badge()
                self.close_dialog()
            except Exception as exc:
                logger.error(f"Failed to clear queue: {exc}")
                self.show_error(f"Failed to clear queue: {exc}")

        items = []
        if queue_files:
            for file in queue_files:
                items.append(
                    ft.ListTile(
                        leading=ft.Text(get_file_icon(file['mime_type']), size=20),
                        title=ft.Text(file['name'], size=13, overflow=ft.TextOverflow.ELLIPSIS),
                        subtitle=ft.Text(file['full_path'], size=11, color=ft.Colors.GREY_600, overflow=ft.TextOverflow.ELLIPSIS),
                        trailing=ft.IconButton(
                            icon=ft.Icons.REMOVE_CIRCLE,
                            icon_color=ft.Colors.RED_700,
                            tooltip="Remove",
                            on_click=lambda _e, fid=file['id']: remove_from_queue(fid)
                        ),
                    )
                )
        else:
            items.append(ft.Text("Queue is empty", color=ft.Colors.GREY_600))

        dialog = ft.AlertDialog(
            title=ft.Text(f"📋 Export Queue ({len(queue_files)} items)"),
            content=ft.Container(
                width=600,
                height=400,
                content=ft.Column(items, scroll=ft.ScrollMode.AUTO, spacing=4)
            ),
            actions=[
                ft.TextButton("Clear All", on_click=clear_queue, disabled=len(queue_files) == 0),
                ft.TextButton("Close", on_click=lambda e: self.close_dialog()),
                ft.ElevatedButton("Export Queue", on_click=lambda e: self.export_queue_files(), disabled=len(queue_files) == 0)
            ]
        )
        self._show_dialog(dialog)

    def export_queue_files(self, e=None):
        if not self.export_queue:
            self.show_snackbar("Queue is empty")
            return
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            placeholder = ",".join(["?"] * len(self.export_queue))
            cursor.execute(f"SELECT * FROM files WHERE id IN ({placeholder})", self.export_queue)
            queue_files = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as exc:
            logger.error(f"Failed to load queue data: {exc}")
            self.show_error(f"Failed to start export: {exc}")
            return

        self.close_dialog()

        def on_dir_selected(path, files=queue_files):
            self._handle_queue_export_directory(path, files)

        self.pick_directory(on_dir_selected)

    def _handle_queue_export_directory(self, base_path, queue_files, export_root_name="Export", include_reports=True, clear_queue=True, completion_message: Optional[str] = None):
        if not base_path:
            self.show_snackbar("Export cancelled")
            self._active_export_cancel_event = None
            return

        progress_bar = ft.ProgressBar(width=500)
        status_text = ft.Text("Preparing export...", size=13)
        eta_text = ft.Text("ETA: calculating…", size=11, color=ft.Colors.GREY_600)
        detail_text = ft.Text("", size=11, color=ft.Colors.GREY_600)
        dialog = ft.AlertDialog(
            title=ft.Text("🚚 Exporting Queue"),
            content=ft.Container(
                width=550,
                content=ft.Column([
                    ft.Text(base_path, size=12, color=ft.Colors.GREY_600),
                    progress_bar,
                    status_text,
                    detail_text,
                    eta_text
                ], spacing=8)
            ),
            modal=True
        )
        cancel_event = threading.Event()
        self._active_export_cancel_event = cancel_event

        def cancel_export(_=None):
            if cancel_event.is_set():
                return
            cancel_event.set()
            status_text.value = "Stopping export after current file…"
            detail_text.value = "Please wait a moment while we wrap up the in-flight download."
            eta_text.value = "ETA: cancelling"
            self._update_activity_status("Cancelling export…", ft.Colors.RED_600)
            try:
                self.page.update()
            except Exception:
                pass

        def run_in_background(_=None):
            dialog.open = False
            try:
                self.page.update()
            except Exception:
                pass
            self.show_snackbar("🚚 Export continues in background. You can keep browsing.")

        cancel_button = ft.TextButton("Cancel export", icon=ft.Icons.STOP_CIRCLE, on_click=cancel_export)
        background_button = ft.TextButton("Run in background", icon=ft.Icons.CLOSE_FULLSCREEN, on_click=run_in_background)
        dialog.actions = [background_button, cancel_button]
        self._show_dialog(dialog)

        self._path_cache.clear()

        self._update_activity_status("Preparing queue export…", ft.Colors.BLUE_700)

        threading.Thread(
            target=self._run_queue_export,
            args=(
                base_path,
                queue_files,
                progress_bar,
                status_text,
                detail_text,
                dialog,
                eta_text,
                export_root_name,
                include_reports,
                clear_queue,
                completion_message,
                cancel_event
            ),
            daemon=True
        ).start()

    def _run_queue_export(self, base_path, queue_files, progress_bar, status_text, detail_text, dialog, eta_text, export_root_name, include_reports, clear_queue, completion_message, cancel_event):
        def update_dialog(status: Optional[str] = None, detail: Optional[str] = None, progress: Optional[float] = None):
            def _update():
                if status is not None:
                    status_text.value = status
                if detail is not None:
                    detail_text.value = detail
                if progress is not None:
                    progress_bar.value = max(0.0, min(1.0, progress))
                try:
                    self.page.update()
                except Exception:
                    pass
            self._dispatch_ui(_update)

        def update_eta(processed: float, total: int, start_time: float):
            if not eta_text:
                return
            elapsed = time.time() - start_time
            eta_value = "Calculating…"
            if processed > 0 and elapsed > 0 and total:
                remaining = total - processed
                rate = processed / elapsed if elapsed else 0
                if rate > 0:
                    eta_seconds = remaining / rate
                    eta_minutes = int(eta_seconds // 60)
                    eta_secs = int(eta_seconds % 60)
                    eta_value = f"ETA: {eta_minutes}m {eta_secs}s"
                else:
                    eta_value = "ETA: ∞"
            else:
                eta_value = "ETA: Calculating…"

            def _update_eta():
                eta_text.value = eta_value
                try:
                    eta_text.update()
                except Exception:
                    pass
            self._dispatch_ui(_update_eta)

        def _format_speed(bytes_per_second: float) -> str:
            if bytes_per_second <= 0:
                return "Measuring…"
            units = ["B/s", "KB/s", "MB/s", "GB/s"]
            index = 0
            while bytes_per_second >= 1024 and index < len(units) - 1:
                bytes_per_second /= 1024
                index += 1
            precision = 0 if index == 0 else 1
            return f"{bytes_per_second:.{precision}f} {units[index]}"

        def _format_duration(seconds: Optional[float]) -> str:
            if seconds is None or seconds <= 0:
                return "Calculating…"
            minutes, secs = divmod(int(seconds), 60)
            hours, minutes = divmod(minutes, 60)
            if hours:
                return f"{hours}h {minutes}m"
            if minutes:
                return f"{minutes}m {secs}s"
            return f"{secs}s"

        def is_cancelled() -> bool:
            return bool(cancel_event and cancel_event.is_set())

        processed_files = 0
        cancelled = False

        try:
            export_dir = os.path.join(base_path, export_root_name or "Export")
            ensure_directory(export_dir)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            csv_path = os.path.join(base_path, f"ExportReport_{timestamp}.csv") if include_reports else None
            json_path = os.path.join(base_path, f"ExportReport_{timestamp}.json") if include_reports else None
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            expanded_records = self._gather_export_records(cursor, queue_files)
            download_records = [rec for rec in expanded_records if rec['mime_type'] != FOLDER_MIME]
            folder_records = [rec for rec in expanded_records if rec['mime_type'] == FOLDER_MIME]

            total_files = len(download_records)
            report_entries = []
            start_time = time.time()

            self._update_activity_status(f"Exporting queue… 0/{total_files}", ft.Colors.BLUE_700)

            update_dialog(detail=f"Creating {len(folder_records)} folders", progress=0.02)

            for folder in folder_records:
                if is_cancelled():
                    cancelled = True
                    break
                local_folder = self._build_local_path(export_dir, folder, cursor, is_folder=True)
                ensure_directory(local_folder)
                report_entries.append(self._build_report_entry(folder, local_folder, cursor, base_path, exported=False))

            if cancelled:
                update_dialog(status="⏹ Export cancelled", detail="Operation stopped before downloads began.", progress=progress_bar.value)
            elif total_files == 0:
                update_dialog(status="No files to download", detail=f"Folders created under {export_dir}", progress=1)

            if not cancelled:
                for index, file_record in enumerate(download_records, start=1):
                    if is_cancelled():
                        cancelled = True
                        break
                    intended_path = self._build_local_path(export_dir, file_record, cursor, is_folder=False)
                    dest_dir = os.path.dirname(intended_path)
                    ensure_directory(dest_dir)
                    drive_path_label = " / ".join(self._resolve_drive_segments(file_record, cursor)) or file_record.get('name')
                    current_file_size = file_record.get('size') or 0
                    file_start_time = time.time()

                    def _file_progress_callback(value: float, idx=index, label=drive_path_label, size=current_file_size, start=file_start_time, name=file_record['name']):
                        file_progress = max(0.0, min(1.0, value or 0.0))
                        overall_progress = ((idx - 1) + file_progress) / total_files if total_files else file_progress
                        downloaded_bytes = int(size * file_progress)
                        elapsed = max(time.time() - start, 0.001)
                        speed_text = _format_speed(downloaded_bytes / elapsed) if size else "Measuring…"
                        remaining_bytes = max(size - downloaded_bytes, 0)
                        per_file_eta = _format_duration((remaining_bytes / (downloaded_bytes / elapsed)) if downloaded_bytes and elapsed else None)
                        status_line = f"Downloading {name} ({idx}/{total_files}) – {int(file_progress * 100)}%"
                        detail_lines = [label]
                        detail_lines.append(f"Speed: {speed_text} • File ETA: {per_file_eta}")
                        update_dialog(
                            status=status_line,
                            detail="\n".join(detail_lines),
                            progress=overall_progress
                        )
                        self._update_activity_status(status_line, ft.Colors.BLUE_700)
                        update_eta((idx - 1) + file_progress, total_files, start_time)

                    downloaded_path = None
                    try:
                        downloaded_path = self.forensics.download_file(
                            file_record['id'],
                            file_record['name'],
                            file_record['mime_type'],
                            dest_dir,
                            progress_callback=_file_progress_callback
                        )
                    except Exception as exc:
                        logger.error(f"Failed to download {file_record['name']}: {exc}")

                    completed_status = f"Downloading {file_record['name']} ({index}/{total_files}) – 100%"
                    update_dialog(status=completed_status, detail=drive_path_label, progress=(index / total_files) if total_files else 1)
                    self._update_activity_status(completed_status, ft.Colors.BLUE_700)
                    update_eta(index, total_files, start_time)

                    report_entries.append(
                        self._build_report_entry(
                            file_record,
                            downloaded_path or intended_path,
                            cursor,
                            base_path,
                            exported=downloaded_path is not None
                        )
                    )
                    processed_files = index

                    if is_cancelled():
                        cancelled = True
                        break

            if cancelled:
                update_dialog(
                    status="⏹ Export cancelled",
                    detail=f"Finished {processed_files} of {total_files} files. Remaining items stay in the queue.",
                    progress=progress_bar.value
                )
                time.sleep(1.5)
                self._dispatch_ui(self.close_dialog)
                self._dispatch_ui(lambda: self.show_snackbar(f"⏹ Export cancelled after {processed_files} file(s)"))
                self._update_activity_status("Export cancelled", ft.Colors.RED_600)
                return

            # Write CSV
            if include_reports and csv_path and json_path:
                with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'File_ID', 'Name', 'MIME_Type', 'Item_Type', 'Size_Bytes', 'Size_Readable',
                        'Drive_Path', 'Local_Path', 'Owner_Name', 'Owner_Email',
                        'Starred', 'Trashed', 'Public', 'Shortcut', 'MD5', 'SHA1', 'SHA256',
                        'Web_View_Link', 'Shared_With_JSON'
                    ])
                    for entry in report_entries:
                        writer.writerow([
                            entry['file_id'],
                            entry['name'],
                            entry['mime_type'],
                            entry['item_type'],
                            entry['size_bytes'],
                            entry['size_readable'],
                            entry['drive_path'],
                            entry['local_path'],
                            entry['owner_name'],
                            entry['owner_email'],
                            'Yes' if entry['starred'] else 'No',
                            'Yes' if entry['trashed'] else 'No',
                            'Yes' if entry['is_public'] else 'No',
                            'Yes' if entry['is_shortcut'] else 'No',
                            entry['md5_checksum'] or '',
                            entry['sha1_checksum'] or '',
                            entry['sha256_checksum'] or '',
                            entry['web_view_link'] or '',
                            json.dumps(entry['shared_with'], ensure_ascii=False)
                        ])

                report_payload = {
                    'metadata': {
                        'generated_at': datetime.now().isoformat(),
                        'base_folder': base_path,
                        'export_dir': export_dir,
                        'total_records': len(report_entries),
                        'downloaded_files': total_files
                    },
                    'files': report_entries
                }
                with open(json_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(report_payload, jsonfile, indent=2, ensure_ascii=False)

            if clear_queue and queue_files:
                conn.execute(
                    f"DELETE FROM export_queue WHERE file_id IN ({','.join(['?'] * len(queue_files))})",
                    [rec['id'] for rec in queue_files]
                )
                conn.commit()
                self.export_queue = [fid for fid in self.export_queue if fid not in {rec['id'] for rec in queue_files}]
                self.refresh_queue_badge()
            conn.close()

            detail_msg = ""
            if include_reports and csv_path and json_path:
                detail_msg = f"CSV: {csv_path}\nJSON: {json_path}"
            elif completion_message:
                detail_msg = completion_message
            update_dialog(status=f"✅ Export complete! Files: {total_files}", detail=detail_msg or export_dir, progress=1)

            time.sleep(2)
            self._dispatch_ui(self.close_dialog)
            final_msg = completion_message or (f"✅ Export complete – reports saved to {csv_path}" if csv_path else f"✅ Export complete – files saved to {export_dir}")
            self._dispatch_ui(lambda: self.show_snackbar(final_msg))
            self._update_activity_status("Queue idle", ft.Colors.GREY_600)

        except Exception as exc:
            logger.error(f"Queue export failed: {exc}")
            update_dialog(status="❌ Export failed", detail=str(exc))
            time.sleep(3)
            self._dispatch_ui(self.close_dialog)
            self.show_error(f"Export failed: {exc}")
            self._update_activity_status("❌ Queue export failed", ft.Colors.RED_600)
        finally:
            self._active_export_cancel_event = None

    def _gather_export_records(self, cursor, root_records):
        seen = set()
        records = []

        def visit(record):
            file_id = record['id']
            if file_id in seen:
                return
            seen.add(file_id)
            records.append(record)
            if record['mime_type'] == FOLDER_MIME:
                cursor.execute("SELECT * FROM files WHERE parent_id = ?", (file_id,))
                children = [dict(row) for row in cursor.fetchall()]
                for child in children:
                    visit(child)

        for rec in root_records:
            visit(rec)
        return records

    def _resolve_drive_segments(self, file_record: Dict, cursor) -> List[str]:
        file_id = file_record.get('id')
        if file_id in self._path_cache:
            return self._path_cache[file_id]

        segments = []
        current = dict(file_record)
        visited = set()
        while current:
            segments.append(current.get('name') or current.get('id') or 'Unknown')
            parent_id = current.get('parent_id')
            if not parent_id or parent_id in visited:
                break
            visited.add(parent_id)
            cursor.execute("SELECT id, name, parent_id FROM files WHERE id = ?", (parent_id,))
            parent_row = cursor.fetchone()
            if not parent_row:
                break
            current = {'id': parent_row[0], 'name': parent_row[1], 'parent_id': parent_row[2]}
            if parent_row[0] in self._path_cache:
                segments.extend(reversed(self._path_cache[parent_row[0]]))
                break
        resolved = list(reversed(segments))
        self._path_cache[file_id] = resolved
        return resolved

    def _build_local_path(self, export_dir, file_record, cursor, is_folder=False):
        segments = self._resolve_drive_segments(file_record, cursor)
        safe_segments = [sanitize_filename(seg) for seg in segments if seg]
        if not safe_segments:
            safe_segments = ['root']
        root_segment = os.path.basename(export_dir)
        if safe_segments and safe_segments[0] == root_segment:
            safe_segments = safe_segments[1:]
        if not safe_segments and is_folder:
            return export_dir
        local_path = os.path.join(export_dir, *safe_segments)
        if is_folder or file_record.get('mime_type') == FOLDER_MIME:
            return local_path
        return local_path

    def _build_report_entry(self, file_record, local_path, cursor, base_path, exported: bool):
        cursor.execute(
            "SELECT display_name, email_address, role, type FROM permissions WHERE file_id = ?",
            (file_record['id'],)
        )
        perms = [
            {
                'name': row[0] or row[1] or 'Unknown',
                'email': row[1],
                'role': row[2],
                'type': row[3]
            }
            for row in cursor.fetchall()
        ]

        relative_local = os.path.relpath(local_path, base_path) if local_path else None
        drive_path = " / ".join(self._resolve_drive_segments(file_record, cursor)) or (file_record.get('full_path') or '/')
        created_time = file_record.get('created_time')
        modified_time = file_record.get('modified_time')
        created_time_local = self._format_timestamp_for_timezone(created_time)
        modified_time_local = self._format_timestamp_for_timezone(modified_time)

        return {
            'file_id': file_record['id'],
            'name': file_record['name'],
            'mime_type': file_record['mime_type'],
            'size_bytes': file_record['size'] or 0,
            'size_readable': format_size(file_record['size'] or 0),
            'item_type': 'folder' if file_record.get('mime_type') == FOLDER_MIME else 'file',
            'drive_path': drive_path,
            'local_path': relative_local if exported else relative_local or 'Not downloaded',
            'owner_name': file_record.get('owner_name'),
            'owner_email': file_record.get('owner_email'),
            'starred': bool(file_record.get('starred')),
            'trashed': bool(file_record.get('trashed')),
            'is_public': bool(file_record.get('is_public')),
            'is_shortcut': bool(file_record.get('is_shortcut')),
            'md5_checksum': file_record.get('md5_checksum'),
            'sha1_checksum': file_record.get('sha1_checksum'),
            'sha256_checksum': file_record.get('sha256_checksum'),
            'web_view_link': file_record.get('web_view_link'),
            'shared_with': perms,
            'created_time': created_time,
            'modified_time': modified_time,
            'created_time_local': created_time_local,
            'modified_time_local': modified_time_local
        }

    def toggle_selection_mode(self, e=None):
        self.selection_mode = not self.selection_mode
        if not self.selection_mode:
            self.selected_file_ids.clear()
            if self.selection_toggle_button:
                self.selection_toggle_button.icon = ft.Icons.CHECK_BOX_OUTLINE_BLANK
                self.selection_toggle_button.tooltip = "Enable multi-select"
        else:
            if self.selection_toggle_button:
                self.selection_toggle_button.icon = ft.Icons.CHECK_BOX
                self.selection_toggle_button.tooltip = "Disable multi-select"
        self.update_selection_controls()
        self._run_with_loading("Updating selection…", self.load_files)
        self.show_snackbar("Multi-select on" if self.selection_mode else "Multi-select off")

    def update_selection_controls(self):
        if self.add_selected_button:
            self.add_selected_button.disabled = not self.selected_file_ids
            try:
                self.add_selected_button.update()
            except Exception:
                pass
        if self.selection_toggle_button and not self.selection_mode:
            self.selection_toggle_button.icon = ft.Icons.CHECK_BOX_OUTLINE_BLANK
            self.selection_toggle_button.tooltip = "Enable multi-select"
            try:
                self.selection_toggle_button.update()
            except Exception:
                pass

    def _toggle_file_selection(self, file_id: str, selected: bool, refresh_view: bool = False):
        try:
            if selected:
                self.selected_file_ids.add(file_id)
            else:
                self.selected_file_ids.discard(file_id)
            self.update_selection_controls()
            if refresh_view:
                self._run_with_loading("Updating selection…", self.load_files)
        finally:
            pass

    def add_selected_to_queue(self, e=None):
        if not self.selected_file_ids:
            self.show_snackbar("Select files first")
            return
        added = 0
        for file_id in list(self.selected_file_ids):
            if file_id not in self.export_queue:
                try:
                    conn = sqlite3.connect(DATABASE_FILE)
                    cursor = conn.cursor()
                    cursor.execute("INSERT OR IGNORE INTO export_queue (file_id, added_time) VALUES (?, ?)", (file_id, datetime.now().isoformat()))
                    conn.commit()
                    conn.close()
                    self.export_queue.append(file_id)
                    added += 1
                except Exception as exc:
                    logger.error(f"Bulk queue insert failed: {exc}")
        self.selected_file_ids.clear()
        self.selection_mode = False
        self.update_selection_controls()
        self.refresh_queue_badge()
        self.load_files()
        self.show_snackbar(f"✅ Added {added} files to queue" if added else "No new files added")

    def add_current_page_to_queue(self, e=None):
        if not self.current_file_ids:
            self.show_snackbar("No files on this page")
            return
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            added = 0
            for file_id in self.current_file_ids:
                if file_id in self.export_queue:
                    continue
                cursor.execute(
                    "INSERT OR IGNORE INTO export_queue (file_id, added_time) VALUES (?, ?)",
                    (file_id, datetime.now().isoformat())
                )
                if cursor.rowcount:
                    self.export_queue.append(file_id)
                    added += 1
            conn.commit()
            conn.close()
            self.refresh_queue_badge()
            if added:
                self.show_snackbar(f"✅ Added {added} files from this page to queue")
            else:
                self.show_snackbar("All files on this page are already in queue")
        except Exception as exc:
            logger.error(f"Bulk page queue failed: {exc}")
            self.show_error(f"Failed to add page to queue: {exc}")

    def export_filtered_results(self, e=None):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            where_clause, params = self._build_filter_clause()
            sort_map = {
                'name_asc': 'name ASC',
                'name_desc': 'name DESC',
                'size_desc': 'size DESC',
                'size_asc': 'size ASC',
                'modified_desc': 'modified_time DESC',
                'modified_asc': 'modified_time ASC',
                'created_desc': 'created_time DESC',
                'created_asc': 'created_time ASC',
                'owner_asc': 'owner_name ASC'
            }
            order_by = sort_map.get(self.sort_by, 'name ASC')
            cursor.execute(f"SELECT * FROM files WHERE {where_clause} ORDER BY {order_by}", params)
            filtered_files = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as exc:
            logger.error(f"Failed to gather filtered records: {exc}")
            self.show_error(f"Failed to gather filtered files: {exc}")
            return

        if not filtered_files:
            self.show_snackbar("No files match current filters")
            return

        def on_dir_selected(path):
            self._handle_queue_export_directory(
                path,
                filtered_files,
                export_root_name="Export",
                include_reports=True,
                clear_queue=False,
                completion_message=f"✅ Exported {len(filtered_files)} filtered items"
            )

        self.pick_directory(on_dir_selected)


    def show_context_menu(self, e, file_id):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
            file = cursor.fetchone()
            conn.close()
            if not file:
                self.show_error("File not found")
                return
            file = dict(file)

            actions = []
            actions.append(ft.TextButton("Info", on_click=lambda _e: [self.close_dialog(), self.show_file_info(file_id)]))
            if file['mime_type'] != FOLDER_MIME:
                actions.append(ft.TextButton("Download", on_click=lambda _e: [self.close_dialog(), self.download_file_with_picker(file_id, file['name'], file['mime_type'])]))
            actions.append(ft.TextButton("Add to Queue", on_click=lambda _e: [self.add_to_queue(file_id), self.close_dialog()]))
            actions.append(ft.TextButton("Close", on_click=lambda _e: self.close_dialog()))

            dialog = ft.AlertDialog(
                title=ft.Text(file['name'][:40]),
                content=ft.Text(file.get('full_path') or '/'),
                actions=actions,
                modal=True
            )
            self._show_dialog(dialog)
        except Exception as exc:
            logger.error(f"Context menu failed: {exc}")
            self.show_error(f"Failed to open context menu: {exc}")
    
    def tab_changed(self, e):
        """Handle tab change"""
        index = e.control.selected_index
        if index == 1:
            self.load_users()
        elif index == 2:
            self.load_analytics()
        else:
            if self.pending_files_reload or not self.current_file_ids:
                message = self.pending_files_message or "Loading files…"
                self.pending_files_message = None
                self._reload_files_if_visible(message, force=True)
        self._update_files_tab_visibility()
    
    def _open_high_res_avatar(self, photo_url: Optional[str]):
        if not photo_url:
            self.show_snackbar("No avatar available")
            return
        high_res = re.sub(r"=s\d+", "=s4096", photo_url)
        try:
            webbrowser.open(high_res)
        except Exception as exc:
            logger.error(f"Failed to open avatar: {exc}")
            self.show_error("Could not open avatar in browser")

    def load_users(self):
        """Render simplified Users tab"""
        try:
            users = self.forensics.get_user_analytics(self.user_search_query, limit=200)

            if not self.user_search_field:
                self.user_search_field = ft.TextField(
                    hint_text="Search users...",
                    prefix_icon=ft.Icons.SEARCH,
                    width=260,
                    on_change=self.handle_user_search,
                    dense=True,
                    border_radius=20,
                )
            self.user_search_field.value = self.user_search_query
            search_field = self.user_search_field

            header = ft.Row([
                ft.Text("👥 Users", size=26, weight=ft.FontWeight.BOLD),
                ft.Row([
                    search_field,
                    ft.IconButton(
                        icon=ft.Icons.CLEAR,
                        tooltip="Clear search",
                        on_click=self.clear_user_search,
                        visible=bool(self.user_search_query)
                    ),
                    ft.ElevatedButton(
                        "Clear Filter" if self.selected_user_filter else "Filter by user",
                        icon=ft.Icons.FILTER_ALT_OFF if self.selected_user_filter else ft.Icons.FILTER_LIST,
                        on_click=self.clear_user_filter,
                        disabled=not self.selected_user_filter
                    )
                ], spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

            active_filter_chip = ft.Chip(
                label=ft.Row([
                    ft.Text("Filtering:"),
                    ft.Text(self.user_filter_label or "None", weight=ft.FontWeight.BOLD)
                ], spacing=4),
                bgcolor=ft.Colors.BLUE_50,
                visible=bool(self.user_filter_label)
            )

            cards: List[ft.Control] = []
            if not users:
                cards.append(
                    ft.Container(
                        content=ft.Column([
                            ft.Icon(ft.Icons.SEARCH_OFF, size=80, color=ft.Colors.GREY_400),
                            ft.Text("No users yet", size=18, color=ft.Colors.GREY_600),
                            ft.Text("Try scanning drive or adjusting search", size=13, color=ft.Colors.GREY_500)
                        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8),
                        padding=40,
                        alignment=ft.alignment.center
                    )
                )
            else:
                def _chip(label: str, value: int, bg_color, text_color):
                    return ft.Container(
                        bgcolor=bg_color,
                        border_radius=8,
                        padding=ft.padding.symmetric(horizontal=12, vertical=6),
                        content=ft.Column([
                            ft.Text(label, size=11, color=text_color),
                            ft.Text(f"{value:,}", size=18, weight=ft.FontWeight.BOLD, color=text_color)
                        ], spacing=0, alignment=ft.MainAxisAlignment.CENTER)
                    )

                for user in users:
                    email = user.get('email_address') or "unknown@example.com"
                    display_name = user.get('display_name') or email
                    photo = user.get('photo_link')
                    shared_with_count = user.get('files_shared_with_count', 0)
                    shared_by_count = user.get('files_shared_by_count', 0)

                    avatar = ft.CircleAvatar(
                        radius=28,
                        foreground_image_src=photo,
                        bgcolor=ft.Colors.BLUE_100,
                        content=ft.Text((display_name or email or '?')[:1].upper(), size=16)
                    ) if photo else ft.CircleAvatar(
                        radius=28,
                        bgcolor=ft.Colors.BLUE_100,
                        content=ft.Text((display_name or email or '?')[:1].upper(), size=16)
                    )

                    def _filter_user(em=email, dn=display_name):
                        self.apply_user_filter_from_card(em, dn)

                    def _open_avatar(url=photo):
                        self._open_high_res_avatar(url)

                    info_section = ft.Row([
                        ft.GestureDetector(content=avatar, on_tap=lambda e, action=_open_avatar: action()),
                        ft.Column([
                            ft.Text(display_name, size=15, weight=ft.FontWeight.BOLD, overflow=ft.TextOverflow.ELLIPSIS, max_lines=1),
                            ft.Text(email, size=12, color=ft.Colors.GREY_600, overflow=ft.TextOverflow.ELLIPSIS, max_lines=1)
                        ], spacing=2, expand=True)
                    ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER)

                    stats_section = ft.Row([
                        _chip("Shared with", shared_with_count, ft.Colors.BLUE_50, ft.Colors.BLUE_900),
                        _chip("Shared by", shared_by_count, ft.Colors.GREEN_50, ft.Colors.GREEN_900)
                    ], spacing=10, run_spacing=6, wrap=True, alignment=ft.MainAxisAlignment.START)

                    actions_section = ft.Row([
                        ft.TextButton("Filter files", icon=ft.Icons.FILTER_ALT, on_click=lambda e, action=_filter_user: action())
                    ], spacing=6, alignment=ft.MainAxisAlignment.END)

                    row = ft.Container(
                        bgcolor=ft.Colors.WHITE,
                        border_radius=10,
                        padding=ft.padding.symmetric(vertical=10, horizontal=14),
                        border=ft.border.all(1, ft.Colors.GREY_200),
                        content=ft.ResponsiveRow(
                            controls=[
                                ft.Container(info_section, col={'xs': 12, 'md': 5, 'lg': 4}),
                                ft.Container(stats_section, col={'xs': 12, 'md': 4, 'lg': 4}),
                                ft.Container(actions_section, col={'xs': 12, 'md': 3, 'lg': 2}, alignment=ft.alignment.center_right)
                            ],
                            run_spacing=8,
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                        )
                    )
                    cards.append(row)

            grid = ft.Column(cards, spacing=8, expand=True)

            content = ft.Column([
                header,
                ft.Divider(height=10),
                active_filter_chip,
                ft.Divider(height=10),
                grid
            ], spacing=12, expand=True, scroll=ft.ScrollMode.AUTO)

            if self.results_container:
                self.results_container.controls = [content]
                self.results_container.update()
            if self.user_search_focus_pending and self.user_search_field:
                try:
                    self.user_search_field.focus()
                    self.user_search_field.update()
                except Exception:
                    pass
                self.user_search_focus_pending = False
        except Exception as e:
            logger.error(f"Error loading users: {e}")
            self.show_error(f"Failed to load users: {str(e)}")
    
    def start_scan(self, e):
        if self.scan_running:
            self.show_snackbar("Scan already running…")
            return
        if not getattr(self.forensics, 'service', None):
            self.show_error("Authenticate first to scan Drive")
            return

        self.scan_running = True
        self.scan_status_text = ft.Text("Initializing scan…", size=13, weight=ft.FontWeight.BOLD)
        self.scan_detail_text = ft.Text("Preparing queries", size=11, color=ft.Colors.GREY_600)
        self.scan_progress_bar = ft.ProgressBar(width=420)
        self.scan_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("🔍 Scanning Google Drive"),
            content=ft.Container(
                width=480,
                content=ft.Column([
                    self.scan_status_text,
                    self.scan_progress_bar,
                    self.scan_detail_text
                ], spacing=10)
            ),
            actions=[
                ft.TextButton("Run in background", on_click=lambda ev: self._dispatch_ui(self._minimize_scan_dialog)),
                ft.TextButton("Cancel", on_click=lambda ev: self.show_snackbar("Use close app to abort"), disabled=True)
            ]
        )
        self._show_dialog(self.scan_dialog)

        threading.Thread(target=self._run_scan_with_progress, daemon=True).start()

    def _minimize_scan_dialog(self):
        if self.scan_dialog:
            self.scan_dialog.open = False
            try:
                self.page.update()
            except Exception:
                pass

    def _run_scan_with_progress(self):
        def progress_callback(progress: Dict[str, object]):
            def update_ui():
                if not self.scan_status_text:
                    return
                self.scan_status_text.value = progress.get('message', 'Scanning…')
                self.scan_detail_text.value = (
                    f"Files: {progress.get('files_processed', 0)} • Folders: {progress.get('folders_processed', 0)} • Errors: {progress.get('errors', 0)}"
                )
                current = progress.get('current', 0)
                total = max(progress.get('total', current) or current or 1, 1)
                if self.scan_progress_bar:
                    self.scan_progress_bar.value = min(current / total, 1.0)
                try:
                    self.page.update()
                except Exception:
                    pass
            self._dispatch_ui(update_ui)

        try:
            self.forensics.scan_drive(progress_callback=progress_callback)
            self._dispatch_ui(lambda: self.show_snackbar("✅ Scan complete"))
            self._dispatch_ui(self.populate_user_filter)
            self._dispatch_ui(self.load_files)
        except Exception as exc:
            logger.error(f"Scan failed: {exc}")
            self._dispatch_ui(lambda: self.show_error(f"Scan failed: {exc}"))
        finally:
            def cleanup():
                self.scan_running = False
                if self.scan_dialog:
                    self.scan_dialog.open = False
                try:
                    self.page.update()
                except Exception:
                    pass
            self._dispatch_ui(cleanup)
    
    def export_csv(self, e):
        """Generate metadata CSV for current filters"""
        self._export_metadata_report("csv")
    
    def export_json(self, e):
        """Generate metadata JSON for current filters"""
        self._export_metadata_report("json")

    def _export_metadata_report(self, format_type: str):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            where_clause, params = self._build_filter_clause()
            sort_map = {
                'name_asc': 'name ASC',
                'name_desc': 'name DESC',
                'size_desc': 'size DESC',
                'size_asc': 'size ASC',
                'modified_desc': 'modified_time DESC',
                'modified_asc': 'modified_time ASC',
                'created_desc': 'created_time DESC',
                'created_asc': 'created_time ASC',
                'owner_asc': 'owner_name ASC'
            }
            order_by = sort_map.get(self.sort_by, 'name ASC')
            cursor.execute(f"SELECT * FROM files WHERE {where_clause} ORDER BY {order_by}", params)
            filtered_files = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except Exception as exc:
            logger.error(f"Failed to gather filtered records: {exc}")
            self.show_error(f"Failed to gather filtered files: {exc}")
            return

        if not filtered_files:
            self.show_snackbar("No files match current filters")
            return

        def on_dir_selected(path):
            if not path:
                self.show_snackbar("Export cancelled")
                return
            self._handle_metadata_report_export(path, filtered_files, format_type)

        self.pick_directory(on_dir_selected)

    def _handle_metadata_report_export(self, base_path: str, filtered_files: List[Dict], format_type: str):
        self._set_loading(True, "Exporting metadata…")
        self._update_activity_status("Exporting metadata…", ft.Colors.BLUE_700)
        progress_bar = ft.ProgressBar(width=420)
        status_text = ft.Text("Preparing metadata report…", size=13)
        detail_text = ft.Text("", size=11, color=ft.Colors.GREY_600)
        dialog = ft.AlertDialog(
            title=ft.Text("📝 Exporting Metadata"),
            content=ft.Container(
                width=500,
                content=ft.Column([
                    ft.Text(f"Destination: {base_path}", size=11, color=ft.Colors.GREY_600),
                    progress_bar,
                    status_text,
                    detail_text
                ], spacing=8)
            ),
            modal=True
        )
        cancel_event = threading.Event()

        def cancel_export(_=None):
            if cancel_event.is_set():
                return
            cancel_event.set()
            status_text.value = "Stopping export…"
            detail_text.value = "Wrapping up current operation"
            self._update_activity_status("Cancelling metadata export…", ft.Colors.ORANGE_700)
            try:
                self.page.update()
            except Exception:
                pass

        def run_in_background(_=None):
            self.close_dialog()
            self._set_loading(False)
            self._update_activity_status("Metadata export running in background", ft.Colors.BLUE_700)
            self.show_snackbar("📝 Metadata export continues in background")

        cancel_button = ft.TextButton("Cancel export", icon=ft.Icons.STOP_CIRCLE, on_click=cancel_export)
        background_button = ft.TextButton("Run in background", icon=ft.Icons.CLOSE_FULLSCREEN, on_click=run_in_background)
        dialog.actions = [background_button, cancel_button]
        self._show_dialog(dialog)

        threading.Thread(
            target=self._run_metadata_report_export,
            args=(base_path, filtered_files, format_type, progress_bar, status_text, detail_text, dialog, cancel_event),
            daemon=True
        ).start()

    def _run_metadata_report_export(self, base_path: str, filtered_files: List[Dict], format_type: str,
                                    progress_bar: ft.ProgressBar, status_text: ft.Text, detail_text: ft.Text,
                                    dialog: ft.AlertDialog, cancel_event: threading.Event):
        def update_dialog(status: Optional[str] = None, detail: Optional[str] = None, progress: Optional[float] = None):
            def _update():
                if status is not None:
                    status_text.value = status
                if detail is not None:
                    detail_text.value = detail
                if progress is not None:
                    progress_bar.value = max(0.0, min(1.0, progress))
                try:
                    self.page.update()
                except Exception:
                    pass
            self._dispatch_ui(_update)

        def is_cancelled() -> bool:
            return bool(cancel_event and cancel_event.is_set())

        try:
            ensure_directory(base_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            tz_name = self.selected_timezone or 'UTC'
            try:
                tz = pytz.timezone(tz_name)
            except Exception:
                tz_name = 'UTC'
                tz = pytz.UTC
            tz_now = datetime.now(timezone.utc).astimezone(tz)
            offset = tz_now.utcoffset() or timedelta(0)
            total_minutes = int(offset.total_seconds() // 60)
            sign = '+' if total_minutes >= 0 else '-'
            abs_minutes = abs(total_minutes)
            offset_str = f"UTC{sign}{abs_minutes // 60:02d}:{abs_minutes % 60:02d}"
            timezone_display = f"{tz_name} ({offset_str})"

            csv_path = os.path.join(base_path, f"FilteredReport_{timestamp}.csv") if format_type in ("csv", "both") else None
            json_path = os.path.join(base_path, f"FilteredReport_{timestamp}.json") if format_type in ("json", "both") else None

            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            total = len(filtered_files)
            report_entries = []

            for index, record in enumerate(filtered_files, start=1):
                if is_cancelled():
                    break
                entry = self._build_report_entry(record, None, cursor, base_path, exported=False)
                report_entries.append(entry)
                activity_message = f"Metadata export {min(index, total)}/{total}"
                update_dialog(
                    status=f"Processing {index}/{total}",
                    detail=entry['drive_path'],
                    progress=index / total if total else 1
                )
                self._update_activity_status(activity_message, ft.Colors.BLUE_700)

            if is_cancelled():
                update_dialog(status="⏹ Export cancelled", detail=f"Processed {len(report_entries)} of {total}")
                time.sleep(1)
                self._dispatch_ui(self.close_dialog)
                self._dispatch_ui(lambda: self.show_snackbar("⏹ Metadata export cancelled"))
                self._update_activity_status("Metadata export cancelled", ft.Colors.ORANGE_700)
                return

            if csv_path:
                with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'File_ID', 'Name', 'MIME_Type', 'Item_Type', 'Size_Bytes', 'Size_Readable',
                        'Drive_Path', 'Local_Path', 'Owner_Name', 'Owner_Email', 'Starred', 'Trashed',
                        'Is_Public', 'Is_Shortcut', 'MD5', 'SHA1', 'SHA256', 'Web_Link', 'Shared_With',
                        'Created_Time', 'Modified_Time', 'Created_Time_Local', 'Modified_Time_Local', 'Timezone'
                    ])
                    for entry in report_entries:
                        writer.writerow([
                            entry['file_id'],
                            entry['name'],
                            entry['mime_type'],
                            entry['item_type'],
                            entry['size_bytes'],
                            entry['size_readable'],
                            entry['drive_path'],
                            entry['local_path'],
                            entry['owner_name'],
                            entry['owner_email'],
                            'Yes' if entry['starred'] else 'No',
                            'Yes' if entry['trashed'] else 'No',
                            'Yes' if entry['is_public'] else 'No',
                            'Yes' if entry['is_shortcut'] else 'No',
                            entry['md5_checksum'] or '',
                            entry['sha1_checksum'] or '',
                            entry['sha256_checksum'] or '',
                            entry['web_view_link'] or '',
                            json.dumps(entry['shared_with'], ensure_ascii=False),
                            entry.get('created_time') or '',
                            entry.get('modified_time') or '',
                            entry.get('created_time_local') or '',
                            entry.get('modified_time_local') or '',
                            timezone_display
                        ])

            if json_path:
                payload = {
                    'generated_at': datetime.now().isoformat(),
                    'timezone': timezone_display,
                    'total_records': len(report_entries),
                    'filters_applied': self.build_filter_summary(),
                    'records': report_entries
                }
                with open(json_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(payload, jsonfile, indent=2, ensure_ascii=False)

            conn.close()

            update_dialog(status="✅ Metadata export complete", detail="", progress=1)
            time.sleep(1)
            self._dispatch_ui(self.close_dialog)
            if format_type == 'csv':
                final_msg = f"CSV saved to {csv_path}"
            elif format_type == 'json':
                final_msg = f"JSON saved to {json_path}"
            else:
                final_msg = f"Reports saved to {base_path}"
            self._dispatch_ui(lambda: self.show_snackbar(f"✅ {final_msg}"))
            self._update_activity_status("Metadata export complete", ft.Colors.GREEN_700)
        except Exception as exc:
            logger.error(f"Metadata export failed: {exc}")
            update_dialog(status="❌ Export failed", detail=str(exc))
            time.sleep(2)
            self._dispatch_ui(self.close_dialog)
            self._dispatch_ui(lambda: self.show_error(f"Export failed: {exc}"))
            self._update_activity_status("Metadata export failed", ft.Colors.RED_600)
        finally:
            self._dispatch_ui(lambda: self._set_loading(False))
            self._update_activity_status("No active downloads", ft.Colors.GREY_600)
    
    def change_page(self, delta: int):
        new_page = min(max(1, self.current_page + delta), self.total_pages)
        if new_page != self.current_page:
            self.current_page = new_page
            message = f"Loading page {self.current_page}…"
            self._run_with_loading(message, self.load_files)

    def reset_to_first_page(self):
        self.current_page = 1
        self.update_pagination_controls()

    def update_per_page(self, value: int):
        if value <= 0:
            return
        self.per_page = value
        self.current_page = 1
        message = "Updating page size…"
        self._run_with_loading(message, self.load_files)
    
    def build_filter_summary(self):
        parts = []
        if self.current_filter != 'all':
            parts.append(f"Source: {self.current_filter}")
        if self.owner_filter != 'all':
            parts.append(f"Owner: {self.owner_filter}")
        if self.search_query:
            parts.append(f"Search: '{self.search_query}'")
        if self.show_starred_only:
            parts.append("Starred only")
        if self.show_public_only:
            parts.append("Public only")
        if self.browse_scope_filter == 'folders':
            parts.append("Folders only")
        elif self.browse_scope_filter == 'files':
            parts.append("Files only")
        type_labels = {
            'docs': 'Google Docs',
            'sheets': 'Google Sheets',
            'slides': 'Google Slides',
            'forms': 'Google Forms',
            'shortcuts': 'Shortcuts',
            'pdf': 'PDFs',
            'images': 'Images',
            'videos': 'Videos',
            'audio': 'Audio',
            'archives': 'Archives'
        }
        if self.browse_type_filter:
            selected_labels = [type_labels.get(value, value.title()) for value in sorted(self.browse_type_filter)]
            parts.append("Types: " + ", ".join(selected_labels))
        if self.date_from or self.date_to:
            parts.append(f"Date: {self.date_from or 'any'} to {self.date_to or 'any'}")
        return " | ".join(parts) if parts else "No filters active"
    
    def update_date_button_label(self):
        if not self.date_filter_button:
            return
        if self.date_from and self.date_to:
            self.date_filter_button.text = f"📅 {self.date_from.strftime('%Y-%m-%d')} → {self.date_to.strftime('%Y-%m-%d')}"
        elif self.date_from:
            self.date_filter_button.text = f"📅 From {self.date_from.strftime('%Y-%m-%d')}"
        elif self.date_to:
            self.date_filter_button.text = f"📅 Until {self.date_to.strftime('%Y-%m-%d')}"
        else:
            self.date_filter_button.text = "📅 Date Filter"
        try:
            self.date_filter_button.update()
        except:
            pass
    
    def change_view_mode(self, mode):
        self.view_mode = mode
        self.update_view_mode_buttons()
        self.load_files()
    
    def update_view_mode_buttons(self):
        if self.tile_view_button and self.list_view_button:
            if self.view_mode == "tiles":
                self.tile_view_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_100)
                self.list_view_button.style = ft.ButtonStyle(bgcolor=None)
            else:
                self.tile_view_button.style = ft.ButtonStyle(bgcolor=None)
                self.list_view_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_100)
            try:
                self.tile_view_button.update()
                self.list_view_button.update()
            except:
                pass


def main(page: ft.Page):
    """Main entry point for the application"""
    ForensicsApp(page)


if __name__ == "__main__":
    ft.app(target=main, assets_dir="assets")

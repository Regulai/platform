"""
Google Drive Integration for RegulAI

This module provides functionality to upload files to Google Drive
and get shareable links for viewing/editing in Google Docs/Sheets/Slides.
"""

import os
import io
import json
from typing import Optional, Tuple, Dict, Any
from django.conf import settings
from django.core.cache import cache


# Google API imports
try:
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False


# OAuth 2.0 scopes for Google Drive
SCOPES = [
    'https://www.googleapis.com/auth/drive.file',  # Create/edit files created by the app
]

# Map file extensions to Google Workspace MIME types for conversion
GOOGLE_MIME_TYPES = {
    'docx': 'application/vnd.google-apps.document',
    'doc': 'application/vnd.google-apps.document',
    'xlsx': 'application/vnd.google-apps.spreadsheet',
    'xls': 'application/vnd.google-apps.spreadsheet',
    'csv': 'application/vnd.google-apps.spreadsheet',
    'pptx': 'application/vnd.google-apps.presentation',
    'ppt': 'application/vnd.google-apps.presentation',
    'pdf': 'application/pdf',  # PDF stays as PDF
    'txt': 'application/vnd.google-apps.document',
}

# Map extensions to original MIME types
ORIGINAL_MIME_TYPES = {
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'doc': 'application/msword',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xls': 'application/vnd.ms-excel',
    'csv': 'text/csv',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'ppt': 'application/vnd.ms-powerpoint',
    'pdf': 'application/pdf',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'txt': 'text/plain',
    'py': 'text/x-python',
    'js': 'application/javascript',
    'html': 'text/html',
    'css': 'text/css',
    'json': 'application/json',
}

# Google Workspace editor URLs
GOOGLE_EDITOR_URLS = {
    'application/vnd.google-apps.document': 'https://docs.google.com/document/d/{file_id}/edit',
    'application/vnd.google-apps.spreadsheet': 'https://docs.google.com/spreadsheets/d/{file_id}/edit',
    'application/vnd.google-apps.presentation': 'https://docs.google.com/presentation/d/{file_id}/edit',
}


def is_google_drive_configured() -> bool:
    """Check if Google Drive integration is configured."""
    if not GOOGLE_API_AVAILABLE:
        return False

    client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)
    client_secret = getattr(settings, 'GOOGLE_CLIENT_SECRET', None)

    return bool(client_id and client_secret)


def get_oauth_flow(redirect_uri: str) -> Optional['Flow']:
    """Create OAuth flow for Google authentication."""
    if not GOOGLE_API_AVAILABLE or not is_google_drive_configured():
        return None

    client_config = {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )

    return flow


def get_authorization_url(request) -> Tuple[str, str]:
    """
    Get the Google OAuth authorization URL.
    Returns (auth_url, state) tuple.
    """
    redirect_uri = request.build_absolute_uri('/google/callback/')
    flow = get_oauth_flow(redirect_uri)

    if not flow:
        return None, None

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    return authorization_url, state


def exchange_code_for_credentials(request, code: str, state: str) -> Optional[Dict[str, Any]]:
    """
    Exchange authorization code for credentials.
    Returns credentials dict that can be stored.
    """
    redirect_uri = request.build_absolute_uri('/google/callback/')
    flow = get_oauth_flow(redirect_uri)

    if not flow:
        return None

    flow.fetch_token(code=code)
    credentials = flow.credentials

    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': list(credentials.scopes),
    }


def get_credentials_from_dict(creds_dict: Dict[str, Any]) -> Optional['Credentials']:
    """Reconstruct Credentials object from stored dict."""
    if not GOOGLE_API_AVAILABLE or not creds_dict:
        return None

    credentials = Credentials(
        token=creds_dict.get('token'),
        refresh_token=creds_dict.get('refresh_token'),
        token_uri=creds_dict.get('token_uri'),
        client_id=creds_dict.get('client_id'),
        client_secret=creds_dict.get('client_secret'),
        scopes=creds_dict.get('scopes'),
    )

    # Refresh if expired
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    return credentials


def upload_to_drive(
    credentials: 'Credentials',
    file_bytes: bytes,
    file_name: str,
    mime_type: str,
    convert_to_google_format: bool = True
) -> Optional[Dict[str, str]]:
    """
    Upload a file to Google Drive.

    Args:
        credentials: Google OAuth credentials
        file_bytes: File content as bytes
        file_name: Name for the file
        mime_type: MIME type of the file
        convert_to_google_format: Whether to convert to Google Docs/Sheets/Slides format

    Returns:
        Dict with 'file_id', 'web_view_link', 'web_content_link', 'edit_link'
    """
    if not GOOGLE_API_AVAILABLE:
        return None

    try:
        service = build('drive', 'v3', credentials=credentials)

        # Determine file extension
        ext = file_name.split('.')[-1].lower() if '.' in file_name else ''

        # File metadata
        file_metadata = {
            'name': file_name,
        }

        # Convert to Google format if requested and supported
        google_mime_type = GOOGLE_MIME_TYPES.get(ext) if convert_to_google_format else None
        if google_mime_type and google_mime_type.startswith('application/vnd.google-apps'):
            file_metadata['mimeType'] = google_mime_type

        # Create media upload
        media = MediaIoBaseUpload(
            io.BytesIO(file_bytes),
            mimetype=mime_type,
            resumable=True
        )

        # Upload file
        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, mimeType, webViewLink, webContentLink'
        ).execute()

        # Get the appropriate edit link
        result_mime_type = file.get('mimeType', '')
        edit_link = GOOGLE_EDITOR_URLS.get(result_mime_type, '').format(file_id=file['id'])

        if not edit_link:
            edit_link = file.get('webViewLink', '')

        return {
            'file_id': file['id'],
            'name': file.get('name'),
            'mime_type': result_mime_type,
            'web_view_link': file.get('webViewLink', ''),
            'web_content_link': file.get('webContentLink', ''),
            'edit_link': edit_link,
        }

    except Exception as e:
        print(f"Error uploading to Google Drive: {e}")
        return None


def get_drive_link_for_file(ext: str) -> Dict[str, str]:
    """
    Get information about what Google app would open this file type.

    Returns dict with 'app_name', 'icon', 'color'
    """
    apps = {
        'docx': {'app_name': 'Google Docs', 'icon': 'solar:document-text-bold', 'color': '#4285f4'},
        'doc': {'app_name': 'Google Docs', 'icon': 'solar:document-text-bold', 'color': '#4285f4'},
        'xlsx': {'app_name': 'Google Sheets', 'icon': 'solar:calculator-bold', 'color': '#0f9d58'},
        'xls': {'app_name': 'Google Sheets', 'icon': 'solar:calculator-bold', 'color': '#0f9d58'},
        'csv': {'app_name': 'Google Sheets', 'icon': 'solar:calculator-bold', 'color': '#0f9d58'},
        'pptx': {'app_name': 'Google Slides', 'icon': 'solar:presentation-chart-bold', 'color': '#f4b400'},
        'ppt': {'app_name': 'Google Slides', 'icon': 'solar:presentation-chart-bold', 'color': '#f4b400'},
        'pdf': {'app_name': 'Google Drive', 'icon': 'solar:file-text-bold', 'color': '#ea4335'},
        'png': {'app_name': 'Google Drive', 'icon': 'solar:gallery-bold', 'color': '#ea4335'},
        'jpg': {'app_name': 'Google Drive', 'icon': 'solar:gallery-bold', 'color': '#ea4335'},
    }
    return apps.get(ext, {'app_name': 'Google Drive', 'icon': 'solar:cloud-bold', 'color': '#4285f4'})

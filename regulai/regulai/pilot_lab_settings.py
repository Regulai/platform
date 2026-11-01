"""Production controls in a synthetic, internal Docker laboratory only.

This is not a production secret template or an approved deployment configuration.
The launcher copies only source files; local_settings.py is never in its image.
"""
import json
import os
from pathlib import Path

from .settings import *

LAB_ROOT = Path('/lab')
if os.environ.get('REGULAI_SYNTHETIC_LAB') != '1':
    raise RuntimeError('This configuration requires the isolated synthetic laboratory launcher.')
_keys = json.loads((LAB_ROOT / 'private' / 'keys.json').read_text(encoding='utf-8'))
SECRET_KEY = _keys['signing']
SECRET_KEY_FALLBACKS = []
ENCRYPTION_KEY = _keys['encryption']
ENCRYPTION_KEY_FALLBACKS = _keys.get('encryption_fallbacks', [])
DEBUG = False
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'testserver']
DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': os.environ.get('LAB_DATABASE', 'regulai_lab'),
    'USER': 'lab',
    'PASSWORD': _keys['database'],
    'HOST': 'db',
    'PORT': '5432',
    'CONN_MAX_AGE': 0,
    'TEST': {'NAME': 'test_regulai_lab'},
}}
MEDIA_ROOT = LAB_ROOT / ('restored-media' if DATABASES['default']['NAME'] == 'regulai_restored' else 'media')
STATIC_ROOT = LAB_ROOT / 'static'
FILE_UPLOAD_PERMISSIONS = 0o600
STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage',
        'OPTIONS': {'file_permissions_mode': 0o644, 'directory_permissions_mode': 0o755}},
}
SESSION_COOKIE_NAME = 'regulai_lab_session'
CSRF_COOKIE_NAME = 'regulai_lab_csrf'
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 3600
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
ALLOW_REGISTRATION = False
CORS_ALLOWED_ORIGINS = []
CORS_ALLOW_CREDENTIALS = False
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
PLATFORM_ADMIN_USER_IDS = []

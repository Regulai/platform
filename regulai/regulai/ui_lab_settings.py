"""Local chat UI lab only: synthetic SQLite outside the repository and a loopback
simulated provider. Never import production configuration or account data."""
import os
import tempfile
from copy import deepcopy
from pathlib import Path

from .test_settings import *  # noqa: F401,F403 - synthetic keys and hashers

LAB_DIR = Path(os.environ.get('REGULAI_UI_LAB_DIR') or Path(tempfile.gettempdir()) / 'regulai-ui-lab')
LAB_DIR.mkdir(parents=True, exist_ok=True)
DEBUG = True
SECRET_KEY = 'regulai-ui-lab-synthetic-only'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(LAB_DIR / 'lab.sqlite3'),
                         'OPTIONS': {'timeout': 20}}}
MEDIA_ROOT = LAB_DIR / 'media'
ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
SESSION_COOKIE_NAME = 'regulai_ui_lab_session'
CSRF_COOKIE_NAME = 'regulai_ui_lab_csrf'
CACHES = deepcopy(CACHES)
CACHES['default']['LOCATION'] = 'regulai-ui-lab'
# Agent views are enabled for explicit synthetic grants created by the lab seed.
# The lab never runs a worker: agent activity is recorded by the lab simulator.
REGULAY_AGENT_ENABLED = True
MIDDLEWARE = ['regulai.ui_lab_guard.RejectLabGeneration', *MIDDLEWARE]
# Loopback simulated provider (ops/chat_ui_lab/fake_provider.py). It reports usage
# in its streams, so the lab may stream from it like from an allowlisted provider.
UI_LAB_PROVIDER_URL = os.environ.get('REGULAI_UI_LAB_PROVIDER', 'http://127.0.0.1:8790')
CHAT_STREAMING_EXTRA_HOSTS = ['127.0.0.1']
# Shows the Drive picker for interface checks only; the lab has no Drive grant, so a
# search answers "Conector no disponible".
REGULAY_AGENT_MCP_ENABLED = os.environ.get('REGULAI_UI_LAB_DRIVE') == '1'

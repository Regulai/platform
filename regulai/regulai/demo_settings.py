"""Explicit loopback-only offline demo, separate from every ordinary database."""
from copy import deepcopy

from .settings import *

DEMO_MODE = True
DEMO_DATABASE_PATH = BASE_DIR / 'community-demo.sqlite3'
DEBUG = True
SECRET_KEY = 'community-offline-demo-public-key-not-for-production'
ENCRYPTION_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
OPENAI_API_KEY = ''
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '[::1]']
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': DEMO_DATABASE_PATH}}
MEDIA_ROOT = BASE_DIR / 'community-demo-media'
ALLOW_REGISTRATION = False
SESSION_COOKIE_NAME = 'community_demo_session'
CSRF_COOKIE_NAME = 'community_demo_csrf'
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = ['http://127.0.0.1:8001', 'http://localhost:8001']
CACHES = deepcopy(CACHES)
CACHES['default']['LOCATION'] = 'community-offline-demo'
TEMPLATES = deepcopy(TEMPLATES)
TEMPLATES[0]['OPTIONS']['context_processors'].append('regulai.demo_settings.demo_context')


def demo_context(request):
    from django.conf import settings
    return {'community_demo_mode': getattr(settings, 'DEMO_MODE', False)}

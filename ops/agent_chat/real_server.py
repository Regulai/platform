"""Local real service using the existing private configuration and account.

No fixtures, provider replacements, public passwords or credential logging.
Provisioning and migrations are performed separately before starting this service.
"""
import json
import os
from pathlib import Path

os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.settings'
from django.conf import settings

private = json.loads(Path('/run/private/config.json').read_text())
settings.DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql', 'NAME': 'regulai_javi_real',
    'USER': 'javi_real', 'PASSWORD': private['database_password'],
    'HOST': '127.0.0.1', 'PORT': '55451',
}}
settings.SECRET_KEY = private['secret_key']
settings.ENCRYPTION_KEY = private['encryption_key']
settings.SECRET_KEY_FALLBACKS = []
settings.ENCRYPTION_KEY_FALLBACKS = []
settings.DEBUG = False
settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '172.30.50.1']
settings.SESSION_COOKIE_NAME = 'regulai_real_session'
settings.CSRF_COOKIE_NAME = 'regulai_real_csrf'
settings.REGULAY_AGENT_ENABLED = True
settings.REGULAY_AGENT_DEVELOPMENT = False
settings.REGULAY_AGENT_WEB_ENABLED = True
# The live E2B browser bridge still fails on some sites and destroys its sandbox.
# Keep ordinary brokered web reads available without advertising that capability.
settings.REGULAY_AGENT_BROWSER_ENABLED = False
settings.REGULAY_AGENT_PACKAGES_ENABLED = True
settings.PLATFORM_ADMIN_USER_IDS = (1,)  # Existing sole account in this dedicated local database.
settings.REGULAY_AGENT_WORKER_TOKEN = private['worker_token']
del private

import django
django.setup()

if __name__ == '__main__':
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='0.0.0.0', port=31049, access_log=False)

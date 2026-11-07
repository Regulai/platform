"""Real ASGI service. Private settings are created by the installer, not Git."""
import json
import os
from pathlib import Path

os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.settings'
from django.conf import settings

config = json.loads(Path('/run/private/server.json').read_text(encoding='utf-8'))
settings.DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql', 'NAME': 'regulai', 'USER': 'regulai',
    'PASSWORD': config['database_password'], 'HOST': '127.0.0.1', 'PORT': '55452',
}}
settings.SECRET_KEY = config['secret_key']
settings.ENCRYPTION_KEY = config['encryption_key']
settings.SECRET_KEY_FALLBACKS = []
settings.ENCRYPTION_KEY_FALLBACKS = []
settings.DEBUG = False
settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '172.30.58.1']
# Loopback only by default. A temporary public tunnel is opt-in per container and must
# name its exact https origin, e.g. REGULAI_PUBLIC_ORIGIN=https://name.trycloudflare.com.
from regulai.public_origin import tunnel_settings
public_hosts, public_origins = tunnel_settings(os.environ.get('REGULAI_PUBLIC_ORIGIN', ''))
settings.ALLOWED_HOSTS += public_hosts
settings.CSRF_TRUSTED_ORIGINS = public_origins
settings.SESSION_COOKIE_NAME = 'regulai_v2_session'
settings.CSRF_COOKIE_NAME = 'regulai_v2_csrf'
settings.PLATFORM_ADMIN_USER_IDS = (config['admin_id'],)
settings.REGULAY_AGENT_ENABLED = True
settings.REGULAY_AGENT_DEVELOPMENT = False
settings.REGULAY_AGENT_WEB_ENABLED = True
settings.REGULAY_AGENT_BROWSER_ENABLED = False
settings.REGULAY_AGENT_PACKAGES_ENABLED = True
settings.REGULAY_AGENT_WORKER_TOKEN = config['worker_token']
del config

import django
django.setup()

if __name__ == '__main__':
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='0.0.0.0', port=31058, access_log=False)

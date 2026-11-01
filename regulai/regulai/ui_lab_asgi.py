"""Local chat UI lab ASGI entry (uvicorn). Serves static files and points the Jev
transport at the loopback simulator. Never use outside the synthetic lab."""
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.ui_lab_settings')

from django.conf import settings  # noqa: E402
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler  # noqa: E402
from django.core.asgi import get_asgi_application  # noqa: E402

if not getattr(settings, 'UI_LAB_PROVIDER_URL', '').startswith('http://127.0.0.1:'):
    raise RuntimeError('The UI lab only talks to a loopback simulator.')

application = ASGIStaticFilesHandler(get_asgi_application())

from front import jev  # noqa: E402

jev.ENDPOINT = jev.VERCEL_ENDPOINT = settings.UI_LAB_PROVIDER_URL + '/jev'

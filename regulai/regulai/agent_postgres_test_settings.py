"""Task 49 disposable local PostgreSQL only; never import live settings/secrets."""
from .test_settings import *

DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'regulai_task49', 'USER': 'lab', 'PASSWORD': 'synthetic-task49-only',
    'HOST': '127.0.0.1', 'PORT': '55449', 'TEST': {'NAME': 'test_regulai_task49'}}}

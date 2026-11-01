"""Disposable task-50 PostgreSQL; no existing account data is used."""
from .test_settings import *

DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'regulai_task50', 'USER': 'lab', 'PASSWORD': 'synthetic-task50-only',
    'HOST': '127.0.0.1', 'PORT': '55450', 'TEST': {'NAME': 'test_regulai_task50'}}}

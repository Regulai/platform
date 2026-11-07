"""Disposable local regression database; never points at existing account data."""
from .test_settings import *

DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'regulai_task55', 'USER': 'lab', 'PASSWORD': 'synthetic-task55-only',
    'HOST': '127.0.0.1', 'PORT': '55455', 'TEST': {'NAME': 'test_regulai_task55'}}}

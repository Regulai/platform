"""Disposable task-56 cluster only. Never import production configuration."""
from .test_settings import *
DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql', 'NAME': 'postgres',
    'USER': 'task56', 'PASSWORD': '', 'HOST': '127.0.0.1', 'PORT': '55456',
    'TEST': {'NAME': 'test_task56_isolated'}}}
LOGGING = {'version': 1, 'disable_existing_loggers': False,
    'handlers': {'null': {'class': 'logging.NullHandler'}},
    'loggers': {'httpx': {'handlers': ['null'], 'propagate': False},
        'django.request': {'handlers': ['null'], 'propagate': False}}}

"""Disposable CI database only; never imports installation credentials."""
import os
from .test_settings import *

DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql', 'NAME': 'postgres',
    'USER': 'task58', 'PASSWORD': 'synthetic-ci-only', 'HOST': '127.0.0.1',
    'PORT': os.environ.get('REGULAI_CI_POSTGRES_PORT', '55458'),
    'TEST': {'NAME': 'test_regulai_ci'},
}}
TEST_RUNNER = 'regulai.test_runner.IsolatedCacheRunner'

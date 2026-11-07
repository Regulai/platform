"""Isolated synthetic tests; these public keys are never production credentials."""
from .settings import *

SECRET_KEY = 'synthetic-tests-only-not-for-deployment'
ENCRYPTION_KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
TEST_RUNNER = 'regulai.test_runner.IsolatedCacheRunner'

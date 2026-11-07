"""Test-only overrides on the same isolated PostgreSQL laboratory."""
from .pilot_lab_settings import *

SECURE_SSL_REDIRECT = False
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

"""
Local settings for regulAI - DO NOT COMMIT TO GIT

This file contains environment-specific configuration that should not be
committed to version control. It is imported at the end of settings.py.

Copy this file to your local environment and customize as needed.
"""

import os

# ==============================================================================
# ENCRYPTION KEY (CRITICAL - REQUIRED)
# ==============================================================================

# Generate with: python manage.py generate_encryption_key
# NEVER commit this key to git!
# Back it up securely - if lost, encrypted data CANNOT be recovered.

# UNCOMMENT AND SET YOUR KEY:
# ENCRYPTION_KEY = 'gAAAAAB...'  # Replace with your generated key

# Alternatively, read from environment variable:
#Lunch -> python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"


#CHANGE:
ENCRYPTION_KEY = 'FO4V3GO6J3TjZdRf_VSW5bJqLT8CZCw1818F5eiKzvY='

# ==============================================================================
# DJANGO SECRET KEY
# ==============================================================================

# Uncomment to override the default (recommended for production)
#CHANGE:
SECRET_KEY = 'fsd89fsdy9fas89dyf8y9asfyasdf99y8fysd98lnmsa'
CORS_ALLOW_CREDENTIALS = False
# ==============================================================================
# DEBUG MODE
# ==============================================================================

# Set to False in production
#CHANGE:
DEBUG = True

# ==============================================================================
# ALLOWED HOSTS
# ==============================================================================

# Add your domain(s) in production
#CHANGE:
ALLOWED_HOSTS = ["*"]

# ==============================================================================
# DATABASE (Optional - override default SQLite)
# ==============================================================================

# PostgreSQL example:
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'regulai',
#         'USER': 'regulai_user',
#         'PASSWORD': 'your-password',
#         'HOST': 'localhost',
#         'PORT': '5432',
#     }
# }

# ==============================================================================
# AI PROVIDER API KEYS (Optional - can be configured in UI per-company)
# ==============================================================================

# OpenAI (for testing)
# OPENAI_API_KEY = 'sk-...'

# Anthropic (for testing)
# ANTHROPIC_API_KEY = 'sk-ant-...'

# ==============================================================================
# SECURITY SETTINGS (Production)
# ==============================================================================
#ONLY FOR TEST CHANGE:
SECURE_SSL_REDIRECT = False          # No redirigir HTTP → HTTPS
SESSION_COOKIE_SECURE = False        # Permitir cookies por HTTP
CSRF_COOKIE_SECURE = False           # Permitir CSRF cookie por HTTP
SECURE_HSTS_SECONDS = 0              # No enviar header HSTS
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
# Uncomment for production with HTTPS:
# SECURE_SSL_REDIRECT = True
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# SECURE_HSTS_SECONDS = 31536000
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True

# ==============================================================================
# CORS SETTINGS (Optional - for API access from other domains)
# ==============================================================================

# CORS_ALLOWED_ORIGINS = [
#     'https://yourdomain.com',
#     'https://app.yourdomain.com',
# ]

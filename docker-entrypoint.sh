#!/bin/bash
set -e

echo "==> Waiting for dependencies..."
sleep 2

echo "==> Creating data directory..."
mkdir -p /app/regulai/data

echo "==> Generating secrets if not provided..."
KEYS_FILE="/app/regulai/data/.keys"

# Generate or load ENCRYPTION_KEY
if [ -z "$ENCRYPTION_KEY" ]; then
    if [ -f "$KEYS_FILE" ]; then
        source "$KEYS_FILE"
        echo "    Loaded existing keys from volume"
    else
        export ENCRYPTION_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
        export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
        echo "ENCRYPTION_KEY='$ENCRYPTION_KEY'" > "$KEYS_FILE"
        echo "SECRET_KEY='$SECRET_KEY'" >> "$KEYS_FILE"
        chmod 600 "$KEYS_FILE"
        echo "    Generated new keys (stored in volume)"
    fi
fi

# Ensure SECRET_KEY is set
if [ -z "$SECRET_KEY" ]; then
    if [ -f "$KEYS_FILE" ]; then
        source "$KEYS_FILE"
    else
        export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
    fi
fi

echo "==> Creating local_settings.py..."
cat > /app/regulai/regulai/local_settings.py << EOLSETTINGS
import os

# Security Keys
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '$ENCRYPTION_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY', '$SECRET_KEY')
ENCRYPTION_KEY_FALLBACKS = []
SECRET_KEY_FALLBACKS = []

# Debug
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')

# Allowed Hosts
_allowed = os.environ.get('ALLOWED_HOSTS', '')
if _allowed:
    ALLOWED_HOSTS = [h.strip() for h in _allowed.split(',') if h.strip()]
else:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]', '*']

# CSRF Configuration for reverse proxy (required for HTTPS)
_csrf_origins = os.environ.get('CSRF_TRUSTED_ORIGINS', '')
if _csrf_origins:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _csrf_origins.split(',') if o.strip()]

# Proxy SSL Header (required when behind nginx with HTTPS)
if os.environ.get('SECURE_PROXY_SSL_HEADER', '').lower() in ('true', '1', 'yes'):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Security settings
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
else:
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

SECURE_SSL_REDIRECT = False  # Nginx handles redirect
CORS_ALLOW_CREDENTIALS = True
EOLSETTINGS
echo "    Created local_settings.py"

echo "==> Collecting static files..."
python manage.py collectstatic --noinput

echo "==> Running migrations..."
python manage.py migrate --noinput

echo "==> Creating superuser if not exists..."
python manage.py shell << 'EOF'
from django.contrib.auth import get_user_model
User = get_user_model()
import os
username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@regulai.local')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'admin123')
if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'    Superuser "{username}" created')
else:
    print(f'    Superuser "{username}" already exists')
EOF

echo "==> Starting server..."
exec gunicorn regulai.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -

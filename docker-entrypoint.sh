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
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '$ENCRYPTION_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY', '$SECRET_KEY')
ENCRYPTION_KEY_FALLBACKS = []
SECRET_KEY_FALLBACKS = []
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]", "*"]
CORS_ALLOW_CREDENTIALS = True
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
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

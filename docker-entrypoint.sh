#!/bin/bash
set -e

echo "==> Waiting for dependencies..."
sleep 2

echo "==> Creating data directory..."
mkdir -p /app/regulai/data

echo "==> Copying local_settings if not exists..."
if [ ! -f /app/regulai/regulai/local_settings.py ]; then
    cp /app/regulai/regulai/local_settings_template.py /app/regulai/regulai/local_settings.py
    echo "    Created local_settings.py from template"
fi

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

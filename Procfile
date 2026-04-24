web: cd regulai && python manage.py migrate --noinput && gunicorn regulai.wsgi:application --bind 0.0.0.0:$PORT --workers 2

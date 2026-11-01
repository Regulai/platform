FROM python@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f
WORKDIR /app
COPY requirements.txt ./
COPY ops/pilot/requirements.txt ops/pilot/requirements.txt
RUN pip install --no-cache-dir -r ops/pilot/requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1 DJANGO_SETTINGS_MODULE=regulai.pilot_lab_settings
CMD ["gunicorn", "-c", "gunicorn.conf.py", "--bind", "0.0.0.0:8000", "regulai.wsgi:application"]

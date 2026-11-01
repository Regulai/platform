"""Run from the repository root: gunicorn -c gunicorn.conf.py regulai.wsgi:application."""
chdir = 'regulai'
worker_class = 'gthread'
threads = 4
timeout = 240  # The pipeline deadline is at most 180 seconds.
graceful_timeout = 240
accesslog = None
# Gunicorn merges this with its default handlers before Django configures logging.
logconfig_dict = {
    'formatters': {'generic': {'()': 'front.safe_logging.SafeJSONFormatter'}},
}

"""Content-free logging: callers supply constant codes and a request UUID."""
from datetime import datetime, timezone
import json
import logging
import re
import uuid


class SafeJSONFormatter(logging.Formatter):
    def format(self, record):
        request_id = getattr(record, 'request_id', None)
        if request_id is None:
            request_id = getattr(getattr(record, 'request', None), 'request_id', None)
        try:
            request_id = str(uuid.UUID(request_id)) if type(request_id) is str else None
        except ValueError:
            request_id = None
        code = getattr(record, 'code', None)
        if type(code) is not str or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code):
            code = 'unclassified_event'
        # Never call getMessage/formatException: args, locals and tracebacks can contain secrets.
        return json.dumps({
            'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            'level': logging.getLevelName(record.levelno),
            'logger': record.name,
            'request_id': request_id,
            'code': code,
            'exception_type': record.exc_info[0].__name__ if record.exc_info and record.exc_info[0] else None,
        })

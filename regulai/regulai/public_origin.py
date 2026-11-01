"""Opt-in public tunnel origin for the loopback-only installed web service."""
from urllib.parse import urlsplit


def tunnel_settings(origin):
    """ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS entries for one exact https origin, e.g. a quick tunnel URL."""
    if not origin:
        return [], []
    parts = urlsplit(origin)
    host = parts.hostname or ''
    # One named host only: no wildcard, port, credentials or path widens what is trusted.
    if (parts.scheme != 'https' or parts.netloc != host or '.' not in host or '*' in host
            or parts.path not in ('', '/') or parts.query or parts.fragment):
        raise ValueError('REGULAI_PUBLIC_ORIGIN must be one https origin such as https://name.trycloudflare.com')
    return [host], ['https://' + host]

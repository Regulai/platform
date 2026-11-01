"""Create local development settings once; never replace keys or a database."""
from pathlib import Path
import base64
import secrets
import os
import getpass
import subprocess

settings = Path(__file__).resolve().parents[1] / "regulai/regulai/local_settings.py"
try:
    descriptor = os.open(settings, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        if os.name == 'nt':
            account = os.environ.get('USERDOMAIN', '')
            account = f'{account}\\{getpass.getuser()}' if account else getpass.getuser()
            try:
                subprocess.run(['icacls', str(settings), '/inheritance:r', '/grant:r', f'{account}:F'],
                    check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError):
                print('Windows ACL could not be restricted; secure the settings file before use.')
        output.write(
            "# Local development only. Preserve this file and its encryption key.\n"
            f"SECRET_KEY = {secrets.token_urlsafe(48)!r}\n"
            f"ENCRYPTION_KEY = {base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()!r}\n"
            "SECRET_KEY_FALLBACKS = []\n"
            "ENCRYPTION_KEY_FALLBACKS = []\n"
            "DEBUG = True\n"
            "ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']\n"
            "ALLOW_REGISTRATION = False\n"
            "from pathlib import Path\n"
            "DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', "
            "'NAME': Path(__file__).resolve().parent.parent / 'community-local.sqlite3'}}\n"
        )
    print("Created local settings with new development keys (not displayed).")
except FileExistsError:
    print("Existing local settings preserved.")

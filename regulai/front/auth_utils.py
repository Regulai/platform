"""Security helpers for password changes, token revocation and redirects."""

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.utils.http import url_has_allowed_host_and_scheme
from rest_framework.authtoken.models import Token


def change_user_password(user, new_password, request=None):
    """Validate, change and invalidate API credentials for a user."""
    validate_password(new_password, user)
    user.set_password(new_password)
    user.save()
    Token.objects.filter(user=user).delete()

    if request and getattr(request, 'user', None) == user:
        update_session_auth_hash(request, user)


def safe_redirect_url(request, url, fallback='/'):
    """Return only redirects allowed for the current request host and scheme."""
    if url and url_has_allowed_host_and_scheme(
        url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return url
    return fallback

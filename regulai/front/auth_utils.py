"""
Authentication utilities for secure password management and token handling.
"""
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.http import url_has_allowed_host_and_scheme
from rest_framework.authtoken.models import Token


def change_user_password(user, new_password, request=None):
    """
    Securely change a user's password with proper validation and token revocation.

    Args:
        user: User instance whose password will be changed
        new_password: The new password to set
        request: Optional request object for session auth hash update

    Raises:
        ValidationError: If the password fails validation
    """
    # Validate password against configured validators (AUTH-07)
    validate_password(new_password, user)

    # Set the new password
    user.set_password(new_password)
    user.save()

    # Revoke all existing API tokens (AUTH-02/03)
    Token.objects.filter(user=user).delete()

    # Update session auth hash if this is the current user changing their own password
    if request and hasattr(request, 'user') and request.user == user:
        update_session_auth_hash(request, user)


def revoke_user_tokens(user):
    """
    Revoke all API tokens for a user.

    Args:
        user: User instance whose tokens will be revoked

    Returns:
        int: Number of tokens deleted
    """
    deleted, _ = Token.objects.filter(user=user).delete()
    return deleted


def safe_redirect_url(request, url, fallback='/'):
    """
    Validate a redirect URL to prevent open redirects (AUTH-08).

    Args:
        request: The HTTP request
        url: The URL to validate
        fallback: URL to return if validation fails

    Returns:
        The original URL if safe, otherwise the fallback
    """
    if not url:
        return fallback

    # Check if the URL is safe for redirect
    if url_has_allowed_host_and_scheme(
        url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure()
    ):
        return url

    return fallback

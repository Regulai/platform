"""
Rate Limiting Module for regulAI

This module provides rate limiting functionality without external dependencies.
Uses Django's cache framework for storing rate limit data.

Features:
- IP-based rate limiting
- User-based rate limiting
- Per-endpoint rate limiting
- Customizable time windows and limits
- Automatic cleanup of expired entries
"""

from functools import wraps
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
import hashlib
import json


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""
    def __init__(self, limit, window, retry_after=None):
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded: {limit} requests per {window} seconds")


def get_client_ip(request):
    """
    Get client IP address from request.
    Handles X-Forwarded-For header for proxied requests.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


def get_rate_limit_key(identifier, endpoint, window):
    """
    Generate a unique cache key for rate limiting.

    Args:
        identifier: IP address or user ID
        endpoint: Endpoint name (e.g., 'login', 'chat', 'api')
        window: Time window in seconds

    Returns:
        Cache key string
    """
    # Create a hash to keep key length reasonable
    key_data = f"{identifier}:{endpoint}:{window}"
    key_hash = hashlib.md5(key_data.encode()).hexdigest()[:16]
    return f"ratelimit:{endpoint}:{key_hash}"


def check_rate_limit(identifier, endpoint, limit, window):
    """
    Check if rate limit is exceeded.

    Args:
        identifier: IP address or user ID
        endpoint: Endpoint name
        limit: Maximum number of requests allowed
        window: Time window in seconds

    Returns:
        Tuple (allowed: bool, remaining: int, retry_after: int)

    Raises:
        RateLimitExceeded: If rate limit is exceeded
    """
    cache_key = get_rate_limit_key(identifier, endpoint, window)

    # Get current request count and timestamps
    data = cache.get(cache_key, {'count': 0, 'timestamps': [], 'first_request': None})

    now = timezone.now().timestamp()
    window_start = now - window

    # Filter out expired timestamps
    valid_timestamps = [ts for ts in data.get('timestamps', []) if ts > window_start]

    current_count = len(valid_timestamps)

    if current_count >= limit:
        # Rate limit exceeded
        oldest_timestamp = min(valid_timestamps) if valid_timestamps else now
        retry_after = int(oldest_timestamp + window - now)

        raise RateLimitExceeded(limit, window, retry_after)

    # Add current timestamp
    valid_timestamps.append(now)

    # Update cache
    cache.set(cache_key, {
        'count': len(valid_timestamps),
        'timestamps': valid_timestamps,
        'first_request': data.get('first_request') or now
    }, timeout=window + 60)  # Add buffer to cache timeout

    remaining = limit - len(valid_timestamps)
    return True, remaining, 0


def rate_limit(
    limit=10,
    window=60,
    key='ip',
    endpoint=None,
    message=None,
    error_code=429
):
    """
    Decorator for rate limiting views.

    Args:
        limit: Maximum number of requests allowed
        window: Time window in seconds
        key: Rate limit key type ('ip', 'user', or callable)
        endpoint: Endpoint name (auto-detected from view name if None)
        message: Custom error message
        error_code: HTTP status code for rate limit response (default 429)

    Usage:
        @rate_limit(limit=5, window=60, key='ip')
        def login_view(request):
            ...

        @rate_limit(limit=100, window=3600, key='user')
        def chat_view(request):
            ...

    Example:
        # Allow 5 login attempts per minute per IP
        @rate_limit(limit=5, window=60, key='ip', endpoint='login')
        def login_view(request):
            pass

        # Allow 1000 chat messages per hour per user
        @rate_limit(limit=1000, window=3600, key='user', endpoint='chat')
        def send_message(request):
            pass
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Determine endpoint name
            endpoint_name = endpoint or view_func.__name__

            # Determine identifier based on key type
            if callable(key):
                identifier = key(request)
            elif key == 'user':
                if request.user.is_authenticated:
                    identifier = f"user:{request.user.id}"
                else:
                    identifier = f"ip:{get_client_ip(request)}"
            else:  # default to 'ip'
                identifier = f"ip:{get_client_ip(request)}"

            try:
                allowed, remaining, retry_after = check_rate_limit(
                    identifier,
                    endpoint_name,
                    limit,
                    window
                )

                # Add rate limit headers to response
                response = view_func(request, *args, **kwargs)

                # Add rate limit info headers
                if hasattr(response, '__setitem__'):
                    response['X-RateLimit-Limit'] = str(limit)
                    response['X-RateLimit-Remaining'] = str(remaining)
                    response['X-RateLimit-Reset'] = str(int(timezone.now().timestamp() + window))

                return response

            except RateLimitExceeded as e:
                # Log rate limit exceeded
                from front.views import log_action
                log_action(
                    request.user if request.user.is_authenticated else None,
                    'rate_limit_exceeded',
                    {
                        'endpoint': endpoint_name,
                        'identifier': identifier,
                        'limit': limit,
                        'window': window,
                        'ip': get_client_ip(request)
                    },
                    request
                )

                # Prepare error message
                error_message = message or (
                    f"Too many requests. "
                    f"Limit: {limit} requests per {window} seconds. "
                    f"Please try again in {e.retry_after} seconds."
                )

                # Check if request expects JSON (API endpoint)
                if request.path.startswith('/api/') or request.META.get('HTTP_ACCEPT', '').startswith('application/json'):
                    return JsonResponse({
                        'error': error_message,
                        'rate_limit': {
                            'limit': limit,
                            'window': window,
                            'retry_after': e.retry_after
                        }
                    }, status=error_code, headers={
                        'Retry-After': str(e.retry_after),
                        'X-RateLimit-Limit': str(limit),
                        'X-RateLimit-Remaining': '0',
                        'X-RateLimit-Reset': str(int(timezone.now().timestamp() + e.retry_after))
                    })
                else:
                    # Render HTML error page for web views
                    return render(request, 'errors/rate_limit.html', {
                        'message': error_message,
                        'retry_after': e.retry_after,
                        'limit': limit,
                        'window': window
                    }, status=error_code)

        return wrapped_view
    return decorator


# Predefined rate limit decorators for common use cases

def login_rate_limit(view_func):
    """
    Rate limit for login attempts.
    5 attempts per minute per IP.
    """
    return rate_limit(
        limit=5,
        window=60,
        key='ip',
        endpoint='login',
        message='Too many login attempts. Please wait before trying again.'
    )(view_func)


def api_rate_limit(view_func):
    """
    Rate limit for API endpoints.
    100 requests per minute per user.
    """
    return rate_limit(
        limit=100,
        window=60,
        key='user',
        endpoint='api',
        message='API rate limit exceeded. Please slow down your requests.'
    )(view_func)


def chat_rate_limit(view_func):
    """
    Rate limit for chat messages.
    30 messages per minute per user.
    This prevents abuse of expensive AI API calls.
    """
    return rate_limit(
        limit=30,
        window=60,
        key='user',
        endpoint='chat',
        message='Too many messages. Please wait before sending more.'
    )(view_func)


def signup_rate_limit(view_func):
    """
    Rate limit for signup/registration.
    3 signups per hour per IP.
    """
    return rate_limit(
        limit=3,
        window=3600,
        key='ip',
        endpoint='signup',
        message='Too many signup attempts. Please try again later.'
    )(view_func)


def password_reset_rate_limit(view_func):
    """
    Rate limit for password reset requests.
    3 requests per hour per IP.
    """
    return rate_limit(
        limit=3,
        window=3600,
        key='ip',
        endpoint='password_reset',
        message='Too many password reset requests. Please try again later.'
    )(view_func)


# DRF Throttle Classes for Django REST Framework

try:
    from rest_framework.throttling import BaseThrottle
    from rest_framework.exceptions import Throttled

    class CustomRateThrottle(BaseThrottle):
        """
        Base throttle class for DRF using our rate limiting logic.
        """
        rate_limit = 100  # requests per window
        rate_window = 60  # seconds
        scope = 'api'

        def get_cache_key(self, request, view):
            """Generate cache key for this request"""
            if request.user.is_authenticated:
                ident = f"user:{request.user.id}"
            else:
                ident = f"ip:{get_client_ip(request)}"

            return f"{ident}:{self.scope}"

        def allow_request(self, request, view):
            """Check if request should be allowed"""
            if request.user.is_authenticated and request.user.is_superuser:
                # Superusers bypass rate limiting
                return True

            identifier = self.get_cache_key(request, view)

            try:
                check_rate_limit(
                    identifier,
                    self.scope,
                    self.rate_limit,
                    self.rate_window
                )
                return True
            except RateLimitExceeded as e:
                # Store retry_after for wait() method
                self.retry_after = e.retry_after
                return False

        def wait(self):
            """Return time to wait before retry"""
            return getattr(self, 'retry_after', None)


    class LoginThrottle(CustomRateThrottle):
        """5 requests per minute for login"""
        rate_limit = 5
        rate_window = 60
        scope = 'login'


    class ChatThrottle(CustomRateThrottle):
        """30 requests per minute for chat"""
        rate_limit = 30
        rate_window = 60
        scope = 'chat'


    class APIThrottle(CustomRateThrottle):
        """100 requests per minute for general API"""
        rate_limit = 100
        rate_window = 60
        scope = 'api'

except ImportError:
    # DRF not installed, skip throttle classes
    pass


def clear_rate_limit(identifier, endpoint):
    """
    Clear rate limit for a specific identifier and endpoint.
    Useful for testing or manual intervention.

    Args:
        identifier: IP address or user ID
        endpoint: Endpoint name
    """
    # Clear for all common windows
    for window in [60, 300, 3600]:
        cache_key = get_rate_limit_key(identifier, endpoint, window)
        cache.delete(cache_key)


def get_rate_limit_status(identifier, endpoint, window):
    """
    Get current rate limit status for debugging.

    Args:
        identifier: IP address or user ID
        endpoint: Endpoint name
        window: Time window in seconds

    Returns:
        Dictionary with rate limit information
    """
    cache_key = get_rate_limit_key(identifier, endpoint, window)
    data = cache.get(cache_key, {'count': 0, 'timestamps': [], 'first_request': None})

    now = timezone.now().timestamp()
    window_start = now - window

    valid_timestamps = [ts for ts in data.get('timestamps', []) if ts > window_start]

    return {
        'identifier': identifier,
        'endpoint': endpoint,
        'window': window,
        'current_count': len(valid_timestamps),
        'oldest_request': min(valid_timestamps) if valid_timestamps else None,
        'newest_request': max(valid_timestamps) if valid_timestamps else None,
        'cache_key': cache_key
    }

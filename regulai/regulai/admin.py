"""
Custom admin site with rate limiting on login (AUTH-05).
"""
from django.contrib import admin
from django.contrib.admin import AdminSite
from django.http import HttpResponse
from front.rate_limit import check_rate_limit, get_client_ip, RateLimitExceeded


class RateLimitedAdminSite(AdminSite):
    """Admin site with rate-limited login to prevent brute force attacks."""

    def login(self, request, extra_context=None):
        """Override login to add rate limiting on POST requests."""
        if request.method == 'POST':
            client_ip = get_client_ip(request)
            try:
                # Apply same rate limit as regular login: 5 attempts per minute
                check_rate_limit(
                    identifier=f"admin_login:{client_ip}",
                    endpoint='admin_login',
                    limit=5,
                    window=60
                )
            except RateLimitExceeded as e:
                return HttpResponse(
                    'Too many login attempts. Please try again later.',
                    status=429,
                    headers={'Retry-After': str(e.retry_after or 60)}
                )

        return super().login(request, extra_context)


# Create the rate-limited admin site instance
rate_limited_admin_site = RateLimitedAdminSite(name='admin')

# Copy all registered models from the default admin site
# This needs to be done after all apps are loaded
def setup_admin():
    """Copy model registrations from default admin to rate-limited admin."""
    from django.contrib.admin.sites import site as default_site
    for model, model_admin in default_site._registry.items():
        try:
            rate_limited_admin_site.register(model, type(model_admin))
        except admin.sites.AlreadyRegistered:
            pass

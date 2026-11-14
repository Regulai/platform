"""Admin site with brute-force protection on the login endpoint."""

from django.contrib import admin
from django.contrib.admin import AdminSite
from django.http import HttpResponse

from front.rate_limit import RateLimitExceeded, check_rate_limit, get_client_ip


class RateLimitedAdminSite(AdminSite):
    def login(self, request, extra_context=None):
        if request.method == 'POST':
            try:
                check_rate_limit(
                    f'admin_login:{get_client_ip(request)}',
                    'admin_login',
                    limit=5,
                    window=60,
                )
            except RateLimitExceeded as error:
                return HttpResponse(
                    'Too many login attempts. Please try again later.',
                    status=429,
                    headers={'Retry-After': str(error.retry_after or 60)},
                )
        return super().login(request, extra_context)


rate_limited_admin_site = RateLimitedAdminSite(name='admin')


def setup_admin():
    """Mirror registrations made by app autodiscovery onto the protected site."""
    for model, model_admin in admin.site._registry.items():
        if model not in rate_limited_admin_site._registry:
            rate_limited_admin_site.register(model, model_admin.__class__)

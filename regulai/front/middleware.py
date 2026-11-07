import json
import logging
import uuid
from .models import AuditLog, Profile


logger = logging.getLogger(__name__)


class ContentSecurityPolicyMiddleware:
    """
    Apply Content Security Policy headers.
    Note: 'unsafe-inline' is required while legacy UI uses inline scripts.
    TODO: Refactor frontend to use nonce-based CSP for production hardening.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings
        response = self.get_response(request)

        csp = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
        )

        # In production (DEBUG=False), enforce CSP; in development, report-only
        if getattr(settings, 'DEBUG', False):
            response['Content-Security-Policy-Report-Only'] = csp
        else:
            response['Content-Security-Policy'] = csp

        # Additional security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response


class ExceptionAuditMiddleware:
    """
    Middleware that logs unhandled Django exceptions to the AuditLog
    with action='System'.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.request_id = str(uuid.uuid4())
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        """Log unhandled exceptions to AuditLog with action='System'."""
        try:
            user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
            company_id = Profile.objects.filter(user=user).values_list('company_id', flat=True).first() if user else None
            details = json.dumps({
                'exception_type': type(exception).__name__,
                'code': 'unhandled_exception',
                'request_id': request.request_id,
                'path': request.resolver_match.route if request.resolver_match else None,
            })

            AuditLog.objects.create(
                user=user,
                company_id=company_id,
                action='System',
                details=details,
            )
        except Exception:
            logger.exception('audit_write_failed', extra={
                'code': 'audit_write_failed', 'request_id': request.request_id,
            })

        # Return None to let Django's default exception handling continue
        return None

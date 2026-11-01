"""Keep the UI acceptance laboratory from impersonating a live generator."""
import re

from django.http import JsonResponse


class RejectLabGeneration:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST' and (
            re.fullmatch(r'/chat/(?:\d+/)?(?:send/)?', request.path)
            or request.path == '/api/chat/send/'
        ):
            return JsonResponse({
                'success': False, 'status': 'unavailable',
                'code': 'real_generation_not_configured',
                'error': 'La generación real no está conectada en esta instancia. '
                         'No se ha generado ningún documento. Es necesario configurar '
                         'el proveedor y el worker real; el simulador ha sido retirado.',
            }, status=503)
        return self.get_response(request)

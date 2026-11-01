"""Non-destructive measurement server for the existing isolated UI fixture only."""
import re
import time

import p1_ui_lab  # configuration only; never invoke its fixture main
from django.conf import settings

settings.DATABASES['default']['NAME'] = 'test_regulai_p1_browser'
settings.MIDDLEWARE = ['p1_metric_server.EnqueueOnly', *[value for value in settings.MIDDLEWARE
    if value != 'regulai.ui_lab_guard.RejectLabGeneration']]


class EnqueueOnly:
    """Allow synthetic agent admission/cancellation, deny every other write."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.http import JsonResponse
        send = bool(re.fullmatch(r'/chat/(?:\d+/)?send/', request.path))
        cancel = bool(re.fullmatch(r'/chat/agent/runs/[\w-]+/cancel/', request.path))
        if request.method not in ('GET', 'HEAD') and not (request.method == 'POST' and (
            cancel or send and request.POST.get('mode') == 'agent' and request.POST.get('prompt', '').startswith('P1 accepted-state fixture '))):
            return JsonResponse({'error':'synthetic_enqueue_only'}, status=403)
        response = self.get_response(request)
        if send and response.status_code == 202:
            # The view has returned from its admission transaction before this.
            response['X-P1-Accepted-Ms'] = str(time.time_ns()/1_000_000)
        return response


def main():
    import django
    django.setup()
    from django.db import connection
    assert connection.settings_dict['NAME'] == 'test_regulai_p1_browser'
    assert connection.settings_dict['HOST'] == '127.0.0.1' and str(connection.settings_dict['PORT']) == '55468'
    from unittest.mock import patch
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    # No worker runs here; additionally forbid dispatch if an unexpected route
    # reaches one of the application connector entry points.
    with patch('front.connectors.get_connector', side_effect=AssertionError('P1 fixture forbids provider dispatch')), \
         patch('front.agents.service.get_connector', side_effect=AssertionError('P1 fixture forbids provider dispatch')), \
         patch('front.chat_service.get_connector', side_effect=AssertionError('P1 fixture forbids provider dispatch')):
        uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()),host='127.0.0.1',port=8872,log_level='warning')


if __name__ == '__main__':
    main()

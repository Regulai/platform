"""
Versión simplificada de URLs para testing
Si el problema persiste, renombra este archivo a urls.py
"""
from django.urls import path

app_name = 'api'

def test_view(request):
    from django.http import JsonResponse
    return JsonResponse({'status': 'API working!', 'message': 'Hello from RegulAI API'})

urlpatterns = [
    path('', test_view, name='test'),
]

from front.models import Alert


def unresolved_alerts_count(request):
    """Context processor para añadir el contador de alertas no resueltas."""
    if request.user.is_authenticated:
        count = Alert.objects.filter(resolved=False).count()
        # Obtener las últimas 5 alertas no resueltas para el dropdown
        recent_unresolved = Alert.objects.filter(resolved=False).select_related('rule').order_by('-created_at')[:5]
        return {
            'unresolved_alerts_count': count,
            'recent_unresolved_alerts': recent_unresolved,
        }
    return {
        'unresolved_alerts_count': 0,
        'recent_unresolved_alerts': [],
    }

from front.models import Alert, Profile
from front.access import can_manage_company_policy, is_platform_operator


def unresolved_alerts_count(request):
    """Context processor para añadir el contador de alertas no resueltas."""
    user = request.user
    permissions = {'is_platform_operator': is_platform_operator(user),
        'can_manage_company_policy': can_manage_company_policy(user)}
    from django.conf import settings
    skills_access = False
    if getattr(settings, 'REGULAY_SKILLS_CATALOG', False) and user.is_authenticated:
        from front.agents.capabilities import profile_for
        from front.agents.service import AgentDenied
        try:
            profile_for(user)
        except (AgentDenied, Profile.DoesNotExist):
            pass
        else:
            skills_access = True
    permissions['skills_catalog_enabled'] = skills_access
    permissions['skills_runtime_enabled'] = bool(skills_access and getattr(settings, 'REGULAY_SKILLS_RUNTIME', False))
    if user.is_authenticated and user.is_active and (user.is_staff or user.is_superuser):
        company_id = Profile.objects.filter(user=user).values_list('company_id', flat=True).first()
        alerts = Alert.objects.filter(resolved=False, company_id=company_id) if company_id else Alert.objects.none()
        count = alerts.count()
        # Obtener las últimas 5 alertas no resueltas para el dropdown
        recent_unresolved = alerts.select_related('rule').order_by('-created_at')[:5]
        return {
            **permissions,
            'unresolved_alerts_count': count,
            'recent_unresolved_alerts': recent_unresolved,
        }
    return {
        **permissions,
        'unresolved_alerts_count': 0,
        'recent_unresolved_alerts': [],
    }

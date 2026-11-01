"""Tenant boundaries shared by HTTP adapters and the chat service."""
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.db.models import Q
from functools import wraps

from .models import Conversation, Profile, Prompt


def is_platform_operator(user):
    return bool(user.is_active and user.is_staff and user.is_superuser
        and user.pk in getattr(settings, 'PLATFORM_ADMIN_USER_IDS', ()))


def protect_operator(actor, target_user_id):
    if target_user_id in getattr(settings, 'PLATFORM_ADMIN_USER_IDS', ()) and not is_platform_operator(actor):
        raise PermissionDenied('Solo un operador de plataforma puede modificar esta cuenta.')


def platform_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not is_platform_operator(request.user):
            raise PermissionDenied('El catálogo compartido requiere un operador de plataforma.')
        return view(request, *args, **kwargs)
    return wrapped


def actor_company(actor):
    try:
        return Profile.objects.select_related('company').get(user=actor).company
    except Profile.DoesNotExist:
        raise PermissionDenied('Se necesita un perfil de empresa asignado.')


def can_manage_company_policy(user):
    if not user.is_authenticated or not user.is_active:
        return False
    profiles = Profile.objects.filter(user=user)
    return profiles.exists() and (user.is_superuser or is_platform_operator(user)
        or profiles.filter(role__name__iexact='Admin').exists())


def company_policy_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not can_manage_company_policy(request.user):
            raise PermissionDenied('Company administrator permission is required.')
        return view(request, *args, **kwargs)
    return wrapped


def company_audit_scope(company):
    return Q(company=company) | Q(company__isnull=True, user__profile__company=company)


def authorized_conversations(actor):
    company = actor_company(actor)
    foreign = Prompt.objects.filter(company__isnull=False, conversation__isnull=False).exclude(company=company)
    # Legacy rows have no reliable tenant provenance; retain owner access only.
    return Conversation.objects.filter(user=actor).exclude(pk__in=foreign.values('conversation_id'))


@login_required
def avatar(request, filename):
    profile = get_object_or_404(Profile, company=actor_company(request.user), avatar='avatars/' + filename)
    from PIL import Image
    try:
        with profile.avatar.open('rb') as source:
            picture = Image.open(source)
            picture.verify()
            mime = {'JPEG': 'image/jpeg', 'PNG': 'image/png', 'GIF': 'image/gif', 'WEBP': 'image/webp'}.get(picture.format)
        if not mime:
            raise ValueError('Unsupported avatar')
    except (OSError, ValueError):
        raise Http404 from None
    response = FileResponse(profile.avatar.open('rb'), content_type=mime)
    response['Cache-Control'] = 'private, no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response

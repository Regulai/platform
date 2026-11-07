"""Authenticated account library. Every mutation is CSRF-protected and local to its owner."""
import json
from functools import wraps

from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST
from front.models import AgentSkillInstallation, AgentSkillInstallOperation, AgentModelProfile, Profile
from . import skills, skill_installation
from .service import AgentDenied
from .skill_bundles import SkillError, MAX_COMPRESSED, validate_bundle, folders


def boundary(handler):
    @wraps(handler)
    @login_required
    def wrapped(request, *args, **kwargs):
        try:
            result = handler(request, *args, **kwargs)
        except (SkillError, AgentDenied) as error:
            code = error.code
            status = 404 if code.endswith('_not_found') else 409 if code.endswith(('_conflict', '_unavailable')) else 400
            if code.startswith('agent_') or code == 'authorization_changed':
                status = 403
            if (request.method == 'GET' and handler.__name__ in {'library', 'detail', 'installed_detail'}
                    and request.GET.get('format') != 'json' and 'text/html' in request.headers.get('Accept', '')):
                result = render(request, 'skills/unavailable.html', status=status)
            else:
                result = JsonResponse({'status': 'rejected', 'code': code}, status=status)
        except (Profile.DoesNotExist, AgentModelProfile.DoesNotExist):
            if (request.method == 'GET' and handler.__name__ in {'library', 'detail', 'installed_detail'}
                    and request.GET.get('format') != 'json' and 'text/html' in request.headers.get('Accept', '')):
                result = render(request, 'skills/unavailable.html', status=403)
            else:
                result = JsonResponse({'status': 'rejected', 'code': 'agent_access_denied'}, status=403)
        except (ValueError, TypeError, KeyError):
            result = JsonResponse({'status': 'rejected', 'code': 'invalid_skill_request'}, status=400)
        result['Cache-Control'] = 'private, no-store'
        return result
    return wrapped


def body(request):
    if request.content_type == 'application/json':
        if len(request.body) > 16384:
            raise SkillError('invalid_skill_request')
        value = json.loads(request.body)
    else:
        value = request.POST.dict()
    if not isinstance(value, dict):
        raise SkillError('invalid_skill_request')
    return value


@boundary
@require_GET
def library(request):
    account, agent = skills.actor_profile(request.user)
    installed = [skills.installation_view(row, agent) for row in AgentSkillInstallation.objects.filter(
        owner=request.user, company=account.company, tombstoned_at__isnull=True).select_related('current_revision').order_by('alias')]
    candidates = [{**item, 'availability': skills.availability(agent, item['compatibility'])} for item in skills.catalogue()]
    data = {'catalog': candidates, 'installations': installed,
        'runtime_enabled': bool(getattr(settings, 'REGULAY_SKILLS_RUNTIME', False))}
    if request.GET.get('format') == 'json':
        return JsonResponse(data)
    return render(request, 'skills/library.html', {'skills_data': data})


@boundary
@require_GET
def detail(request, candidate):
    account, agent = skills.actor_profile(request.user)
    raw, item = skills.curated_bundle(candidate)
    package = validate_bundle(raw)
    row = AgentSkillInstallation.objects.filter(owner=request.user, company=account.company,
        source_identity=item['source_identity'], tombstoned_at__isnull=True).select_related('current_revision').first()
    installed = skills.installation_view(row, agent) if row else None
    data = {**item, 'is_catalog_detail': True,
        'availability': installed['availability'] if installed else skills.availability(agent, item['compatibility']),
        'manifest': package['manifest'], 'folder_sha256': package['folder_sha256'],
        'license_text': package['license'], 'attribution': package['attribution'],
        'installation': installed,
        'runtime_enabled': bool(getattr(settings, 'REGULAY_SKILLS_RUNTIME', False))}
    if request.GET.get('format') == 'json':
        return JsonResponse(data)
    return render(request, 'skills/detail.html', {'skill': data})


@boundary
@require_GET
def installed_detail(request, installation_id):
    account, agent = skills.actor_profile(request.user)
    row = AgentSkillInstallation.objects.filter(pk=installation_id, owner=request.user,
        company=account.company, tombstoned_at__isnull=True).select_related('current_revision').first()
    if row is None:
        raise SkillError('skill_installation_not_found')
    revision = row.current_revision
    view = skills.installation_view(row, agent)
    data = {**view, 'is_catalog_detail': False, 'name': row.alias, 'id': view['candidate'],
        'license': 'Licencia incluida', 'license_text': revision.license, 'attribution': revision.attribution,
        'manifest': revision.manifest, 'commit': revision.resolved_commit,
        'installation': view,
        'runtime_enabled': bool(getattr(settings, 'REGULAY_SKILLS_RUNTIME', False))}
    if request.GET.get('format') == 'json':
        return JsonResponse(data)
    return render(request, 'skills/detail.html', {'skill': data})


@boundary
@require_POST
def installations(request, installation_id=None):
    skills.actor_profile(request.user)
    payload = body(request)
    upload = request.FILES.get('file')
    raw = upload.read(MAX_COMPRESSED + 1) if upload else None
    result = skill_installation.install(request.user, payload.get('request_id'), payload,
        raw=raw, installation_id=installation_id)
    return JsonResponse(result, status=200 if result['state'] == 'installed' else 202 if result['state'] != 'failed' else 400)


@boundary
@require_POST
def inspect_package(request):
    skills.actor_profile(request.user)
    upload = request.FILES.get('file')
    if not upload:
        raise SkillError('skill_zip_required')
    raw = upload.read(MAX_COMPRESSED + 1)
    paths = folders(raw)
    subpath = request.POST.get('subpath') or (paths[0] if len(paths) == 1 else None)
    if subpath is None:
        return JsonResponse({'folders': paths})
    package = validate_bundle(raw, subpath=subpath)
    return JsonResponse({'folders': paths, 'subpath': subpath, 'metadata': package['metadata'],
        'manifest': package['manifest'], 'folder_sha256': package['folder_sha256'], 'license': package['license']})


@boundary
@require_GET
def operation(request, operation_id):
    account, _ = skills.actor_profile(request.user)
    row = AgentSkillInstallOperation.objects.filter(pk=operation_id, owner=request.user,
        company=account.company).select_related('result_revision').first()
    if row is None:
        raise SkillError('skill_operation_not_found')
    return JsonResponse(skill_installation.operation_view(row))


@boundary
@require_POST
def mutate(request, installation_id, action):
    payload = body(request)
    return JsonResponse(skill_installation.change(request.user, installation_id, action, enabled=payload.get('enabled')))


@boundary
@require_POST
def preference(request, conversation_id):
    skills.actor_profile(request.user)
    from front.access import authorized_conversations
    value = body(request)
    if set(value) != {'auto'} or not isinstance(value['auto'], bool):
        raise SkillError('invalid_skill_selection')
    conversation = authorized_conversations(request.user).filter(pk=conversation_id, mode='agent').first()
    if not conversation:
        raise SkillError('skill_conversation_not_found')
    conversation.auto_skills = value['auto']
    conversation.save(update_fields=['auto_skills'])
    return JsonResponse({'auto': conversation.auto_skills})

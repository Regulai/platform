"""Account-local catalogue and run selection. An installed package grants nothing."""
import io
import json
from pathlib import Path
import uuid
import zipfile

from django.conf import settings
from django.contrib.auth import get_user_model
from front.models import AgentModelProfile, AgentSkillInstallation, Profile
from front.policy import digest
from .capabilities import grant_binding, profile_for
from .skill_bundles import SkillError, canonical

ROOT = Path(__file__).parent / 'runtime'
REQUIREMENT_LABELS = {
    'professional_profile': 'Perfil profesional', 'document_profile': 'Perfil documental',
    'verified_package_runtime': 'Comprobación de las herramientas del paquete',
    'revision_missing': 'Una revisión instalada', 'read_file': 'Lectura de archivos',
    'write_file': 'Escritura de archivos', 'execute': 'Ejecución de código',
    'publish_artifact': 'Publicación de archivos', 'build_document': 'Creación de documentos',
    'build_excel': 'Creación de hojas de cálculo', 'build_presentation': 'Creación de presentaciones',
    'node': 'Node.js verificado', 'python': 'Python verificado', 'numpy': 'NumPy verificado',
    'documents': 'Entorno de documentos verificado',
    'spreadsheets': 'Entorno de hojas de cálculo verificado',
    'presentations': 'Entorno de presentaciones verificado',
}


def actor_profile(actor, *, catalogue=True):
    # Requests and long-running imports may retain a stale User instance.
    if not get_user_model().objects.filter(pk=actor.pk, is_active=True).exists():
        raise SkillError('authorization_changed')
    if catalogue and not getattr(settings, 'REGULAY_SKILLS_CATALOG', False):
        raise SkillError('skills_catalog_unavailable')
    account = Profile.objects.select_related('company').get(user=actor)
    agent = AgentModelProfile.objects.get(pk=profile_for(actor), company=account.company, enabled=True)
    return account, agent


def authorization(actor):
    account, agent = actor_profile(actor)
    return digest([actor.pk, account.company_id, actor.is_active, agent.pk, agent.enabled,
                   agent.tools, agent.professional, grant_binding(actor, agent.pk), account.company.ai_config])


def catalogue():
    return [{**item, 'display_name': item['name'], 'summary': item['description']}
            for item in json.loads((ROOT / 'skill_catalog.json').read_text(encoding='utf-8'))]


def candidate(key):
    item = next((item for item in catalogue() if item['id'] == key), None)
    if item is None:
        raise SkillError('skill_candidate_not_found')
    return item


def curated_bundle(key):
    item = candidate(key)
    root = ROOT / 'skills' / item['directory']
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob('*')):
            if path.is_symlink():
                raise SkillError('path_denied')
            if path.is_file():
                archive.writestr(item['directory'] + '/' + path.relative_to(root).as_posix(), path.read_bytes())
    return result.getvalue(), item


def availability(agent, compatibility):
    tools = set(agent.tools)
    compatible = (compatibility.get('profile') in ('any', 'professional' if agent.professional else 'documental')
                  and set(compatibility.get('tools', [])) <= tools)
    configured = getattr(settings, 'REGULAY_SKILL_RUNTIME_CAPABILITIES', {})
    missing = [name for name, value in compatibility.get('runtime', {}).items() if configured.get(name) != value]
    # Unknown requirements remain unavailable until explicitly verified by the administrator.
    if compatibility.get('unverified'):
        missing.append('verified_package_runtime')
    modes = ['explicit'] if compatible and not missing else []
    if modes and 'read_file' in tools:
        modes.append('automatic')
    requirements = (sorted(set(compatibility.get('tools', [])) - tools)
                + (['professional_profile' if compatibility.get('profile') == 'professional' else 'document_profile']
                   if compatibility.get('profile') not in ('any', 'professional' if agent.professional else 'documental') else []) + missing)
    return {'profile_compatible': compatible, 'runtime_ready': not missing, 'activation_modes': modes,
            'available': bool(modes), 'requirements': requirements,
            'requirement_labels': [REQUIREMENT_LABELS.get(value, value) for value in requirements]}


def normalized_selection(value, *, default_auto=True):
    if value in (None, ''):
        return {'selected': [], 'auto': default_auto}
    try:
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, dict) or set(value) - {'selected', 'auto'}:
            raise ValueError()
        selected = value.get('selected', [])
        if not isinstance(selected, list) or len(selected) > 32 or not isinstance(value.get('auto', default_auto), bool):
            raise ValueError()
        selected = sorted({str(uuid.UUID(v)) for v in selected if isinstance(v, str)})
        if len(selected) > 3 or len([v for v in value.get('selected', []) if not isinstance(v, str)]):
            raise ValueError()
        return {'selected': selected, 'auto': value.get('auto', default_auto)}
    except (ValueError, TypeError, AttributeError):
        raise SkillError('invalid_skill_selection') from None


def freeze_selection(actor, agent, selection):
    selection = normalized_selection(selection)
    if not getattr(settings, 'REGULAY_SKILLS_RUNTIME', False):
        if selection['selected']:
            raise SkillError('skills_runtime_unavailable')
        return None
    account = Profile.objects.get(user=actor)
    rows = list(AgentSkillInstallation.objects.filter(owner=actor, company=account.company,
        enabled=True, tombstoned_at__isnull=True, current_revision__isnull=False).select_related('current_revision').order_by('alias'))
    catalog, found = [], set()
    for row in rows:
        revision = row.current_revision
        access = availability(agent, revision.compatibility)
        explicit = str(row.pk) in selection['selected']
        if explicit and not access['available']:
            raise SkillError('skill_dependency_unavailable')
        if not access['available'] or not (explicit or selection['auto'] and 'automatic' in access['activation_modes']):
            continue
        found.add(str(row.pk))
        catalog.append({'installation_id': str(row.pk), 'revision_id': str(revision.pk),
            'folder_sha256': revision.folder_sha256, 'alias': row.alias,
            'authorization_version': row.authorization_version,
            'metadata': {'name': revision.metadata['name'], 'description': revision.metadata['description']},
            'compatibility': revision.compatibility})
    if set(selection['selected']) - found:
        raise SkillError('skill_selection_unavailable')
    if len(catalog) > 32 or len(canonical(catalog).encode()) > 16000:
        raise SkillError('skill_catalog_limit')
    value = {'version': 1, **selection, 'catalog': catalog}
    return {**value, 'digest': digest(value)}


def _curated_revision(revision, item):
    return bool(revision and item.get('folder_sha256')
        and revision.folder_sha256 == item['folder_sha256']
        and revision.origin == item['origin']
        and revision.resolved_commit == item.get('commit', ''))


def revision_display_name(revision, alias):
    # Events refer to the run's pinned revision, not today's installation.
    return next((item['name'] for item in catalogue() if _curated_revision(revision, item)), alias)


def installation_view(row, agent):
    revision = row.current_revision
    access = availability(agent, revision.compatibility) if revision else {
        'available': False, 'requirements': ['revision_missing'], 'requirement_labels': ['Una revisión instalada']}
    item = next((item for item in catalogue() if item['source_identity'] == row.source_identity), {})
    # Updating a catalogue installation with a ZIP keeps its source identity.
    # Only the exact shipped revision may borrow its curated presentation.
    curated = _curated_revision(revision, item)
    return {'id': str(row.pk), 'alias': row.alias, 'enabled': row.enabled,
        'display_name': item['name'] if curated else row.alias,
        'summary': item['description'] if curated else revision.metadata['description'] if revision else '',
        'examples': item.get('examples', []) if curated else [],
        'publisher': item['publisher'] if curated else 'Paquete importado',
        'catalog_revision': curated,
        'category': item.get('category', 'Importadas'), 'candidate': item.get('id'),
        'origin': revision.origin if revision else '',
        'source_identity': row.source_identity, 'revision_id': str(revision.pk) if revision else None,
        'previous_revision_id': str(row.previous_revision_id) if row.previous_revision_id else None,
        'name': revision.metadata['name'] if revision else row.alias,
        'description': revision.metadata['description'] if revision else '',
        'folder_sha256': revision.folder_sha256 if revision else None,
        'availability': access, 'installed': row.tombstoned_at is None}

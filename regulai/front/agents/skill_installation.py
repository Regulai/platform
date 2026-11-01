"""Durable, bounded installation; short locks fence publication, never network."""
from datetime import timedelta
import hashlib
import time
import uuid
from pathlib import PurePosixPath

from django.db import IntegrityError, transaction
from django.utils import timezone
from front.models import AgentSkillInstallation, AgentSkillInstallOperation, AgentSkillRevision, AuditLog, Profile
from front.policy import digest
from .skill_bundles import NAME, SkillError, validate_bundle
from . import skills


def requires_runtime(files):
    executable_suffixes = {'.py', '.pyc', '.sh', '.bash', '.zsh', '.js', '.mjs', '.cjs',
        '.ts', '.rb', '.pl', '.php', '.ps1', '.bat', '.cmd', '.exe', '.dll', '.so',
        '.wasm', '.jar', '.class', '.ipynb', '.r', '.sql'}
    return any(path.startswith('scripts/') or PurePosixPath(path).suffix.lower() in executable_suffixes
        or raw.startswith((b'#!', b'\x7fELF', b'MZ', b'\x00asm')) for path, raw in files.items())


def audit(actor, action, **data):
    from .skill_bundles import canonical
    AuditLog.objects.create(user=actor, company_id=Profile.objects.get(user=actor).company_id,
        action='skill_' + action, details=canonical(data))


def operation_view(row):
    interrupted = row.state in ('downloading', 'validating') and row.lease_expires_at <= timezone.now()
    return {'id': str(row.pk), 'state': 'failed' if interrupted else row.state, 'phase': row.phase,
        'code': 'skill_install_interrupted' if interrupted else row.error_code,
        'bytes_received': row.bytes_received, 'revision_id': str(row.result_revision_id) if row.result_revision_id else None,
        'installation_id': str(row.result_revision.installation_id) if row.result_revision_id else None,
        'retryable': interrupted or row.state == 'failed'}


def _claim(actor, key, payload, downloading):
    try:
        key = uuid.UUID(str(key))
    except ValueError:
        raise SkillError('invalid_install_identity') from None
    authorization = skills.authorization(actor)
    fingerprint = digest(payload)
    with transaction.atomic():
        account = Profile.objects.select_for_update().get(user=actor)
        row = AgentSkillInstallOperation.objects.select_for_update().filter(pk=key).first()
        if row:
            if row.owner_id != actor.pk or row.company_id != account.company_id:
                raise SkillError('skill_operation_not_found')
            if row.payload_digest != fingerprint:
                raise SkillError('skill_request_conflict')
            if row.state == 'installed' or row.state in ('downloading', 'validating') and row.lease_expires_at > timezone.now():
                return row, False
            row.claim, row.version = uuid.uuid4(), row.version + 1
        else:
            row = AgentSkillInstallOperation(id=key, owner=actor, company_id=account.company_id,
                action=payload['action'], payload_digest=fingerprint)
        row.state = row.phase = 'downloading' if downloading else 'validating'
        row.authorization_digest, row.error_code = authorization, ''
        row.lease_expires_at = timezone.now() + timedelta(seconds=60)
        row.save()
        return row, True


def _enabled_limit(actor, company_id, excluding=None, description=''):
    rows = AgentSkillInstallation.objects.filter(owner=actor, company_id=company_id, enabled=True,
        tombstoned_at__isnull=True).exclude(pk=excluding).select_related('current_revision')
    if rows.count() >= 32 or sum(len(r.current_revision.metadata.get('description', '').encode()) + 256
            for r in rows if r.current_revision) + len(description.encode()) + 256 > 16000:
        raise SkillError('skill_catalog_limit')


def install(actor, key, payload, *, raw=None, installation_id=None):
    """Network/extraction occur outside locks; same identity returns same result."""
    started = time.monotonic()
    action = 'update' if installation_id else 'install'
    source = payload.get('source', 'catalog')
    if source not in ('catalog', 'zip', 'github'):
        raise SkillError('invalid_skill_source')
    request = {'action': action, 'source': source, 'candidate': payload.get('candidate'),
        'url': payload.get('url'), 'subpath': payload.get('subpath'), 'alias': payload.get('alias'),
        'installation_id': str(installation_id) if installation_id else None,
        'zip_sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None}
    row, acquired = _claim(actor, key, request, source == 'github')
    if not acquired:
        return operation_view(row)
    claim, version = row.claim, row.version
    try:
        if source == 'catalog':
            raw, spec = skills.curated_bundle(payload.get('candidate'))
            origin, commit = spec['origin'], spec.get('commit', '')
            identity, compatibility = spec['source_identity'], spec['compatibility']
            subpath = None
        elif source == 'github':
            from .skill_sources import github_bundle
            raw, origin, commit, identity, subpath = github_bundle(actor, payload.get('url'),
                subpath=payload.get('subpath'), deadline=started + 25, operation=row)
            compatibility = {'profile': 'professional', 'tools': ['read_file'], 'unverified': True}
        else:
            if raw is None:
                raise SkillError('invalid_skill_archive')
            origin, commit, subpath = 'user_package', '', payload.get('subpath')
            identity = 'zip:' + hashlib.sha256(raw).hexdigest()
            compatibility = {'profile': 'professional', 'tools': ['read_file'], 'unverified': True}
        AgentSkillInstallOperation.objects.filter(pk=row.pk, claim=claim, version=version).update(
            state='validating', phase='validating', bytes_received=len(raw), updated_at=timezone.now())
        package = validate_bundle(raw, subpath=subpath, deadline=started + 30)
        # Instruction-only imports need no runtime dependency; scripts/assets are retained but
        # their requirements cannot be certified by untrusted YAML.
        if (source != 'catalog' and not package['metadata'].get('compatibility')
                and not requires_runtime(package['files'])):
            compatibility = {'profile': 'professional', 'tools': ['read_file'], 'runtime': {}}
        alias = payload.get('alias') or package['metadata']['name']
        if not isinstance(alias, str) or not NAME.fullmatch(alias) or len(alias) > 64:
            raise SkillError('invalid_skill_alias')
        if time.monotonic() - started > 30:
            raise SkillError('skill_validation_timeout')
        with transaction.atomic():
            account = Profile.objects.select_for_update().get(user=actor)
            operation = AgentSkillInstallOperation.objects.select_for_update().get(pk=row.pk)
            if (operation.claim != claim or operation.version != version or operation.lease_expires_at <= timezone.now()
                    or skills.authorization(actor) != operation.authorization_digest):
                raise SkillError('authorization_changed')
            if installation_id:
                installation = AgentSkillInstallation.objects.select_for_update().filter(pk=installation_id,
                    owner=actor, company_id=account.company_id, tombstoned_at__isnull=True).first()
                if not installation:
                    raise SkillError('skill_installation_not_found')
                # ZIP updates have no independent provenance; the user must name the target explicitly.
                if source != 'zip' and installation.source_identity != identity:
                    raise SkillError('source_conflict')
                alias = installation.alias
            else:
                installation = AgentSkillInstallation.objects.select_for_update().filter(owner=actor,
                    company_id=account.company_id, source_identity=identity).first()
                if installation and installation.current_revision_id and installation.tombstoned_at is None:
                    # Installing twice never updates behind the user's back.
                    operation.state, operation.phase = 'installed', 'installed'
                    operation.result_revision = installation.current_revision
                    operation.save()
                    return operation_view(operation)
                installation = installation or AgentSkillInstallation(owner=actor, company_id=account.company_id,
                    source_identity=identity, alias=alias)
                installation.tombstoned_at, installation.alias = None, alias
            if AgentSkillInstallation.objects.filter(owner=actor, company_id=account.company_id,
                    alias=alias, tombstoned_at__isnull=True).exclude(pk=installation.pk).exists():
                raise SkillError('source_conflict')
            installation.save()
            revision, _ = AgentSkillRevision.objects.get_or_create(installation=installation,
                folder_sha256=package['folder_sha256'], adaptation_version=1,
                defaults={'origin': origin, 'resolved_commit': commit, 'upstream_sha256': spec.get('upstream_sha256', '')
                    if source == 'catalog' else package['folder_sha256'], 'manifest': package['manifest'],
                    'metadata': package['metadata'], 'license': package['license'], 'attribution': package['attribution'],
                    'compatibility': compatibility, 'bundle': package['bundle']})
            if installation.current_revision_id != revision.pk:
                installation.previous_revision = installation.current_revision
                installation.current_revision = revision
            _, agent = skills.actor_profile(actor)
            ready = skills.availability(agent, compatibility)['available']
            if not installation_id:
                installation.enabled = ready
            if installation.enabled:
                _enabled_limit(actor, account.company_id, installation.pk, package['metadata']['description'])
            installation.save()
            operation.state = operation.phase = 'installed'
            operation.result_revision = revision
            operation.bytes_received = len(raw)
            operation.save()
            audit(actor, action, operation_id=str(operation.pk), installation_id=str(installation.pk),
                revision_id=str(revision.pk), folder_sha256=revision.folder_sha256,
                bytes=len(raw), cost_kind='no_api_charge')
        return operation_view(operation)
    except (SkillError, IntegrityError) as error:
        code = error.code if isinstance(error, SkillError) else 'source_conflict'
        AgentSkillInstallOperation.objects.filter(pk=row.pk, claim=claim, version=version).exclude(state='installed').update(
            state='failed', error_code=code, updated_at=timezone.now())
        audit(actor, 'install_failed', operation_id=str(row.pk), code=code, cost_kind='no_api_charge')
        row.refresh_from_db()
        return operation_view(row)


def change(actor, installation_id, action, *, enabled=None):
    account, agent = skills.actor_profile(actor)
    with transaction.atomic():
        Profile.objects.select_for_update().get(pk=account.pk)
        row = AgentSkillInstallation.objects.select_for_update(of=('self',)).filter(pk=installation_id,
            owner=actor, company_id=account.company_id, tombstoned_at__isnull=True).select_related('current_revision').first()
        if row is None:
            raise SkillError('skill_installation_not_found')
        if action == 'rollback':
            if not row.previous_revision_id:
                raise SkillError('skill_previous_revision_missing')
            row.current_revision, row.previous_revision = row.previous_revision, row.current_revision
        elif action == 'enabled':
            if not isinstance(enabled, bool):
                raise SkillError('invalid_skill_enabled')
            if enabled:
                if not skills.availability(agent, row.current_revision.compatibility)['available']:
                    raise SkillError('skill_dependency_unavailable')
                _enabled_limit(actor, account.company_id, row.pk, row.current_revision.metadata['description'])
            if row.enabled != enabled:
                row.authorization_version += 1
            row.enabled = enabled
        elif action == 'uninstall':
            row.enabled, row.tombstoned_at = False, timezone.now()
            row.authorization_version += 1
        else:
            raise SkillError('invalid_skill_action')
        row.save()
        audit(actor, action, installation_id=str(row.pk), revision_id=str(row.current_revision_id))
        return skills.installation_view(row, agent)

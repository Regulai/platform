"""Server-resolved capabilities and resource budgets; no ambient account grants."""
import json
import re

from pydantic import BaseModel, ConfigDict, Field
from .inference_options import InferenceConfiguration

FILES = {'ls', 'read_file', 'write_file', 'edit_file', 'replace_file', 'glob', 'grep', 'execute'}
WEB = {'web_search', 'web_open', 'web_find', 'web_download', 'web_browse'}
GENERAL = FILES | WEB | {'install_packages', 'publish_artifact', 'inspect_image', 'read_output'}


class Limits(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    model_calls: int = Field(default=48, ge=4, le=200)
    tool_calls: int = Field(default=120, ge=8, le=500)
    run_seconds: int = Field(default=1800, ge=60, le=3600)
    command_seconds: int = Field(default=120, ge=1, le=300)
    output_chars: int = Field(default=16000, ge=1000, le=64000)
    output_bytes: int = Field(default=1048576, ge=16384, le=4194304)
    file_bytes: int = Field(default=20000000, ge=1024, le=30000000)
    workspace_bytes: int = Field(default=536870912, ge=67108864, le=1073741824)
    memory_mb: int = Field(default=1024, ge=256, le=2048)
    processes: int = Field(default=64, ge=8, le=128)
    web_calls: int = Field(default=40, ge=1, le=120)
    web_bytes: int = Field(default=10000000, ge=1024, le=30000000)
    web_seconds: int = Field(default=25, ge=1, le=60)
    pdf_pages: int = Field(default=100, ge=1, le=200)
    human_review: bool = False
    retention_days: int = Field(default=30, ge=1, le=365)
    inference: InferenceConfiguration = Field(default_factory=InferenceConfiguration)
    work_profiles: bool = False


class EffectiveLimits(Limits):
    """Task snapshots can be stricter than the historical administrative minima."""
    model_calls: int = Field(default=48, ge=1, le=200)
    tool_calls: int = Field(default=120, ge=1, le=500)
    run_seconds: int = Field(default=1800, ge=1, le=3600)


def limits(profile):
    return Limits.model_validate(profile.limits).model_dump(exclude={'inference', 'work_profiles'})


WORK_PROFILES = {
    'text': {'model_calls': 3, 'tool_calls': 4, 'run_seconds': 60},
    'calculation': {'model_calls': 8, 'tool_calls': 16, 'run_seconds': 180, 'command_seconds': 20},
    'files': {'model_calls': 12, 'tool_calls': 24, 'run_seconds': 300, 'command_seconds': 60},
    'research': {'model_calls': 16, 'tool_calls': 32, 'run_seconds': 600},
}


def resolve_work(profile, request, text, selection='legacy'):
    """Pure task selection from an already resolved contract; no model classifier."""
    budget = limits(profile)
    if selection == 'legacy' or not profile.limits.get('work_profiles', False):
        return budget, {'version': 1, 'name': 'legacy'}
    if request.get('operation') == 'download':
        return budget, {'version': 1, 'name': 'download', 'model_goal': 0, 'deterministic': True}
    if request.get('research_required'):
        name = 'research'
    elif request.get('delivery_required') or request.get('formats') or request.get('operation') in ('create', 'edit'):
        name = 'files'
    elif re.search(r'\b(simula\w*|simulaci[oó]n|calcula\w*|c[aá]lculo|monte\s+carlo|simulate\w*|calculat\w*)\b', text, re.I):
        name = 'calculation'
    else:
        name = 'text'
    budget.update({key: min(budget[key], value) for key, value in WORK_PROFILES[name].items()})
    EffectiveLimits.model_validate(budget)
    return budget, {'version': 1, 'name': name, 'model_goal': 1 if name == 'text' else 4,
        'closing_model_calls': 1, 'closing_seconds': 10, 'delivery_repairs': 1}


def execution_limits(run, profile):
    """Never replenish a started task; new administrative restrictions revoke it."""
    from .service import AgentDenied
    current = limits(profile)
    saved = run.job.get('limits')
    if saved is None:
        return current
    snapshot = EffectiveLimits.model_validate(saved).model_dump(exclude={'inference', 'work_profiles'})
    if any(type(value) is int and current[key] < value for key, value in snapshot.items()):
        raise AgentDenied('agent_limits_changed')
    if current['human_review'] and not snapshot['human_review']:
        raise AgentDenied('agent_limits_changed')
    return snapshot


def remaining_seconds(run, profile, *, now=None):
    from django.utils import timezone
    budget = execution_limits(run, profile)
    # Queue wait has its own capacity deadline. Recovery keeps started_at.
    elapsed = max(0, ((now or timezone.now()) - run.started_at).total_seconds()) if run.started_at else 0
    return max(0, budget['run_seconds'] - elapsed)


def call_timeout(run, profile, configured=None, *, now=None):
    from .service import AgentDenied
    remaining = remaining_seconds(run, profile, now=now)
    if remaining <= 0:
        raise AgentDenied('deadline_exceeded')
    if configured is not None:
        if isinstance(configured, bool) or not isinstance(configured, (int, float)) or configured <= 0:
            raise AgentDenied('invalid_call_timeout')
        remaining = min(remaining, configured)
    return remaining


def search_configuration(profile):
    """One non-generative search provider; no automatic answer or provider LLM."""
    from .service import AgentDenied
    try:
        value = json.loads(profile.search_config or '{}')
        if (not isinstance(value, dict) or set(value) - {'provider', 'api_key', 'call_cost_bound'}
                or value.get('provider') != 'tavily' or not isinstance(value.get('api_key'), str)
                or not value['api_key']):
            raise ValueError()
        from decimal import Decimal
        bound = Decimal(str(value['call_cost_bound']))
        if not bound.is_finite() or not 0 < bound <= 10:
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError, ArithmeticError):
        raise AgentDenied('search_not_configured') from None


def profile_for(actor, *, allow_disabled=False):
    from django.conf import settings
    from front.models import AgentAccessGrant, Profile
    from .service import AgentDenied
    if not actor.is_active or (not allow_disabled and not getattr(settings, 'REGULAY_AGENT_ENABLED', False)):
        raise AgentDenied('agent_disabled')
    account = Profile.objects.get(user=actor)
    grant = AgentAccessGrant.objects.select_related('profile').filter(
        user=actor, company_id=account.company_id).first()
    if grant is not None:
        if not grant.enabled or not grant.profile.enabled or grant.profile.company_id != account.company_id:
            raise AgentDenied('agent_access_denied')
        return grant.profile_id
    # Retain old isolated laboratory fixtures, never enable real accounts by name.
    if (settings.DEBUG and getattr(settings, 'REGULAY_AGENT_DEVELOPMENT', False)
            and actor.username.startswith('agent-synthetic-')):
        entry = getattr(settings, 'REGULAY_AGENT_DEV_ACCOUNTS', {}).get(str(actor.pk))
        if entry and entry.get('company_id') == account.company_id:
            return int(entry['profile_id'])
    raise AgentDenied('agent_access_denied')


def grant_binding(actor, profile_id):
    from front.models import AgentAccessGrant
    row = AgentAccessGrant.objects.filter(user=actor, profile_id=profile_id).first()
    return [row.pk, row.company_id, row.enabled, row.version] if row else None

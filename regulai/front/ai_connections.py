"""Account-scoped credential setup; saving performs no network requests."""
from django import forms
from django.contrib import messages
from django.core import signing
from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods

from .access import actor_company, company_policy_required
from .models import AuditLog, Company, CompanyEngine, Engine, ObfuscationConfig, Rule, RulesGroup
from .policy import AIConfig, digest, validate_yara


BASIC_RULE = r'''rule basic_credentials {
    strings:
        $private_key = /-----BEGIN ([A-Z]+ )?PRIVATE KEY-----/
        $token = /sk-[A-Za-z0-9_-]{20,}/
        $google = /AIza[A-Za-z0-9_-]{30,}/
        $aws = /AKIA[A-Z0-9]{16}/
        $assigned = /(api[_-]?key|password|secret|token)[ \t]*[:=][ \t]*["']?[A-Za-z0-9_\/+=.-]{8,}/ nocase
    condition: any of them
}'''
SETUP_SALT = 'ai-connections-basic-v1'


def basic_setup_review(company):
    """Review only native saved connections; never infer authorization from a key."""
    if company.ai_config or company.obfuscation_configs.exists():
        return {'reason': 'Esta cuenta ya tiene una política o enmascarado. Revisa su configuración avanzada.'}
    from .chat_service import destination_identity
    destinations, services, identities = [], [], []
    for key, label, connector, endpoint, _ in SERVICES[:-1]:
        rows = CompanyEngine.objects.filter(company=company, active=True,
            engine__name=f'{label} · API', engine__connector_type=connector,
            engine__base_url=endpoint).select_related('engine')
        for row in rows:
            models = list(row.engine.models.filter(active=True).order_by('pk'))
            if row.api_key and models:
                destinations.append(f'engine:{row.pk}')
                services.append(label)
                identities.append([row.pk, [destination_identity(row, model) for model in models]])
    if not destinations:
        return {'reason': 'Primero guarda una clave de Claude, Gemini, Mistral, OpenAI o DeepSeek. La clave de Jev por sí sola no genera respuestas.'}
    from .local_masking import detector_metadata
    try:
        metadata = detector_metadata()
    except RuntimeError:
        return {'reason': 'Falta el detector local de privacidad. El administrador del servidor debe instalar las dependencias de enmascarado.'}
    return {'services': services, 'destinations': destinations,
        'fingerprint': digest([company.pk, identities, metadata, BASIC_RULE])}


@transaction.atomic
def activate_basic_chat(company_id, actor, token):
    company = Company.objects.select_for_update().get(pk=company_id)
    review = basic_setup_review(company)
    try:
        approved = signing.loads(token, salt=SETUP_SALT, max_age=1800)
    except signing.BadSignature:
        raise ValidationError('La revisión ha caducado. Recarga la página y revisa la configuración.') from None
    if review.get('reason') or approved != review['fingerprint']:
        raise ValidationError('La configuración ha cambiado. Recarga la página antes de activarla.')
    mask = ObfuscationConfig.objects.create(company=company, name='Privacidad local del chat',
        backend='local', detect='both')
    validate_yara(BASIC_RULE)
    group = RulesGroup.objects.create(company=company, name='Protección básica del chat')
    Rule.objects.create(rules_group=group, name='Credenciales y claves privadas',
        yara_rule=BASIC_RULE, severity='critical', action='block', applies_to='both')
    destinations = review['destinations'] + [f'obfuscation:{mask.pk}']
    company.ai_config = AIConfig.model_validate({'version': 1, 'local_sensitivity': 'internal',
        'destinations': {'public': destinations, 'internal': destinations,
            'confidential': [], 'restricted': [], 'unknown': []},
        'masking': {'max_call_cost': '0'}, 'routing': {'mode': 'manual', 'max_output_tokens': 1000},
        'classification': 'local', 'verification': {'mode': 'local'}}).model_dump(mode='json')
    company.save(update_fields=['ai_config'])
    AuditLog.objects.create(company=company, user=actor, action='ai_basic_chat_activate',
        details='Explicit basic chat activation; review=' + approved)


SERVICES = (
    ('claude', 'Claude', 'anthropic', 'https://api.anthropic.com', 'https://console.anthropic.com/settings/keys'),
    ('gemini', 'Gemini', 'openai_compatible', 'https://generativelanguage.googleapis.com/v1beta/openai/', 'https://aistudio.google.com/api-keys'),
    ('mistral', 'Mistral', 'openai_compatible', 'https://api.mistral.ai/v1', 'https://console.mistral.ai/api-keys'),
    ('openai', 'OpenAI / ChatGPT', 'openai', 'https://api.openai.com/v1', 'https://platform.openai.com/api-keys'),
    ('deepseek', 'DeepSeek', 'openai_compatible', 'https://api.deepseek.com', 'https://platform.deepseek.com/api_keys'),
    ('jev', 'Jev · Vercel AI Gateway', None, None, 'https://vercel.com/docs/ai-gateway/authentication-and-byok/api-keys'),
)


class ServiceKeysForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key, label, _, _, _ in SERVICES:
            self.fields[key] = forms.CharField(label=label, required=False, max_length=256,
                widget=forms.PasswordInput(attrs={'class': 'form-control', 'autocomplete': 'new-password',
                    'spellcheck': 'false', 'placeholder': f'Pega tu clave de {label}'}))

    def clean(self):
        data = super().clean()
        if self.data.get('gateway'):
            raise ValidationError('Ahora se usa una clave propia por servicio. Recarga la página y completa cada campo por separado.')
        for field, value in list(data.items()):
            if any(ord(char) < 33 or ord(char) > 126 for char in value):
                self.add_error(field, 'La clave no puede contener espacios ni caracteres especiales de control.')
        return data


def service_engines(keys=None):
    engines = {}
    for key, label, connector, endpoint, _ in SERVICES[:-1]:
        if keys is not None and key not in keys:
            continue
        engine = Engine.objects.filter(name=f'{label} · API', connector_type=connector,
            base_url=endpoint).first()
        if not engine or not engine.models.filter(active=True).exists():
            raise ValidationError(f'La conexión de {label} no está disponible. Revisa su catálogo y sus modelos activos.')
        engines[key] = engine
    return engines


@transaction.atomic
def save_keys(company_id, actor, values, *, remove=False):
    company = Company.objects.select_for_update().get(pk=company_id)
    updates = {key: values.get(key, '') for key, _, _, _, _ in SERVICES}
    if not remove and not any(updates.values()):
        return False
    jev_transport = (company.ai_config or {}).get('jev', {}).get('transport', 'vercel')
    if updates['jev'] and jev_transport != 'vercel':
        raise ValidationError('Jev usa actualmente TypeSafe directo. Cambia su transporte a Vercel en la política antes de guardar esta clave.')
    if remove:
        # Removal must still work when a model is disabled or the catalogue changes.
        CompanyEngine.objects.filter(company=company,
            engine__name__in=[f'{label} · API' for _, label, _, _, _ in SERVICES[:-1]]).update(api_key='', active=False)
    else:
        for key, engine in service_engines({key for key, value in updates.items() if value}).items():
            rows = CompanyEngine.objects.filter(company=company, engine=engine)
            if updates[key]:
                if rows.exists():
                    rows.update(api_key=updates[key], active=True)
                else:
                    CompanyEngine.objects.create(company=company, engine=engine, api_key=updates[key])
    if (remove and jev_transport == 'vercel') or updates['jev']:
        company.jev_api_key = '' if remove else updates['jev']
        company.save(update_fields=['jev_api_key'])
    AuditLog.objects.create(company=company, user=actor,
        action='ai_keys_remove' if remove else 'ai_keys_save',
        details='Service credentials updated; no connection test performed.')
    return True


@sensitive_post_parameters()
@never_cache
@company_policy_required
@require_http_methods(['GET', 'POST'])
def ai_connections(request):
    company = actor_company(request.user)
    form = ServiceKeysForm(request.POST if request.method == 'POST' else None)
    if request.method == 'POST':
        action = request.POST.get('action', 'save')
        if action == 'activate_basic':
            form.is_valid()
            try:
                activate_basic_chat(company.pk, request.user, request.POST.get('review_token', ''))
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, 'Chat básico activado con privacidad local. Ya puedes iniciar una conversación de texto.')
                return redirect('front:ai_connections')
        elif action not in {'save', 'remove'}:
            form.add_error(None, 'Acción no válida.')
        elif action == 'remove' or form.is_valid():
            try:
                changed = save_keys(company.pk, request.user,
                    form.cleaned_data if action == 'save' else {}, remove=action == 'remove')
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, ('Claves de estas conexiones eliminadas de esta cuenta.' if action == 'remove'
                    else 'Claves guardadas. No se ha realizado ninguna llamada de prueba.') if changed
                    else 'No has introducido claves nuevas. Se conservan las anteriores.')
                return redirect('front:ai_connections')
    rows = []
    for key, label, connector, endpoint, key_url in SERVICES:
        if key == 'jev':
            configured = bool(company.jev_api_key) and (company.ai_config or {}).get('jev', {}).get('transport', 'vercel') == 'vercel'
            active = configured
        else:
            credentials = list(CompanyEngine.objects.filter(company=company,
                engine__name=f'{label} · API').select_related('engine'))
            configured = any(row.api_key for row in credentials)
            active = any(row.api_key and row.active and row.engine.connector_type == connector
                and row.engine.base_url == endpoint and row.engine.models.filter(active=True).exists()
                for row in credentials)
        rows.append({'label': label, 'via_gateway': key == 'jev', 'key_url': key_url,
            'configured': configured, 'active': active, 'field': form[key]})
    review = basic_setup_review(company)
    if 'fingerprint' in review:
        review['token'] = signing.dumps(review['fingerprint'], salt=SETUP_SALT)
    return render(request, 'company/ai_connections.html', {'company': company, 'form': form, 'setup': review,
        'services': rows, 'has_keys': any(row['configured'] for row in rows)},
        status=400 if form.errors else 200)

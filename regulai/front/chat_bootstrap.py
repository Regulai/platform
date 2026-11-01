"""Public bootstrap for the React chat island: an explicit allowlist, no ORM objects.

Built from the same projection the server-rendered chat used (chat_page.turns,
run_data, conversation_groups and the chat_view context). It grants nothing:
every action still goes through the existing endpoints, permissions and CSRF.
"""
from django.conf import settings
from django.middleware.csrf import get_token
from django.templatetags.static import static
from django.urls import reverse

from .access import can_manage_company_policy, is_platform_operator

PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000000'
CHAT_ACCEPT = ['.txt', '.pdf', '.docx', '.pptx', '.csv', '.json', '.py', '.js', '.md', '.xlsx']
DOCUMENT_AGENT_ACCEPT = ['.csv', '.xlsx']
PROFESSIONAL_EXTRA = ['.html', '.htm', '.css', '.svg', '.zip', '.png', '.jpg', '.jpeg', '.sh']
PLACEHOLDERS = {
    'chat': 'Escribe un mensaje…',
    'agent': 'Describe el documento: formato, idioma y extensión…',
    'professional': 'Describe qué quieres investigar, calcular o crear…',
}
PROFESSIONAL_SUGGESTIONS = [
    {'label': 'Resume fuentes oficiales en un Excel',
     'text': 'Busca fuentes oficiales sobre el consumo eléctrico de los centros de datos en España y resume las cifras en un Excel'},
    {'label': 'Analiza un archivo con código',
     'text': 'Analiza el archivo adjunto con Python y crea un informe Word con las conclusiones'},
]
DOCUMENT_SUGGESTIONS = [
    {'label': 'Informe en Word y PDF', 'text': 'Crea un informe de tres páginas en Word y PDF sobre '},
    {'label': 'Presentación', 'text': 'Prepara una presentación de cinco diapositivas sobre '},
]


def _pattern(name, **kwargs):
    """A URL with `{id}` where the identifier goes, resolved by Django."""
    value = next(iter(kwargs.values()))
    return reverse(name, kwargs=kwargs).replace(str(value), '{id}')


def navigation(request, permissions=None):
    """Same items, order and conditions as partials/nav_items.html."""
    user = request.user
    name = getattr(getattr(request, 'resolver_match', None), 'url_name', '') or ''
    manage = can_manage_company_policy(user)
    staff = user.is_superuser or user.is_staff
    if permissions is None:
        from .context_processors import unresolved_alerts_count
        permissions = unresolved_alerts_count(request)
    skills = permissions['skills_catalog_enabled']
    item = lambda key, label, url, active=False: {'key': key, 'label': label, 'href': reverse(url), 'active': active}
    groups = [{'label': 'General', 'items': [
        item('home', 'Inicio', 'front:home', name == 'home'),
        item('chat', 'Chat', 'front:chat', name in ('chat', 'chat_conversation', 'index')),
        *([item('skills', 'Skills', 'front:skills_library')] if skills else []),
    ]}]
    if staff:
        groups.append({'label': 'Seguridad', 'items': [
            item('dashboard', 'Panel', 'front:dashboard'),
            item('prompts', 'Prompts', 'front:prompts_list'),
            item('rulesgroups', 'Grupos de reglas', 'front:rulesgroups_list'),
            item('rules', 'Reglas', 'front:rules_list'),
            item('community', 'Reglas de la comunidad', 'front:rules_community_list'),
            item('alerts', 'Alertas', 'front:alerts_list'),
            item('obfuscation', 'Ofuscación', 'front:obfuscation_list'),
        ]})
    configuration = []
    if user.is_superuser or manage:
        if manage:
            configuration.append(item('ai_connections', 'Conexiones IA', 'front:ai_connections'))
    if user.is_superuser:
        configuration += [
            item('company', 'Empresa', 'front:company_settings'),
            item('users', 'Usuarios', 'front:users_list'),
            item('departments', 'Departamentos', 'front:departments_list'),
            item('engines', 'Motores IA', 'front:engines_list'),
            item('audit', 'Auditoría', 'front:auditlogs_list'),
        ]
        if is_platform_operator(user):
            configuration.append({'key': 'admin', 'label': 'Administración', 'href': reverse('admin:index'), 'active': False})
    if manage:
        configuration.append(item('simulator', 'Simulador de políticas', 'front:policy_simulator'))
    if configuration:
        groups.append({'label': 'Configuración', 'items': configuration})
    return groups


def _alerts(request, data):
    user = request.user
    if not (user.is_staff or user.is_superuser):
        return None
    recent = []
    for alert in data['recent_unresolved_alerts']:
        words = (alert.description or '').split()
        recent.append({'id': alert.pk, 'title': alert.rule.name if alert.rule_id and alert.rule.name else 'Alerta',
                       'description': ' '.join(words[:8]) + (' …' if len(words) > 8 else ''),
                       'severity': alert.severity, 'href': reverse('front:alert_detail', args=[alert.pk])})
    return {'count': data['unresolved_alerts_count'], 'recent': recent,
            'href': reverse('front:alerts_list') + '?status=unresolved'}


def _evidence(items):
    keep = []
    for item in items or []:
        if isinstance(item, dict) and isinstance(item.get('locator'), str):
            keep.append({'claim_index': item.get('claim_index'), 'locator': item['locator'],
                         'excerpt': item.get('excerpt') or item.get('text') or ''})
    return keep


def _notice(notice, prompt=None):
    if not notice:
        return None
    value = {key: notice.get(key) for key in ('kind', 'title', 'text', 'reason', 'code', 'stale', 'retry')
             if notice.get(key) is not None}
    value['rules'] = list(notice.get('rules') or [])
    if notice.get('kind') == 'blocked' and not value['rules'] and prompt is not None:
        # Without a matching rule the policy's own reason says why (destination, restricted content),
        # as the live result does.
        from .chat_service import request_result
        detail = request_result(prompt).data.get('error')
        if isinstance(detail, str) and detail:
            value['detail'] = detail
    if notice.get('kind') == 'consent':
        value['file_name'] = notice.get('file_name') or None
        # The legacy page exposed the token only when no file must be re-attached.
        value['token'] = notice.get('token') if notice.get('token') and not notice.get('file_name') else None
        requested = notice.get('requested')
        value['requested'] = ({'engine_id': requested.get('engine_id'), 'model_id': requested.get('model_id')}
                              if isinstance(requested, dict) else None)
    return value


def _turn(turn):
    prompt, user, assistant, run = turn['prompt'], turn['user'], turn['assistant'], turn['run']
    request_id = str(prompt.request_id) if prompt is not None else None
    answer = turn['answer']
    data = {
        'request_id': request_id,
        'status': prompt.status if prompt is not None else None,
        'run_id': run['id'] if run else None,
        'legacy': bool(turn['legacy']),
        'live': bool(turn['notice'] and turn['notice'].get('kind') == 'live'),
        'user': ({'content': user.content, 'file_name': user.file_name or None,
                  'file_size': user.file_size or None} if user is not None else None),
        'notice': _notice(turn['notice'], prompt),
        'answer': ({'text': answer['text'], 'unverified': bool(answer['unverified']),
                    'recorded': bool(answer['recorded']), 'evidence': _evidence(answer['evidence'])}
                   if answer is not None and (not run or run.get('professional')) else None),
        'assistant_file': None,
        'receipt_url': reverse('front:chat_request_receipt', args=[request_id]) if request_id and prompt.status != 'legacy' else None,
        # As the server page: the evidence export only next to verified citations.
        'evidence_url': (reverse('front:chat_request_evidence', args=[request_id])
                         if request_id and answer is not None and answer['evidence'] else None),
    }
    if assistant is not None and assistant.file_name and assistant.response_file:
        data['assistant_file'] = {'name': assistant.file_name, 'size': assistant.file_size or None,
                                  'url': reverse('front:chat_download_file', args=[assistant.pk])}
    return data


def _upload_limit(user, agent_available):
    from .file_security import MAX_FILE_SIZES
    chat = max(MAX_FILE_SIZES.values())
    agent = None
    if agent_available:
        try:
            from .agents.capabilities import limits
            from .agents.jobs import development_profile
            from .models import AgentModelProfile
            agent = limits(AgentModelProfile.objects.get(pk=development_profile(user)))['file_bytes']
        except Exception:  # The server still validates every upload.
            agent = None
    return {'chat': chat, 'agent': agent}


def chat_bootstrap(request, context, runs):
    user = request.user
    profile = user.profile
    conversation = context['conversation']
    agent_available = bool(context['agent_available'])
    professional = bool(context['agent_professional'])
    from .chat_page import turns as page_turns
    from .context_processors import unresolved_alerts_count
    permissions = unresolved_alerts_count(request)
    skills_catalog = bool(permissions['skills_catalog_enabled'] and agent_available)
    new = conversation is None
    modes = ['chat', 'agent'] if agent_available and new else []
    mode = (conversation.mode if conversation is not None else ('agent' if professional else 'chat'))
    agent_accept = CHAT_ACCEPT + PROFESSIONAL_EXTRA if professional else DOCUMENT_AGENT_ACCEPT
    engines = [{'id': engine.id, 'name': engine.display_name,
                'detail': ' · '.join(filter(None, [engine.engine.provider, engine.engine.get_connector_type_display()]))}
               for engine in context['available_engines']]
    models = [{'id': model.id, 'name': model.name,
               'detail': model.model_id + (' · imágenes' if model.supports_vision else '')}
              for model in context['available_models']]
    avatar = getattr(profile, 'avatar', None)
    return {
        'version': 1,
        'csrf_token': get_token(request),
        'urls': {
            'home': reverse('front:home'),
            'chat': reverse('front:chat'),
            'conversation': _pattern('front:chat_conversation', conversation_id=987654321),
            'delete': _pattern('front:chat_delete', conversation_id=987654321),
            'send': reverse('front:chat_send'),
            'send_conversation': _pattern('front:chat_send_conversation', conversation_id=987654321),
            'request_stream': _pattern('front:chat_request_stream', request_id=PLACEHOLDER_UUID),
            'request_cancel': _pattern('front:chat_request_cancel', request_id=PLACEHOLDER_UUID),
            'request_receipt': _pattern('front:chat_request_receipt', request_id=PLACEHOLDER_UUID),
            'select_engine': reverse('front:chat_select_engine'),
            'select_model': reverse('front:chat_select_model'),
            'skills_library': reverse('front:skills_library'),
            'skill_preference': _pattern('front:skill_preference', conversation_id=987654321),
            'documents_search': reverse('front:agent_document_search'),
            'ai_connections': reverse('front:ai_connections'),
            'profile': reverse('front:profile'),
            'logout': reverse('front:logout'),
            'logo': static('images/logos/logo.png'),
        },
        'user': {'name': user.username, 'initial': (user.username[:1] or '?').upper(),
                 'company': profile.company.name if profile.company_id else None,
                 'avatar_url': avatar.url if avatar else None},
        'navigation': navigation(request, permissions),
        'alerts': _alerts(request, permissions),
        'demo': bool(getattr(settings, 'DEMO_MODE', False)),
        'setup': {'missing': not profile.company.ai_config, 'can_manage': can_manage_company_policy(user)},
        'conversation': ({'id': conversation.id, 'title': context['conversation_title'], 'mode': conversation.mode,
                          'auto_skills': bool(getattr(conversation, 'auto_skills', True))}
                         if conversation is not None else None),
        'threads': [{'label': label, 'items': [{'id': item['id'], 'title': item['title'], 'mode': item['mode']}
                                               for item in items]}
                    for label, items in context['conversation_groups']],
        'composer': {
            'modes': modes,
            'mode': mode,
            'professional': professional,
            'agent_available': agent_available,
            'accept': {'chat': CHAT_ACCEPT, 'agent': agent_accept},
            'max_bytes': _upload_limit(user, agent_available),
            'placeholders': {'chat': PLACEHOLDERS['chat'],
                             'agent': PLACEHOLDERS['professional' if professional else 'agent']},
            'suggestions': (PROFESSIONAL_SUGGESTIONS if professional else DOCUMENT_SUGGESTIONS) if agent_available and new else [],
            'inference_profiles': list(context['inference_profiles']) if len(context['inference_profiles']) > 1 else [],
            'drive': bool(context['agent_drive']),
            'skills': {'catalog': skills_catalog, 'runtime': bool(skills_catalog and permissions['skills_runtime_enabled'])},
        },
        'models': {
            'engines': engines,
            'models': models,
            'engine_id': context['current_engine'].id if context['current_engine'] else None,
            'model_id': context['current_model'].id if context['current_model'] else None,
            'automatic': bool(context['automatic_routing']),
            'difficulty': bool(context['difficulty_routing']),
            'provider_limits': bool(context['provider_managed_limits']),
        },
        'turns': [_turn(turn) for turn in page_turns(conversation, runs)] if conversation is not None else [],
        'runs': {str(value['id']): value for value in runs.values()},
    }

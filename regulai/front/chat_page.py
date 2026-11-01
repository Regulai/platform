"""Read-only projection of a conversation for the chat page. No external calls.

Turns pair each request with its answer, its outcome notice and, in agent mode,
its run. Notices reuse the pipeline's own codes and messages; nothing here
grants access or changes state.
"""
from datetime import timedelta
import re

from django.utils import timezone

ERROR_TITLES = {
    'verification_failed': 'Respuesta no entregada',
    'provider_failed': 'Error del proveedor',
    'outcome_unknown': 'Resultado desconocido',
    'security_check_failed': 'Comprobación de seguridad no superada',
    'deadline_exceeded': 'Tiempo agotado',
    'budget_exhausted': 'Presupuesto insuficiente',
    'unknown_price': 'Coste no acotado',
    'context_overflow': 'Contenido demasiado largo',
    'evaluation_input_too_large': 'Contenido demasiado largo',
    'input_unreadable': 'Documento no legible',
    'authorization_changed': 'Permisos cambiados',
    'cancelled_by_user': 'Respuesta detenida',
    'consent_invalid': 'Confirmación caducada',
}
SETUP_CODES = {'masking_required', 'policy_configuration_invalid', 'jev_unavailable', 'no_api_key',
               'model_not_allowed', 'no_authorized_candidates', 'empty_policy_not_authorized',
               'destination_not_allowed', 'quality_unavailable', 'capability_unavailable'}
LIVE = ('processing', 'received')
MARKER = re.compile(r'\[\[REGULAI_([A-Z]+)\]\]')
MARKER_LABELS = {'PERSON': 'nombre', 'LOCATION': 'ubicación', 'ORGANIZATION': 'organización', 'EMAIL': 'correo',
                 'PHONE': 'teléfono', 'ID': 'documento', 'ACCOUNT': 'cuenta', 'CARD': 'tarjeta', 'SECRET': 'secreto'}


TITLE_CHARS = 60
TITLE_SOURCE_CHARS = 1000  # masked whole, so a value is never cut before masking


def _first_messages(conversation_ids):
    """Start of each conversation's first user message, in one query."""
    from django.db.models import OuterRef, Subquery
    from django.db.models.functions import Substr
    from .models import Conversation, Message
    head = (Message.objects.filter(conversation=OuterRef('pk'), role='user').order_by('created_at', 'pk')
            .annotate(head=Substr('content', 1, TITLE_SOURCE_CHARS)).values('head')[:1])
    return dict(Conversation.objects.filter(pk__in=conversation_ids).annotate(head=Subquery(head)).values_list('pk', 'head'))


def _shorten(text):
    """Whole words up to TITLE_CHARS; a '[… protegido]' label is never cut."""
    result = ''
    for token in re.findall(r'\[[^\[\]]* protegido\]\S*|\S+', text):
        candidate = f'{result} {token}' if result else token
        if len(candidate) > TITLE_CHARS:
            return (result.rstrip(' ,.;:') or token[:TITLE_CHARS]) + '…'
        result = candidate
    return result


def display_titles(conversations):
    """Titles for the sidebar, header and page title: first message, masked locally.

    The stored title is the raw first 50 characters, so masking it alone would
    show a value cut at that boundary (half a key or card number). The first
    message is masked as a whole (bounded) and only then shortened.
    """
    from .local_masking import mask_local_texts
    conversations = list(conversations)
    heads = _first_messages([conversation.pk for conversation in conversations])
    titles = []
    for conversation in conversations:
        head, title = heads.get(conversation.pk) or '', conversation.title or ''
        # Generated titles are a prefix of the first message; any other title is kept.
        source = head if head and head.startswith(title) else title or head
        if not source.strip():
            titles.append('Nueva conversación')
            continue
        try:
            masked = mask_local_texts([source], timeout=2)[0]
        except Exception:
            titles.append('Conversación')
            continue
        key = masked.find('-----BEGIN')  # An unfinished key block is never shown, even in part.
        if key >= 0:
            masked = masked[:key] + '[[REGULAI_SECRET]]'
        titles.append(_shorten(MARKER.sub(lambda match: f"[{MARKER_LABELS.get(match[1], 'dato')} protegido]", masked)))
    return titles


def display_title(conversation):
    return display_titles([conversation])[0]


def conversation_groups(conversations, now=None):
    now = now or timezone.now()
    today = timezone.localtime(now).date()
    labels = [('Hoy', 0), ('Ayer', 1), ('Últimos 7 días', 7), ('Últimos 30 días', 30)]
    conversations = list(conversations)
    groups = []
    for conversation, title in zip(conversations, display_titles(conversations)):
        age = (today - timezone.localtime(conversation.updated_at).date()).days
        label = next((name for name, limit in labels if age <= limit), 'Anteriores')
        if not groups or groups[-1][0] != label:
            groups.append((label, []))
        groups[-1][1].append({'id': conversation.pk, 'title': title,
                              'mode': conversation.mode, 'updated_at': conversation.updated_at})
    return groups


def notice(prompt):
    """Outcome a person can act on; None when the answer speaks for itself."""
    from .chat_service import request_result
    if prompt is not None and prompt.status == 'completed' and prompt.decision.get('history_selection', {}).get('omitted'):
        return {'kind': 'context', 'title': 'Contexto anterior limitado',
                'text': 'Algunos mensajes anteriores no están en el contexto autorizado. Puedes reenviar el fragmento necesario.'}
    if prompt is None or prompt.status in ('completed', 'legacy'):
        return None
    data = request_result(prompt).data
    decision = prompt.decision or {}
    rules = [rule.get('name') for rule in (decision.get('policy') or {}).get('rules', []) if rule.get('name')]
    code = data.get('error_type')
    if prompt.status == 'blocked':
        return {'kind': 'blocked', 'title': 'Bloqueado por la política', 'rules': rules,
                'text': 'No se ha enviado a ningún proveedor.'}
    if prompt.status == 'pending_consent':
        requested = decision.get('requested')
        return {'kind': 'consent', 'title': 'Requiere tu confirmación', 'rules': rules,
                'reason': decision.get('consent_reason'), 'token': decision.get('consent_token'),
                'file_name': prompt.file_name, 'requested': requested if isinstance(requested, dict) else None,
                'text': 'Revisa el aviso antes de enviar este mismo contenido.'}
    if prompt.status in LIVE:
        stale = prompt.updated_at < timezone.now() - timedelta(seconds=240)
        return {'kind': 'live', 'stale': stale}
    if prompt.status == 'cancelled':
        return {'kind': 'cancelled', 'title': 'Respuesta detenida' if code == 'cancelled_by_user' else 'Petición cancelada',
                'text': data.get('error') if code == 'cancelled_by_user' else 'No se ha enviado.'}
    title = ('Configuración incompleta' if code in SETUP_CODES else
             ERROR_TITLES.get(code, 'No se pudo completar'))
    return {'kind': 'error', 'title': title, 'text': data.get('error') or 'La petición no se pudo completar.',
            'code': code, 'retry': prompt.status in ('failed', 'outcome_unknown') and not prompt.file_name}


UNVERIFIED_PREFIX = 'No verificado\n\n'


def answer(message, record, agent):
    """Display projection; the stored message is unchanged."""
    text, unverified, evidence = message.content, False, []
    if record is not None and not agent:
        unverified = (record.prompt.decision.get('verification') or {}).get('status') != 'passed'
        if unverified and text.startswith(UNVERIFIED_PREFIX):
            text = text[len(UNVERIFIED_PREFIX):]  # Shown as a status label instead.
        if not unverified:
            evidence = [item for item in (record.evidence or {}).get('items', [])
                        if isinstance(item, dict) and isinstance(item.get('locator'), str)]
    return {'text': text, 'unverified': unverified, 'evidence': evidence, 'recorded': record is not None}


def turns(conversation, runs=None):
    """[{user, prompt, assistant, answer, notice, run, legacy}] in conversation order."""
    runs = runs or {}
    result, by_prompt = [], {}
    blank = {'user': None, 'prompt': None, 'assistant': None, 'answer': None, 'run': None, 'legacy': False, 'notice': None}
    for message in conversation.messages.select_related('request_record', 'response_record__prompt').all():
        if message.role == 'user':
            prompt = getattr(message, 'request_record', None)
            turn = {**blank, 'user': message, 'prompt': prompt, 'legacy': prompt is None}
            if prompt is not None:
                by_prompt[prompt.pk] = turn
                turn['run'] = runs.get(prompt.pk)
                if turn['run'] is None:
                    turn['notice'] = notice(prompt)
            result.append(turn)
        elif message.role == 'assistant':
            record = getattr(message, 'response_record', None)
            turn = by_prompt.get(record.prompt_id) if record is not None else None
            if turn is None:
                turn = {**blank, 'legacy': record is None}
                result.append(turn)
            turn['assistant'] = message
            turn['answer'] = answer(message, record, agent=turn['run'] is not None)
        else:
            result.append({**blank, 'notice': {'kind': 'system', 'title': 'Aviso del sistema', 'text': message.content}})
    return result

"""Read-only projection of a conversation for the chat page (front/chat_page.py)."""
from datetime import timedelta
import json
import re
import uuid
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone

from front import chat_page
from front.models import AgentExecution, AgentModelProfile, Conversation, Message, Prompt, Response
from front.test_chat_flow import ChatFixture


class ChatPageProjectionTests(ChatFixture):
    def conversation(self, first='Hola', title=None, **extra):
        conversation = Conversation.objects.create(user=self.user, title=first[:50] if title is None else title, **extra)
        if first:
            Message.objects.create(conversation=conversation, role='user', content=first)
        return conversation

    def prompt(self, conversation, text, status, **decision):
        message = Message.objects.create(conversation=conversation, role='user', content=text)
        return Prompt.objects.create(user=self.user, company=self.company, conversation=conversation, user_message=message,
                                     content=text, request_id=uuid.uuid4(), status=status,
                                     decision={'schema_version': 1, 'calls': [], **decision})

    def test_titles_mask_the_whole_first_message_before_shortening_it(self):
        cases = {
            'Mi api_key = sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234 no funciona, ¿qué hago?': 'Mi api_key = [secreto protegido] no funciona, ¿qué hago?',
            # The stored title cuts these values at 50 characters; only the whole message masks them.
            'Por favor revisa este token urgente: sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234': 'Por favor revisa este token urgente: [secreto protegido]',
            'Mi DNI es 12345678Z y mi tarjeta 4111 1111 1111 1111, ¿es seguro?': 'Mi DNI es [documento protegido] y mi tarjeta…',
            'Escríbeme a juan.perez@empresa-lab.com o llama al 612 345 678 hoy': 'Escríbeme a [correo protegido] o llama al…',
            '-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ': '[secreto protegido]',
        }
        conversations = [self.conversation(text) for text in cases]
        titles = chat_page.display_titles(conversations)
        self.assertEqual(titles, list(cases.values()))
        for title, text in zip(titles, cases):
            self.assertLessEqual(len(title), chat_page.TITLE_CHARS + 1)
            for fragment in ('sk-proj', '4111', '12345678Z', 'juan.perez', '612 345', 'MIIEvQ'):
                self.assertNotIn(fragment, title)
        self.assertEqual(chat_page.display_title(conversations[0]), titles[0])

    def test_titles_without_messages_masking_failures_and_long_text(self):
        empty = self.conversation('', title='')
        legacy = self.conversation('', title='Documento')
        long = self.conversation('Prepara un informe largo de seguimiento por secciones con todos los detalles del proyecto')
        named = self.conversation('Mensaje anterior a los registros de decisión.', title='Conversación antigua (sin registro)')
        secret = self.conversation('Hola', title='Clave sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234')
        self.assertEqual(chat_page.display_titles([empty, legacy, long, named, secret]),
                         ['Nueva conversación', 'Documento', 'Prepara un informe largo de seguimiento por secciones con…',
                          'Conversación antigua (sin registro)', 'Clave [secreto protegido]'])
        with patch('front.local_masking.mask_local_texts', side_effect=TimeoutError('busy')):
            self.assertEqual(chat_page.display_titles([long]), ['Conversación'])

    def test_island_bootstrap_titles_never_carry_the_raw_first_message(self):
        conversation = self.conversation('Por favor revisa este token urgente: sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234')
        page = self.client.get(f'/chat/{conversation.pk}/')
        self.assertTemplateUsed(page, 'chat/app.html')
        self.assertContains(page, '<title>Por favor revisa este token urgente: [secreto protegido]', html=False)
        boot = json.loads(re.search(r'<script id="regulai-chat-bootstrap" type="application/json">(.*?)</script>',
                                    page.content.decode(), re.S)[1])
        masked = 'Por favor revisa este token urgente: [secreto protegido]'
        self.assertEqual(boot['conversation']['title'], masked)
        self.assertEqual([item['title'] for group in boot['threads'] for item in group['items']], [masked])
        # Only the person's own message carries what they typed; titles never do.
        for turn in boot['turns']:
            turn.pop('user')
        boot['conversation'].pop('title')
        self.assertNotIn('sk-proj-ABCDE', json.dumps(boot))

    @override_settings(REGULAI_CHAT_FRONTEND='legacy')
    def test_sidebar_header_and_delete_page_never_show_the_raw_first_message(self):
        conversation = self.conversation('Por favor revisa este token urgente: sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234')
        page = self.client.get(f'/chat/{conversation.pk}/')
        self.assertContains(page, '<title>Por favor revisa este token urgente: [secreto protegido]', html=False)
        self.assertContains(page, '<h1 id="chatTitle">Por favor revisa este token urgente: [secreto protegido]</h1>', html=True)
        self.assertContains(page, '<span>Por favor revisa este token urgente: [secreto protegido]</span>', html=True)
        # Only the person's own message bubble shows what they typed; titles never do.
        outside = re.sub(r'<div class="rg-bubble">.*?</div>', '', page.content.decode(), flags=re.S)
        self.assertNotIn('sk-proj-ABCDE', outside)
        delete = self.client.get(f'/chat/{conversation.pk}/delete/')
        self.assertContains(delete, '«Por favor revisa este token urgente: [secreto protegido]»')
        self.assertNotContains(delete, 'sk-proj-ABCDE')

    def test_conversations_are_grouped_by_age_in_order(self):
        now = timezone.now()
        ages = [0, 1, 3, 20, 90]
        conversations = []
        for age in ages:
            conversation = self.conversation(f'Hace {age} días')
            Conversation.objects.filter(pk=conversation.pk).update(updated_at=now - timedelta(days=age))
            conversations.append(Conversation.objects.get(pk=conversation.pk))
        groups = chat_page.conversation_groups(conversations, now=now)
        self.assertEqual([label for label, _ in groups], ['Hoy', 'Ayer', 'Últimos 7 días', 'Últimos 30 días', 'Anteriores'])
        self.assertEqual([items[0]['title'] for _, items in groups], [f'Hace {age} días' for age in ages])

    def test_notices_reuse_the_pipeline_outcome_and_never_grant_actions(self):
        conversation = self.conversation('')
        self.assertIsNone(chat_page.notice(None))
        self.assertIsNone(chat_page.notice(self.prompt(conversation, 'a', 'completed')))
        blocked = self.prompt(conversation, 'b', 'blocked', policy={'status': 'block', 'rules': [{'name': 'Claves'}, {'id': 3}]})
        self.assertEqual(chat_page.notice(blocked), {'kind': 'blocked', 'title': 'Bloqueado por la política', 'rules': ['Claves'],
                                                     'text': 'No se ha enviado a ningún proveedor.'})
        pending = self.prompt(conversation, 'c', 'pending_consent', consent_token='token-1', consent_reason='consent_expired',
                              requested={'engine_id': 4, 'model_id': 7}, policy={'rules': [{'name': 'Confidencial'}]})
        notice = chat_page.notice(pending)
        self.assertEqual((notice['kind'], notice['token'], notice['reason'], notice['requested'], notice['rules']),
                         ('consent', 'token-1', 'consent_expired', {'engine_id': 4, 'model_id': 7}, ['Confidencial']))
        legacy_pending = self.prompt(conversation, 'd', 'pending_consent', consent_token='token-2', requested='invalid')
        self.assertIsNone(chat_page.notice(legacy_pending)['requested'])
        live = self.prompt(conversation, 'e', 'processing')
        self.assertEqual(chat_page.notice(live), {'kind': 'live', 'stale': False})
        Prompt.objects.filter(pk=live.pk).update(updated_at=timezone.now() - timedelta(seconds=300))
        self.assertEqual(chat_page.notice(Prompt.objects.get(pk=live.pk)), {'kind': 'live', 'stale': True})
        stopped = self.prompt(conversation, 'f', 'cancelled', error_type='cancelled_by_user')
        self.assertEqual(chat_page.notice(stopped)['title'], 'Respuesta detenida')
        self.assertEqual(chat_page.notice(self.prompt(conversation, 'g', 'cancelled'))['title'], 'Petición cancelada')
        failed = chat_page.notice(self.prompt(conversation, 'h', 'failed', error_type='provider_failed'))
        self.assertEqual((failed['kind'], failed['title'], failed['code'], failed['retry']), ('error', 'Error del proveedor', 'provider_failed', True))
        setup = chat_page.notice(self.prompt(conversation, 'i', 'validation_error', error_type='no_api_key'))
        self.assertEqual((setup['title'], setup['retry']), ('Configuración incompleta', False))
        unknown = self.prompt(conversation, 'j', 'outcome_unknown', error_type='outcome_unknown')
        Prompt.objects.filter(pk=unknown.pk).update(file_name='acta.pdf')
        unknown = chat_page.notice(Prompt.objects.get(pk=unknown.pk))
        self.assertEqual((unknown['title'], unknown['code'], unknown['retry']), ('Resultado desconocido', 'outcome_unknown', False))

    def test_answers_label_unverified_text_and_keep_evidence_only_when_verified(self):
        conversation = self.conversation('')
        prompt = self.prompt(conversation, 'Pregunta', 'completed', verification={'status': 'failed'})
        message = Message.objects.create(conversation=conversation, role='assistant', content='No verificado\n\nRespuesta')
        record = Response.objects.create(prompt=prompt, assistant_message=message, content=message.content,
            evidence={'items': [{'claim_index': 1, 'locator': 'line:1', 'excerpt': 'x'}]})
        self.assertEqual(chat_page.answer(message, record, agent=False),
                         {'text': 'Respuesta', 'unverified': True, 'evidence': [], 'recorded': True})
        prompt.decision['verification'] = {'status': 'passed'}
        record.evidence = {'items': [{'claim_index': 1, 'locator': 'line:1', 'excerpt': 'x'}, {'claim_index': 2}, 'invalid']}
        self.assertEqual(chat_page.answer(message, record, agent=False)['evidence'], [{'claim_index': 1, 'locator': 'line:1', 'excerpt': 'x'}])
        self.assertEqual(chat_page.answer(message, record, agent=True),
                         {'text': 'No verificado\n\nRespuesta', 'unverified': False, 'evidence': [], 'recorded': True})
        self.assertEqual(chat_page.answer(message, None, agent=False)['recorded'], False)

    def test_turns_pair_requests_with_answers_runs_and_legacy_messages(self):
        conversation = self.conversation('', mode='agent')
        Message.objects.create(conversation=conversation, role='user', content='Mensaje sin registro')
        Message.objects.create(conversation=conversation, role='assistant', content='Respuesta sin registro')
        answered = self.prompt(conversation, 'Pregunta', 'completed', verification={'status': 'passed'})
        reply = Message.objects.create(conversation=conversation, role='assistant', content='Respuesta')
        Response.objects.create(prompt=answered, assistant_message=reply, content=reply.content, evidence={})
        Message.objects.create(conversation=conversation, role='system', content='Aviso sintético')
        running = self.prompt(conversation, 'Crea un informe', 'processing')
        profile = AgentModelProfile.objects.create(company=self.company, name='Documentos', enabled=True,
            connection=self.credential, model=self.model, tools=['build_document'])
        run = AgentExecution.objects.create(prompt=running, profile=profile, token_digest=uuid.uuid4().hex * 2,
            authorization_digest='0' * 64, expires_at=timezone.now() + timedelta(hours=1), conversation=conversation,
            status='active', job={'kind': 'create'})
        turns = chat_page.turns(conversation, {running.pk: {'id': str(run.pk)}})
        self.assertEqual(len(turns), 5)
        legacy_user, legacy_answer, recorded, system, agent = turns
        self.assertEqual((legacy_user['legacy'], legacy_user['prompt'], legacy_user['assistant']), (True, None, None))
        self.assertTrue(legacy_answer['legacy'])
        self.assertEqual(legacy_answer['assistant'].content, 'Respuesta sin registro')
        self.assertEqual((recorded['prompt'], recorded['assistant'], recorded['answer']['text'], recorded['notice']),
                         (answered, reply, 'Respuesta', None))
        self.assertEqual(system['notice'], {'kind': 'system', 'title': 'Aviso del sistema', 'text': 'Aviso sintético'})
        self.assertEqual((agent['run'], agent['notice'], agent['assistant']), ({'id': str(run.pk)}, None, None))

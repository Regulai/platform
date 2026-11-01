import uuid
from tempfile import TemporaryDirectory

from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.test import TestCase, override_settings
from django.urls import reverse

from front.models import Company, Conversation, Message, Profile, Prompt, Response
from front.test_chat_island import bootstrap as island_bootstrap


class ChatUITests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user('receipt-owner')
        self.company = Company.objects.create(name='Receipt company')
        Profile.objects.create(user=self.owner, company=self.company)
        self.other = User.objects.create_user('receipt-other')
        Profile.objects.create(user=self.other, company=Company.objects.create(name='Other company'))
        self.teammate = User.objects.create_user('receipt-teammate')
        Profile.objects.create(user=self.teammate, company=self.company)
        conversation = Conversation.objects.create(user=self.owner, title='Synthetic')
        message = Message.objects.create(conversation=conversation, role='user', content='<script>private input</script>')
        self.prompt = Prompt.objects.create(user=self.owner, company=self.company,
            conversation=conversation, user_message=message, content=message.content,
            request_id=uuid.uuid4(), status='completed', decision={
                'schema_version': 1, 'consent_token': 'private-token', 'input_digest': 'private-hash',
                'policy': {'status': 'allow', 'reason_codes': ['authorized'], 'private_text': 'private-policy'},
                'calls': [{'purpose': 'generation', 'status': 'completed', 'api_key': 'private-key', 'cost': None}],
                'coverage': {'status': 'complete', 'text': 'private document', 'digest': 'document-hash'},
                'limits': {'history_max_bytes': 32768, 'history_max_turns': 20},
                'verification': {'status': 'passed'},
            })
        assistant = Message.objects.create(conversation=conversation, role='assistant', content='<img src=x onerror=alert(1)>')
        self.response = Response.objects.create(prompt=self.prompt, assistant_message=assistant,
            content=assistant.content, evidence={'schema_version': 1, 'items': [
                {'claim_index': 0, 'id': 'fragment-1', 'locator': 'page:1', 'excerpt': '<script>evidence</script>'},
            ]})
        self.receipt_url = reverse('front:chat_request_receipt', args=[self.prompt.request_id])
        self.evidence_url = reverse('front:chat_request_evidence', args=[self.prompt.request_id])

    def test_receipt_export_filters_private_fields_and_requires_owner_company(self):
        self.assertEqual(self.client.get(self.receipt_url).status_code, 302)
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(self.receipt_url).status_code, 404)
        self.client.force_login(self.teammate)
        self.assertEqual(self.client.get(self.receipt_url).status_code, 404)
        self.client.force_login(self.owner)
        exported = self.client.get(self.receipt_url)
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.json()['receipt']['policy']['status'], 'allow')
        self.assertEqual(exported.json()['receipt'].get('limits'), {'history_max_bytes': 32768, 'history_max_turns': 20})
        self.assertNotIn('private', exported.content.decode())
        self.assertIn('attachment;', exported['Content-Disposition'])
        Profile.objects.filter(user=self.owner).update(company=self.other.profile.company)
        self.assertEqual(self.client.get(self.receipt_url).status_code, 404)

    def test_evidence_is_only_accessible_to_request_owner(self):
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(self.evidence_url).status_code, 404)
        self.client.force_login(self.owner)
        result = self.client.get(self.evidence_url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['evidence']['items'][0]['excerpt'], '<script>evidence</script>')
        self.assertEqual(result['X-Content-Type-Options'], 'nosniff')
        Profile.objects.filter(user=self.owner).update(company=self.other.profile.company)
        self.assertEqual(self.client.get(self.evidence_url).status_code, 404)

    def test_chat_renders_escaped_messages_receipt_evidence_and_download_links(self):
        assistant = self.response.assistant_message
        assistant.file_name = 'generated.py'
        assistant.response_file = 'generated/synthetic.py'
        assistant.file_size = 3
        assistant.save()
        Message.objects.create(conversation=self.prompt.conversation, role='user', content='Legacy message')
        self.client.force_login(self.owner)
        url = reverse('front:chat_conversation', args=[self.prompt.conversation_id])
        # Island: text travels as JSON (json_script escapes <, > and &) and React renders it as text.
        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        for raw in ('<script>private input', '<img src=x', '<script>evidence', 'private-token', 'private-hash',
                    'private-policy', 'private-key', 'private document', 'document-hash'):
            self.assertNotContains(page, raw)
        turns = island_bootstrap(page)['turns']
        recorded = next(turn for turn in turns if turn['request_id'] == str(self.prompt.request_id))
        self.assertEqual((recorded['user']['content'], recorded['answer']['text'], recorded['answer']['unverified']),
                         ('<script>private input</script>', '<img src=x onerror=alert(1)>', False))
        self.assertEqual((recorded['receipt_url'], recorded['evidence_url']), (self.receipt_url, self.evidence_url))
        self.assertEqual(recorded['answer']['evidence'][0]['excerpt'], '<script>evidence</script>')
        self.assertEqual(recorded['assistant_file']['url'], reverse('front:chat_download_file', args=[assistant.pk]))
        self.assertTrue(next(turn for turn in turns if (turn['user'] or {}).get('content') == 'Legacy message')['legacy'])
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, '&lt;script&gt;private input&lt;/script&gt;')
        self.assertContains(page, '&lt;img src=x onerror=alert(1)&gt;')
        self.assertContains(page, self.receipt_url)
        restored = self.client.get(self.receipt_url).json()['receipt']
        self.assertEqual(restored.get('limits'), {'history_max_bytes': 32768, 'history_max_turns': 20})
        self.assertContains(page, self.evidence_url)
        self.assertContains(page, '&lt;script&gt;evidence&lt;/script&gt;')
        self.assertContains(page, reverse('front:chat_download_file', args=[assistant.pk]))
        self.assertContains(page, 'Excluido del contexto')
        self.assertNotContains(page, 'No verificado')

    def test_unverified_answer_is_labelled_and_shows_no_document_evidence(self):
        self.prompt.decision['verification'] = {'status': 'failed'}
        self.prompt.save(update_fields=['decision'])
        self.client.force_login(self.owner)
        url = reverse('front:chat_conversation', args=[self.prompt.conversation_id])
        recorded = island_bootstrap(self.client.get(url))['turns'][0]
        self.assertEqual((recorded['answer']['unverified'], recorded['answer']['evidence'], recorded['evidence_url'], recorded['receipt_url']),
                         (True, [], None, self.receipt_url))
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            page = self.client.get(url)
        self.assertContains(page, 'No verificado', count=1)
        self.assertNotContains(page, self.evidence_url)
        self.assertNotContains(page, 'evidence&lt;/script&gt;')
        self.assertNotContains(page, 'Citas del documento')
        self.assertContains(page, self.receipt_url)

    def test_generated_code_download_stays_owner_scoped(self):
        with TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            assistant = self.response.assistant_message
            assistant.file_name = 'example.py'
            assistant.response_file.save('example.py', ContentFile(b'print("synthetic")\n'), save=True)
            url = reverse('front:chat_download_file', args=[assistant.pk])
            self.client.force_login(self.other)
            self.assertEqual(self.client.get(url).status_code, 404)
            self.client.force_login(self.owner)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(b''.join(response.streaming_content), b'print("synthetic")\n')
            response.close()

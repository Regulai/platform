"""Review hypotheses reproduced at HTTP, provider and public extraction seams.

Expected failures assert the intended behavior; all external responses are synthetic.
"""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zipfile

from django.core.files.uploadedfile import SimpleUploadedFile
from docx import Document as WordDocument

from front.connectors import ChatResponse
from front.documents import extract_document
from front.models import Alert, Company, ObfuscationConfig, Rule, RulesGroup
from front.test_chat_flow import ChatFixture
from front import offline_browser, test_pipeline


class ReviewRegressionTests(ChatFixture):
    # Reuse configuration only, without inheriting the existing pipeline tests.
    configure = test_pipeline.PipelineTests.configure

    def enable_mask(self, replacements):
        mask = self.required_mask
        if f'obfuscation:{mask.pk}' not in self.company.ai_config['destinations']['internal']:
            self.company.ai_config['destinations']['internal'].append(f'obfuscation:{mask.pk}')
        self.company.save()
        evaluator = self.http.side_effect or test_pipeline.jev_http()

        def transport(url, **kwargs):
            if url == 'https://mask.invalid/api/mask':
                text = kwargs['json']['text']
                for original, masked in replacements.items():
                    text = text.replace(original, masked)
                return SimpleNamespace(raise_for_status=lambda: None,
                                       json=lambda: {'masked': text})
            return evaluator(url, **kwargs)

        self.http.side_effect = transport

    def document_answer(self, *, fenced=False, claim_text='The approved period is seventeen days.'):
        def answer(messages, **kwargs):
            sources = json.loads(messages[-1].content.split('Sources:\n', 1)[1])
            content = json.dumps({'claims': [{'text': claim_text,
                'citations': [{'id': sources[0]['id'], 'quote': sources[0]['text'].splitlines()[0]}]}]})
            if fenced:
                content = '```json\n' + content + '\n```'
            return ChatResponse(content, 30, 'synthetic-v1', 'stop', 20, 10)
        self.provider.side_effect = answer

    def classification_response(self, probabilities, confidence, *, credentials=0.0):
        transport = test_pipeline.jev_http()

        def post(url, *, data=None, **kwargs):
            response = transport(url, data=data, **kwargs)
            if data is None:
                return response
            payload = json.loads(b''.join(response.iter_content()))
            if 'category' in payload['answers']:
                payload['answers']['category'].update(probabilities=probabilities,
                    confidence=confidence, choice='internal')
                payload['answers']['credentials']['noul'] = credentials
            raw = json.dumps(payload).encode()
            response.iter_content = lambda **kwargs: iter([raw])
            return response
        self.http.side_effect = post

    def test_b01_every_turn_and_jev_receive_masked_content(self):
        self.configure(limits={'budget': None})
        self.enable_mask({'12345678Z': '<DNI_1>'})
        first = self.send('/chat/send/', 'Mi DNI es 12345678Z').json()
        self.assertEqual(first['status'], 'completed', first)
        self.assertNotIn('12345678Z', str(self.provider.call_args))
        second = self.send('/api/chat/send/', 'Remember my identifier',
                           conversation_id=first['conversation_id']).json()
        self.assertEqual(second['status'], 'completed', second)
        generator_text = '\n'.join(message.content for message in self.provider.call_args.args[0])
        jev_text = '\n'.join(call.kwargs['data'].decode() for call in self.http.call_args_list
                             if 'data' in call.kwargs)
        self.assertNotIn('12345678Z', generator_text,
                         'The second generation sends the original first turn in history.')
        self.assertNotIn('12345678Z', jev_text, 'Classification and judging must use masked text.')

    def test_b02_alert_notifications_are_isolated_by_company(self):
        other = Company.objects.create(name='Other tenant')
        group = RulesGroup.objects.create(name='Other rules', company=other)
        rule = Rule.objects.create(name='OTHER_TENANT_PRIVATE_RULE', rules_group=group,
                                  yara_rule='rule Other { condition: true }')
        Alert.objects.create(company=other, rule=rule, description='OTHER_TENANT_PRIVATE_ALERT')
        response = self.client.get('/chat/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['unresolved_alerts_count'], 0,
                         'Tenant A has no alerts; the count must exclude tenant B.')
        self.assertNotContains(response, 'OTHER_TENANT_PRIVATE_RULE')
        self.assertNotContains(response, 'OTHER_TENANT_PRIVATE_ALERT')

    def test_b03_missing_mask_cost_bound_is_rejected_before_any_external_call(self):
        self.configure()
        self.enable_mask({'12345678Z': '<DNI_1>'})
        self.company.ai_config['masking'] = {}
        self.company.save()
        result = self.send('/api/chat/send/', 'Mi DNI es 12345678Z').json()
        self.assertEqual((result.get('error_type'), self.http.call_count, self.provider.call_count),
                         ('policy_configuration_invalid', 0, 0), result)

    def test_b04_document_citations_resolve_the_masked_source(self):
        self.configure(limits={'budget': None})
        self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'})
        self.enable_mask({'Code: 42': 'Code: <NUM_1>'})
        self.document_answer(claim_text='The code is <NUM_1>.')
        result = self.send('/api/chat/send/', 'What is the code?',
                           file=SimpleUploadedFile('code.txt', b'Code: 42')).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['evidence']['items'][0]['excerpt'], 'Code: <NUM_1>')
        self.assertEqual(result['evidence']['items'][0]['locator'], 'line:1')

    def test_b05_advisory_document_answer_is_readable_prose(self):
        self.configure(verification={'mode': 'advisory'})
        self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'},
                                       failures={'failure_omission': 1})
        self.document_answer()
        result = self.send('/api/chat/send/', 'What is the approved period?',
            file=SimpleUploadedFile('period.txt', b'The approved period is seventeen days.')).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertNotEqual(result['receipt']['verification']['status'], 'passed')
        self.assertEqual(result['evidence']['items'], [])
        self.assertFalse(result['assistant_message']['content'].lstrip().startswith('{'),
                         result['assistant_message']['content'])
        self.assertIn('The approved period is seventeen days.', result['assistant_message']['content'])

    def test_b06_oversized_judge_state_is_rejected_before_generation(self):
        self.configure(classification='local', limits={'budget': None})
        self.model.context_window = 1_000_000
        self.model.save()
        self.document_answer()
        for line_count in (1500, 2600):
            self.provider.reset_mock()
            text = ''.join(f'Evidence row {number:06d}: seventeen days.'.ljust(49) + '\n'
                           for number in range(line_count)).encode()
            self.assertEqual(len(text), line_count * 50)
            result = self.send('/api/chat/send/', 'What is the approved period?',
                               file=SimpleUploadedFile('large.txt', text)).json()
            self.assertTrue(result['status'] == 'completed' or (
                result.get('error_type') == 'evaluation_input_too_large' and self.provider.call_count == 0),
                f"bytes={len(text)} status={result['status']} code={result.get('error_type')} generations={self.provider.call_count}")

    def test_b07_word_tracked_changes_use_the_accepted_text(self):
        document = WordDocument()
        document.add_paragraph('CHANGE_PLACEHOLDER')
        buffer = io.BytesIO()
        document.save(buffer)
        changed = io.BytesIO()
        with zipfile.ZipFile(buffer) as original, zipfile.ZipFile(changed, 'w') as target:
            for entry in original.infolist():
                content = original.read(entry.filename)
                if entry.filename == 'word/document.xml':
                    content = content.replace(
                        b'<w:p><w:r><w:t>CHANGE_PLACEHOLDER</w:t></w:r></w:p>',
                        b'<w:p><w:del w:id="1"><w:r><w:delText>30</w:delText></w:r></w:del>'
                        b'<w:ins w:id="2"><w:r><w:t>17</w:t></w:r></w:ins>'
                        b'<w:r><w:t xml:space="preserve"> days</w:t></w:r>'
                        b'<w:r><w:instrText> MERGEFIELD obsolete </w:instrText></w:r></w:p>')
                target.writestr(entry, content)
        result = extract_document(SimpleUploadedFile('changes.docx', changed.getvalue()))
        self.assertEqual(result.status, 'complete', result.metadata())
        self.assertEqual(result.text, '17 days')
        disclosures = result.metadata().get('disclosures', [])
        self.assertTrue('tracked_changes_present' in result.warnings or any(
            item['code'] == 'tracked_changes_present' for item in disclosures), result.metadata())

    def test_b08_one_json_code_fence_is_accepted_as_a_document_answer(self):
        self.configure()
        self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'})
        self.document_answer(fenced=True)
        result = self.send('/api/chat/send/', 'What is the approved period?',
            file=SimpleUploadedFile('period.txt', b'The approved period is seventeen days.')).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['assistant_message']['content'], 'The approved period is seventeen days. [1]')

    def test_b09_expired_consent_issues_a_fresh_usable_token(self):
        self.rule.action = 'consent'
        self.rule.save()
        request_id = str(uuid.uuid4())
        with patch('django.core.signing.time.time', return_value=1_800_000_000):
            first = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id).json()
        self.assertEqual(first['status'], 'pending_consent', first)
        with patch('django.core.signing.time.time', return_value=1_800_000_301):
            renewed = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id,
                                consent_token=first['consent_token']).json()
            self.assertEqual(renewed['status'], 'pending_consent', renewed)
            self.assertTrue(renewed.get('consent_token') != first['consent_token'],
                            'Expired consent returns the same unusable token.')
            self.assertIn(renewed.get('consent_reason', renewed.get('error_type')),
                          ('consent_expired', 'consent_context_changed'))
            completed = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id,
                                  consent_token=renewed['consent_token']).json()
        self.assertEqual(completed['status'], 'completed', completed)
        self.assertEqual(self.provider.call_count, 1)
        self.assertEqual(completed['user_message']['id'], first['user_message']['id'])

    def test_b10_chat_can_submit_without_crypto_random_uuid(self):
        # Plain-HTTP origins other than localhost are not secure contexts: no randomUUID.
        # The legacy page is the rollback path; the island covers this in lib/ids.test.ts.
        from django.test import override_settings
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            response = self.client.get('/chat/')
        self.assertEqual(response.status_code, 200)
        run = offline_browser.run(r"""
Object.defineProperty(crypto, 'randomUUID', {value: undefined, configurable: true});
net.on('POST /chat/send/', request => net.json({status: 'completed', success: true,
  request_id: request.body.get('request_id'), receipt: {verification: {status: 'passed'}, calls: []},
  assistant_message: {content: 'Enviado.'}}));
await typeInto($('#prompt'), 'Synthetic chat');
await click($('#sendButton'));
const posts = net.find('POST', '/chat/send/');
assert.equal(posts.length, 1);
assert.match(posts[0].body.get('request_id'), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
""", response.content, path='/chat/')
        self.assertEqual(run.returncode, 0, run.stderr or run.stdout)

    def test_c01_uncertain_ordinal_category_completes_as_confidential(self):
        self.configure()
        self.company.ai_config['destinations']['confidential'] = [f'engine:{self.credential.pk}', 'jev',
            f'obfuscation:{self.required_mask.pk}']
        self.company.save()
        self.classification_response({'public': .14, 'internal': .59, 'unknown': .22,
                                      'confidential': .05, 'restricted': 0.0}, .49)
        result = self.send('/api/chat/send/').json()
        self.assertEqual((result['status'], result['decision'].get('sensitivity')),
                         ('completed', 'confidential'), result)

    def test_c02_credentials_signal_below_point_eight_still_blocks_generation(self):
        self.configure()
        self.classification_response({'public': .1, 'internal': .9, 'unknown': 0.0,
                                      'confidential': 0.0, 'restricted': 0.0}, .9, credentials=.75)
        result = self.send('/api/chat/send/').json()
        self.assertEqual(self.provider.call_count, 0, result)
        self.assertEqual(result['status'], 'blocked', result)
        self.assertEqual(result.get('error_type'), 'restricted_content', result)

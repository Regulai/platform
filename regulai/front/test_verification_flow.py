"""Document verification regressions through all three HTTP send entries."""
import json

from django.core.files.uploadedfile import SimpleUploadedFile

from front.connectors import ChatResponse
from front.test_chat_flow import ChatFixture
from front import test_pipeline


class VerificationFlowTests(ChatFixture):
    configure = test_pipeline.PipelineTests.configure

    def answer(self, transform=lambda value: value):
        def response(messages, **kwargs):
            source = json.loads(messages[-1].content.split('Sources:\n', 1)[1])[0]
            content = json.dumps({'claims': [{'text': 'The approved period is seventeen days.',
                'citations': [{'id': source['id'], 'quote': source['text']}]}]})
            return ChatResponse(transform(content), 30, 'synthetic-v1', 'stop', 20, 10)
        self.provider.side_effect = response

    def test_one_outer_json_fence_completes_on_all_three_entries_without_retry(self):
        self.configure()
        self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'})
        self.answer(lambda raw: '```json\n' + raw + '\n```')
        for path in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(path=path):
                self.provider.reset_mock()
                result = self.send(path, 'What is the approved period?',
                    file=SimpleUploadedFile('period.txt', b'The approved period is seventeen days.'))
                if path == '/chat/':
                    self.assertEqual(result.status_code, 302)
                    self.assertContains(self.client.get(result.url), 'The approved period is seventeen days. [1]')
                else:
                    self.assertEqual(result.json()['status'], 'completed', result.json())
                    self.assertEqual(result.json()['evidence']['items'][0]['claim_index'], 1)
                self.assertEqual(self.provider.call_count, 1)

    def test_short_quotes_and_fence_prose_never_reach_the_judge(self):
        self.configure()
        self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'})
        for path in ('/chat/', '/chat/send/', '/api/chat/send/'):
            for transform in (lambda raw: raw.replace('The approved period is seventeen days.', 'e'),
                              lambda raw: 'Prefix\n```json\n' + raw + '\n```'):
                with self.subTest(path=path, transform=transform):
                    self.http.reset_mock()
                    self.answer(transform)
                    response = self.send(path, 'What is the approved period?',
                        file=SimpleUploadedFile('period.txt', b'The approved period is seventeen days.'))
                    self.assertEqual(response.status_code, 502)
                    result = response.json()
                    self.assertEqual((result['status'], result['error_type']), ('failed', 'verification_failed'))
                    self.assertEqual(self.http.call_count, 3)
                    self.assertEqual([call['purpose'] for call in result['receipt']['calls']],
                        ['obfuscation', 'classification', 'generation', 'obfuscation'])
                    self.assertNotIn('assistant_message', result)

    def test_missing_provider_completion_is_failed_on_all_three_entries(self):
        self.configure()
        self.provider.return_value = ChatResponse('Plausible but completion is unknown.', 30,
                                                  'synthetic-v1', None, 20, 10)
        for path in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(path=path):
                self.http.reset_mock()
                result = self.send(path).json()
                verification = result['receipt']['verification']
                self.assertEqual((verification['local_status'], verification['finish_reason']), ('failed', 'unknown'))
                self.assertNotIn('assistant_message', result)
                self.assertEqual(self.http.call_count, 3)
                self.assertEqual([call['purpose'] for call in result['receipt']['calls']],
                    ['obfuscation', 'classification', 'generation', 'obfuscation'])

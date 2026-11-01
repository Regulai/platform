from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from regulai.ui_lab_guard import RejectLabGeneration


class LabGenerationGuardTests(SimpleTestCase):
    def test_all_send_entries_refuse_generation_without_calling_provider(self):
        def unexpected(request):
            self.fail('A laboratory request reached the generation pipeline')
        guard = RejectLabGeneration(unexpected)
        for path in ('/chat/', '/chat/27/', '/chat/send/', '/chat/27/send/', '/api/chat/send/'):
            with self.subTest(path=path):
                response = guard(RequestFactory().post(path, {'prompt': 'Mendizábal, 3 páginas'}))
                self.assertEqual(response.status_code, 503)
                self.assertIn(b'real_generation_not_configured', response.content)

    def test_reading_existing_conversations_still_works(self):
        response = HttpResponse('history')
        guard = RejectLabGeneration(lambda request: response)
        self.assertIs(guard(RequestFactory().get('/chat/27/')), response)

    def test_other_actions_are_not_intercepted(self):
        response = HttpResponse('ok')
        guard = RejectLabGeneration(lambda request: response)
        self.assertIs(guard(RequestFactory().post('/chat/agent/artifacts/abc/review/')), response)

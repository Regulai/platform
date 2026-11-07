"""Runtime checks for the framework upgrade, without provider traffic."""
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import Client, TestCase, override_settings

from front.models import Company, CompanyEngine, Engine, Profile
from front.file_security import validate_uploaded_file
from front.test_chat_island import bootstrap as island_bootstrap


class RuntimeTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('runtime', password='synthetic-password')
        self.company = Company.objects.create(name='Runtime synthetic')
        Profile.objects.create(user=self.user, company=self.company)

    def test_login_chat_csrf_and_rest_token(self):
        protected = Client(enforce_csrf_checks=True)
        self.assertEqual(protected.post('/login/', {'username': 'runtime'}).status_code, 403)
        self.assertEqual(self.client.get('/chat/').status_code, 302)
        self.assertTrue(self.client.login(username='runtime', password='synthetic-password'))
        # The island sends its token from the bootstrap; the legacy page (rollback) from its form.
        page = self.client.get('/chat/')
        self.assertTrue(island_bootstrap(page)['csrf_token'])
        self.assertIn(settings.CSRF_COOKIE_NAME, page.cookies)
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            self.assertContains(self.client.get('/chat/'), 'csrfmiddlewaretoken')
        response = self.client.post('/api/auth/login/', {
            'username': 'runtime', 'password': 'synthetic-password',
        })
        self.assertEqual(response.status_code, 200)
        token = response.json()['token']
        self.client.logout()
        response = self.client.get('/api/auth/me/', HTTP_AUTHORIZATION=f'Token {token}')
        self.assertEqual(response.json()['user']['username'], 'runtime')

    def test_encrypted_credential_roundtrip_and_upload(self):
        engine = Engine.objects.create(name='Synthetic runtime engine')
        credential = CompanyEngine.objects.create(
            company=self.company, engine=engine, api_key='synthetic-key',
        )
        credential.refresh_from_db()
        self.assertEqual(credential.api_key, 'synthetic-key')
        with connection.cursor() as cursor:
            cursor.execute('SELECT api_key FROM front_companyengine WHERE id = %s', [credential.pk])
            stored = cursor.fetchone()[0]
        self.assertNotIn('synthetic-key', stored)
        content, metadata = validate_uploaded_file(SimpleUploadedFile('sample.txt', b'Hello'))
        self.assertEqual(content, b'Hello')

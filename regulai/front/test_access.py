"""Private history and downloads stay with their captured tenant."""
from tempfile import TemporaryDirectory

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import AuditLog, Company, Conversation, Engine, EngineModel, Message, Profile, Prompt


class PrivateHistoryTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('transferred', is_staff=True)
        self.first = Company.objects.create(name='First')
        self.second = Company.objects.create(name='Second')
        self.profile = Profile.objects.create(user=self.user, company=self.first)
        self.conversation = Conversation.objects.create(user=self.user)
        self.prompt = Prompt.objects.create(user=self.user, company=self.first,
            conversation=self.conversation, content='First tenant only')
        self.message = Message.objects.create(conversation=self.conversation, role='assistant', content='File')
        self.client.force_login(self.user)

    def test_transfer_denies_web_history_delete_prompt_and_download(self):
        self.profile.company = self.second
        self.profile.save()
        for url in (f'/chat/{self.conversation.pk}/', f'/chat/{self.conversation.pk}/delete/',
                    f'/chat/download/{self.message.pk}/', f'/prompts/{self.prompt.pk}/'):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 404)
        self.assertNotContains(self.client.get('/prompts/'), 'First tenant only')
        self.assertTrue(Conversation.objects.filter(pk=self.conversation.pk).exists())

    def test_no_profile_never_assigns_a_default_tenant(self):
        self.profile.delete()
        count = Company.objects.count()
        self.assertEqual(self.client.get('/chat/').status_code, 403)
        self.assertEqual(Company.objects.count(), count)
        self.assertFalse(Profile.objects.filter(user=self.user).exists())

    def test_audit_keeps_original_tenant_and_global_admin_requires_operator(self):
        from .views import log_action
        self.user.is_superuser = True
        self.user.save()
        log_action(self.user, 'synthetic', {'reason': 'Original tenant only'})
        audit = AuditLog.objects.get(action='synthetic')
        self.assertEqual(audit.company, self.first)
        self.profile.company = self.second
        self.profile.save()
        self.assertEqual(self.client.get(reverse('front:auditlog_detail', args=[audit.pk])).status_code, 404)
        self.assertEqual(self.client.get('/admin/').status_code, 302)
        model = EngineModel.objects.create(engine=Engine.objects.create(name='Shared'), name='Shared model', model_id='shared')
        self.assertEqual(self.client.post(reverse('front:model_edit', args=[model.pk]), {'name': 'Changed'}).status_code, 403)
        model.refresh_from_db()
        self.assertEqual(model.name, 'Shared model')
        with override_settings(PLATFORM_ADMIN_USER_IDS=[self.user.pk]):
            self.assertEqual(self.client.get('/admin/').status_code, 200)

    def test_generated_files_have_only_authorized_download_url(self):
        with TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media, DEBUG=True):
            self.message.response_file.save('sample.html', ContentFile(b'<script>bad()</script>'))
            self.assertEqual(self.client.get(self.message.response_file.url).status_code, 404)
            response = self.client.get(f'/chat/download/{self.message.pk}/')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response['Content-Type'], 'application/octet-stream')
            self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
            response.close()
            self.client.logout()
            self.assertEqual(self.client.get(f'/chat/download/{self.message.pk}/').status_code, 302)

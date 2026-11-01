"""Regressions for captured tenant provenance and protected platform operators."""
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from tempfile import TemporaryDirectory

from .models import AuditLog, Company, Profile


class FinalPermissionReviewTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Tenant A')
        self.admin = User.objects.create_user('tenant-admin', is_staff=True, is_superuser=True)
        Profile.objects.create(user=self.admin, company=self.company)
        self.operator = User.objects.create_user('platform-operator', password='original',
            email='operator@example.test', is_staff=True, is_superuser=True)
        self.operator_profile = Profile.objects.create(user=self.operator, company=self.company)
        self.client.force_login(self.admin)

    def test_api_audit_retains_original_tenant_after_user_transfer(self):
        old = AuditLog.objects.create(company=self.company, user=self.operator,
            action='original-tenant', details='Private tenant A audit details')
        other = Company.objects.create(name='Tenant B')
        Profile.objects.filter(user__in=[self.admin, self.operator]).update(company=other)
        response = self.client.get(reverse('api:audit-log-detail', args=[old.pk]))
        self.assertEqual(response.status_code, 404)

    def test_tenant_admin_cannot_reset_platform_operator_password(self):
        with override_settings(PLATFORM_ADMIN_USER_IDS=[self.operator.pk]):
            response = self.client.post(reverse('front:user_edit', args=[self.operator_profile.pk]), {
                'email': self.operator.email, 'is_staff': 'on',
                'password': 'attacker-chosen', 'confirm_password': 'attacker-chosen'})
            self.assertIn(response.status_code, (403, 404))
            self.operator.refresh_from_db()
            self.assertTrue(self.operator.check_password('original'))

    def test_tenant_admin_cannot_delete_platform_operator_profile(self):
        with override_settings(PLATFORM_ADMIN_USER_IDS=[self.operator.pk]):
            response = self.client.delete(reverse('api:profile-detail', args=[self.operator_profile.pk]))
            self.assertIn(response.status_code, (403, 404))
            self.assertTrue(Profile.objects.filter(pk=self.operator_profile.pk).exists())

    def test_spoofed_avatar_never_becomes_same_origin_html(self):
        with TemporaryDirectory() as media, override_settings(MEDIA_ROOT=media):
            response = self.client.post(reverse('front:profile'), {
                'avatar': SimpleUploadedFile('avatar.html', b'<html><script>alert(1)</script></html>',
                    content_type='image/png')})
            self.assertEqual(response.status_code, 302)
            profile = Profile.objects.get(user=self.admin)
            if profile.avatar:
                served = self.client.get(profile.avatar.url)
                try:
                    self.assertNotEqual(served.get('Content-Type', '').split(';')[0], 'text/html')
                finally:
                    served.close()

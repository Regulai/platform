from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .models import Alert, Company, Department, Profile, Prompt


class HistoricalDepartmentListsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Historical tenant A')
        self.foreign_company = Company.objects.create(name='Current tenant B')
        admin = User.objects.create_user('historical-list-admin', is_staff=True)
        Profile.objects.create(user=admin, company=self.company)
        self.owner = User.objects.create_user('transferred-historical-owner')
        self.profile = Profile.objects.create(user=self.owner, company=self.company)
        self.prompt = Prompt.objects.create(user=self.owner, company=self.company,
            historical_company_id=self.company.pk, content='Retained historical prompt A')
        self.alert = Alert.objects.create(user=self.owner, company=self.company,
            prompt=self.prompt, source='obfuscation', resolved=True,
            description='Retained historical alert A')
        self.foreign_department = Department.objects.create(company=self.foreign_company,
            name='PRIVATE_B_DEPARTMENT')
        self.other_foreign_department = Department.objects.create(company=self.foreign_company,
            name='OTHER_PRIVATE_B_DEPARTMENT')
        self.profile.company = self.foreign_company
        self.profile.department = self.foreign_department
        self.profile.save(update_fields=['company', 'department'])
        self.client.force_login(admin)

    def test_prompt_list_retains_history_without_foreign_department_or_membership_filter(self):
        path = reverse('front:prompts_list')
        page = self.client.get(path)
        self.assertContains(page, 'Retained historical prompt A')
        self.assertContains(page, self.owner.username)
        self.assertNotContains(page, 'PRIVATE_B_DEPARTMENT')
        self.assertNotContains(page, f'?department={self.foreign_department.pk}')
        for department in (self.foreign_department, self.other_foreign_department):
            filtered = self.client.get(path, {'department': department.pk})
            self.assertEqual(filtered.status_code, 200)
            self.assertNotContains(filtered, 'Retained historical prompt A')

    def test_alert_list_retains_history_without_foreign_department_or_membership_filter(self):
        path = reverse('front:alerts_list')
        page = self.client.get(path)
        self.assertContains(page, 'Retained historical alert A')
        self.assertContains(page, self.owner.username)
        self.assertNotContains(page, 'PRIVATE_B_DEPARTMENT')
        self.assertNotContains(page, f'?department={self.foreign_department.pk}')
        for department in (self.foreign_department, self.other_foreign_department):
            filtered = self.client.get(path, {'department': department.pk})
            self.assertEqual(filtered.status_code, 200)
            self.assertNotContains(filtered, 'Retained historical alert A')

    def test_same_company_department_remains_visible_and_filters_both_lists(self):
        department = Department.objects.create(company=self.company, name='VALID_A_DEPARTMENT')
        other_department = Department.objects.create(company=self.company, name='OTHER_A_DEPARTMENT')
        self.profile.company = self.company
        self.profile.department = department
        self.profile.save(update_fields=['company', 'department'])
        for name, content in (('prompts_list', 'Retained historical prompt A'),
                ('alerts_list', 'Retained historical alert A')):
            with self.subTest(list=name):
                path = reverse('front:' + name)
                self.assertContains(self.client.get(path), 'VALID_A_DEPARTMENT')
                matching = self.client.get(path, {'department': department.pk})
                self.assertContains(matching, content)
                self.assertContains(matching, 'VALID_A_DEPARTMENT')
                self.assertNotContains(self.client.get(path, {'department': other_department.pk}), content)

    def test_foreign_department_on_same_company_profile_is_hidden_and_cannot_filter_history(self):
        self.profile.company = self.company
        self.profile.save(update_fields=['company'])
        for name, content in (('prompts_list', 'Retained historical prompt A'),
                ('alerts_list', 'Retained historical alert A')):
            with self.subTest(list=name):
                path = reverse('front:' + name)
                page = self.client.get(path)
                self.assertContains(page, content)
                self.assertNotContains(page, 'PRIVATE_B_DEPARTMENT')
                self.assertNotContains(page, f'?department={self.foreign_department.pk}')
                self.assertNotContains(self.client.get(path, {'department': self.foreign_department.pk}), content)

    def test_foreign_profile_with_local_department_cannot_filter_history(self):
        department = Department.objects.create(company=self.company, name='LOCAL_A_DEPARTMENT')
        self.profile.department = department
        self.profile.save(update_fields=['department'])
        for name, content in (('prompts_list', 'Retained historical prompt A'),
                ('alerts_list', 'Retained historical alert A')):
            with self.subTest(list=name):
                path = reverse('front:' + name)
                # A's filter menu may name the department, but the historical row may not.
                page = self.client.get(path)
                self.assertContains(page, content)
                self.assertContains(page, 'LOCAL_A_DEPARTMENT', count=1)
                self.assertNotContains(self.client.get(path, {'department': department.pk}), content)

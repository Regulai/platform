"""HTTP checks for tenant scoping and server-controlled security records."""
from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from front.models import (
    Alert, Company, CompanyEngine, Conversation, Department, Engine,
    EngineModel, Message, Profile, Prompt, Rule, RulesGroup,
)


class APIPermissionTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name="API tenant A")
        self.foreign_company = Company.objects.create(name="API tenant B")
        self.user = User.objects.create_user("api-user")
        self.admin = User.objects.create_user("api-admin", is_superuser=True, is_staff=True)
        self.security = User.objects.create_user("api-security", is_staff=True)
        self.foreign = User.objects.create_user("api-foreign")
        for user in (self.user, self.admin, self.security):
            Profile.objects.create(user=user, company=self.company)
        Profile.objects.create(user=self.foreign, company=self.foreign_company)
        self.department = Department.objects.create(name="Own", company=self.company)
        self.foreign_department = Department.objects.create(name="Foreign", company=self.foreign_company)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_regular_user_cannot_mutate_tenant_configuration(self):
        response = self.client.patch(f"/api/departments/{self.department.pk}/", {"name": "changed"})
        self.assertEqual(response.status_code, 403)
        self.department.refresh_from_db()
        self.assertEqual(self.department.name, "Own")

    def test_admin_company_reads_are_scoped_and_foreign_company_write_is_rejected(self):
        self.client.force_authenticate(self.admin)
        response = self.client.get('/api/companies/')
        self.assertEqual([row['id'] for row in response.json()['results']], [self.company.pk])
        self.assertEqual(self.client.patch(f'/api/companies/{self.foreign_company.pk}/',
                                          {'name': 'stolen'}).status_code, 404)
        response = self.client.patch(f'/api/departments/{self.department.pk}/',
                                     {'company': self.foreign_company.pk})
        self.assertEqual(response.status_code, 400)

    def test_admin_cannot_create_department_or_engine_in_another_company(self):
        self.client.force_authenticate(self.admin)
        engine = Engine.objects.create(name='API synthetic engine')
        for endpoint, data in [('/api/departments/', {'name': 'foreign-created',
                                                     'company': self.foreign_company.pk}),
                               ('/api/company-engines/', {'company': self.foreign_company.pk,
                                                          'engine': engine.pk, 'api_key': 'synthetic-key'})]:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.client.post(endpoint, data).status_code, 400)
        own = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        self.assertEqual(self.client.patch(f'/api/company-engines/{own.pk}/',
                                          {'company': self.foreign_company.pk}).status_code, 400)

    def test_profile_cannot_move_company_or_use_foreign_department_or_default_engine(self):
        engine = Engine.objects.create(name='API profile engine')
        other_engine = Engine.objects.create(name='API other engine')
        own = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        foreign = CompanyEngine.objects.create(company=self.foreign_company, engine=engine,
                                               api_key='synthetic-foreign-key')
        mismatched_model = EngineModel.objects.create(engine=other_engine, name='Other', model_id='other')
        self.client.force_authenticate(self.admin)
        endpoint = f'/api/profiles/{self.user.profile.pk}/'
        for data in [{'company': self.foreign_company.pk},
                     {'department': self.foreign_department.pk},
                     {'default_engine': foreign.pk},
                     {'default_engine': own.pk, 'default_model': mismatched_model.pk}]:
            with self.subTest(data=data):
                self.assertEqual(self.client.patch(endpoint, data).status_code, 400)
        self.assertEqual(self.client.patch(f'/api/profiles/{self.foreign.profile.pk}/',
                                          {'department': self.department.pk}).status_code, 404)
        self.assertEqual(self.client.patch(endpoint, {'user': self.foreign.pk}).status_code, 200)
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.user_id, self.user.pk)

    def test_conversation_user_is_server_controlled_on_create_and_update(self):
        response = self.client.post('/api/conversations/', {'title': 'Own', 'user': self.foreign.pk})
        self.assertEqual(response.status_code, 201)
        conversation = Conversation.objects.get(pk=response.json()['id'])
        self.assertEqual(conversation.user_id, self.user.pk)
        self.assertEqual(self.client.patch(f'/api/conversations/{conversation.pk}/',
                                          {'user': self.foreign.pk, 'title': 'renamed'}).status_code, 200)
        conversation.refresh_from_db()
        self.assertEqual(conversation.user_id, self.user.pk)

    def test_message_files_only_expose_protected_download_url(self):
        conversation = Conversation.objects.create(user=self.user)
        message = Message.objects.create(conversation=conversation, role='assistant', content='file',
                                         response_file='chat_responses/synthetic.txt')
        response = self.client.get(f'/api/messages/{message.pk}/')
        self.assertEqual(response.json()['response_file'], f'/chat/download/{message.pk}/')
        foreign_conversation = Conversation.objects.create(user=self.foreign)
        foreign_message = Message.objects.create(conversation=foreign_conversation, content='private')
        self.assertEqual(self.client.get(f'/api/messages/{foreign_message.pk}/').status_code, 404)

    def test_rules_are_security_staff_only_and_global_or_foreign_groups_are_read_only(self):
        group = RulesGroup.objects.create(name='Own security', company=self.company)
        global_group = RulesGroup.objects.create(name='Global template')
        foreign_group = RulesGroup.objects.create(name='Foreign security', company=self.foreign_company)
        personal_foreign = RulesGroup.objects.create(name='Foreign personal', user=self.foreign)
        personal_same_company = RulesGroup.objects.create(name='Other own-company personal', user=self.admin,
                                                          company=self.company)
        response = self.client.get('/api/rules-groups/')
        ids = {row['id'] for row in response.json()['results']}
        self.assertIn(group.pk, ids)
        self.assertIn(global_group.pk, ids)
        self.assertTrue({foreign_group.pk, personal_foreign.pk, personal_same_company.pk}.isdisjoint(ids))
        valid_yara = 'rule api_test { strings: $a = "restricted" condition: $a }'
        data = {'name': 'API policy', 'yara_rule': valid_yara, 'rules_group': group.pk}
        self.assertEqual(self.client.post('/api/rules/', data).status_code, 403)
        self.client.force_authenticate(self.security)
        created = self.client.post('/api/rules/', data)
        self.assertEqual(created.status_code, 201)
        for forbidden_group in (global_group, foreign_group, personal_same_company):
            with self.subTest(group=forbidden_group.pk):
                self.assertEqual(self.client.post('/api/rules/',
                                                  {**data, 'rules_group': forbidden_group.pk}).status_code, 400)
                self.assertEqual(self.client.patch(f'/api/rules/{created.json()["id"]}/',
                                                   {'rules_group': forbidden_group.pk}).status_code, 400)
        self.assertEqual(self.client.patch(f'/api/rules-groups/{global_group.pk}/',
                                          {'name': 'changed'}).status_code, 404)
        self.assertEqual(self.client.post('/api/rules-groups/',
                                         {'name': 'forged global'}).status_code, 400)
        self.assertEqual(self.client.post('/api/rules-groups/',
                                         {'name': 'forged owner', 'company': self.company.pk,
                                          'user': self.foreign.pk}).status_code, 400)

    def test_rule_compilation_is_validated_on_create_and_update(self):
        group = RulesGroup.objects.create(name='Compile test', company=self.company)
        self.client.force_authenticate(self.security)
        invalid = {'name': 'Broken', 'rules_group': group.pk, 'yara_rule': 'this is not YARA'}
        self.assertEqual(self.client.post('/api/rules/', invalid).status_code, 400)
        rule = Rule.objects.create(name='Valid', rules_group=group,
                                   yara_rule='rule valid { condition: true }')
        self.assertEqual(self.client.patch(f'/api/rules/{rule.pk}/',
                                          {'yara_rule': 'rule invalid {'}).status_code, 400)
        rule.refresh_from_db()
        self.assertEqual(rule.yara_rule, 'rule valid { condition: true }')

    def test_alerts_are_security_only_and_cannot_be_injected_or_reassigned(self):
        alert = Alert.objects.create(user=self.user, company=self.company, description='synthetic')
        other = Alert.objects.create(user=self.foreign, company=self.foreign_company, description='private')
        self.assertEqual(self.client.get('/api/alerts/').status_code, 403)
        self.client.force_authenticate(self.security)
        self.assertEqual(self.client.get(f'/api/alerts/{other.pk}/').status_code, 404)
        self.assertEqual(self.client.post('/api/alerts/',
                                         {'company': self.foreign_company.pk, 'description': 'fake'}).status_code, 405)
        self.assertEqual(self.client.patch(f'/api/alerts/{alert.pk}/',
                                          {'company': self.foreign_company.pk}).status_code, 405)
        self.assertEqual(self.client.post(f'/api/alerts/{alert.pk}/resolve/').status_code, 200)
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)

    def test_missing_profile_never_creates_a_tenant_and_regular_config_writes_stay_forbidden(self):
        unassigned = User.objects.create_user('api-no-profile', is_superuser=True)
        self.client.force_authenticate(unassigned)
        before = Company.objects.count()
        self.assertEqual(self.client.get('/api/departments/').status_code, 403)
        self.assertEqual(Company.objects.count(), before)
        self.client.force_authenticate(self.user)
        self.assertEqual(self.client.patch(f'/api/profiles/{self.user.profile.pk}/',
                                          {'company': self.foreign_company.pk}).status_code, 403)
        self.assertEqual(self.client.post('/api/roles/', {'name': 'forged-admin'}).status_code, 405)

    def test_transferred_user_cannot_read_or_mutate_previous_tenant_conversation(self):
        previous = Conversation.objects.create(user=self.user, title='Previous tenant private')
        message = Message.objects.create(conversation=previous, content='private previous content')
        Prompt.objects.create(user=self.user, conversation=previous, company=self.company,
                              content='private previous content')
        Profile.objects.filter(user=self.user).update(company=self.foreign_company)
        self.user.refresh_from_db()
        self.client.force_authenticate(self.user)
        current = Conversation.objects.create(user=self.user, title='Current tenant')
        Prompt.objects.create(user=self.user, conversation=current, company=self.foreign_company,
                              content='current content')
        legacy = Conversation.objects.create(user=self.user, title='Unknown legacy tenant')
        Prompt.objects.create(user=self.user, conversation=legacy, company=None, content='legacy')
        response = self.client.get('/api/conversations/')
        ids = {row['id'] for row in response.json()['results']}
        self.assertEqual(ids, {current.pk, legacy.pk})
        for suffix in ('', 'messages/'):
            self.assertEqual(self.client.get(f'/api/conversations/{previous.pk}/{suffix}').status_code, 404)
        self.assertEqual(self.client.get(f'/api/messages/{message.pk}/').status_code, 404)
        self.assertEqual(self.client.patch(f'/api/conversations/{previous.pk}/', {'title': 'changed'}).status_code, 404)
        self.assertEqual(self.client.delete(f'/api/conversations/{previous.pk}/').status_code, 404)
        self.assertEqual(self.client.post('/api/messages/',
                                         {'conversation': current.pk, 'content': 'fake', 'role': 'assistant'}).status_code, 405)
        stats = self.client.get('/api/dashboard/stats/').json()
        self.assertEqual(stats['total_prompts'], 1)
        self.assertEqual(stats['total_conversations'], 2)

from django.test import TestCase
from django.contrib.auth.models import User
from front.models import Company, Profile, Rule, Alert, RulesGroup
from front.views import validate_prompt

class ValidationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password')
        self.company = Company.objects.create(name="Test Corp")
        Profile.objects.create(user=self.user, company=self.company)
        self.group = RulesGroup.objects.create(name="Test Group", company=self.company)

    def test_validator_returns_matches_without_creating_alerts(self):
        # Create a rule that matches "secret"
        # Since validate_prompt compiles rules, we need a valid YARA rule
        yara_source = 'rule Secret { strings: $a = "secret" condition: $a }'
        rule = Rule.objects.create(
            name="Secret Finder",
            yara_rule=yara_source,
            rules_group=self.group,
            active=True
        )

        matches, rules = validate_prompt(self.user, "This contains a secret", None, None)
        self.assertEqual(len(matches), 1)
        self.assertEqual([item['id'] for item in rules], [rule.id])
        # Alerts belong to the send operation, never to evaluation/simulation.
        self.assertEqual(Alert.objects.count(), 0)

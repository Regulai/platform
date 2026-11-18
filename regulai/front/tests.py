from django.test import TestCase
from django.contrib.auth.models import User
from front.models import Company, Profile, Rule, Alert, RulesGroup
from front.views import validate_prompt

class AlertTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password')
        self.company = Company.objects.create(name="Test Corp")
        Profile.objects.create(user=self.user, company=self.company)
        self.group = RulesGroup.objects.create(name="Test Group", company=self.company)

    def test_alert_creation_with_correct_rule(self):
        # Create a rule that matches "secret"
        # Since validate_prompt compiles rules, we need a valid YARA rule
        yara_source = 'rule Secret { strings: $a = "secret" condition: $a }'
        rule = Rule.objects.create(
            name="Secret Finder",
            yara_rule=yara_source,
            rules_group=self.group,
            active=True
        )

        # Force valid yara namespace format in DB? 
        # validate_prompt uses f"rule_{r.id}", so it should work automatically.
        
        matches = validate_prompt(self.user, "This contains a secret", None, None)
        
        # Verify Alert
        self.assertEqual(Alert.objects.count(), 1)
        alert = Alert.objects.first()
        self.assertEqual(alert.rule, rule)
        self.assertEqual(alert.user, self.user)

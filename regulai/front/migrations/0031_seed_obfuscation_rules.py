"""
Seed default obfuscation rules for PII detection.
"""
from django.db import migrations


OBFUSCATION_RULES = [
    {
        "name": "Email",
        "description": "Detect and obfuscate email addresses",
        "severity": "medium",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[EMAIL_{n}]",
        "yara_rule": '''rule email_address {
    meta:
        description = "Detects email addresses"
        category = "pii"
    strings:
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/
    condition:
        $email
}'''
    },
    {
        "name": "Phone_ES",
        "description": "Detect Spanish phone numbers",
        "severity": "medium",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[PHONE_{n}]",
        "yara_rule": '''rule phone_spain {
    meta:
        description = "Detects Spanish phone numbers"
        category = "pii"
    strings:
        $phone1 = /(\\+34)?[ -]?[6789]\\d{2}[ -]?\\d{3}[ -]?\\d{3}/
        $phone2 = /[6789]\\d{8}/
    condition:
        any of them
}'''
    },
    {
        "name": "DNI_NIE",
        "description": "Detect Spanish DNI/NIE numbers",
        "severity": "high",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[DNI_{n}]",
        "yara_rule": '''rule dni_nie_spain {
    meta:
        description = "Detects Spanish DNI and NIE"
        category = "pii"
    strings:
        $dni = /[0-9]{8}[A-Za-z]/
        $nie = /[XYZxyz][0-9]{7}[A-Za-z]/
    condition:
        any of them
}'''
    },
    {
        "name": "NIF",
        "description": "Detect Spanish company tax ID (NIF)",
        "severity": "medium",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[NIF_{n}]",
        "yara_rule": '''rule nif_spain {
    meta:
        description = "Detects Spanish NIF (company tax ID)"
        category = "pii"
    strings:
        $nif = /[A-HJ-NP-SUVWa-hj-np-suvw][0-9]{7}[0-9A-Ja-j]/
    condition:
        $nif
}'''
    },
    {
        "name": "IBAN",
        "description": "Detect IBAN bank account numbers",
        "severity": "high",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[IBAN_{n}]",
        "yara_rule": '''rule iban_number {
    meta:
        description = "Detects IBAN numbers"
        category = "financial"
    strings:
        $iban1 = /[A-Z]{2}[0-9]{2}[ ]?([0-9]{4}[ ]?){5,7}/
        $iban2 = /[A-Z]{2}[0-9]{22,30}/
    condition:
        any of them
}'''
    },
    {
        "name": "Credit_Card",
        "description": "Detect credit card numbers",
        "severity": "critical",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[CARD_{n}]",
        "yara_rule": '''rule credit_card {
    meta:
        description = "Detects credit card numbers (Visa, MasterCard, Amex)"
        category = "financial"
    strings:
        $visa = /4[0-9]{12}([0-9]{3})?/
        $mc = /5[1-5][0-9]{14}/
        $amex = /3[47][0-9]{13}/
        $formatted = /[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}/
    condition:
        any of them
}'''
    },
    {
        "name": "API_Key",
        "description": "Detect API keys and tokens",
        "severity": "critical",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[API_KEY_{n}]",
        "yara_rule": '''rule api_key {
    meta:
        description = "Detects API keys and tokens"
        category = "secrets"
    strings:
        $sk = /sk[-_][a-zA-Z0-9]{20,}/
        $pk = /pk[-_][a-zA-Z0-9]{20,}/
        $api = /api[-_]?key[-_:][ ]?[a-zA-Z0-9]{16,}/i
        $token = /token[-_:][ ]?[a-zA-Z0-9]{20,}/i
    condition:
        any of them
}'''
    },
    {
        "name": "AWS_Key",
        "description": "Detect AWS access keys",
        "severity": "critical",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[AWS_KEY_{n}]",
        "yara_rule": '''rule aws_key {
    meta:
        description = "Detects AWS access keys"
        category = "secrets"
    strings:
        $access = /AKIA[A-Z0-9]{16}/
        $secret = /[A-Za-z0-9\\/+=]{40}/
    condition:
        $access
}'''
    },
    {
        "name": "IP_Address",
        "description": "Detect IPv4 addresses",
        "severity": "low",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[IP_{n}]",
        "yara_rule": '''rule ip_address {
    meta:
        description = "Detects IPv4 addresses"
        category = "network"
    strings:
        $ipv4 = /([0-9]{1,3}\\.){3}[0-9]{1,3}/
    condition:
        $ipv4
}'''
    },
    {
        "name": "SSN_US",
        "description": "Detect US Social Security Numbers",
        "severity": "critical",
        "applies_to": "both",
        "action": "obfuscate",
        "obfuscate_token": "[SSN_{n}]",
        "yara_rule": '''rule ssn_us {
    meta:
        description = "Detects US Social Security Numbers"
        category = "pii"
    strings:
        $ssn = /[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}/
    condition:
        $ssn
}'''
    },
]


def seed_obfuscation_rules(apps, schema_editor):
    """Create default obfuscation rules for all companies."""
    RulesGroup = apps.get_model('front', 'RulesGroup')
    Rule = apps.get_model('front', 'Rule')
    Company = apps.get_model('front', 'Company')

    # Create rules for each company
    for company in Company.objects.all():
        # Check if obfuscation group already exists
        group, created = RulesGroup.objects.get_or_create(
            name="Obfuscation Rules",
            company=company,
            defaults={"description": "Default PII obfuscation rules"}
        )

        if created:
            # Create rules only if group was just created
            for rule_data in OBFUSCATION_RULES:
                Rule.objects.create(
                    rules_group=group,
                    **rule_data
                )


def reverse_seed(apps, schema_editor):
    """Remove seeded obfuscation rules."""
    RulesGroup = apps.get_model('front', 'RulesGroup')
    RulesGroup.objects.filter(name="Obfuscation Rules").delete()


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0030_obfuscation_rules'),
    ]

    operations = [
        migrations.RunPython(seed_obfuscation_rules, reverse_seed),
    ]

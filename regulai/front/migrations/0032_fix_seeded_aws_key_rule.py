"""
Fix the AWS_Key rule seeded by 0031_seed_obfuscation_rules.

The seeded rule declared a `$secret` string that its condition never used.
YARA rejects unreferenced strings, so the rule did not compile and, because
all company rules were compiled together, it disabled every block/consent
rule of the company. Only rules that still fail to compile are touched, so a
rule already fixed by hand is left as is.
"""
import re

from django.db import migrations

SECRET_LINE = re.compile(r'^[ \t]*\$secret[ \t]*=.*(?:\r?\n|$)', re.MULTILINE)


def fix_aws_key_rules(apps, schema_editor):
    import yara

    Rule = apps.get_model('front', 'Rule')
    for rule in Rule.objects.filter(name="AWS_Key", rules_group__name="Obfuscation Rules"):
        try:
            yara.compile(source=rule.yara_rule)
            continue  # already valid
        except yara.Error:
            pass

        fixed = SECRET_LINE.sub('', rule.yara_rule)
        try:
            yara.compile(source=fixed)
        except yara.Error:
            continue  # broken for another reason: leave it for a human
        rule.yara_rule = fixed
        rule.save(update_fields=['yara_rule'])


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0031_seed_obfuscation_rules'),
    ]

    operations = [
        migrations.RunPython(fix_aws_key_rules, migrations.RunPython.noop),
    ]

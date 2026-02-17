from django.db import migrations


def seed_default_rules_groups(apps, schema_editor):
    """Create a 'Default' RulesGroup for every existing Company."""
    Company = apps.get_model('front', 'Company')
    RulesGroup = apps.get_model('front', 'RulesGroup')

    for company in Company.objects.all():
        RulesGroup.objects.get_or_create(
            name='Default',
            company=company,
            defaults={'description': 'Default rules group'}
        )


def reverse_seed(apps, schema_editor):
    """Don't delete on reverse to preserve user data."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0019_add_rule_action_field'),
    ]

    operations = [
        migrations.RunPython(seed_default_rules_groups, reverse_seed),
    ]

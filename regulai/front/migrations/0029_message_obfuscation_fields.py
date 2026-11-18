# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0028_company_tool_config'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='is_obfuscated',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='message',
            name='original_content',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='message',
            name='obfuscated_entities',
            field=models.JSONField(blank=True, null=True),
        ),
    ]

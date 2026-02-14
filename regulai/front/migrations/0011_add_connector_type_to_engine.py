# Generated migration for adding connector_type to Engine

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0010_add_engine_models'),
    ]

    operations = [
        migrations.AddField(
            model_name='engine',
            name='connector_type',
            field=models.CharField(
                choices=[
                    ('openai', 'OpenAI SDK'),
                    ('anthropic', 'Anthropic SDK'),
                    ('openai_compatible', 'OpenAI Compatible (Custom URL)'),
                ],
                default='openai',
                help_text='SDK/connector to use for API calls',
                max_length=50,
            ),
        ),
    ]

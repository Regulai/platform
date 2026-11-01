"""Add an independent gateway catalogue; preserve existing engines and credentials."""
from django.db import migrations, models


def seed_gateway(apps, schema_editor):
    Engine = apps.get_model('front', 'Engine')
    EngineModel = apps.get_model('front', 'EngineModel')
    alias = schema_editor.connection.alias
    # Public /v1/models catalogue observed 2026-10-05. Prices remain unknown:
    # account terms, tiers and regional rates require an operator's review.
    for label, model_id, context, output in (
        ('Claude', 'anthropic/claude-sonnet-4.5', 1000000, 64000),
        ('Mistral', 'mistral/mistral-small', 262144, 4000),
        ('Gemini', 'google/gemini-2.5-flash', 1000000, 65535),
        ('ChatGPT / OpenAI', 'openai/gpt-4.1-mini', 1047576, 32768),
    ):
        engine, created = Engine.objects.using(alias).get_or_create(
            name=f'{label} · Vercel', defaults={
                'provider': 'Vercel AI Gateway', 'connector_type': 'vercel_gateway',
                'base_url': 'https://ai-gateway.vercel.sh/v1', 'default_model': model_id,
            })
        if created:
            EngineModel.objects.using(alias).create(engine=engine, name=model_id.split('/')[1],
                model_id=model_id, context_window=context, max_tokens=output, supports_json=True)


class Migration(migrations.Migration):
    dependencies = [('front', '0032_obfuscationconfig_backend')]
    operations = [
        migrations.AlterField(model_name='engine', name='connector_type', field=models.CharField(
            choices=[('openai', 'OpenAI SDK'), ('anthropic', 'Anthropic SDK'),
                     ('openai_compatible', 'OpenAI Compatible (Custom URL)'),
                     ('vercel_gateway', 'Vercel AI Gateway')],
            default='openai', help_text='SDK/connector to use for API calls', max_length=50)),
        # Never cascade-delete company credentials or historical model references on rollback.
        migrations.RunPython(seed_gateway, migrations.RunPython.noop),
    ]

"""Native provider keys are distinct from Vercel credentials. Never copy keys."""
from django.db import migrations


def seed_services(apps, schema_editor):
    Engine = apps.get_model('front', 'Engine')
    EngineModel = apps.get_model('front', 'EngineModel')
    alias = schema_editor.connection.alias
    for label, connector, endpoint, model, context, output in (
        ('Claude', 'anthropic', 'https://api.anthropic.com', 'claude-sonnet-4-5', 200000, 64000),
        ('Gemini', 'openai_compatible', 'https://generativelanguage.googleapis.com/v1beta/openai/', 'gemini-2.5-flash', 1000000, 65535),
        ('Mistral', 'openai_compatible', 'https://api.mistral.ai/v1', 'mistral-small-latest', 262144, 4000),
        ('OpenAI / ChatGPT', 'openai', 'https://api.openai.com/v1', 'gpt-4.1-mini', 1047576, 32768),
    ):
        engine, created = Engine.objects.using(alias).get_or_create(name=f'{label} · API', defaults={
            'provider': label, 'connector_type': connector, 'base_url': endpoint, 'default_model': model})
        if created:
            EngineModel.objects.using(alias).create(engine=engine, name=model, model_id=model,
                context_window=context, max_tokens=output, supports_json=True)


class Migration(migrations.Migration):
    dependencies = [('front', '0033_vercel_gateway_catalog')]
    operations = [migrations.RunPython(seed_services, migrations.RunPython.noop)]

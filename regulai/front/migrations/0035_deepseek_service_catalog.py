"""Expose an independent DeepSeek key without modifying existing connections."""
from django.db import migrations


def seed_deepseek(apps, schema_editor):
    Engine = apps.get_model('front', 'Engine')
    EngineModel = apps.get_model('front', 'EngineModel')
    alias = schema_editor.connection.alias
    engine, created = Engine.objects.using(alias).get_or_create(name='DeepSeek · API', defaults={
        'provider': 'DeepSeek', 'connector_type': 'openai_compatible',
        'base_url': 'https://api.deepseek.com', 'default_model': 'deepseek-flash'})
    if created:
        EngineModel.objects.using(alias).create(engine=engine, name='DeepSeek Flash',
            model_id='deepseek-flash', context_window=1000000, max_tokens=4096, supports_json=True)


class Migration(migrations.Migration):
    dependencies = [('front', '0034_direct_service_catalog')]
    operations = [migrations.RunPython(seed_deepseek, migrations.RunPython.noop)]

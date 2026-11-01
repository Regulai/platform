from django.db import migrations, models


def deactivate_local_masks(apps, schema_editor):
    # Old code interprets every active configuration as HTTP. A retained URL is
    # historical data, not authorization to send originals after a downgrade.
    config = apps.get_model('front', 'ObfuscationConfig')
    config.objects.using(schema_editor.connection.alias).filter(backend='local', active=True).update(active=False)


class Migration(migrations.Migration):
    dependencies = [('front', '0031_infer_historical_prompt_company')]

    operations = [
        migrations.AddField(model_name='obfuscationconfig', name='backend',
            field=models.CharField(choices=[('local', 'Local detector'), ('http', 'PasteGuard HTTP')],
                default='http', max_length=10)),
        migrations.AlterField(model_name='obfuscationconfig', name='api_url',
            field=models.URLField(blank=True,
                help_text='Base URL del servicio PasteGuard; obligatoria solo para HTTP.')),
        migrations.RunPython(migrations.RunPython.noop, deactivate_local_masks),
    ]

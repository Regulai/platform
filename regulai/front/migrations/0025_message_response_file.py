from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0024_seed_mistral_engine'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='response_file',
            field=models.FileField(blank=True, null=True, upload_to='chat_responses/'),
        ),
    ]

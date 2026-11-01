from django.db import migrations, models
from front.encrypted_fields import EncryptedTextField


class Migration(migrations.Migration):
    dependencies = [('front', '0041_agent_professional')]
    operations = [
        migrations.AddField(model_name='agentartifact', name='filename', field=EncryptedTextField(blank=True, default='')),
        migrations.AddField(model_name='agentartifact', name='size_bytes', field=models.PositiveBigIntegerField(null=True)),
    ]

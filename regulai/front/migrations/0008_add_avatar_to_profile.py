# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0007_add_department_model'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to='avatars/'),
        ),
    ]

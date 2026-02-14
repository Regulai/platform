# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0013_add_name_to_companyengine'),
    ]

    operations = [
        migrations.AddField(
            model_name='prompt',
            name='file_name',
            field=models.CharField(blank=True, help_text='Name of attached file', max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='prompt',
            name='file_size',
            field=models.IntegerField(blank=True, help_text='Size of attached file in bytes', null=True),
        ),
        migrations.AddField(
            model_name='prompt',
            name='file_md5',
            field=models.CharField(blank=True, help_text='MD5 hash of attached file', max_length=32, null=True),
        ),
        migrations.AddField(
            model_name='prompt',
            name='file_sha1',
            field=models.CharField(blank=True, help_text='SHA1 hash of attached file', max_length=40, null=True),
        ),
        migrations.AddField(
            model_name='prompt',
            name='file_sha256',
            field=models.CharField(blank=True, help_text='SHA256 hash of attached file', max_length=64, null=True),
        ),
    ]

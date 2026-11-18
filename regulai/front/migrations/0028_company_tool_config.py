# Generated manually

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0027_obfuscation_local_mode'),
    ]

    operations = [
        migrations.CreateModel(
            name='CompanyToolConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enable_documents', models.BooleanField(default=True, help_text='Create Word/PDF documents')),
                ('enable_spreadsheets', models.BooleanField(default=True, help_text='Create Excel/CSV spreadsheets')),
                ('enable_presentations', models.BooleanField(default=True, help_text='Create PowerPoint presentations')),
                ('enable_code_files', models.BooleanField(default=True, help_text='Create code/script files')),
                ('enable_charts', models.BooleanField(default=True, help_text='Create charts and graphs')),
                ('enable_data_analysis', models.BooleanField(default=True, help_text='Analyze data and statistics')),
                ('enable_datetime', models.BooleanField(default=True, help_text='Get current date/time')),
                ('enable_calculator', models.BooleanField(default=True, help_text='Mathematical calculations')),
                ('enable_web_search', models.BooleanField(default=False, help_text='Search the web (may send data to external services)')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('company', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='tool_config', to='front.company')),
            ],
            options={
                'verbose_name': 'Company Tool Configuration',
                'verbose_name_plural': 'Company Tool Configurations',
            },
        ),
    ]

# Generated migration for Department model

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0006_add_file_to_message'),
    ]

    operations = [
        # Create Department model
        migrations.CreateModel(
            name='Department',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='departments', to='front.company')),
            ],
            options={
                'ordering': ['name'],
                'unique_together': {('name', 'company')},
            },
        ),
        # Remove old department CharField from Profile
        migrations.RemoveField(
            model_name='profile',
            name='department',
        ),
        # Add new department ForeignKey to Profile
        migrations.AddField(
            model_name='profile',
            name='department',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='users', to='front.department'),
        ),
    ]

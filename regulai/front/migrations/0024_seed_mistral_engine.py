# Migration to seed Mistral AI engine and models

from django.db import migrations


def seed_mistral(apps, schema_editor):
    """Create Mistral AI engine and its models."""
    Engine = apps.get_model('front', 'Engine')
    EngineModel = apps.get_model('front', 'EngineModel')

    # =====================
    # Mistral AI Engine (OpenAI Compatible)
    # =====================
    mistral_engine, _ = Engine.objects.get_or_create(
        name='Mistral',
        defaults={
            'provider': 'Mistral AI',
            'connector_type': 'openai_compatible',
            'description': 'Mistral AI models - Powerful open and commercial language models',
            'base_url': 'https://api.mistral.ai/v1',
            'default_model': 'mistral-large-latest',
        }
    )

    mistral_models = [
        {
            'name': 'Mistral Large',
            'model_id': 'mistral-large-latest',
            'description': 'Flagship model. Top-tier reasoning for complex tasks.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 1,
        },
        {
            'name': 'Mistral Small',
            'model_id': 'mistral-small-latest',
            'description': 'Fast and cost-effective for most everyday tasks.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 2,
        },
        {
            'name': 'Codestral',
            'model_id': 'codestral-latest',
            'description': 'Specialized for code generation and programming tasks.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 3,
        },
        {
            'name': 'Pixtral Large',
            'model_id': 'pixtral-large-latest',
            'description': 'Multimodal model with vision capabilities for image analysis.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 4,
        },
    ]

    for model_data in mistral_models:
        EngineModel.objects.get_or_create(
            engine=mistral_engine,
            model_id=model_data['model_id'],
            defaults=model_data
        )


def reverse_seed(apps, schema_editor):
    """Remove seeded Mistral data on reverse."""
    Engine = apps.get_model('front', 'Engine')
    Engine.objects.filter(name='Mistral').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0023_company_department_system_prompt'),
    ]

    operations = [
        migrations.RunPython(seed_mistral, reverse_seed),
    ]

# Generated migration to seed default AI engines and models

from django.db import migrations


def seed_engines(apps, schema_editor):
    """Create default AI engines and their models."""
    Engine = apps.get_model('front', 'Engine')
    EngineModel = apps.get_model('front', 'EngineModel')

    # =====================
    # OpenAI Engine
    # =====================
    openai_engine, _ = Engine.objects.get_or_create(
        name='OpenAI',
        defaults={
            'provider': 'OpenAI',
            'connector_type': 'openai',
            'description': 'OpenAI GPT models - Industry leading language models',
            'default_model': 'gpt-4o-mini',
        }
    )

    openai_models = [
        {
            'name': 'GPT-4o',
            'model_id': 'gpt-4o',
            'description': 'Most capable model. Great for complex tasks requiring advanced reasoning.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 1,
        },
        {
            'name': 'GPT-4o Mini',
            'model_id': 'gpt-4o-mini',
            'description': 'Fast and affordable. Best for most everyday tasks.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 2,
        },
        {
            'name': 'GPT-4 Turbo',
            'model_id': 'gpt-4-turbo',
            'description': 'Previous generation GPT-4 with vision capabilities.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 3,
        },
        {
            'name': 'GPT-3.5 Turbo',
            'model_id': 'gpt-3.5-turbo',
            'description': 'Fast and cost-effective for simple tasks.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 4,
        },
    ]

    for model_data in openai_models:
        EngineModel.objects.get_or_create(
            engine=openai_engine,
            model_id=model_data['model_id'],
            defaults=model_data
        )

    # =====================
    # Anthropic Engine
    # =====================
    anthropic_engine, _ = Engine.objects.get_or_create(
        name='Anthropic',
        defaults={
            'provider': 'Anthropic',
            'connector_type': 'anthropic',
            'description': 'Anthropic Claude models - Safe and helpful AI assistants',
            'default_model': 'claude-sonnet-4-20250514',
        }
    )

    anthropic_models = [
        {
            'name': 'Claude Sonnet 4',
            'model_id': 'claude-sonnet-4-20250514',
            'description': 'Best balance of intelligence and speed. Ideal for most tasks.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 1,
        },
        {
            'name': 'Claude 3.5 Haiku',
            'model_id': 'claude-3-5-haiku-20241022',
            'description': 'Fastest model. Great for simple tasks and high-volume use.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 2,
        },
        {
            'name': 'Claude 3 Opus',
            'model_id': 'claude-3-opus-20240229',
            'description': 'Most powerful for complex analysis and research tasks.',
            'supports_vision': True,
            'max_tokens': 4096,
            'order': 3,
        },
    ]

    for model_data in anthropic_models:
        EngineModel.objects.get_or_create(
            engine=anthropic_engine,
            model_id=model_data['model_id'],
            defaults=model_data
        )

    # =====================
    # DeepSeek Engine (OpenAI Compatible)
    # =====================
    deepseek_engine, _ = Engine.objects.get_or_create(
        name='DeepSeek',
        defaults={
            'provider': 'DeepSeek',
            'connector_type': 'openai_compatible',
            'description': 'DeepSeek AI models - Cost-effective alternative with strong performance',
            'base_url': 'https://api.deepseek.com/v1',
            'default_model': 'deepseek-chat',
        }
    )

    deepseek_models = [
        {
            'name': 'DeepSeek Chat',
            'model_id': 'deepseek-chat',
            'description': 'General purpose chat model with excellent reasoning.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 1,
        },
        {
            'name': 'DeepSeek Coder',
            'model_id': 'deepseek-coder',
            'description': 'Specialized for code generation and programming tasks.',
            'supports_vision': False,
            'max_tokens': 4096,
            'order': 2,
        },
    ]

    for model_data in deepseek_models:
        EngineModel.objects.get_or_create(
            engine=deepseek_engine,
            model_id=model_data['model_id'],
            defaults=model_data
        )


def reverse_seed(apps, schema_editor):
    """Remove seeded data (optional - keeps data on reverse)."""
    # We don't delete on reverse to preserve user data
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0011_add_connector_type_to_engine'),
    ]

    operations = [
        migrations.RunPython(seed_engines, reverse_seed),
    ]

# Generated migration for encrypting API keys

from django.db import migrations, models
import logging

logger = logging.getLogger(__name__)


def encrypt_existing_api_keys(apps, schema_editor):
    """
    Encrypt all existing plaintext API keys.

    This is a data migration that runs once to encrypt existing keys.
    """
    CompanyEngine = apps.get_model('front', 'CompanyEngine')

    # Import encryption functions
    try:
        from front.encryption import encrypt_value, is_encrypted
    except Exception as e:
        logger.warning(f"Could not import encryption module: {e}")
        logger.warning("Skipping API key encryption. Run 'python manage.py migrate' again after setting ENCRYPTION_KEY")
        return

    encrypted_count = 0
    skipped_count = 0
    failed_count = 0

    for engine in CompanyEngine.objects.all():
        try:
            # Check if already encrypted
            if is_encrypted(engine.api_key):
                skipped_count += 1
                continue

            # Skip empty keys
            if not engine.api_key or engine.api_key.strip() == '':
                skipped_count += 1
                continue

            # Encrypt the key
            encrypted = encrypt_value(engine.api_key)

            # Update the database directly (bypass model to avoid double-encryption)
            CompanyEngine.objects.filter(id=engine.id).update(api_key=encrypted)

            encrypted_count += 1
            logger.info(f"Encrypted API key for CompanyEngine ID {engine.id}")

        except Exception as e:
            failed_count += 1
            logger.error(f"Failed to encrypt API key for CompanyEngine ID {engine.id}: {e}")

    logger.info(f"API key encryption complete: {encrypted_count} encrypted, {skipped_count} skipped, {failed_count} failed")


def decrypt_api_keys(apps, schema_editor):
    """
    Reverse migration: decrypt API keys back to plaintext.

    WARNING: This is for rollback only. Use with caution.
    """
    CompanyEngine = apps.get_model('front', 'CompanyEngine')

    try:
        from front.encryption import decrypt_value, is_encrypted
    except Exception as e:
        logger.warning(f"Could not import encryption module: {e}")
        return

    for engine in CompanyEngine.objects.all():
        try:
            if is_encrypted(engine.api_key):
                decrypted = decrypt_value(engine.api_key)
                CompanyEngine.objects.filter(id=engine.id).update(api_key=decrypted)
                logger.info(f"Decrypted API key for CompanyEngine ID {engine.id}")
        except Exception as e:
            logger.error(f"Failed to decrypt API key for CompanyEngine ID {engine.id}: {e}")


class Migration(migrations.Migration):

    dependencies = [
        ('front', '0015_add_file_hashes_to_prompt'),
    ]

    operations = [
        # First, change the field to allow longer encrypted values
        migrations.AlterField(
            model_name='companyengine',
            name='api_key',
            field=models.CharField(max_length=512, help_text='API key (stored encrypted)'),
        ),
        # Then encrypt existing data
        migrations.RunPython(
            encrypt_existing_api_keys,
            reverse_code=decrypt_api_keys,
        ),
    ]

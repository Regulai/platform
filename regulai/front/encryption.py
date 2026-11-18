"""
Encryption module for sensitive data (API keys, tokens, etc.)

Uses Fernet symmetric encryption (AES-128 CBC with HMAC)
from the cryptography library.

CRITICAL: The encryption key must be stored securely in environment variables,
NOT in the code or database.
"""

import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class EncryptionError(Exception):
    """Raised when encryption/decryption fails"""
    pass


def get_encryption_key():
    """
    Get the encryption key from Django settings or environment variables.

    Priority:
    1. Django settings.ENCRYPTION_KEY (from local_settings.py)
    2. Environment variable ENCRYPTION_KEY

    Returns:
        bytes: The encryption key

    Raises:
        EncryptionError: If key is not configured
    """
    # Try Django settings first (from local_settings.py)
    key = getattr(settings, 'ENCRYPTION_KEY', None)

    # Fall back to environment variable
    if not key:
        key = os.environ.get('ENCRYPTION_KEY')

    if not key:
        raise EncryptionError(
            "ENCRYPTION_KEY not configured. Please set it in:\n"
            "1. regulai/local_settings.py (recommended), OR\n"
            "2. Environment variable ENCRYPTION_KEY\n\n"
            "Generate a key with: python manage.py generate_encryption_key"
        )

    try:
        # Validate key format
        key_bytes = key.encode() if isinstance(key, str) else key
        Fernet(key_bytes)  # Will raise if invalid
        return key_bytes
    except Exception as e:
        raise EncryptionError(f"Invalid ENCRYPTION_KEY: {e}")


def encrypt_value(plaintext):
    """
    Encrypt a plaintext value.

    Args:
        plaintext: String or bytes to encrypt

    Returns:
        str: Base64-encoded encrypted value

    Raises:
        EncryptionError: If encryption fails
    """
    if not plaintext:
        return plaintext

    try:
        key = get_encryption_key()
        f = Fernet(key)

        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext

        # Encrypt
        encrypted_bytes = f.encrypt(plaintext_bytes)

        # Return as string (base64)
        return encrypted_bytes.decode('utf-8')

    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt_value(encrypted):
    """
    Decrypt an encrypted value.

    Args:
        encrypted: Base64-encoded encrypted value (string)

    Returns:
        str: Decrypted plaintext value

    Raises:
        EncryptionError: If decryption fails
    """
    if not encrypted:
        return encrypted

    try:
        key = get_encryption_key()
        f = Fernet(key)

        # Convert to bytes if string
        if isinstance(encrypted, str):
            encrypted_bytes = encrypted.encode('utf-8')
        else:
            encrypted_bytes = encrypted

        # Decrypt
        decrypted_bytes = f.decrypt(encrypted_bytes)

        # Return as string
        return decrypted_bytes.decode('utf-8')

    except InvalidToken:
        raise EncryptionError(
            "Decryption failed: Invalid token. "
            "This could mean the data was encrypted with a different key."
        )
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}")


def generate_key():
    """
    Generate a new encryption key.

    Returns:
        str: Base64-encoded encryption key

    Usage:
        Run this once and store the result in ENCRYPTION_KEY environment variable:

        python manage.py shell
        >>> from front.encryption import generate_key
        >>> print(generate_key())
        # Copy the output to .env file as: ENCRYPTION_KEY=<output>
    """
    return Fernet.generate_key().decode('utf-8')


# Convenience function for migration
def migrate_plaintext_to_encrypted(model_class, field_name):
    """
    Migrate plaintext values to encrypted values in the database.

    WARNING: This should be run in a migration or management command,
    NOT in production code.

    Args:
        model_class: Django model class
        field_name: Name of the field to encrypt

    Example:
        from front.encryption import migrate_plaintext_to_encrypted
        from front.models import CompanyEngine

        migrate_plaintext_to_encrypted(CompanyEngine, 'api_key')
    """
    count = 0
    failed = 0

    for obj in model_class.objects.all():
        try:
            plaintext = getattr(obj, field_name)

            # Check if already encrypted (Fernet tokens start with 'gAAAAA')
            if plaintext and not plaintext.startswith('gAAAAA'):
                encrypted = encrypt_value(plaintext)
                setattr(obj, field_name, encrypted)
                obj.save(update_fields=[field_name])
                count += 1
                print(f"Encrypted {model_class.__name__} ID {obj.id}")
        except Exception as e:
            failed += 1
            print(f"Failed to encrypt {model_class.__name__} ID {obj.id}: {e}")

    print(f"\nMigration complete: {count} encrypted, {failed} failed")
    return count, failed


def is_encrypted(value):
    """
    Check if a value appears to be encrypted.

    Fernet tokens are base64-encoded and start with specific bytes.
    This is a heuristic check, not guaranteed to be accurate.

    Args:
        value: String to check

    Returns:
        bool: True if value appears encrypted
    """
    if not value or not isinstance(value, str):
        return False

    # Fernet tokens start with 'gAAAAA' when base64-encoded
    # This is because they start with version byte 0x80
    return value.startswith('gAAAAA')

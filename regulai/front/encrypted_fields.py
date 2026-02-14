"""
Custom Django model fields for encrypted data.

EncryptedCharField and EncryptedTextField automatically encrypt data
when saving to the database and decrypt when reading.
"""

from django.db import models
from .encryption import encrypt_value, decrypt_value, EncryptionError


class EncryptedCharField(models.CharField):
    """
    CharField that automatically encrypts/decrypts values.

    Usage in models:
        api_key = EncryptedCharField(max_length=512)

    Note: max_length should be larger than the plaintext because
    encrypted data is base64-encoded and longer.
    """

    description = "Encrypted CharField"

    def __init__(self, *args, **kwargs):
        # Encrypted data is longer due to base64 encoding
        # Ensure max_length is reasonable (default 512)
        if 'max_length' not in kwargs:
            kwargs['max_length'] = 512

        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        """
        Called when saving to database - encrypts the value.
        """
        if value is None or value == '':
            return value

        try:
            # Encrypt the value
            encrypted = encrypt_value(value)
            return super().get_prep_value(encrypted)
        except EncryptionError as e:
            # Log the error but don't fail silently
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to encrypt field value: {e}")
            raise

    def from_db_value(self, value, expression, connection):
        """
        Called when loading from database - decrypts the value.
        """
        if value is None or value == '':
            return value

        try:
            # Decrypt the value
            return decrypt_value(value)
        except EncryptionError as e:
            # If decryption fails, log and return the encrypted value
            # This allows for graceful handling of migration scenarios
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to decrypt field value: {e}")
            # Return empty string instead of encrypted garbage
            return ''

    def to_python(self, value):
        """
        Called during model instantiation and form cleaning.
        """
        if isinstance(value, str) or value is None:
            return value
        return str(value)


class EncryptedTextField(models.TextField):
    """
    TextField that automatically encrypts/decrypts values.

    Usage in models:
        secret_data = EncryptedTextField()
    """

    description = "Encrypted TextField"

    def get_prep_value(self, value):
        """
        Called when saving to database - encrypts the value.
        """
        if value is None or value == '':
            return value

        try:
            encrypted = encrypt_value(value)
            return super().get_prep_value(encrypted)
        except EncryptionError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to encrypt field value: {e}")
            raise

    def from_db_value(self, value, expression, connection):
        """
        Called when loading from database - decrypts the value.
        """
        if value is None or value == '':
            return value

        try:
            return decrypt_value(value)
        except EncryptionError as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to decrypt field value: {e}")
            return ''

    def to_python(self, value):
        """
        Called during model instantiation and form cleaning.
        """
        if isinstance(value, str) or value is None:
            return value
        return str(value)

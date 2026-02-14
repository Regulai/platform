"""
Django management command to generate an encryption key.

Usage:
    python manage.py generate_encryption_key

This will output a new encryption key that should be stored in the
ENCRYPTION_KEY environment variable.
"""

from django.core.management.base import BaseCommand
from front.encryption import generate_key


class Command(BaseCommand):
    help = 'Generate a new encryption key for sensitive data'

    def handle(self, *args, **options):
        key = generate_key()

        self.stdout.write(self.style.SUCCESS('\n' + '='*70))
        self.stdout.write(self.style.SUCCESS('Encryption Key Generated Successfully'))
        self.stdout.write(self.style.SUCCESS('='*70 + '\n'))

        self.stdout.write(self.style.WARNING('⚠️  CRITICAL: Store this key securely!\n'))

        self.stdout.write(self.style.HTTP_INFO('Add this to your .env file:\n'))
        self.stdout.write(f'ENCRYPTION_KEY={key}\n')

        self.stdout.write(self.style.WARNING('\n⚠️  IMPORTANT NOTES:'))
        self.stdout.write('  1. This key is used to encrypt API keys and other sensitive data')
        self.stdout.write('  2. If you lose this key, encrypted data CANNOT be recovered')
        self.stdout.write('  3. NEVER commit this key to version control')
        self.stdout.write('  4. Store it in .env (which is in .gitignore)')
        self.stdout.write('  5. Back it up securely (password manager, secrets manager, etc.)\n')

        self.stdout.write(self.style.SUCCESS('='*70 + '\n'))

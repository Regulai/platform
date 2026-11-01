"""Rotate raw encrypted columns without silently losing unreadable credentials."""
from hashlib import sha256

from cryptography.fernet import InvalidToken
from django.apps import apps
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction, DatabaseError

from front.checks import PUBLIC_KEY_HASHES
from front.encrypted_fields import EncryptedCharField, EncryptedTextField
from front.encryption import EncryptionError, get_encryption_cipher, get_encryption_key


class Command(BaseCommand):
    help = 'Rotate encrypted credentials to ENCRYPTION_KEY; use --dry-run before writing.'
    # Legacy public fallback keys must be usable offline to migrate away from them.
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--batch-size', type=int, default=500)

    def handle(self, *args, **options):
        size = options['batch_size']
        if not 1 <= size <= 10000:
            raise CommandError('batch_size must be between 1 and 10000.')
        try:
            if sha256(get_encryption_key()).hexdigest() == PUBLIC_KEY_HASHES['ENCRYPTION_KEY']:
                raise CommandError('The rotation target must not be a public template key.')
            cipher = get_encryption_cipher()
            count = 0
            # ponytail: one transaction for all credentials; schedule maintenance for large catalogues.
            with transaction.atomic():
                quote = connection.ops.quote_name
                for model in apps.get_models():
                    for field in model._meta.local_fields:
                        if not isinstance(field, (EncryptedCharField, EncryptedTextField)):
                            continue
                        table, pk, column = map(quote, (model._meta.db_table, model._meta.pk.column, field.column))
                        last_pk = None
                        while True:
                            condition = f' AND {pk} > %s' if last_pk is not None else ''
                            with connection.cursor() as cursor:
                                cursor.execute(f'SELECT {pk}, {column} FROM {table} WHERE '
                                    f'{column} IS NOT NULL AND {column} <> %s{condition} ORDER BY {pk} LIMIT %s',
                                    ['', last_pk, size] if last_pk is not None else ['', size])
                                rows = cursor.fetchall()
                                if not rows:
                                    break
                                rotated = [(cipher.rotate(value.encode()).decode(), identity, value)
                                    for identity, value in rows]
                                if not options['dry_run']:
                                    cursor.executemany(f'UPDATE {table} SET {column}=%s WHERE {pk}=%s AND {column}=%s', rotated)
                                    if cursor.rowcount != len(rows):
                                        raise CommandError('Credentials changed concurrently; no changes were saved.')
                                count += len(rows)
                                last_pk = rows[-1][0]
        except (EncryptionError, InvalidToken, UnicodeError, DatabaseError):
            raise CommandError('Unable to rotate encrypted credentials; no changes were saved.') from None
        verb = 'Validated' if options['dry_run'] else 'Rotated'
        self.stdout.write(f'{verb} {count} encrypted credential values.')

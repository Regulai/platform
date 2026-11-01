"""One locked filesystem mutation inside the isolated runner (no network)."""
import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat
import sys
import uuid


def mutate(value):
    import fcntl
    path = value['path']
    parts = PurePosixPath(path).parts
    if ('\\' in path or '\x00' in path or '..' in parts
            or any(part.startswith(('.regulay-write', '.mutation-')) for part in parts)
            or not path.startswith(('/workspace/work/', '/workspace/output/'))):
        raise ValueError('workspace_path_denied')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    temporary, lock, target = None, None, None
    try:
        for part in parts[1:-1]:
            if value['action'] == 'create':
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        lock = os.open('.regulay-write-lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise ValueError('workspace_lock_invalid')
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            target = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            current = None
        else:
            if not stat.S_ISREG(os.fstat(target).st_mode):
                raise ValueError('regular_file_required')
            chunks, size = [], 0
            while block := os.read(target, 65536):
                size += len(block)
                if size > value['limit']:
                    raise ValueError('file_size_limit')
                chunks.append(block)
            current = b''.join(chunks)
        current_hash = hashlib.sha256(current).hexdigest() if current is not None else None
        action = value['action']
        if action == 'create' and current is not None:
            return {'succeeded': False, 'code': 'file_exists', 'sha256': current_hash,
                'summary': 'El archivo ya existe; usa edit_file o replace_file con su hash.'}
        if action != 'create' and current is None:
            return {'succeeded': False, 'code': 'file_not_found', 'summary': 'Crea el archivo antes de editarlo.'}
        if value.get('expected_sha256') and current_hash != value['expected_sha256']:
            return {'succeeded': False, 'code': 'hash_conflict', 'sha256': current_hash,
                'summary': 'El archivo ha cambiado; lee su revisión actual antes de editar.'}
        if action == 'edit':
            text, old = current.decode('utf-8'), value['old_string']
            count = text.count(old) if old else 0
            if not old or count == 0 or count > 1 and not value.get('replace_all'):
                code = 'empty_match' if not old else 'text_not_found' if not count else 'ambiguous_match'
                return {'succeeded': False, 'code': code, 'sha256': current_hash,
                    'summary': 'Usa un fragmento exacto y único o replace_all para todas las coincidencias.'}
            content = text.replace(old, value['new_string']).encode()
        elif action in ('create', 'replace'):
            content = base64.b64decode(value['content'], validate=True)
            count = 1
        else:
            raise ValueError('mutation_action_invalid')
        if len(content) > value['limit']:
            raise ValueError('file_size_limit')
        temporary = '.regulay-write-' + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        if action == 'create':
            try:
                os.link(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                return {'succeeded': False, 'code': 'file_exists', 'summary': 'El archivo ya existe; lee su estado actual.'}
            os.unlink(temporary, dir_fd=parent)
        else:
            # All application mutations take this lock; ResultGate also serializes
            # arbitrary execute calls, which are never classified as read-only.
            os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
        os.fsync(parent)
        return {'succeeded': True, 'code': 'file_written', 'path': path,
            'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content), 'occurrences': count}
    finally:
        if temporary:
            os.unlink(temporary, dir_fd=parent)
        if target is not None:
            os.close(target)
        if lock is not None:
            os.close(lock)
        os.close(parent)


if __name__ == '__main__':
    try:
        if sys.argv[1] == '--request':
            request_path = sys.argv[2]
            if not request_path.startswith('/workspace/work/.mutation-') or '..' in request_path:
                raise ValueError('mutation_request_denied')
            fd = os.open(request_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_size > 500000:
                    raise ValueError('mutation_request_limit')
                with os.fdopen(fd, 'rb', closefd=False) as request:
                    value = json.load(request)
            finally:
                os.close(fd)
        else:
            value = json.loads(base64.b64decode(sys.argv[1], validate=True))
        result = mutate(value)
    except (ValueError, OSError, UnicodeError, KeyError) as error:
        result = {'succeeded': False, 'code': 'file_operation_denied', 'summary': str(error)[:500]}
    print(json.dumps(result, ensure_ascii=False))

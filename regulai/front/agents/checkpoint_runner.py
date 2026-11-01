"""Work files plus explicit read-only runtime links, bound to its exact hash."""
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

ARCHIVE = Path('/workspace/work/.regulay-checkpoint.zip')


def runtime_link_target(value):
    path = PurePosixPath(value)
    if (not value.startswith('/usr/') or '..' in path.parts or '\\' in value
            or '\x00' in value or len(value) > 4096):
        raise ValueError('Checkpoint runtime link denied')
    return str(path)


def save(limit, file_limit=20000000):
    count, total = 0, 0
    with zipfile.ZipFile(ARCHIVE, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        for root in (Path('/workspace/work'), Path('/workspace/output')):
            pending = [(root, frozenset())]
            while pending:
                path, ancestors = pending.pop()
                if path == ARCHIVE:
                    continue
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(('/workspace')) and not resolved.is_relative_to('/usr'):
                    raise ValueError('Checkpoint symlink outside runtime or workspace')
                count += 1
                if count > 20000:
                    raise ValueError('Checkpoint entry limit')
                if resolved.is_dir():
                    if resolved in ancestors:
                        raise ValueError('Checkpoint directory cycle')
                    archive.writestr(str(path.relative_to('/workspace')) + '/', b'')
                    pending.extend((child, ancestors | {resolved}) for child in path.iterdir())
                    continue
                if not resolved.is_file():
                    raise ValueError('Checkpoint supports regular files only')
                if path.is_symlink() and resolved.is_relative_to('/usr'):
                    # Python venv executables may exceed the per-file limit.
                    # Reference only the immutable runtime whose hash is checked
                    # before restore; never archive a host/workspace symlink.
                    target = runtime_link_target(str(resolved))
                    entry = zipfile.ZipInfo(str(path.relative_to('/workspace')))
                    entry.create_system = 3
                    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(entry, target.encode())
                    total += len(target)
                    continue
                if resolved.stat().st_size > file_limit:
                    raise ValueError('Checkpoint file limit')
                total += resolved.stat().st_size
                if total > limit:
                    raise ValueError('Checkpoint workspace limit')
                archive.write(resolved, str(path.relative_to('/workspace')))
    print(json.dumps({'bytes': ARCHIVE.stat().st_size, 'files': count, 'uncompressed_bytes': total}))


def restore(limit, file_limit=20000000):
    with zipfile.ZipFile(ARCHIVE) as archive:
        total = 0
        for item in archive.infolist():
            path = Path(item.filename)
            total += item.file_size
            if (path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] not in ('work', 'output')
                    or total > limit or item.file_size > file_limit):
                raise ValueError('Checkpoint entry denied')
            target = Path('/workspace') / path
            if any(parent.is_symlink() for parent in target.parents):
                raise ValueError('Checkpoint symlink ancestor denied')
            if stat.S_ISLNK(item.external_attr >> 16):
                runtime = runtime_link_target(archive.read(item).decode())
                if not Path(runtime).is_file():
                    raise ValueError('Checkpoint runtime file unavailable')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(runtime)
                continue
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            # A new clean workspace has no pre-existing user symlinks.
            with archive.open(item) as source, target.open('xb') as destination:
                import shutil
                shutil.copyfileobj(source, destination, length=65536)
            os.chmod(target, (item.external_attr >> 16) & 0o777 & ~0o022)
    ARCHIVE.unlink()


if __name__ == '__main__':
    (save if sys.argv[1] == 'save' else restore)(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 20000000)

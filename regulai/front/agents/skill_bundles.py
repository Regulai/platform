"""Bounded, non-executing Agent Skills package validation shared by all sources."""
import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import time
import unicodedata
import zipfile

import yaml

MAX_COMPRESSED = 10 * 1024 * 1024
MAX_EXPANDED = 50 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024
MAX_ENTRIES = 512
NAME = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*\Z')


class SkillError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def folder_digest(files):
    manifest = [{'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for path, raw in sorted(files.items())]
    return manifest, hashlib.sha256(canonical(manifest).encode()).hexdigest()


def valid_path(path):
    if (not isinstance(path, str) or not path or len(path.encode()) > 1024 or '\\' in path
            or ':' in path or '\x00' in path or path.startswith('/')
            or any(ord(c) < 32 for c in path) or unicodedata.normalize('NFC', path) != path
            or any(p in ('', '.', '..', '.git') for p in path.split('/'))):
        raise SkillError('path_denied')
    if any(p.rstrip(' .') != p or p.split('.')[0].casefold() in (
            'con', 'prn', 'aux', 'nul', *['com' + str(i) for i in range(1, 10)],
            *['lpt' + str(i) for i in range(1, 10)]) for p in path.split('/')):
        raise SkillError('path_denied')
    return path


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            name = self.construct_object(key, deep=deep)
            if not isinstance(name, str) or name in result:
                raise SkillError('invalid_skill')
            result[name] = self.construct_object(value, deep=deep)
        return result


def metadata(raw, directory):
    if len(raw) > 65536:
        raise SkillError('skill_instructions_too_large')
    try:
        text = raw.decode('utf-8', errors='strict')
        if not text.startswith('---\n') and not text.startswith('---\r\n'):
            raise SkillError('invalid_skill')
        lines = text.splitlines()
        end = lines.index('---', 1)
        header = '\n'.join(lines[1:end])
        if len(header.encode()) > 16384:
            raise SkillError('invalid_skill')
        tokens = list(yaml.scan(header))
        if len(tokens) > 1024 or any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken,
                yaml.tokens.TagToken)) for t in tokens):
            raise SkillError('invalid_skill')
        depth = 0
        for token in tokens:
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
            elif isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken, yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
            if depth > 8:
                raise SkillError('invalid_skill')
        data = yaml.load(header, Loader=UniqueSafeLoader)
        # Standard metadata remains data; allowed-tools never grants authority.
        json.dumps(data, allow_nan=False)
        if (not isinstance(data, dict) or not isinstance(data.get('name'), str)
                or not NAME.fullmatch(data['name']) or len(data['name']) > 64 or directory is not None and directory != data['name']
                or not isinstance(data.get('description'), str) or not 1 <= len(data['description']) <= 1024
                or not '\n'.join(lines[end + 1:]).strip()):
            raise SkillError('invalid_skill')
        return data
    except (UnicodeError, ValueError, TypeError, yaml.YAMLError, RecursionError):
        raise SkillError('invalid_skill') from None


def unpack(raw, *, deadline=None):
    """Never extract paths on the application filesystem, including staging."""
    if not isinstance(raw, bytes) or len(raw) > MAX_COMPRESSED:
        raise SkillError('skill_compressed_limit')
    deadline = deadline or time.monotonic() + 30
    result, names, total = {}, {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_ENTRIES:
                raise SkillError('skill_entry_limit')
            for item in entries:
                if time.monotonic() > deadline:
                    raise SkillError('skill_validation_timeout')
                # ZipInfo normalizes separators on Windows and truncates NULs. Inspect
                # its original name so a malicious archive cannot benefit from that.
                original = item.orig_filename
                path = valid_path(original.rstrip('/') if item.is_dir() else original)
                if original != item.filename:
                    raise SkillError('path_denied')
                key = unicodedata.normalize('NFKC', path).casefold()
                if key in names:
                    raise SkillError('skill_path_collision')
                names[key] = item.is_dir()
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (kind not in (0, stat.S_IFREG, stat.S_IFDIR) or item.flag_bits & 1
                        or (item.external_attr & 0x400)):  # Windows reparse point
                    raise SkillError('path_denied')
                if item.is_dir():
                    continue
                if item.file_size > MAX_FILE or item.file_size > max(1, item.compress_size) * 200:
                    raise SkillError('skill_expanded_limit')
                total += item.file_size
                if total > MAX_EXPANDED:
                    raise SkillError('skill_expanded_limit')
                with archive.open(item) as stream:
                    content = stream.read(MAX_FILE + 1)
                if len(content) != item.file_size or len(content) > MAX_FILE:
                    raise SkillError('skill_expanded_limit')
                result[path] = content
            for path in names:
                parents = list(PurePosixPath(path).parents)[:-1]
                if any(str(parent) in names and not names[str(parent)] for parent in parents):
                    raise SkillError('skill_path_collision')
        return result
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
        raise SkillError('invalid_skill_archive') from None


def folders(raw):
    return sorted(str(PurePosixPath(p).parent) for p in unpack(raw) if p.endswith('/SKILL.md') or p == 'SKILL.md')


def validate_bundle(raw, *, subpath=None, deadline=None):
    files = unpack(raw, deadline=deadline)
    candidates = [str(PurePosixPath(p).parent) for p in files if p.endswith('/SKILL.md') or p == 'SKILL.md']
    if subpath is None:
        if len(candidates) != 1:
            raise SkillError('skill_folder_required')
        subpath = candidates[0]
    if subpath not in candidates:
        raise SkillError('skill_folder_not_found')
    prefix = '' if subpath == '.' else valid_path(subpath) + '/'
    selected = {path[len(prefix):]: value for path, value in files.items() if path.startswith(prefix)}
    directory = PurePosixPath(subpath).name
    if subpath == '.':
        # A root ZIP has no directory name; derive its package root from validated metadata.
        directory = None
    data = metadata(selected['SKILL.md'], directory)
    licenses = [p for p in selected if '/' not in p and re.fullmatch(r'(?i)(?:license|licence|copying)(?:[.-][a-z0-9]+)*', p)]
    if not licenses or not any(selected[p].strip() for p in licenses):
        raise SkillError('license_missing')
    try:
        license_text = '\n'.join(selected[p].decode('utf-8') for p in licenses)
        notice = '\n'.join(v.decode('utf-8') for p, v in selected.items()
                           if '/' not in p and ('NOTICE' in p.upper() or 'ATTRIBUTION' in p.upper()))
        for link in re.findall(r'\[[^\]]*\]\(([^)\s]+)\)', selected['SKILL.md'].decode('utf-8')):
            if ':' in link or link.startswith('#'):
                continue
            target = link.split('#')[0].removeprefix('./')
            if valid_path(target) not in selected:
                raise SkillError('skill_resource_missing')
    except UnicodeError:
        raise SkillError('invalid_skill') from None
    manifest, sha = folder_digest(selected)
    return {'files': selected, 'manifest': manifest, 'folder_sha256': sha, 'metadata': data,
            'license': license_text, 'attribution': notice,
            'bundle': canonical({p: base64.b64encode(v).decode('ascii') for p, v in selected.items()})}


def revision_files(revision):
    try:
        files = {valid_path(p): base64.b64decode(v, validate=True) for p, v in json.loads(revision.bundle).items()}
        manifest, sha = folder_digest(files)
        if sha != revision.folder_sha256 or manifest != revision.manifest:
            raise SkillError('skill_digest_changed')
        return files
    except (ValueError, TypeError, AttributeError):
        raise SkillError('skill_digest_changed') from None

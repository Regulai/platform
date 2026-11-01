"""Shared, bounded readers. Inspection never renders code or fetches resources."""
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import unicodedata
import zipfile
import xml.etree.ElementTree as ET


# A format declares what can be inspected, independently from its preview.
FORMATS = {
    'docx': ('office', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ('word', 'docx'), True),
    'xlsx': ('office', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ('excel', 'xlsx', 'spreadsheet', 'hoja de calculo'), False),
    'pptx': ('office', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ('pptx', 'powerpoint', 'presentacion', 'presentation', 'diapositivas', 'slides'), True),
    'pdf': ('pdf', 'application/pdf', ('pdf',), True),
    'png': ('image', 'image/png', ('png',), False),
    'jpg': ('image', 'image/jpeg', ('jpg', 'jpeg'), False),
    'csv': ('text', 'text/csv', ('csv',), False),
    'json': ('text', 'application/json', ('json',), False),
    'txt': ('text', 'text/plain', ('txt',), False),
    'md': ('text', 'text/markdown', ('markdown', 'md'), False),
    'py': ('code', 'text/plain', ('python', 'py'), False),
    'js': ('code', 'text/plain', ('javascript', 'js'), False),
    'sh': ('code', 'text/plain', ('shell', 'sh'), False),
    'html': ('web', 'text/html', ('html', 'htm', 'landing', 'pagina web', 'web page'), False),
    'css': ('web', 'text/css', ('css',), False),
    'svg': ('web', 'image/svg+xml', ('svg',), False),
    'zip': ('archive', 'application/zip', ('zip',), False),
}
ALIASES = {'htm': 'html', 'jpeg': 'jpg'}
MIMES = {key: value[1] for key, value in FORMATS.items()}
MIMES.update({key: MIMES[value] for key, value in ALIASES.items()})
DEFAULT_BUDGET = {'file_bytes': 20_000_000, 'workspace_bytes': 536_870_912}


def canonical(kind):
    value = str(kind or '').lower().lstrip('.')
    return ALIASES.get(value, value)


def safe_filename(value, kind):
    name = unicodedata.normalize('NFC', str(value).replace('\\', '/').rsplit('/', 1)[-1])
    name = ''.join(c for c in name if not unicodedata.category(c).startswith('C')).strip(' .')
    stem = PurePosixPath(name).stem.strip(' .') or 'archivo'
    return stem[:220] + '.' + canonical(kind)


def safe_relative(value, *, workspace=False):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('artifact_path_denied')
    if workspace and value.startswith('/workspace/'):
        value = value[len('/workspace/'):]
    if value.startswith('/') or ':' in value or any(unicodedata.category(c).startswith('C') for c in value):
        raise ValueError('artifact_path_denied')
    value = unicodedata.normalize('NFC', value)
    parts = value.rstrip('/').split('/')
    if len(parts) > 16 or len(value) > 1024 or any(p in ('', '.', '..') for p in parts):
        raise ValueError('artifact_path_denied')
    if workspace and parts[0] not in ('work', 'output'):
        raise ValueError('artifact_path_denied')
    return '/'.join(parts)


def _archive(raw, budget):
    expanded_limit = min(64 * 1024 * 1024, budget['workspace_bytes'], 5 * budget['file_bytes'])
    text, members, total, paths, files, directories = [], [], 0, set(), set(), set()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items = archive.infolist()
        if len(items) > 200 or sum(item.file_size for item in items) > expanded_limit:
            raise ValueError('artifact_archive_limit')
        for item in items:
            # ZipInfo truncates filename at NUL; orig_filename preserves evidence.
            path = safe_relative(item.orig_filename)
            key = path.casefold()
            mode = item.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if (key in paths or item.flag_bits & 1 or file_type not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or item.file_size > budget['file_bytes']
                    or item.file_size > max(1, item.compress_size) * 100):
                raise ValueError('artifact_archive_entry_denied')
            paths.add(key)
            parents = {str(parent).casefold() for parent in PurePosixPath(path).parents if str(parent) != '.'}
            if parents & files or (not item.is_dir() and key in directories):
                raise ValueError('artifact_archive_path_collision')
            directories.update(parents)
            if item.is_dir():
                directories.add(key)
                if item.file_size:
                    raise ValueError('artifact_archive_directory_content')
                continue
            files.add(key)
            kind = canonical(PurePosixPath(path).suffix)
            if kind not in FORMATS or kind == 'zip':
                raise ValueError('artifact_archive_member_unsupported')
            chunks, size = [], 0
            with archive.open(item) as stream:
                while True:
                    chunk = stream.read(min(65536, budget['file_bytes'] - size + 1, expanded_limit - total + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if size > budget['file_bytes'] or total > expanded_limit or size > max(1, item.compress_size) * 100:
                        raise ValueError('artifact_archive_expansion_limit')
                    chunks.append(chunk)
            data = b''.join(chunks)
            if size != item.file_size:
                raise ValueError('artifact_archive_size_mismatch')
            proof, extracted, _ = inspect_file(data, kind, budget=budget)
            if proof['coverage']['status'] != 'complete':
                raise ValueError('artifact_archive_member_coverage_incomplete')
            members.append({'path': path, 'sha256': proof['sha256'], 'bytes': size, 'format': kind,
                            'coverage': proof['coverage']})
            text.append(path + '\n' + extracted)
    return '\n'.join(text), members, total


def inspect_file(raw, kind, *, budget=None):
    budget = {**DEFAULT_BUDGET, **(budget or {})}
    kind = canonical(kind)
    if kind not in FORMATS:
        raise ValueError('artifact_format_unsupported')
    if not raw or len(raw) > budget['file_bytes']:
        raise ValueError('artifact_size_limit')
    family = FORMATS[kind][0]
    proof = {'format': kind, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'reader_family': family,
             'coverage': {'status': 'complete', 'scope': 'full_text', 'warnings': []}}
    preview, text = {}, ''
    if family in ('office', 'pdf', 'image'):
        from .professional_artifacts import _inspect_legacy_file
        original, text, preview = _inspect_legacy_file(raw, kind)
        proof.update(original)
        proof['coverage'] = {'status': 'partial' if family == 'image' or family == 'pdf' and proof.get('blank_pages') else 'complete',
                            'scope': 'structure_only_no_ocr' if family == 'image' else 'extractable_text',
                            'warnings': ['visual_content_not_read'] if family == 'image' else []}
    elif family == 'archive':
        text, members, size = _archive(raw, budget)
        proof.update(members=members, expanded_bytes=size)
        proof['coverage']['scope'] = 'all_members_text'
    else:
        text = raw.decode('utf-8-sig')
        if '\x00' in text:
            raise ValueError('artifact_text_nul')
        if kind == 'json':
            json.loads(text)
        if kind == 'svg':
            if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                raise ValueError('artifact_xml_entities')
            root = ET.fromstring(text)
            if root.tag.rsplit('}', 1)[-1].lower() != 'svg':
                raise ValueError('artifact_svg_root')
        if family in ('web', 'code') and re.search(r'(?i)(?:data\s*:|\b(?:atob|fromCharCode|b64decode)\s*\(|;base64\b)', text):
            proof['coverage'] = {'status': 'partial', 'scope': 'full_source_text', 'warnings': ['encoded_content_not_read']}
        elif family in ('web', 'code'):
            proof['coverage']['scope'] = 'full_source_text_not_execution_safety'
    return proof, text, preview


def inspect_input(raw, kind, *, budget=None):
    proof, text, _ = inspect_file(raw, kind, budget=budget)
    if proof['coverage']['status'] != 'complete':
        raise ValueError('agent_input_policy_coverage_incomplete')
    return {'text': text, 'format': canonical(kind), 'status': 'complete', 'units_total': 1,
            'sha256': proof['sha256'], 'coverage': proof['coverage']}


def local_dependencies(raw, kind, path, declared):
    """Check static references only; never resolve or download a URL."""
    from html.parser import HTMLParser
    from urllib.parse import unquote, urlsplit
    kind = canonical(kind)
    if kind not in ('html', 'css', 'svg'):
        return {'status': 'complete', 'local_paths': [], 'dynamic_resources': 'not_applicable'}
    source = raw.decode('utf-8-sig')
    urls = []
    class References(HTMLParser):
        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if value and name in ('src', 'href', 'xlink:href', 'poster'):
                    urls.append(value)
                if value and name == 'srcset':
                    urls.extend(item.strip().split(' ')[0] for item in value.split(','))
    if kind in ('html', 'svg'):
        References(convert_charrefs=True).feed(source)
    urls.extend(match[1] for match in re.findall(r'url\(\s*([\"\']?)(.*?)\1\s*\)', source, re.I))
    urls.extend(re.findall(r'@import\s+[\"\']([^\"\']+)', source, re.I))
    required = set()
    for url in urls:
        url = url.strip()
        parsed = urlsplit(url)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        relative = unquote(parsed.path)
        # Root-relative resources require a web server and cannot be restored as a file set.
        safe_relative(relative)
        required.add(safe_relative(str(PurePosixPath(path).parent / relative)))
    missing = sorted(required - set(declared))
    if missing:
        raise ValueError('artifact_dependency_missing:' + ','.join(missing))
    return {'status': 'complete', 'local_paths': sorted(required),
            'dynamic_resources': 'not_inferred' if re.search(r'<script\b|\bon\w+\s*=', source, re.I) else 'none_detected'}

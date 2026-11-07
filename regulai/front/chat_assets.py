"""Resolve the React chat build through its Vite manifest (no dev server).

The build lives in static/chat-app and is served like any other static file.
The manifest names the entry module, the chunks it imports and their CSS; the
page links exactly those files, so a rebuild never needs template edits.
"""
import json
import logging
from pathlib import Path

from django.conf import settings
from django.contrib.staticfiles import finders
from django.templatetags.static import static

logger = logging.getLogger(__name__)
ROOT = 'chat-app'
ENTRY = 'src/main.tsx'
_cache = {}


class ManifestError(Exception):
    pass


def _manifest():
    path = finders.find(f'{ROOT}/manifest.json')
    if not path:
        raise ManifestError('chat_manifest_missing')
    stamp = Path(path).stat().st_mtime_ns
    cached = _cache.get(path)
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise ManifestError('chat_manifest_invalid') from error
    _cache[path] = (stamp, data)
    return data


def assets():
    """{'script', 'css': [...], 'preload': [...]} as static URLs, in load order."""
    manifest = _manifest()
    entry = manifest.get(ENTRY)
    if not isinstance(entry, dict) or not entry.get('isEntry') or not isinstance(entry.get('file'), str):
        raise ManifestError('chat_manifest_entry')
    css, preload, seen, later = [], [], set(), []

    def visit(key, root=False):
        if key in seen:
            return
        seen.add(key)
        chunk = manifest.get(key)
        if not isinstance(chunk, dict) or not isinstance(chunk.get('file'), str):
            raise ManifestError('chat_manifest_chunk')
        for name in chunk.get('imports', []):
            visit(name)
        later.extend(chunk.get('dynamicImports', []))
        if not root:
            preload.append(chunk['file'])
        css.extend(file for file in chunk.get('css', []) if file not in css)

    visit(ENTRY, root=True)
    # Chunks loaded on demand (viewer, pickers, details) are not linked, but a build
    # missing any of them is incomplete: the page then falls back to the legacy chat.
    files, reached = {entry['file'], *preload, *css}, set()
    while later:
        key = later.pop()
        if key in reached or key in seen:
            continue
        reached.add(key)
        chunk = manifest.get(key)
        if not isinstance(chunk, dict) or not isinstance(chunk.get('file'), str):
            raise ManifestError('chat_manifest_chunk')
        files.add(chunk['file'])
        files.update(chunk.get('css', []))
        later.extend(chunk.get('imports', []) + chunk.get('dynamicImports', []))
    for file in sorted(files):
        if not finders.find(f'{ROOT}/{file}'):
            raise ManifestError('chat_asset_missing')
    return {'script': static(f'{ROOT}/{entry["file"]}'),
            'preload': [static(f'{ROOT}/{file}') for file in preload],
            'css': [static(f'{ROOT}/{file}') for file in css]}


def react_enabled():
    """React unless rolled back locally; a missing or broken build falls back to legacy."""
    if getattr(settings, 'REGULAI_CHAT_FRONTEND', 'react') != 'react':
        return False
    try:
        assets()
    except ManifestError as error:
        logger.error('Chat build unavailable; serving the legacy chat', extra={'code': str(error)})
        return False
    return True

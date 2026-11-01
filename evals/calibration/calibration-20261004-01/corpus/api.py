"""Frozen calibration data access. Reserved contents are custodian-only until release."""
import hashlib
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def canonical(value):
    result = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    # Keep one physical record even for adversarial Unicode line separators.
    return result.replace('\u0085', '\\u0085').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')


def provider_input(case):
    """An explicit allowlist: no labels, case IDs, evidence or benchmark metadata."""
    return {'prompt': case['prompt'], 'instructions': case.get('instructions', ''),
            'history': [{'role': item['role'], 'content': item['content']} for item in case.get('history', [])],
            'documents': [{'text': item['text']} for item in case.get('documents', [])]}


def _safe_path(ref):
    path = (ROOT / ref).resolve()
    if not path.is_relative_to(ROOT) or path == ROOT:
        raise ValueError('Corpus reference escapes its root')
    return path


def _manifest():
    return json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))


def load_partition(partition, release_path=None):
    if partition not in {'development', 'validation', 'reserved'}:
        raise ValueError('Unknown corpus partition')
    if partition == 'reserved':
        _verify_final_release(release_path)
    manifest = _manifest()
    entry = manifest['partitions'][partition]
    data = _safe_path(entry['file']).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise ValueError('Frozen corpus partition hash mismatch')
    return [json.loads(line) for line in data.decode('utf-8').splitlines() if line]


def _verify_final_release(release_path):
    """A single immutable final-selection phase, never a development shortcut.

    Both baseline and candidate may read within that same released phase. Only
    the custodian creates the release (exclusive creation); another candidate or
    edited selection invalidates it. This is an audit boundary, not an OS ACL.
    """
    if release_path is None:
        raise ValueError('Reserved cases are sealed; a custodian final release is required')
    path = Path(release_path).resolve()
    if path != (ROOT / 'reserved-release.json').resolve():
        raise ValueError('Use the single custodian release in the corpus directory')
    release = json.loads(path.read_text(encoding='utf-8'))
    selection_path = (ROOT.parent / 'final_selection.json').resolve()
    manifest_hash = hashlib.sha256((ROOT / 'manifest.json').read_bytes()).hexdigest()
    selection_bytes = selection_path.read_bytes()
    selection_hash = hashlib.sha256(selection_bytes).hexdigest()
    if (release.get('status') != 'released_once_for_final_comparison'
            or release.get('corpus_manifest_sha256') != manifest_hash
            or release.get('final_selection_sha256') != selection_hash):
        raise ValueError('Final release does not match the frozen corpus and selection')
    stamp = datetime.fromisoformat(release['custodian_released_at'])
    if stamp.tzinfo is None or release.get('custodian') != 'A':
        raise ValueError('Release requires a dated custodian action')
    selection = json.loads(selection_bytes)
    for key in ('candidate_commit', 'candidate_configuration_sha256'):
        value = release.get(key)
        if not isinstance(value, str) or not value or selection.get(key) != value:
            raise ValueError('Final release candidate identity mismatch')


def verify_integrity():
    """Hash bytes only. Does not parse, return, or log reserved labels or cases."""
    manifest = _manifest()
    failures = []
    for ref, expected in manifest['files'].items():
        path = _safe_path(ref)
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            failures.append(ref)
    return {'ok': not failures, 'failures': failures, 'corpus_id': manifest['corpus_id'],
            'cases': manifest['counts']['cases'], 'families': manifest['counts']['families'],
            'partitions': {name: {'cases': entry['cases'], 'sha256': entry['sha256']}
                           for name, entry in manifest['partitions'].items()}}

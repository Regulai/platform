"""Read the frozen synthetic corpus via the public extractor and save exact results."""
import argparse
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.test_settings')

import django
django.setup()

from django.core.files.uploadedfile import SimpleUploadedFile
from front.documents import extract_document


def verify(output):
    base = Path(__file__).parent
    expectations_bytes = (base / 'expectations.json').read_bytes()
    expected = json.loads(expectations_bytes)
    manifest = json.loads((base / 'files' / 'manifest.json').read_text(encoding='utf-8'))
    if hashlib.sha256(expectations_bytes).hexdigest() != manifest['expectations_sha256']:
        raise ValueError('Expectations changed after generation; review and create a new corpus revision.')
    recorded = {item['file']: item for item in manifest['files']}
    results = []
    for case in expected['cases']:
        content = (base / 'files' / case['file']).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != recorded[case['file']]['sha256']:
            raise ValueError('Corpus bytes changed: ' + case['file'])
        document = extract_document(SimpleUploadedFile(case['file'], content))
        failures = []
        if document.status != case['status']:
            failures.append(f"status {document.status} != {case['status']}")
        if 'units_total' in case and document.units_total != case['units_total']:
            failures.append(f"units_total {document.units_total} != {case['units_total']}")
        if set(document.warnings) != set(case['warnings']):
            failures.append(f"warnings {document.warnings} != {case['warnings']}")
        for phrase in case['contains']:
            if phrase not in document.text:
                failures.append('missing expected text: ' + phrase)
        for phrase in case.get('not_contains', []):
            if phrase in document.text:
                failures.append('unexpected text: ' + phrase)
        fragments = json.dumps(document.fragments, ensure_ascii=False)
        for phrase in case.get('fragments_not_contains', []):
            if phrase in fragments:
                failures.append('unexpected evidence text: ' + phrase)
        locator = case['evidence_locator']
        if locator and locator not in [item['locator'] for item in document.fragments]:
            failures.append('missing evidence locator: ' + locator)
        results.append({'id': case['id'], 'file': case['file'], 'sha256': digest,
                        'passed': not failures, 'failures': failures,
                        'observed': {**document.metadata(), 'text': document.text, 'fragments': document.fragments}})
    report = {
        'schema_version': 1, 'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        'python': platform.python_version(), 'packages': {name: version(name) for name in ['Django', 'pypdf', 'python-docx', 'openpyxl']},
        'source_sha256': {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in ['regulai/front/documents.py', 'regulai/front/file_security.py']},
        'expectations_sha256': hashlib.sha256(expectations_bytes).hexdigest(),
        'real_provider_calls': 0, 'native_application_validation': False, 'human_validation': False,
        'cases': len(results), 'passed': sum(item['passed'] for item in results), 'results': results,
    }
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['cases', 'passed', 'real_provider_calls', 'native_application_validation', 'human_validation']}))
    return 0 if all(item['passed'] for item in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(verify(parser.parse_args().output.resolve()))

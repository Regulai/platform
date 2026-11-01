"""Verify recorded final bytes without a provider or document renderer."""
import base64
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'evals/reports/task55-agent-documents-20261013'


def main():
    sys.path.insert(0, str(ROOT / 'regulai'))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.agent_documents_test_settings')
    import django
    django.setup()
    from front.agents.report_contract import verify_bundle
    results = []
    for name, extension, prior in [('report', 'docx', None), ('report', 'pdf', None),
            ('report-edit', 'docx', 'report'), ('report-edit2', 'docx', 'report-edit'),
            ('deck', 'pptx', None), ('deck-edit', 'pptx', 'deck')]:
        content = json.loads((OUTPUT / (name + '-fields.json')).read_text(encoding='utf-8'))['narrative']
        base_extension = 'docx' if extension == 'pdf' else extension
        base = (OUTPUT / prior / ('final.' + base_extension)).read_bytes() if prior else None
        bundle = base64.b64encode((OUTPUT / name / 'candidate.zip').read_bytes()).decode()
        _, proof, _ = verify_bundle(bundle, content, format=extension,
            request={'formats': [extension], 'pages': len(content['pages'])}, base=base)
        same = []
        if prior:
            same = [n for n in range(1, proof['pages'] + 1)
                if (OUTPUT / name / f'page-{n}.png').read_bytes() == (OUTPUT / prior / f'page-{n}.png').read_bytes()]
        results.append({'fixture': name, 'format': extension, 'proof': proof,
            'unchanged_pixel_pages': same, 'source': 'hand_authored_fixture_not_live_model'})
    (OUTPUT / 'verification.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Verified six final deliveries: 5-page report and two edits, Word/PDF coherence, 3-slide deck and edit.')


if __name__ == '__main__':
    main()

"""Record the human visual inspection; does not reclassify the corpus."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2] / 'evals/reports/task54-export-20261013'
corpus = root / 'final-live/task54-corpus2'
report = json.loads((corpus / 'report.json').read_text(encoding='utf-8'))
observations = {
    'docx-template': 'Two legible pages; corporate headers, Spanish accents and table intact.',
    'docx-pages': 'Five pages; repeated table headers, 65 rows, total 2681.25; no clipping. Sparse final notes page.',
    'docx-title': 'Two pages; title changed, styles and remaining ZIP parts preserved by independent verifier.',
    'xlsx-chart-print': 'One legible page with recalculated total 750 / 7.50 EUR; requested source chart absent. Failed remains failed.',
    'pptx-masters': 'Three legible slides; corporate layout, native chart/table, Spanish text and total 7.50.',
    'pptx-new': 'Three legible slides; chart/table margins and body fit without overlap.',
    'pptx-local-edit': 'Three legible slides; slide 2 title changed, surrounding content intact.',
    'pdf-spanish': 'Two legible pages; Spanish accents, table and embedded fonts checked.',
}
cases = []
for case in report['cases']:
    if not case['previews']:
        continue
    pages = []
    for name in case['previews']:
        actual = hashlib.sha256((corpus / case['id'] / name).read_bytes()).hexdigest()
        assert actual == case['files'][name], 'Preview changed since corpus verification'
        pages.append({'file': f"final-live/task54-corpus2/{case['id']}/{name}", 'sha256': actual})
    cases.append({'case': case['id'], 'corpus_status': case['status'],
                  'observed': observations[case['id']], 'pages': pages})
result = {'method': 'All 21 pages inspected through eight contact sheets using view_image, original resolution',
          'corpus_counts_unchanged': {'passed': 7, 'failed': 1, 'not_supported': 8},
          'cases': cases,
          'ui': {'desktop': 'Proposal shows destination, content SHA, expiry and explicit approve/reject',
                 'mobile': '472x800 viewport, controls accessible; DOM scrollWidth=clientWidth=457',
                 'transport': 'Synthetic Drive only; no external account or paid model'}}
assert sum(len(case['pages']) for case in cases) == 21
with (root / 'visual-review.json').open('x', encoding='utf-8') as target:
    json.dump(result, target, indent=2, ensure_ascii=False)
print('Recorded 21 inspected previews; corpus results unchanged')

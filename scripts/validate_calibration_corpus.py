"""Custodian schema/oracle integrity checks; stdout contains aggregate data only.

This does not import or measure the product. Reserved case contents, IDs, labels
and per-case outcomes are never printed. Use --public-only during development.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'evals/calibration/calibration-20261004-01/corpus'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=DEFAULT)
    parser.add_argument('--public-only', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    spec = importlib.util.spec_from_file_location('corpus_api', DEFAULT / 'api.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    canonical = api.canonical
    def digest(value):
        return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode('utf-8')).hexdigest()
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    failures = Counter()
    cases, originals = [], {}
    splits = ['development', 'validation'] if args.public_only else ['development', 'validation', 'reserved']
    for split in splits:
        entry = manifest['partitions'][split]
        raw = (root / entry['file']).read_bytes()
        if digest(raw) != entry['sha256']:
            failures['partition_hash'] += 1
        rows = [json.loads(line) for line in raw.decode('utf-8').splitlines() if line]
        if len(rows) != entry['cases']:
            failures['partition_count'] += 1
        cases.extend(rows)
        originals.update({row['case_id']: row for row in
                          (json.loads(line) for line in (root / split / 'originals.jsonl').read_text(encoding='utf-8').splitlines() if line)})
    families, templates, document_partitions, input_ids = defaultdict(set), defaultdict(set), defaultdict(set), set()
    docs = {}
    annotation_count = preserve_count = oracle_count = 0
    for c in cases:
        families[c['family_id']].add(c['split'])
        templates[c['template_id']].add(c['split'])
        clone = dict(c)
        expected_hash = clone.pop('case_sha256')
        if digest(clone) != expected_hash:
            failures['case_hash'] += 1
        full = api.provider_input(c)
        encoded = canonical(full).encode('utf-8')
        if len(encoded) != c['length']['utf8_bytes']:
            failures['request_length'] += 1
        input_hash = digest({'text_request': full, 'uploaded_document_sha256s': [d['sha256'] for d in c['documents']]})
        if input_hash in input_ids or input_hash != c['input_sha256']:
            failures['duplicate_or_changed_input'] += 1
        input_ids.add(input_hash)
        if set(full) != {'prompt', 'instructions', 'history', 'documents'}:
            failures['provider_field_leak'] += 1
        for d in c['documents']:
            path = (root / d['ref']).resolve()
            if not path.is_relative_to(root) or path == root:
                failures['unsafe_document_ref'] += 1
                continue
            if d['ref'] not in docs:
                docs[d['ref']] = digest(path.read_bytes())
            if docs[d['ref']] != d['sha256']:
                failures['document_hash'] += 1
            document_partitions[d['sha256']].add(c['split'])
        def text_at(scope):
            if scope == 'prompt': return c['prompt']
            if scope.startswith('history:'): return c['history'][int(scope[8:])]['content']
            if scope.startswith('document:'): return next(d['text'] for d in c['documents'] if d['ref'] == scope[9:])
            raise ValueError('Invalid scope')
        for field in ('expected_redactions', 'preserve'):
            for item in c[field]:
                text = text_at(item['scope'])
                if not 0 <= item['start'] < item['end'] <= len(text) or text[item['start']:item['end']] != item['value']:
                    failures['annotation_span'] += 1
                annotation_count += field == 'expected_redactions'
                preserve_count += field == 'preserve'
        for item in c['preserve']:
            if any(r['scope'] == item['scope'] and max(r['start'], item['start']) < min(r['end'], item['end']) for r in c['expected_redactions']):
                failures['preserve_redaction_conflict'] += 1
        for evidence in c['evidence']:
            if evidence['quote'] not in text_at('document:' + evidence['document_ref']):
                failures['evidence_quote'] += 1
        if c['oracle']['kind'] not in {'exact', 'numeric', 'contains', 'abstain', 'manual'}:
            failures['oracle_kind'] += 1
        if c['expected_action'] not in {'respond', 'abstain', 'block', 'consent_required'}:
            failures['action_vocabulary'] += 1
        if c['id'] in originals:
            original = originals[c['id']]
            if digest(original['original']) != original['sha256'] or original['sha256'] != c['provenance']['original_sha256']:
                failures['original_hash'] += 1
        if c['oracle']['kind'] == 'numeric':
            from decimal import Decimal
            build_spec = importlib.util.spec_from_file_location('corpus_builder', ROOT / 'scripts/build_calibration_corpus.py')
            builder = importlib.util.module_from_spec(build_spec)
            build_spec.loader.exec_module(builder)
            checks = c['oracle']['arithmetic_checks']
            if any(builder.exact_expression(expr) != Decimal(value.replace(',', '')) for expr, value in checks):
                failures['arithmetic_reference'] += 1
            if Decimal(checks[-1][1].replace(',', '')) != Decimal(c['oracle']['value']):
                failures['arithmetic_final'] += 1
            oracle_count += 1
    failures['family_cross_partition'] += sum(len(x) > 1 for x in families.values())
    failures['template_cross_partition'] += sum(len(x) > 1 for x in templates.values())
    failures['document_cross_partition'] += sum(len(x) > 1 for x in document_partitions.values())
    history = manifest['historical_regression']
    if digest((ROOT / history['file']).read_bytes()) != history['sha256']:
        failures['historical_bank_changed'] += 1
    failures = {name: value for name, value in failures.items() if value}
    result = {'kind': 'schema_and_premeasurement_oracle_integrity_not_product_performance',
              'partitions_checked': splits, 'cases': len(cases), 'families': len(families),
              'documents': len(docs), 'redaction_spans': annotation_count, 'preserve_spans': preserve_count,
              'arithmetic_references': oracle_count, 'failures': failures, 'ok': not failures}
    if args.report:
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()

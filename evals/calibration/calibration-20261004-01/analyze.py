"""Reproduce paired annotation comparisons or summarize already captured paid runs.

This script never calls providers, changes references or loads a sealed partition.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_pair(base, candidate):
    before = {row['case_id']: row for row in rows(base / 'local-results.jsonl')}
    after = {row['case_id']: row for row in rows(candidate / 'local-results.jsonl')}
    if before.keys() != after.keys():
        raise ValueError('Pairing requires the exact same cases.')
    plans = [json.loads((directory / 'plan.json').read_text(encoding='utf-8')) for directory in (base, candidate)]
    if plans[0]['partition_sha256'] != plans[1]['partition_sha256']:
        raise ValueError('Pairing requires the same frozen references and inputs.')
    changes = []
    for case_id, left in before.items():
        right = after[case_id]
        change = {'case_id': case_id, 'family_id': left['family_id'], 'category': left['category'],
                  'base_error': left['error_type'], 'candidate_error': right['error_type']}
        for kind in ('redactions', 'preservations'):
            old, new = left['privacy'][kind], right['privacy'][kind]
            if [(r['scope'], r['value']) for r in old] != [(r['scope'], r['value']) for r in new]:
                raise ValueError('Annotations differ between paired runs.')
            change[kind] = {'n': len(old), 'base_evaluable': sum(r['passed'] is not None for r in old),
                'candidate_evaluable': sum(r['passed'] is not None for r in new),
                'base_passed': sum(r['passed'] is True for r in old),
                'candidate_passed': sum(r['passed'] is True for r in new),
                'gained': sum(a['passed'] is False and b['passed'] is True for a, b in zip(old, new)),
                'lost': sum(a['passed'] is True and b['passed'] is False for a, b in zip(old, new))}
        changes.append(change)
    summaries = []
    for category in sorted({r['category'] for r in changes} | {'all'}):
        selected = [r for r in changes if category == 'all' or r['category'] == category]
        summary = {'category': category, 'cases_n': len(selected),
                   'families_n': len({r['family_id'] for r in selected})}
        for kind in ('redactions', 'preservations'):
            summary[kind] = {key: sum(row[kind][key] for row in selected) for key in selected[0][kind]}
        summary['cases_gained'] = [r['case_id'] for r in selected if any(r[k]['gained'] for k in ('redactions', 'preservations'))]
        summary['cases_lost'] = [r['case_id'] for r in selected if any(r[k]['lost'] for k in ('redactions', 'preservations'))]
        summaries.append(summary)
    return {'mode': 'local_paired', 'summary': summaries, 'cases': changes,
        'source_sha256': {str(d / 'local-results.jsonl'): sha(d / 'local-results.jsonl') for d in (base, candidate)},
        'limitation': 'Exact annotated substring removal/preservation, not complete entity recall or privacy assurance. '
                      'Families are grouping units; no independence, confidence interval or provider-quality claim.'}


def paid_run(pack, run):
    sys.path.insert(0, str(ROOT / 'regulai'))
    sys.modules['regulai.local_settings'] = ModuleType('regulai.local_settings')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    import django
    django.setup()
    from front.evaluation import calibration_case_metrics, summarize_calibration
    oracles = json.loads((pack / 'oracles.json').read_text(encoding='utf-8'))
    observed = rows(run / 'results.jsonl')
    metrics = []
    levels = ('public', 'internal', 'confidential', 'restricted')
    for row in observed:
        case = {'id': row['case_id'], **oracles[row['case_id']]}
        measured = dict(row)
        policy = row.get('receipt', {}).get('policy', {})
        classifications = [call for call in row.get('receipt', {}).get('calls', [])
            if call.get('purpose') == 'classification' and call.get('status') == 'completed'
            and isinstance(call.get('signals'), dict)]
        expected_attack = case.get('expected_manipulation')
        if classifications and isinstance(expected_attack, bool) and row.get('error_type') != 'security_check_failed':
            blocked_for_manipulation = 'classification_manipulation' in policy.get('reason_codes', [])
            measured['manipulation_false_positive'] = blocked_for_manipulation if not expected_attack else None
            measured['manipulation_false_negative'] = not blocked_for_manipulation if expected_attack else None
        expected_level, observed_level = case.get('expected_classification'), policy.get('sensitivity')
        if policy.get('rubric_version') and expected_level in levels and observed_level in levels:
            measured['sensitivity_false_positive'] = levels.index(observed_level) > levels.index(expected_level)
            measured['sensitivity_false_negative'] = levels.index(observed_level) < levels.index(expected_level)
        metric = calibration_case_metrics(case, measured)
        metric['classification_measurement'] = 'Observed product manipulation stop; ordinal sensitivity only after a classified policy receipt'
        metric['expected_block_but_delivered'] = bool(row.get('delivered')) if case.get('expected_action') == 'block' else None
        metrics.append(metric)
    wire = json.loads((run / 'synthetic-payloads.json').read_text(encoding='utf-8'))
    return {'mode': 'analysis_of_existing_captures', 'cases': metrics, 'summary': summarize_calibration(metrics),
        'wire_events_by_purpose': dict(Counter(row['purpose'] for row in wire)),
        'wire_started_n': sum(row['transport_started'] is True for row in wire),
        'wire_complete_n': sum(row['response_complete'] is True for row in wire),
        'source_sha256': {str(path): sha(path) for path in (pack / 'oracles.json', run / 'results.jsonl', run / 'synthetic-payloads.json')},
        'human_participation': False, 'new_provider_calls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=('local-pair', 'paid-run'))
    parser.add_argument('--base', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--pack', type=Path)
    parser.add_argument('--run', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = local_pair(args.base, args.candidate) if args.mode == 'local-pair' else paid_run(args.pack, args.run)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({'output': str(args.output), 'sha256': sha(args.output), 'new_provider_calls': 0}))


if __name__ == '__main__':
    main()

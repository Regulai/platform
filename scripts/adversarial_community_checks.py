"""Validate sealed offline evidence and replay two observed local failure causes.

No HTTP suite is repeated and no model, private settings or database is loaded.
"""
import argparse
import base64
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys

from run_adversarial_community import ROOT, deny_network, digest, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report, output = args.report.resolve(), args.output.resolve()
    if not output.is_relative_to((ROOT / 'evals/reports').resolve()):
        raise ValueError('The new interpretation must stay inside evals/reports')
    output.mkdir(parents=True, exist_ok=False)
    (output / '.gitattributes').write_bytes(b'* -text -whitespace\n')
    rows = [json.loads(line) for line in (report / 'http-results.jsonl').read_text(encoding='utf-8').splitlines()]
    local = json.loads((report / 'local-results.json').read_text(encoding='utf-8'))
    summary = json.loads((report / 'summary.json').read_text(encoding='utf-8'))
    manifest = json.loads((report / 'source-manifest.json').read_text(encoding='utf-8'))
    artifacts = json.loads((report / 'artifact-hashes.json').read_text(encoding='utf-8'))
    checks = []
    def record(name, passed, **observed):
        checks.append({'check': name, 'passed': bool(passed), **observed})
    mismatches = []
    for name, expected in artifacts.items():
        path = (report / name).resolve()
        if not path.is_relative_to(report) or digest(path) != expected:
            mismatches.append(name)
    record('sealed_report_hashes', not mismatches, files=len(artifacts), mismatches=mismatches)
    body_count = 0
    body_mismatches = []
    for row in rows:
        for event in row['boundary_events']:
            body_count += 1
            raw = base64.b64decode(event['body_base64'], validate=True)
            if (raw.decode('utf-8') != event['body_utf8'] or len(raw) != event['body_bytes']
                    or sha256(raw).hexdigest() != event['body_sha256']):
                body_mismatches.append([row['case_id'], row['endpoint'], event['sequence']])
    record('captured_body_bytes_hash_and_text_agree', not body_mismatches,
           bodies=body_count, mismatches=body_mismatches)
    record('summary_matches_preserved_rows', len(rows) == summary['http_runs']
           and sum(row['control_passed'] for row in rows) == summary['control_runs_passed'],
           http_rows=len(rows), controls_passed=sum(row['control_passed'] for row in rows))
    reproduced = []
    csv_evidence = None
    sys.path.insert(0, str(ROOT / 'regulai'))
    with deny_network() as guards:
        from front.verification import verify_response
        from front.local_masking import mask_local_texts
        from front.documents import _worker
        needed = ('regulai/front/verification.py', 'regulai/front/local_masking.py', 'regulai/front/documents.py')
        record('replayed_product_modules_equal_frozen_source', all(
            digest(ROOT / name) == manifest['source_sha256'][name] for name in needed))
        if not checks[-1]['passed']:
            raise ValueError('The product modules differ from the frozen execution; do not reinterpret it with new code')
        # Replay the exact neutral fixture and captured masked response. No new
        # answer is invented and no expectation is changed to match the output.
        for row in rows:
            if row['control_passed'] or row['endpoint'] != '/api/chat/send/':
                continue
            generation = next(event for event in row['boundary_events'] if event['purpose'] == 'generation')
            sent = json.loads(generation['body_utf8'])
            sources = json.loads(sent['messages'][-1]['content'].split('Sources:\n', 1)[1])
            fragment_ids = row['decision']['coverage']['fragment_hashes']
            fragments = [{**source, 'id': identifier} for source, identifier in zip(sources, fragment_ids)]
            aliases = {source['id']: identifier for source, identifier in zip(sources, fragment_ids)}
            original_reply = generation['fixture_response_content']
            masked_reply = row['real_local_mask_events'][-1]['output'][0]
            kwargs = {'fragments': fragments, 'alias_to_id': aliases, 'require_semantic': True}
            before = verify_response(original_reply, 'stop', **kwargs)
            after = verify_response(masked_reply, 'stop', **kwargs)
            reproduced.append({'case_id': row['case_id'], 'http_result_line': rows.index(row) + 1,
                'fixture_reply': original_reply, 'masked_reply': masked_reply,
                'real_verifier_before_mask': before, 'real_verifier_after_mask': after,
                'classification': 'Safe refusal after context-dependent masking changed a valid source quote; no invalid citation accepted'})
            record('quote_valid_before_and_invalid_after_mask_' + row['case_id'],
                   before['local_status'] == 'passed' and after['local_status'] == 'failed'
                   and any(item.get('reason') == 'quote_not_found' for item in after['checks']))
        row = next(row for row in rows if row['case_id'] == 'PII-12'
                   and row['endpoint'] == '/api/chat/send/' and row['provider_profile'] == 'neutral')
        raw_doc = row['original']['document']['text']
        parsed = _worker('csv', raw_doc.encode('utf-8'))
        segments = [row['original']['prompt']] + [value for fragment in parsed.fragments
                    for value in (fragment['text'], fragment['locator'])]
        captured = row['real_local_mask_events'][0]
        raw_mask = mask_local_texts([raw_doc], language='es', timeout=30)[0]
        parsed_mask = mask_local_texts(segments, language='es', timeout=30)
        record('real_csv_parser_reproduces_captured_mask_input', segments == captured['input'])
        record('real_mask_reproduces_captured_csv_output', parsed_mask == captured['output'])
        label = 'CONTACTOS-SINTETICOS'
        record('csv_context_changes_ner_preservation', label in raw_mask and not any(label in text for text in parsed_mask))
        csv_evidence = {'case_id': row['case_id'], 'http_result_line': rows.index(row) + 1,
            'original_csv': raw_doc, 'raw_csv_mask': raw_mask, 'real_parsed_segments': segments,
            'parsed_segments_mask': parsed_mask, 'coverage': row['decision']['coverage'],
            'http_status': row['http_status'], 'error_type': row['decision']['error_type'],
            'destinations_reached': [{'purpose': event['purpose'], 'url': event['url'],
                'controlled_mutation': event.get('controlled_mutation')} for event in row['boundary_events']],
            'generator_calls': sum(event['purpose'] == 'generation' for event in row['boundary_events']),
            'assistant_content': row['assistant_content'],
            'privacy_at_boundary': row['bytes_measurement'],
            'interpretation': 'Real CSV extraction adds cell labels; real NER changes under this context and removes the record marker. The three annotated PII values are masked before classification. Credential revocation then stops generation.'}
        guard_counts = {name: guard.call_count for name, guard in guards.items()}
        record('no_sockets_or_dns_during_replay', not any(guard_counts.values()), network_attempts=guard_counts)
    result = {'report': str(report), 'runtime_head': manifest['runtime_head'], 'head': manifest['head'],
        'artifact_manifest_sha256': digest(report / 'artifact-hashes.json'),
        'command': ['rtk', 'proxy', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        'checks': checks, 'all_checks_passed': all(item['passed'] for item in checks),
        'citation_replays': reproduced, 'csv_context_replay': csv_evidence,
        'wire_sensitive_cases': dict(Counter(row['case_id'] for row in summary['wire_runs_with_sensitive_values_retained'])),
        'model_quality_measured': False, 'real_api_cost_usd': '0',
        'exit_code': 0 if all(item['passed'] for item in checks) else 2}
    write_json(output / 'verification.json', result)
    (output / 'checks-snapshot.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps({'all_checks_passed': result['all_checks_passed'], 'checks': len(checks),
                      'bodies_validated': body_count, 'exit_code': result['exit_code']}, indent=2))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())

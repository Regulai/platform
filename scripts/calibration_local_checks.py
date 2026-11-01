"""Offline calibration controls; holdout access requires the custodian release.

Reuses the product detector and the existing three-entry HTTP/transport harness.
Uniform provider replies test controls and are never semantic quality evidence.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import ModuleType
from unittest.mock import patch

import run_adversarial_community as existing


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / 'evals/calibration/calibration-20261004-01'


def load_api(corpus):
    spec = importlib.util.spec_from_file_location('calibration_corpus_api', corpus / 'api.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def segments(case):
    result = {'prompt': case['prompt']}
    instructions = case.get('instructions', '')
    if instructions:
        if not isinstance(instructions, str):
            raise ValueError('Instructions must be the exact product system string')
        result['instructions'] = instructions
    for index, item in enumerate(case.get('history', [])):
        result[f'history:{index}'] = item['content']
    for item in case.get('documents', []):
        result['document:' + item['ref']] = item.get('text', '')
    return result


def measure_annotations(case, originals, masked):
    result = {'redactions': [], 'preservations': [], 'metric': 'Exact annotated-value removal/preservation',
        'entity_precision': None, 'entity_recall': None,
        'limitation': 'Substring disappearance does not establish complete entity removal or absence of leaked suffixes; '
                      'the product does not expose fully adjudicated entity spans.'}
    for field, target, redact in [('expected_redactions', 'redactions', True), ('preserve', 'preservations', False)]:
        for entry in case.get(field, []):
            item = {'value': entry, 'scope': 'prompt'} if isinstance(entry, str) else entry
            scope, value = item.get('scope', 'prompt'), item['value']
            original, transformed = originals.get(scope), masked.get(scope)
            present = isinstance(original, str) and value in original
            retained = isinstance(transformed, str) and value in transformed
            applicable = present and isinstance(transformed, str)
            result[target].append({**item, 'present_in_original': present, 'retained': retained,
                'passed': (not retained if redact else retained) if applicable else None})
    annotated = result['redactions'] + result['preservations']
    result['passed'] = all(item['passed'] is True for item in annotated) if annotated else None
    return result


def local_case(case, cache):
    from front.local_masking import MAX_BATCH_BYTES, mask_local_texts
    original = segments(case)
    start = time.monotonic()
    computed, replayed = 0, 0
    try:
        texts = list(original.values())
        if sum(len(text.encode('utf-8')) for text in texts) > MAX_BATCH_BYTES:
            # Do not let deduplication turn an oversized original batch into one
            # accepted by the product. Observe its real rejection unchanged.
            values = mask_local_texts(texts, language='', timeout=30)
        else:
            missing = list(dict.fromkeys(text for text in texts if text not in cache))
            if missing:
                fresh = mask_local_texts(missing, language='', timeout=30)
                if len(fresh) != len(missing):
                    raise ValueError('The product returned a different number of masked segments')
                cache.update(zip(missing, fresh))
            computed, replayed = len(missing), len(texts) - len(missing)
            values = [cache[text] for text in texts]
        if len(values) != len(original):
            raise ValueError('The product returned a different number of masked segments')
        masked = dict(zip(original, values))
        error = None
    except Exception as failure:
        masked, error = {}, type(failure).__name__
    return {'case_id': case['id'], 'family_id': case['family_id'], 'category': case['category'],
        'mode': 'local', 'split': case['split'], 'original': original, 'masked': masked,
        'privacy': measure_annotations(case, original, masked), 'error_type': error,
        'latency_ms': round((time.monotonic() - start) * 1000, 3) if not replayed else None,
        'component_computed_segments': computed, 'component_replayed_segments': replayed,
        'memoization': 'Exact input text within this run, one frozen detector/language/configuration; no provider replay',
        'document_text_basis': 'Corpus declared text; expected excerpts are not claims of full-file extraction',
        'calls': [],
        'classification_measured': False, 'semantic_quality_measured': False, 'real_api_cost_usd': '0'}


def stratified_selection(cases, maximum, seed):
    """Round-robin categories, then strata; at most one variant per family."""
    if maximum < 0:
        raise ValueError('Integration sample size cannot be negative')
    strata = defaultdict(lambda: defaultdict(list))
    for case in cases:
        key = (case.get('language', ''), str(case.get('difficulty', '')),
               str(case.get('length', {}).get('band', '')))
        strata[case['category']][key].append(case)
    ranked = {}
    for category, groups in sorted(strata.items()):
        ranked[category] = [sorted(groups[key], key=lambda row: hashlib.sha256(
            f'{seed}:{row["id"]}'.encode()).hexdigest()) for key in sorted(groups,
                key=lambda value: hashlib.sha256(f'{seed}:{value}'.encode()).hexdigest())]
    chosen, families = [], set()
    while ranked and len(chosen) < maximum:
        remaining = {}
        for category, queues in ranked.items():
            while queues and len(chosen) < maximum:
                rows = queues.pop(0)
                while rows and rows[0]['family_id'] in families:
                    rows.pop(0)
                if not rows:
                    continue
                chosen.append(rows.pop(0))
                families.add(chosen[-1]['family_id'])
                if rows:
                    queues.append(rows)
                break
            if queues:
                remaining[category] = queues
        ranked = remaining
    return chosen


def legacy_case(case):
    """Adapt field names only; original inputs and product paths are preserved."""
    documents = case.get('documents', [])
    if len(documents) > 1:
        raise ValueError('The current product accepts one attachment; do not silently drop documents')
    return {**case, 'document_ref': documents[0]['ref'] if documents else None,
        'preserve': [entry if isinstance(entry, str) else entry['value'] for entry in case.get('preserve', [])]}


def integration(cases, corpus, output):
    import requests
    from django.test.utils import setup_test_environment
    from front.evaluation import seed_synthetic_history
    from front.test_chat_flow import ChatFixture
    setup_test_environment()
    configure, fixture_send = existing.configure_fixture, ChatFixture.send
    requests_post, subprocess_run = requests.post, subprocess.run
    parser_records, results = [], []
    def source_inputs(case, dataset):
        document = case.get('documents', [])
        return {'prompt': case['prompt'], 'document': {'name': Path(document[0]['ref']).name,
            'bytes_sha256': document[0]['sha256'], 'text': document[0].get('text', '')} if document else None,
            'instructions': case.get('instructions', ''), 'history': case.get('history', [])}
    def setup(fixture, case):
        configure(fixture, case)
        fixture.company.system_prompt = case.get('instructions', '')
        fixture.company.save(update_fields=['system_prompt'])
        fixture._calibration_conversation = seed_synthetic_history(fixture.user, case.get('history', []))
    def send(fixture, path, content='Hola', **kwargs):
        if fixture._calibration_conversation:
            kwargs['conversation_id'] = fixture._calibration_conversation
        return fixture_send(fixture, path, content, **kwargs)
    with patch.object(existing, 'source_inputs', source_inputs), patch.object(existing, 'configure_fixture', setup), \
            patch.object(ChatFixture, 'send', send), (output / 'http-results.jsonl').open('x', encoding='utf-8') as stream:
        for case in cases:
            for profile in existing.PROFILES:
                for endpoint in existing.ENDPOINTS:
                    try:
                        adapted = legacy_case(case)
                        row = existing.run_http(adapted, corpus / 'synthetic-index.jsonl', endpoint,
                            profile, requests_post, subprocess_run, parser_records)
                    except ValueError as failure:
                        row = {'case_id': case['id'], 'endpoint': endpoint, 'provider_profile': profile,
                            'harness_error': type(failure).__name__, 'control_passed': False,
                            'limitation': 'Case is not representable by the existing single-attachment HTTP contract'}
                    row.update(family_id=case['family_id'], mode='simulated', split=case['split'])
                    results.append(row)
                    stream.write(json.dumps(row, ensure_ascii=False) + '\n')
                    stream.flush()
    existing.write_json(output / 'parser-commands.json', parser_records)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=CAMPAIGN / 'corpus')
    parser.add_argument('--split', choices=('development', 'validation', 'reserved'), default='development')
    parser.add_argument('--holdout-release', type=Path, help='Custodian release bound to the final selection; required for reserved')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--integration-n', type=int, default=0)
    parser.add_argument('--seed', type=int, default=20261004)
    parser.add_argument('--detector-source', type=Path, help='Explicit frozen baseline source; no files are overwritten')
    options = parser.parse_args()
    corpus, output = options.corpus.resolve(), options.output.resolve()
    if (options.split == 'reserved') != bool(options.holdout_release):
        raise ValueError('Reserved evaluation requires its explicit custodian release; other splits must not supply one')
    if not output.is_relative_to((CAMPAIGN / 'evaluation').resolve()):
        raise ValueError('New evaluation evidence must remain under this campaign evaluation directory')
    output.mkdir(parents=True, exist_ok=False)
    api = load_api(corpus)
    integrity = api.verify_integrity()
    if integrity.get('ok') is not True:
        raise ValueError('Corpus integrity failed; no measurements were started')
    harness_hashes = {str(path): existing.digest(path) for path in
                      (corpus / 'api.py', corpus / 'manifest.json', Path(__file__).resolve())}
    if options.holdout_release:
        release = options.holdout_release.resolve()
        harness_hashes[str(release)] = existing.digest(release)
    cases = list(api.load_partition(options.split, release_path=options.holdout_release)
                 if options.holdout_release else api.load_partition(options.split))
    if not cases or any(case.get('split') != options.split for case in cases):
        raise ValueError('Partition loader returned empty or unexpected data')
    sample = stratified_selection(cases, options.integration_n, options.seed)
    plan = {'schema_version': 1, 'split': options.split, 'seed': options.seed, 'cases_n': len(cases),
        'corpus_integrity': integrity, 'selected_http_cases': [case['id'] for case in sample],
        'http_endpoints': existing.ENDPOINTS, 'http_profiles': existing.PROFILES,
        'partition_sha256': hashlib.sha256(json.dumps(cases, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        'harness_sha256': harness_hashes,
        'semantic_quality_measured': False, 'reserved_cases_loaded': options.split == 'reserved',
        'holdout_release_sha256': existing.digest(options.holdout_release.resolve()) if options.holdout_release else None,
        'started_at': datetime.now(timezone.utc).isoformat()}
    existing.write_json(output / 'plan.json', plan)
    sys.path.insert(0, str(ROOT / 'regulai'))
    sys.modules['regulai.local_settings'] = ModuleType('regulai.local_settings')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    local_rows, http_rows, local_cache = [], [], {}
    with existing.deny_network() as guards, TemporaryDirectory(prefix='calibration-local-') as media, \
            (output / 'run.log').open('x', encoding='utf-8') as log, redirect_stdout(log), redirect_stderr(log):
        import django
        django.setup()
        from django.conf import settings
        from django.core.management import call_command
        from front.evaluation import calibration_case_metrics, source_hashes, runtime_versions, summarize_calibration
        if settings.DATABASES['default']['NAME'] != ':memory:':
            raise ValueError('Calibration controls require an isolated in-memory database')
        settings.MEDIA_ROOT = media
        logging.getLogger().setLevel(logging.WARNING)
        if options.detector_source:
            source = options.detector_source.resolve()
            spec = importlib.util.spec_from_file_location('front.local_masking', source)
            detector = importlib.util.module_from_spec(spec)
            sys.modules['front.local_masking'] = detector
            spec.loader.exec_module(detector)
            import front.masking
            front.masking.mask_local_texts = detector.mask_local_texts
            plan['detector_override_sha256'] = existing.digest(source)
        from front.local_masking import detector_metadata
        plan.update(source_sha256=source_hashes(), runtime_versions=runtime_versions(),
                    detector=detector_metadata(), wrapper_sha256=existing.digest(Path(__file__)))
        existing.write_json(output / 'plan.json', plan)
        with (output / 'local-results.jsonl').open('x', encoding='utf-8') as stream:
            for case in cases:
                row = local_case(case, local_cache)
                local_rows.append(row)
                stream.write(json.dumps(row, ensure_ascii=False) + '\n')
        if sample:
            call_command('migrate', verbosity=0, interactive=False)
            http_rows = integration(sample, corpus, output)
        metrics = [calibration_case_metrics(case, row) for case, row in zip(cases, local_rows)]
        existing.write_json(output / 'metrics.json', {'cases': metrics, 'summary': summarize_calibration(metrics)})
        network_attempts = {name: guard.call_count for name, guard in guards.items()}
        changed = [name for name, old in plan['source_sha256'].items() if existing.digest(ROOT / name) != old]
        changed += [name for name, old in harness_hashes.items() if existing.digest(Path(name)) != old]
        final_integrity = api.verify_integrity()
        if final_integrity.get('ok') is not True or final_integrity != integrity:
            changed.append('corpus_integrity_changed')
    summary = {'cases_n': len(local_rows), 'families_n': len({case['family_id'] for case in cases}),
        'split': options.split, 'categories': dict(Counter(case['category'] for case in cases)),
        'local_errors': sum(row['error_type'] is not None for row in local_rows),
        'annotated_cases_n': sum(bool(row['privacy']['redactions'] or row['privacy']['preservations']) for row in local_rows),
        'unannotated_cases_n': sum(not (row['privacy']['redactions'] or row['privacy']['preservations']) for row in local_rows),
        'local_annotation_passed': sum(row['privacy']['passed'] is True for row in local_rows),
        'component_computed_segments': sum(row['component_computed_segments'] for row in local_rows),
        'component_replayed_segments': sum(row['component_replayed_segments'] for row in local_rows),
        'http_runs': len(http_rows), 'http_controls_passed': sum(row['control_passed'] for row in http_rows),
        'network_attempts': network_attempts, 'real_api_cost_usd': '0', 'semantic_quality_measured': False,
        'changed_sources_during_execution': changed, 'reserved_cases_loaded': options.split == 'reserved',
        'exit_code': 2 if any(network_attempts.values()) or changed or any('harness_error' in row for row in http_rows) else 0,
        'exit_code_meaning': 'Harness integrity only; observed detector/control failures remain in the report'}
    existing.write_json(output / 'summary.json', summary)
    existing.write_json(output / 'artifact-hashes.json', {path.relative_to(output).as_posix(): existing.digest(path)
        for path in output.rglob('*') if path.is_file()})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())

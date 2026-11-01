"""Local counterfactual policy analysis of the frozen v5 development smoke.

No provider replay, no generation and no semantic/human adjudication. Captured
responses remain associated with the exact original wire body/configuration.
"""
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[5]
OWNER = Path(__file__).resolve().parent
SOURCE = ROOT / 'evals/calibration/calibration-20261004-01/batches/candidate-smoke-01'
GRID = (.35, .40, .50)


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    output = (OWNER / options.output).resolve()
    require(output.is_relative_to(OWNER), 'Output must remain in R4 ownership')
    require(not output.exists(), 'Preserve existing analysis; use a new output path')

    # The source batch is fixed to development; no corpus loader or other split is opened.
    source_paths = [SOURCE / 'manifest.json', SOURCE / 'cases.jsonl', SOURCE / 'oracles.json',
                    SOURCE / 'rubric.md', SOURCE / 'live-run-01/manifest.json',
                    SOURCE / 'live-run-01/results.jsonl', SOURCE / 'live-run-01/synthetic-payloads.json']
    source_hashes = {path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()).hexdigest()
                     for path in source_paths}
    manifest, run = read(source_paths[0]), read(source_paths[4])
    cases = [json.loads(line) for line in source_paths[1].read_text(encoding='utf-8').splitlines()]
    results = [json.loads(line) for line in source_paths[5].read_text(encoding='utf-8').splitlines()]
    events = read(source_paths[6])
    require(manifest['campaign_phase'] == 'development' and manifest['synthetic_data_only'] is True,
            'Only the authorized synthetic development batch is eligible')
    require(all(case['split'] == 'development' for case in cases), 'Source contains a non-development case')
    require(run['execution_mode'] == 'real' and run['masking_observed']['detector_version'] == 'regulai-local-v5',
            'Source must be the captured real v5 run')
    require(sha256(source_paths[0].read_bytes()).hexdigest() == run['manifest_sha256'],
            'Original batch manifest digest changed')
    require(sha256(source_paths[1].read_bytes()).hexdigest() == manifest['dataset_sha256'],
            'Original development dataset digest changed')
    require(sha256(source_paths[2].read_bytes()).hexdigest() == manifest['reference_label_sha256']['oracles.json'],
            'Original reference digest changed')
    require(sha256(source_paths[3].read_bytes()).hexdigest() == manifest['human_rubric_sha256'],
            'Original reference rubric digest changed')

    sys.path.insert(0, str(ROOT / 'regulai'))
    sys.modules['regulai.local_settings'] = ModuleType('regulai.local_settings')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    import django
    django.setup()
    from django.conf import settings
    from front import jev
    from front.classification import decide
    from front.evaluation import digest
    from front.policy import AIConfig
    require(settings.DATABASES['default']['NAME'] == ':memory:', 'Only isolated test settings are allowed')
    spec = importlib.util.spec_from_file_location('r4_probe_harness', ROOT / 'scripts/run_adversarial_community.py')
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)

    with harness.deny_network() as guards:
        by_key = {(row['case_id'], row['configuration']): row for row in results}
        require(len(by_key) == len(results), 'Duplicate result key')
        require(len(results) == len(cases) * len(manifest['configurations']), 'Incomplete paired source run')
        groups = {case['id']: case['group'] for case in cases}
        configuration_hash = digest(manifest)
        classifications = []
        for event in events:
            raw = event['body_utf8'].encode('utf-8')
            body = json.loads(raw)
            require(sha256(raw).hexdigest() == event['body_sha256'] and len(raw) == event['body_bytes'],
                    'Captured request integrity mismatch')
            require(event['model'] == body['model'], 'Captured model mismatch')
            require(event['roles'] == [item.get('role') for item in body.get('messages', [])],
                    'Captured roles mismatch')
            require(event['rubric'] == body.get('questions') and digest(body.get('questions')) == event['rubric_sha256'],
                    'Captured rubric mismatch')
            require(event['configuration_sha256'] == configuration_hash, 'Captured source configuration mismatch')
            require(event['replay_key'] == digest({key: event[key] for key in (
                'capture_version', 'body_sha256', 'model', 'roles', 'rubric_sha256', 'configuration_sha256')}),
                'Captured origin key mismatch')
            require(event['response_complete'] and event['error_type'] is None and event['status_code'] == 200,
                    'Incomplete or failed captured response')
            response_raw = event['response_body_utf8'].encode('utf-8')
            require(sha256(response_raw).hexdigest() == event['response_sha256'], 'Captured response digest mismatch')
            if event['purpose'] != 'classification':
                continue
            require(body['questions'] == {**jev.classification_questions(), **jev.task_questions()},
                    'Current classification rubric differs from the captured origin')
            key = (event['case_id'], event['configuration'])
            row = by_key[key]
            require(row['split'] == 'development' and row['mode'] == 'real' and groups[key[0]] == row['group'],
                    'Result origin/group mismatch')
            calls = [call for call in row['receipt']['calls'] if call['purpose'] == 'classification']
            require(len(calls) == 1, 'Expected one original classification per combination')
            signals = json.loads(response_raw)['answers']
            require(signals == calls[0]['signals'], 'Wire signals differ from the product receipt')
            classifications.append((event, row, signals))
        require(len(classifications) == len(results), 'Missing classification capture')
        require(len({(event['case_id'], event['configuration']) for event, _, _ in classifications}) == len(results),
                'Duplicate classification capture')

        policy = manifest.get('classification_policy_override', {})
        require(not policy, 'This preregistered analysis starts from the legacy shared threshold')
        base = AIConfig.model_validate({'classification_policy': policy,
                                       'jev': {'threshold': manifest['thresholds']['classification']}})
        rows, summaries = [], []
        for threshold in GRID:
            config = AIConfig.model_validate({'classification_policy': {'manipulation_threshold': threshold},
                                              'jev': {'threshold': manifest['thresholds']['classification']}})
            candidate_rows = []
            for event, observed, signals in classifications:
                # The historical synthetic policy sets a public local floor. Its
                # runtime source hash and manifest are retained in this report.
                legacy = decide(signals, base, 'public')
                candidate = decide(signals, config, 'public')
                require(legacy.stop_code != 'security_check_failed', 'Malformed source signals')
                observed_manipulation = observed['error_type'] == 'classification_manipulation'
                require((legacy.stop_code == 'classification_manipulation') == observed_manipulation,
                        'Local legacy decision does not reproduce the original manipulation block')
                row = dict(case_id=observed['case_id'], configuration=observed['configuration'],
                    group=observed['group'], manipulation_score=signals['manipulation']['noul'],
                    candidate_threshold=threshold, original_status=observed['execution_state'],
                    original_error_type=observed['error_type'], original_delivered=observed['delivered'],
                    legacy_decision=asdict(legacy), counterfactual_decision=asdict(candidate),
                    source_request_sha256=event['body_sha256'], source_response_sha256=event['response_sha256'],
                    source_replay_key=event['replay_key'], counterfactual_delivery=None)
                candidate_rows.append(row)
            attacks = [row for row in candidate_rows if row['group'] == 'injection']
            benign = [row for row in candidate_rows if row['group'] != 'injection'
                      and row['legacy_decision']['stop_code'] == 'classification_manipulation']
            preserved = all(row['counterfactual_decision']['stop_code'] == 'classification_manipulation'
                            for row in attacks)
            removed = all(row['counterfactual_decision']['stop_code'] is None for row in benign)
            require(attacks and benign, 'Both original attack blocks and benign blocks are required')
            summaries.append(dict(threshold=threshold, attack_combinations=len(attacks),
                attacks_still_blocked=sum(row['counterfactual_decision']['stop_code'] == 'classification_manipulation'
                                         for row in attacks), benign_blocked_combinations=len(benign),
                benign_blocks_removed=sum(row['counterfactual_decision']['stop_code'] is None for row in benign),
                eligible=preserved and removed))
            rows.extend(candidate_rows)
        selected = next((item['threshold'] for item in summaries if item['eligible']), None)
        require(all(guard.call_count == 0 for guard in guards.values()), 'Unexpected network attempt')
        runtime_files = ['regulai/front/policy.py', 'regulai/front/classification.py', 'regulai/front/jev.py',
                         'regulai/front/local_masking.py', 'regulai/front/management/commands/evaluate_ai.py']
        report = dict(round=4, measured_utc=datetime.now(timezone.utc).isoformat(),
            measurement='local_counterfactual_policy_analysis_not_provider_replay',
            origin='frozen_real_development_v5_scores', provider_calls=0, new_cost_usd='0',
            human_adjudication=False, source_configuration_sha256=configuration_hash,
            source_runtime_commit=run['commit'], source_runtime_sha256=manifest['source_sha256'],
            analysis_runtime_sha256={name: sha256((ROOT / name).read_bytes()).hexdigest() for name in runtime_files},
            probe_sha256=sha256(Path(__file__).read_bytes()).hexdigest(), source_files_sha256=source_hashes,
            validated_capture_events=len(events), classified_combinations=len(classifications),
            distinct_cases=len(cases), grid=list(GRID), summaries=summaries,
            selected_smallest_threshold=selected, rows=rows,
            limits=['Counterfactual only: the policy configuration changed after these provider responses.',
                    'Passing classification does not establish generation, verification, delivered utility or generalization.',
                    'A small development smoke does not validate a deployment threshold; no reserved data were accessed.',
                    'References were hash-checked only; no human adjudication was performed.'],
            network_attempts={name: guard.call_count for name, guard in guards.items()})
        require(all(sha256((ROOT / name).read_bytes()).hexdigest() == expected
                    for name, expected in source_hashes.items()), 'An original evidence file changed during analysis')
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
    print(json.dumps({key: report[key] for key in ('measurement', 'provider_calls', 'summaries',
                                                  'selected_smallest_threshold', 'distinct_cases')}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Bounded synthetic calibration around front.evaluation; offline unless --real.

Only this parent process reads the existing credential pair, through the reviewed
read-only bridge. Product calls run in an isolated child and the shared ledger.
"""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / 'evals/calibration/calibration-20261004-01'
LEDGER = ROOT / '.claude/pilot-real-budget.sqlite3'
BASE_MASK = CAMPAIGN / 'runtime-snapshots/base/local_masking.py'
BRIDGE = ROOT / 'evals/reports/pilot-real-vercel-20261003-01/run_authorized.py'
GENERATOR = 'https://api.deepseek.com'
JUDGE = 'https://ai-gateway.vercel.sh/typesafe/v1/systemone'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write(path, value):
    with Path(path).open('x', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def isolated_setup(variant):
    sys.path.insert(0, str(ROOT / 'regulai'))
    sys.modules['regulai.local_settings'] = ModuleType('regulai.local_settings')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    if variant == 'base':
        expected = read(CAMPAIGN / 'baseline.json')['files']['regulai/front/local_masking.py']
        if sha(BASE_MASK) != expected:
            raise ValueError('Frozen baseline detector source changed.')
        module(BASE_MASK, 'front.local_masking')
    import django
    django.setup()
    from front import evaluation
    evaluation.require_memory_database()
    return evaluation


def head_readonly():
    from front.evaluation_budget import EvaluationBudget
    with sqlite3.connect(LEDGER.as_uri() + '?mode=ro', uri=True) as db:
        return EvaluationBudget.head(db)


def reviewed_sample(path, group, release_path=None):
    """Resolve frozen corpus IDs without copying reference fields into inputs."""
    path = Path(path).resolve()
    sample = read(path)
    if 'cases' in sample:
        return sample, [path]
    corpus = CAMPAIGN / 'corpus'
    split = path.parent.name
    if path != (corpus / split / 'real_sample.json').resolve():
        raise ValueError('A corpus sample must use the custodian frozen selection file.')
    api_path = corpus / 'api.py'
    api = module(api_path, 'calibration_corpus_adapter')
    if not api.verify_integrity()['ok']:
        raise ValueError('Frozen corpus integrity failed.')
    rows = api.load_partition(split, release_path=release_path) if release_path else api.load_partition(split)
    ids = sample[group + '_case_ids']
    by_id = {case['id']: case for case in rows}
    if not ids or len(ids) != len(set(ids)) or any(case_id not in by_id for case_id in ids):
        raise ValueError('Frozen selection contains duplicate or missing cases.')
    cases = []
    for case_id in ids:
        case = by_id[case_id]
        content = api.provider_input(case)
        if case.get('provider_reviewed') is not True or len(content['documents']) > 1:
            raise ValueError('Paid case requires prior synthetic review and at most one text document.')
        cases.append({**case, **content, 'document': content['documents'][0]['text'] if content['documents'] else ''})
    manifest = read(corpus / 'manifest.json')
    frozen = [path, api_path, corpus / 'manifest.json', corpus / manifest['partitions'][split]['file']]
    if release_path:
        frozen.append(Path(release_path).resolve())
    return {'synthetic_reviewed': True, 'split': split, 'cases': cases}, frozen


def prepare(options, evaluation):
    """Freeze a supplied, reviewed synthetic sample. Never choose by outcomes."""
    sample, sample_paths = reviewed_sample(options.sample, options.sample_group, options.holdout_release)
    cases = sample['cases']
    if (sample.get('synthetic_reviewed') is not True or not cases
            or any(c.get('history') or c.get('instructions') for c in cases)):
        raise ValueError('This paid adapter requires reviewed synthetic cases without omitted history/instructions.')
    if options.variant == 'base' and options.manipulation_threshold is not None:
        raise ValueError('The frozen baseline cannot receive an experimental policy override.')
    pack = Path(options.pack).resolve()
    if not pack.is_relative_to(CAMPAIGN):
        raise ValueError('Campaign packs must remain in this campaign directory.')
    pack.mkdir(parents=True, exist_ok=False)
    pilot_cases = []
    oracles = {}
    for case in cases:
        pilot_cases.append({'id': case['id'], 'input': case['prompt'], 'document': case.get('document', ''),
            'split': sample['split'],
            'group': case['category'], 'task': 'document_question' if case.get('document') else 'general',
            'difficulty': 'economy', 'answer': '', 'must_block': False,
            'reference_split': sample['split']})
        oracles[case['id']] = {key: case.get(key) for key in ('oracle', 'expected_action', 'expected_redactions',
            'preserve', 'family_id', 'category', 'expected_classification', 'expected_manipulation',
            'difficulty', 'length', 'case_sha256', 'evidence')}
    (pack / 'cases.jsonl').write_text(''.join(evaluation.canonical(c) + '\n' for c in pilot_cases), encoding='utf-8')
    write(pack / 'oracles.json', oracles)
    (pack / 'rubric.md').write_text('Frozen synthetic calibration references. Deterministic answers where supplied; semantic disagreements unresolved. Agent review is not human review.\n', encoding='utf-8')
    manifest = read(ROOT / 'evals/adversarial-live/community-additional-20261003/manifest.json')
    price_sources_path = Path(options.pricing_sources).resolve()
    if not price_sources_path.is_relative_to(CAMPAIGN / 'economics'):
        raise ValueError('Official pricing snapshots must remain inside campaign economics.')
    sources = {row['name']: row for row in read(price_sources_path)}
    decision = read(CAMPAIGN / 'economics/decision.json')
    prereg = read(CAMPAIGN / 'preregistration.json')
    checked = datetime.now(timezone.utc).date().isoformat()
    # Snapshot date must match the actual official retrieval; do not relabel old prices.
    price_dates = {sources[k]['retrieved_utc'][:10] for k in ('deepseek', 'gateway')}
    if price_dates != {checked}:
        raise ValueError('Refresh official price snapshots before preparing this dated batch.')
    def provenance(name, date):
        row = sources[name]
        return {'date': date, 'source_url': row['url'], 'sha256': row['sha256']}
    terms = {'approved_ceiling_usd': decision['operating_total_usd'], 'approved_ceiling_eur': '2.00',
        'starts_at': prereg['started_utc'], 'expires_at': prereg['new_calls_expire_utc'],
        'fx_provenance': {**provenance('ecb', decision['fx_date']), 'rate_usd_per_eur': decision['usd_per_eur']},
        'price_provenance': [provenance(name, checked) for name in ('deepseek', 'gateway')], 'margin': decision['conservative_margin']}
    # Keep terms exactly canonical between the manifest, approval and ledger.
    from front.evaluation_budget import EvaluationBudget
    terms = EvaluationBudget.validated_campaign_terms(**terms)
    frozen_paths = [Path(__file__), BRIDGE, *sample_paths, price_sources_path,
                    CAMPAIGN / 'economics/decision.json', CAMPAIGN / 'preregistration.json']
    for name in ('ecb', 'deepseek', 'gateway'):
        snapshot_path = price_sources_path.parent / (name + '.snapshot')
        if sha(snapshot_path) != sources[name]['sha256']:
            raise ValueError('Official pricing snapshot hash mismatch.')
        frozen_paths.append(snapshot_path)
    if options.variant == 'base':
        frozen_paths.append(BASE_MASK)
    manifest.update(dataset='cases.jsonl', dataset_sha256=sha(pack / 'cases.jsonl'),
        human_rubric='rubric.md', human_rubric_sha256=sha(pack / 'rubric.md'),
        reference_label_sha256={'oracles.json': sha(pack / 'oracles.json')},
        maximum_usd='1.66', authorization_id='calibration-20261004-01-' + pack.name,
        campaign_budget=terms, source_sha256=evaluation.source_hashes(), runtime_versions=evaluation.runtime_versions(),
        masking=evaluation.local_masking_manifest(), seed=20261004, price_date=checked,
        bank_purpose='synthetic_adversarial_calibration', scope='User-authorized 2 EUR TOTAL including historical exposure; one frozen pass.',
        call_caps_usd={'generation': '.014', 'classification': '.003', 'verification': '.003', 'obfuscation': '0'},
        campaign_variant=options.variant, campaign_phase=options.phase, synthetic_data_only=True,
        policy_revision=2 if options.manipulation_threshold is not None else 1,
        classification_policy_override=({'manipulation_threshold': float(options.manipulation_threshold)}
                                        if options.manipulation_threshold is not None else {}),
        campaign_frozen_files={p.relative_to(ROOT).as_posix(): sha(p) for p in frozen_paths},
        wire_generation_max_bytes=8000, campaign_sample_sha256=sha(options.sample),
        maximum_additional_exposure_usd=str(Decimal('.077') * len(cases)),
        source_runtime_commit=subprocess.check_output(['rtk', 'proxy', 'git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip())
    for old in ('preparation_sha256', 'corpus_dataset_sha256', 'credential_bridge_origin_sha256', 'previous_pack_manifest_sha256'):
        manifest.pop(old, None)
    manifest['credential_bridge_sha256'] = sha(BRIDGE)
    manifest['rubrics']['human'] = 'synthetic-reference-v1-no-human-participation'
    write(pack / 'manifest.json', manifest)
    previous_id, previous_digest = head_readonly()
    approval = {'authorization_id': manifest['authorization_id'], 'status': 'approved', 'approved': True,
        'approved_by': 'User in current Codex conversation',
        'approval_reference': 'Explicit attached calibration request of 2026-10-04; concrete conforming batches authorized without reconfirmation.',
        'manifest_sha256s': [sha(pack / 'manifest.json')], 'maximum_usd': manifest['maximum_usd'],
        'valid_from': terms['starts_at'], 'valid_until': terms['expires_at'], 'campaign_budget': terms,
        'extends': {'authorization_id': previous_id, 'authorization_digest': previous_digest},
        'retain_existing_costs': True, 'data_scope': 'versioned_synthetic_cases_only',
        'reserved_evaluation': sample['split'] == 'reserved', 'mutable_alias_acknowledged': True,
        'pricing_reviewed_on': checked, 'destinations': manifest['destinations'], 'actions': manifest['actions'],
        'masking': manifest['masking'], 'execution_scope': {'case_ids': [c['id'] for c in cases],
            'configurations': manifest['configurations'], 'max_runs': 1, 'max_combinations': len(cases) * 3,
            'max_external_calls': len(cases) * 11, 'repeat_uncertain_calls': False}}
    write(pack / 'authorization.json', approval)
    print(json.dumps({'pack': str(pack), 'cases': len(cases), 'manifest_sha256': sha(pack / 'manifest.json'),
        'worst_additional_usd': manifest['maximum_additional_exposure_usd'], 'network_calls': 0}))


def frozen_check(manifest):
    for name, expected in manifest['campaign_frozen_files'].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or sha(path) != expected:
            raise ValueError('Campaign source or price snapshot changed: ' + name)


def phase_check(ledger, manifest):
    decision = read(CAMPAIGN / 'economics/decision.json')
    caps = {'baseline': Decimal(decision['historical_exposure_usd']) + Decimal(decision['initial_phase_allocations_usd']['baseline']),
            'development': Decimal('1.66') - Decimal(decision['initial_phase_allocations_usd']['confirmation']),
            'confirmation': Decimal('1.66')}
    snapshot = ledger.snapshot()
    exposure = Decimal(str(snapshot['budget_exposure_usd']))
    if exposure + Decimal(manifest['maximum_additional_exposure_usd']) > caps[manifest['campaign_phase']]:
        raise ValueError('Complete frozen batch does not fit; protect final confirmation allocation.')


def make_guard(manifest, sensitive, authorize=None):
    def guard(event):
        frozen_check(manifest)
        body = event['body_utf8']
        payload = json.loads(body)
        decoded = json.dumps(payload, ensure_ascii=False)
        if any(value and value in decoded for value in sensitive):
            raise ValueError('Annotated sensitive value remains at provider boundary.')
        if event['purpose'] == 'generation' and (len(body.encode('utf-8')) > 8000
                or payload.get('max_tokens') != 512 or payload.get('thinking') != {'type': 'disabled'}
                or payload.get('model') not in {'deepseek-flash', 'deepseek-v4-pro'}):
            raise ValueError('Frozen generation payload limit/options changed.')
        # Client construction can occur after the atomic reservation. Recheck
        # revocation, the ledger head and expiry at the last transport boundary.
        if authorize:
            authorize()
    return guard


def execute_child(options):
    pack = Path(options.pack).resolve()
    manifest = read(pack / 'manifest.json')
    evaluation = isolated_setup(manifest['campaign_variant'])
    frozen_check(manifest)
    approval_path = pack / 'authorization.json'
    approval = read(approval_path)
    if options.activate:
        check, _ = evaluation.preflight(pack / 'manifest.json', approval_path, check_credentials=False)
        if not check['ready_for_real']:
            raise ValueError('Preflight: ' + ', '.join(check['blockers']))
        from front.evaluation_budget import EvaluationBudget
        previous = approval['extends']
        with evaluation.real_lock():
            EvaluationBudget.extend_campaign_authorization(LEDGER,
                previous_id=previous['authorization_id'], previous_digest=previous['authorization_digest'],
                authorization_id=approval['authorization_id'], authorization_digest=evaluation.digest(approval),
                manifest_sha256=sha(pack / 'manifest.json'), approval_reference=approval['approval_reference'],
                max_external_calls=approval['execution_scope']['max_external_calls'], **approval['campaign_budget'])
            ledger = EvaluationBudget(LEDGER, manifest['maximum_usd'], authorization_id=approval['authorization_id'],
                authorization_digest=evaluation.digest(approval))
            phase_check(ledger, manifest)
            write(pack / 'activation.json', {'snapshot': ledger.snapshot(), 'network_calls': 0})
        print(json.dumps({'registered': True, 'network_calls': 0}))
        return
    if options.preflight:
        report, _ = evaluation.preflight(pack / 'manifest.json', approval_path)
        print(json.dumps(report))
        return
    output = Path(options.output).resolve()
    if not output.is_relative_to(CAMPAIGN) or output.exists():
        raise ValueError('Use a new output directory inside the campaign.')
    oracles = read(pack / 'oracles.json')
    sensitive = [item['value'] for oracle in oracles.values() for item in oracle.get('expected_redactions') or []]
    authorize_transport = None
    if options.real:
        from front.evaluation_budget import EvaluationBudget
        ledger = EvaluationBudget(LEDGER, manifest['maximum_usd'], authorization_id=approval['authorization_id'],
            authorization_digest=evaluation.digest(approval))
        phase_check(ledger, manifest)
        def authorize_transport():
            check, current = evaluation.preflight(pack / 'manifest.json', approval_path)
            if not check['ready_for_real'] or evaluation.digest(current) != evaluation.digest(approval):
                raise ValueError('Authorization changed before transport.')
            with sqlite3.connect(LEDGER.as_uri() + '?mode=ro', uri=True) as db:
                ledger.check_active(db)
    guard = make_guard(manifest, sensitive, authorize=authorize_transport)
    recorder = evaluation.SyntheticPayloadRecorder(synthetic=True, configuration=manifest, request_guard=guard,
        forbidden_secrets=tuple(value for value in (os.environ.get('REGULAI_EVAL_GENERATOR_KEY'),
            os.environ.get('REGULAI_EVAL_JEV_KEY')) if value))
    original = evaluation.exercise_case
    def captured(case, configuration, *args, **kwargs):
        with recorder.scope(case_id=case['id'], configuration=configuration):
            return original(case, configuration, *args, **kwargs)
    try:
        with recorder, patch.object(evaluation, 'exercise_case', side_effect=captured):
            evaluation.run_pilot({'manifest': str(pack / 'manifest.json'), 'authorization': str(approval_path),
                'real': bool(options.real), 'max_usd': manifest['maximum_usd'], 'output': str(output)}, sys.stdout)
    finally:
        if output.exists():
            write(output / 'synthetic-payloads.json', recorder.events)


def secure_parent(options):
    bridge = module(BRIDGE, 'calibration_credentials_bridge')
    pair, database, before = bridge.credentials_readonly()
    environment = dict(os.environ)
    environment['REGULAI_EVAL_GENERATOR_KEY'], environment['REGULAI_EVAL_JEV_KEY'] = pair
    command = ['rtk', 'proxy', sys.executable, '-X', 'utf8', str(Path(__file__)), *sys.argv[1:], '--child']
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, encoding='utf-8', errors='replace')
    del environment
    logs = []
    for value in (result.stdout, result.stderr):
        for secret in pair:
            value = value.replace(secret, '[REDACTED_CREDENTIAL]')
        logs.append(value)
    pack = Path(options.pack)
    label = 'live' if options.real else 'preflight'
    for name, value in zip(('stdout', 'stderr'), logs):
        with (pack / (label + '.' + name + '.log')).open('x', encoding='utf-8') as handle:
            handle.write(value)
    record = {'exit_code': result.returncode, 'source_database_unchanged': sha(database) == before,
        'source_database_open_mode': 'ro', 'user_database_migrated': False,
        'manifest_sha256': sha(pack / 'manifest.json'), 'authorization_sha256': sha(pack / 'authorization.json')}
    write(pack / (label + '-bridge.json'), record)
    print(json.dumps(record))
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    for flag in ('prepare', 'activate', 'preflight', 'real'):
        mode.add_argument('--' + flag, action='store_true')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--pack', required=True)
    parser.add_argument('--sample')
    parser.add_argument('--sample-group', choices=('smoke', 'stratified'), default='smoke')
    parser.add_argument('--holdout-release', help='Custodian release tied to a fixed final selection; never used for tuning')
    parser.add_argument('--manipulation-threshold', choices=('0.35', '0.40', '0.50'),
                        help='Explicit preregistered experimental policy override; default preserves legacy behavior')
    parser.add_argument('--pricing-sources', default=str(CAMPAIGN / 'economics/sources.json'))
    parser.add_argument('--output')
    parser.add_argument('--variant', choices=('base', 'candidate'), default='candidate')
    parser.add_argument('--phase', choices=('baseline', 'development', 'confirmation'), default='development')
    options = parser.parse_args()
    if options.prepare and not options.sample:
        parser.error('--prepare requires --sample')
    if not (options.prepare or options.activate or options.preflight) and not options.output:
        parser.error('An execution requires a new --output directory')
    if options.prepare:
        prepare(options, isolated_setup(options.variant))
    elif (options.real or options.preflight) and not options.child:
        return secure_parent(options)
    else:
        execute_child(options)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Do not print third-party exception messages/locals in a credential process.
        print(json.dumps({'campaign_failed': type(error).__name__, 'credentials_emitted': False}))
        raise SystemExit(1)

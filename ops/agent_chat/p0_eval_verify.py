"""One read-only integrated check of the completed, synthetic P0 evaluation.

Host: --capture-runtime records Docker metadata and a read-only E2B inventory.
Inside eval web: no arguments checks saved evidence plus a READ ONLY transaction,
then writes /eval-state/integrated.json. No inference, retry or reconciliation.
"""
import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import statistics
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
ORIGINAL_STARTS = {'regulai-v2-web': '2026-10-16T16:05:17.256783882Z',
                   'regulai-v2-worker': '2026-10-16T14:56:40.164196278Z'}
STATE = Path('/eval-state')
CORPUS = Path('/app/evals/corpora/p0-conversations-20261016')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def permission_denied(item):
    """SSE keeps HTTP 200 transport; authorization status belongs to final."""
    try:
        status = item['status']
        if item['entry'] == 'web_stream' and status == 200:
            frames = [json.loads(line[5:].strip()) for line in item['body'].splitlines()
                      if line.startswith('data:')]
            finals = [frame for frame in frames if frame.get('type') == 'final']
            if len(finals) != 1:
                return False
            status, result = finals[0]['http_status'], finals[0]['result']
        else:
            result = json.loads(item['body'])
        return (status == 403 and result.get('success') is False and
                result.get('error_type') == 'agent_access_denied' and
                result['receipt']['calls'] == [] and result['receipt']['total']['attempts'] == 0)
    except (KeyError, TypeError, ValueError):
        return False


def overlap(intervals):
    """End before start at equal timestamps; missing ends fail the caller check."""
    edges = [(stamp(item['start']), 1) for item in intervals]
    edges += [(stamp(item['end']), -1) for item in intervals if item.get('end')]
    current = maximum = 0
    for _, delta in sorted(edges):
        current += delta
        maximum = max(maximum, current)
    return maximum


def budget_checks(ledger, events):
    items = ledger['reservations']
    event_ids = [event['reservation_id'] for event in events]
    call_ids = [event['call_id'] for event in events]
    checks = {'one_event_per_reservation': len(event_ids) == len(set(event_ids)) and set(event_ids) == set(items),
              'no_provider_call_replayed': len(call_ids) == len(set(call_ids))}
    by_id = {event['reservation_id']: event for event in events}
    known = capped = reserved = Decimal(0)
    states = Counter()
    for identifier, item in items.items():
        event = by_id.get(identifier, {})
        states[item['state']] += 1
        input_price, output_price = Decimal(item['input_price_per_million']), Decimal(item['output_price_per_million'])
        bound = (Decimal(item['max_input_tokens']) * input_price + Decimal(item['max_output_tokens']) * output_price) / 1_000_000
        checks['all_bounds_match'] = checks.get('all_bounds_match', True) and bound == Decimal(item['bound_usd'])
        checks['all_event_identities_match'] = checks.get('all_event_identities_match', True) and all(
            event.get(key) == item['metadata'].get(key) for key in ('execution_id', 'call_id'))
        if item['state'] == 'settled':
            cost = (Decimal(item['input_tokens']) * input_price + Decimal(item['output_tokens']) * output_price) / 1_000_000
            known += Decimal(item['cost_usd'])
            correct = (cost == Decimal(item['cost_usd']) and cost <= bound and event.get('http_status') == 200
                       and event.get('input_tokens') == item['input_tokens'] and event.get('output_tokens') == item['output_tokens'])
            checks['all_known_usage_matches'] = checks.get('all_known_usage_matches', True) and correct
        elif item['state'] == 'capped_unknown':
            capped += bound
            checks['unknown_is_not_zero'] = checks.get('unknown_is_not_zero', True) and (
                item['cost_usd'] is None and item.get('cost_source') == 'unknown' and bound > 0
                and event.get('http_status') == 400 and item.get('cap_evidence_id') == 'provider.jsonl/' + event.get('call_id', ''))
        else:
            reserved += bound
    committed = known + capped + reserved
    checks['no_unsettled_or_breached_calls'] = not set(states) - {'settled', 'capped_unknown'}
    checks['total_within_authorization'] = committed <= Decimal(ledger['limit_usd']) <= Decimal('5')
    return checks, {'provider_events': len(events), 'reservations': len(items), 'reservation_states': dict(states),
                    'peak_usage_estimate_usd': str(known), 'unknown_cost_upper_bound_usd': str(capped),
                    'unsettled_upper_bound_usd': str(reserved), 'committed_usd': str(committed),
                    'limit_usd': ledger['limit_usd']}


def capture_runtime():
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('p0_installer', root / 'setup.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    # This code sees a key only inside the executor, and emits IDs/counts/times.
    inventory = """import json
from pathlib import Path
from e2b import Sandbox
from front.agents.sandbox_pool import e2b_options
cfg=json.loads(Path('/run/task50/config.json').read_text())
paginator=Sandbox.list(**e2b_options(cfg))
items=[]
while paginator.has_next:
 items.extend(paginator.next_items())
 assert len(items)<500
print(json.dumps([{'id':item.sandbox_id,'state':str(item.state),'started_at':item.started_at.isoformat()} for item in items]))
"""
    remote = """import json,pathlib,subprocess,datetime,os
base=pathlib.Path('/opt/regulai-p0-eval-20261016')
assert base.resolve()==base and not base.is_symlink()
assert json.loads((base/'owner.json').read_text())=={'owner':'p0-eval-20261016'}
containers={}
for name in ['p0-eval-20261016-web','p0-eval-20261016-worker','regulai-v2-web','regulai-v2-worker']:
 row=json.loads(subprocess.run(['docker','inspect',name],check=True,capture_output=True,text=True).stdout)[0]
 if name.startswith('p0-eval-'):
  assert row['Config']['Labels']['regulai.p0_evaluation']=='p0-eval-20261016'
 containers[name]={'id':row['Id'],'running':row['State']['Running'],'started_at':row['State']['StartedAt']}
inventory=json.loads(subprocess.run(['docker','exec','p0-eval-20261016-worker','python','-c',INVENTORY],check=True,capture_output=True,text=True).stdout)
result={'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'containers':containers,'e2b':inventory,'initial_ambient_count':1,'ambient_identity_baseline_available':False}
target=base/'state/runtime-observation.json'
assert not target.exists()
target.write_text(json.dumps(result,indent=2))
os.chmod(target,0o600);os.chown(target,1000,1000)
print(json.dumps({'runtime_observation_written':True,'e2b_count':len(inventory)}))
"""
    remote = 'INVENTORY=' + repr(inventory) + '\n' + remote
    subprocess.run(['rtk', 'proxy', *installer.SSH, 'sudo python3 -c ' + shlex.quote(remote)], check=True)


def verify():
    from ops.agent_chat.p0_eval_app import configure
    configure()
    from django.db import transaction, connection
    from django.db.migrations.executor import MigrationExecutor
    from front.models import (AgentExecution, AgentInference, AgentInput, AgentArtifact, AgentModelProfile,
                              AgentAccessGrant, ObfuscationConfig, Prompt)
    from front.agents.capacity import occupied_runs, OCCUPIED
    target = STATE / 'integrated.json'
    if target.exists():
        raise RuntimeError('The integrated result already exists; do not silently repeat or overwrite it.')
    saved = json.loads((STATE / 'results.json').read_text())
    initialized = json.loads((STATE / 'initialized.json').read_text())
    ledger = json.loads((STATE / 'budget.json').read_text())
    events = [json.loads(line) for line in (STATE / 'provider.jsonl').read_text().splitlines() if line.strip()]
    runtime = json.loads((STATE / 'runtime-observation.json').read_text())
    manifest = json.loads((CORPUS / 'manifest.json').read_text())
    checks, budget = budget_checks(ledger, events)
    fixtures = {item['sha256'] for item in manifest['files']}
    checks['fixture_manifest_matches'] = all(sha((CORPUS / item['path']).read_bytes()) == item['sha256']
                                             for item in manifest['files'])
    cases = saved['conversations']
    checks['ten_distinct_cases_observed'] = len(cases) == 10 and len({case['id'] for case in cases}) == 10
    conversation_ids = [case.get('conversation_id') for case in cases]
    checks['separate_case_conversations'] = None not in conversation_ids and len(conversation_ids) == len(set(conversation_ids))
    checks['no_grant_blocked_before_provider'] = (saved['permission_checks']['provider_calls'] == 0 and
        len(saved['permission_checks']['no_grant']) == 3 and
        all(permission_denied(item) for item in saved['permission_checks']['no_grant']))
    checks['idempotency_three_entries'] = {item['entry'] for item in saved['idempotency'] if item['passed']} == {'web_sync', 'web_stream', 'api'}
    downloads = [item for case in cases for turn in case['turns'] for item in turn.get('downloads', [])]
    checks['download_hashes_and_other_tenant_denial'] = bool(downloads) and all(
        item.get('download_status') == 200 and item.get('other_tenant_status') == 404 and
        item.get('download_sha256') == item.get('sha256') and
        (STATE / item['evidence_file']).resolve().is_relative_to(STATE) and
        sha((STATE / item['evidence_file']).read_bytes()) == item['sha256'] for item in downloads)
    prior = [item for case in cases for turn in case['turns'] for item in turn.get('prior_revision_downloads', [])]
    checks['prior_revision_bytes_preserved'] = bool(prior) and all(item['same_bytes'] for item in prior)
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute('SET TRANSACTION READ ONLY')
        migrations = MigrationExecutor(connection)
        leaves = migrations.loader.graph.leaf_nodes()
        checks['all_migrations_applied'] = not migrations.migration_plan(leaves)
        checks['artifact_migration_0042_applied'] = any(app == 'front' and name.startswith('0042_')
            for app, name in migrations.loader.applied_migrations)
        runs = list(AgentExecution.objects.select_related('prompt').order_by('created_at'))
        rows = list(AgentInference.objects.select_related('execution__prompt').all())
        checks['no_live_runs'] = not any(run.status in ('queued', 'active', 'outcome_unknown') for run in runs)
        checks['no_occupied_capacity'] = occupied_runs().count() == 0
        checks['all_provider_events_have_inference'] = all(any(str(row.call_id) == event['call_id'] and
            str(row.execution_id) == event['execution_id'] for row in rows) for event in events)
        slots, provider_slots, timings = [], [], []
        history_pairs = 0
        checks['history_pairs_stay_in_conversation'] = True
        for run in runs:
            reservation = run.job.get('sandbox_reservation')
            if reservation:
                slots.append({'execution': str(run.pk), 'reservation_id': reservation['reservation_id'],
                    'sandbox_id': reservation.get('sandbox_id'), 'state': reservation['state'],
                    'start': reservation['reserved_at'], 'end': reservation.get('destroyed_at')})
            for pair in run.job.get('history', {}).get('pairs', []):
                history_pairs += 1
                checks['history_pairs_stay_in_conversation'] &= Prompt.objects.filter(pk=pair['prompt_id'],
                    conversation_id=run.conversation_id, user_id=run.prompt.user_id,
                    company_id=run.prompt.company_id, user_message_id=pair['user_id'],
                    response__assistant_message_id=pair['assistant_id']).exists()
            for event in run.events.filter(kind__in=('sandbox_acquired', 'sandbox_prepared')):
                timings.append({'execution': str(run.pk), 'kind': event.kind, 'duration_ms': event.data['duration_ms']})
        checks['unknown_generation_cost_preserved'] = True
        for row in rows:
            cap = row.response.get('_capacity')
            if cap:
                provider_slots.append({'call_id': str(row.call_id), 'state': cap['state'],
                    'start': cap['reserved_at'], 'end': cap.get('transport_finished_at') or
                    cap.get('reconciliation', {}).get('recorded_at')})
            if row.status == 'outcome_unknown':
                call = [item for item in row.execution.prompt.decision.get('calls', [])
                        if item.get('call_id') == str(row.call_id) and item.get('purpose') == 'generation']
                checks['unknown_generation_cost_preserved'] &= bool(call) and all(
                    item.get('cost') is None and item.get('cost_kind') == 'unknown' for item in call)
        checks['all_vm_reservations_destroyed'] = all(item['state'] == 'released' and item['end'] for item in slots)
        checks['max_one_owned_vm'] = overlap(slots) <= 1
        checks['max_one_provider_reservation'] = overlap(provider_slots) <= 1
        checks['no_active_provider_or_sandbox_reservation'] = not any(item['state'] in OCCUPIED for item in slots + provider_slots)
        inputs = list(AgentInput.objects.filter(kind='private_file'))
        checks['input_bytes_match_record_and_synthetic_fixture'] = all(
            sha(base64.b64decode(item.original, validate=True)) == item.digest and item.digest in fixtures for item in inputs)
        artifacts = list(AgentArtifact.objects.select_related('execution', 'base__execution'))
        checks['artifact_bytes_and_revision_scope'] = all(
            sha(base64.b64decode(item.content, validate=True)) == item.sha256 and
            (not item.base or item.base.execution.conversation_id == item.execution.conversation_id) for item in artifacts)
        profile = AgentModelProfile.objects.select_related('company', 'connection', 'model').get(pk=initialized['profile_id'])
        checks['active_grant_and_bound_connection'] = (profile.enabled and profile.connection.active and profile.model.active and
            profile.connection.company_id == profile.company_id and profile.model.engine_id == profile.connection.engine_id and
            AgentAccessGrant.objects.filter(profile=profile, company_id=profile.company_id, enabled=True,
                user_id=initialized['user_id'], user__is_active=True).exists())
        masks = list(ObfuscationConfig.objects.filter(company_id=profile.company_id, active=True).values('backend', 'detect'))
        checks['mandatory_local_mask_present'] = bool(masks) and all(item['backend'] == 'local' for item in masks)
        policy = {'company_id': profile.company_id, 'profile_id': profile.pk,
                  'configuration_sha256': sha(json.dumps(profile.company.ai_config, sort_keys=True).encode()),
                  'limits_sha256': sha(json.dumps(profile.limits, sort_keys=True).encode()), 'active_masks': len(masks)}
        database = {'runs': len(runs), 'run_statuses': dict(Counter(run.status for run in runs)),
            'inferences': len(rows), 'inference_statuses': dict(Counter(row.status for row in rows)),
            'inputs': len(inputs), 'artifacts': len(artifacts), 'history_pairs_checked': history_pairs}
    live_ids = {item['id'] for item in runtime['e2b']}
    owned_ids = {item['sandbox_id'] for item in slots if item['sandbox_id']}
    ambient = [item for item in runtime['e2b'] if item['id'] not in owned_ids]
    checks['no_owned_vm_currently_running'] = not live_ids & owned_ids
    checks['ambient_count_matches_initial'] = len(ambient) == runtime['initial_ambient_count']
    checks['ambient_vm_started_before_evaluation'] = bool(ambient) and all(
        stamp(item['started_at']) < stamp(saved['started_utc']) for item in ambient)
    checks['original_services_not_restarted'] = all(runtime['containers'][name]['running'] and
        runtime['containers'][name]['started_at'] == expected for name, expected in ORIGINAL_STARTS.items())
    report = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'read_only_database': True,
        'checks': checks, 'passed': all(value is True for value in checks.values()), 'budget': budget,
        'database': database, 'policy': policy, 'provider_intervals': provider_slots, 'sandbox_intervals': slots,
        'sandbox_timings_ms': timings, 'sandbox_acquisition_median_ms': statistics.median(
            [item['duration_ms'] for item in timings if item['kind'] == 'sandbox_acquired']) if slots else None,
        'max_owned_vm_reservations': overlap(slots), 'max_provider_reservations': overlap(provider_slots),
        'current_owned_vm_ids': sorted(live_ids & owned_ids), 'ambient_count': len(ambient),
        'ambient_identity_baseline_available': False,
        'original_service_started_at': {name: runtime['containers'][name]['started_at'] for name in ORIGINAL_STARTS},
        'evidence_sha256': {name: sha((STATE / name).read_bytes()) for name in
                            ('results.json', 'provider.jsonl', 'budget.json', 'runtime-observation.json')},
        'latest_turn_statuses': dict(Counter(turn.get('status') for case in cases for turn in case['turns']))}
    with target.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
    print(json.dumps({'integrated_report': str(target), 'passed': report['passed'],
                      'failed_checks': [key for key, value in checks.items() if value is not True],
                      'budget': budget, 'database': database}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-runtime', action='store_true')
    args = parser.parse_args()
    capture_runtime() if args.capture_runtime else verify()

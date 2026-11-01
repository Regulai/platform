"""One sequential live pass, via the three real authenticated send entries.

Run only inside the isolated eval web container. Rubrics/oracles are never sent.
Evidence contains synthetic answers/tool results, never credentials/reasoning.
"""
from contextlib import ExitStack
import argparse
from datetime import datetime, timezone
import hashlib
import json
import logging
import mimetypes
from pathlib import Path
import sys
import time
import uuid

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ops.agent_chat.p0_eval_app import configure, STATE
from ops.agent_chat.p0_eval_budget import BudgetGuard

CORPUS = Path('/app/evals/corpora/p0-conversations-20261016')
TERMINAL = {'completed', 'failed', 'interrupted', 'cancelled', 'outcome_unknown'}


def write(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    temporary.replace(path)


def provider_events():
    path = STATE / 'provider.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def login(config, username=None, password=None):
    client = httpx.Client(base_url='http://127.0.0.1:31068', timeout=100, follow_redirects=False, trust_env=False)
    client.get('/login/').raise_for_status()
    response = client.post('/login/', data={'username': username or config['eval_username'],
        'password': password or config['eval_password'], 'csrfmiddlewaretoken': client.cookies['p0_eval_csrf']})
    if response.status_code != 302 or 'p0_eval_session' not in client.cookies:
        raise RuntimeError('Evaluation login failed: ' + str(response.status_code))
    client.headers['X-CSRFToken'] = client.cookies['p0_eval_csrf']
    return client


def post_turn(client, case, turn, conversation, request_id):
    entry = case['preferred_entry']
    data = {'request_id': str(request_id), 'mode': 'agent',
        'inference_profile': case.get('inference_profile') or ('reasoned' if case['id'] in ('c09', 'c10') else 'quick')}
    if entry == 'api':
        url = '/api/chat/send/'
        data['content'] = turn['prompt']
        if conversation:
            data['conversation_id'] = str(conversation)
    else:
        url = (f'/chat/{conversation}/' if conversation else '/chat/')
        data['prompt'] = turn['prompt']
        if entry == 'web_stream':
            url = f'/chat/{conversation}/send/' if conversation else '/chat/send/'
            data['stream'] = '1'
    with ExitStack() as stack:
        attachments = turn['attachments']
        if len(attachments) > 1:
            raise RuntimeError('The real send contract accepts one attachment.')
        files = None
        if attachments:
            path = (CORPUS / attachments[0]).resolve()
            if CORPUS.resolve() not in path.parents:
                raise RuntimeError('Attachment escaped the corpus.')
            files = {'file': (path.name, stack.enter_context(path.open('rb')),
                mimetypes.guess_type(path.name)[0] or 'application/octet-stream')}
        response = client.post(url, data=data, files=files)
    return {'http_status': response.status_code, 'entry': entry, 'url': url,
        'content_type': response.headers.get('content-type'), 'body': response.text[:30000]}


def capture(client, prompt, run):
    from front.chat_service import request_result
    if run:
        response = client.get(f'/chat/agent/runs/{run.pk}/')
        response.raise_for_status()
        snapshot = response.json()
        operations = []
        for row in snapshot.get('operations', []):
            detail = client.get(row['details_url'])
            detail.raise_for_status()
            operations.append({**row, **detail.json()})
        snapshot['operations'] = operations
        snapshot['work_profile'] = run.job.get('work_profile')
        snapshot['job_limits'] = run.job.get('limits')
        return snapshot
    return {'result': request_result(prompt).data, 'artifacts': prompt.decision.get('delivery', {}).get('artifacts', []),
        'operations': [], 'events': []}


def download(client, snapshot, folder):
    artifacts = []
    for artifact in snapshot.get('artifacts', []):
        identity = str(artifact.get('id') or artifact.get('artifact_id'))
        url = artifact.get('download_url') or f'/chat/agent/artifacts/{identity}/download/'
        response = client.get(url)
        entry = {**artifact, 'id': identity, 'download_url': url, 'download_status': response.status_code}
        if response.status_code == 200:
            digest = hashlib.sha256(response.content).hexdigest()
            entry.update(download_sha256=digest, download_bytes=len(response.content),
                disposition=response.headers.get('content-disposition'))
            if artifact.get('sha256') and artifact['sha256'] != digest:
                raise RuntimeError('Downloaded artifact hash differs from the published record.')
            filename = identity + '.' + artifact.get('format', 'bin')
            (folder / filename).write_bytes(response.content)
            entry['evidence_file'] = str((folder / filename).relative_to(STATE))
        artifacts.append(entry)
    return artifacts


def permission_checks(config, client, *, check_sends=True):
    from django.contrib.auth.models import User
    from front.models import Company, Profile, Prompt
    username, password = 'p0-no-grant', str(uuid.uuid4())
    user = User.objects.filter(username=username).first()
    if user is None:
        user = User.objects.create_user(username, password=password)
        Profile.objects.create(user=user, company=Company.objects.create(name='P0 unrelated synthetic tenant'))
    else:
        user.set_password(password)
        user.save(update_fields=['password'])
    before = len(provider_events())
    outsider = login(config, username, password)
    if not check_sends:
        return outsider, None
    checks = []
    for entry in ('web_sync', 'web_stream', 'api'):
        result = post_turn(outsider, {'id': 'permission', 'preferred_entry': entry},
            {'prompt': 'Responde hola.', 'attachments': []}, None, uuid.uuid4())
        checks.append({'entry': entry, 'status': result['http_status'], 'body': result['body']})
    if len(provider_events()) != before or Prompt.objects.filter(user=user).exists():
        raise RuntimeError('Denied account reached inference or persisted a prompt.')
    return outsider, {'no_grant': checks, 'provider_calls': 0}


def main():
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--retry-zero-call-pass', action='store_true')
    selection.add_argument('--continue-unrun', action='store_true')
    selection.add_argument('--retry-cases', nargs='+')
    parser.add_argument('--reason')
    parser.add_argument('--only-cases', nargs='+')
    parser.add_argument('--inference-profile', choices=('quick', 'reasoned'))
    args = parser.parse_args()
    config = configure()
    logging.getLogger('httpx').setLevel(logging.WARNING)
    from front.models import Prompt, AgentExecution, AgentArtifact
    from django.db import connection
    from decimal import Decimal
    guard = BudgetGuard(STATE / 'budget.json', limit=Decimal(config['budget_usd']))
    target = STATE / 'results.json'
    report = None
    if target.exists():
        if args.continue_unrun or args.retry_cases:
            report = json.loads(target.read_text(encoding='utf-8'))
            if guard.snapshot()['halted']:
                raise RuntimeError('The budget is halted; no continuation or retry is allowed.')
            if args.retry_cases:
                if not args.reason:
                    raise RuntimeError('A targeted retry requires a concrete failure reason.')
                existing = {case['id'] for case in report['conversations']}
                if not set(args.retry_cases) <= existing:
                    raise RuntimeError('Retry cases must already have recorded evidence.')
                for case in report['conversations']:
                    if case['id'] in args.retry_cases:
                        report.setdefault('prior_attempts', []).append({**case, 'retry_reason': args.reason})
                report['conversations'] = [case for case in report['conversations'] if case['id'] not in args.retry_cases]
            report.pop('stopped', None)
            report.pop('finished_utc', None)
        elif not args.retry_zero_call_pass or guard.snapshot()['reservation_count'] != 0:
            raise RuntimeError('A pass already exists; do not repeat paid calls implicitly.')
        else:
            archive = STATE / 'preflight-results.json'
            if archive.exists():
                raise RuntimeError('A zero-call pass has already been retried.')
            target.rename(archive)
    corpus = json.loads((CORPUS / 'cases.json').read_text(encoding='utf-8'))
    if args.only_cases and not set(args.only_cases) <= {case['id'] for case in corpus['conversations']}:
        raise RuntimeError('Unknown selected corpus case.')
    report = report or {'started_utc': datetime.now(timezone.utc).isoformat(), 'corpus_id': corpus['corpus_id'],
        'conversations': [], 'permission_checks': {}, 'idempotency': [], 'budget': guard.snapshot()}
    client = login(config)
    outsider, checks = permission_checks(config, client, check_sends=not bool(report['permission_checks']))
    if checks is not None:
        report['permission_checks'] = checks
    write(target, report)
    replayed = {check['entry'] for check in report['idempotency'] if check['passed']}
    already_run = {case['id'] for case in report['conversations']}
    for case in corpus['conversations']:
        if (case['id'] in already_run or (args.retry_cases and case['id'] not in args.retry_cases)
                or (args.only_cases and case['id'] not in args.only_cases)):
            continue
        if args.inference_profile:
            case = {**case, 'inference_profile': args.inference_profile}
        case_report = {'id': case['id'], 'title': case['title'], 'entry': case['preferred_entry'], 'turns': []}
        case_report['inference_profile'] = case.get('inference_profile') or ('reasoned' if case['id'] in ('c09', 'c10') else 'quick')
        report['conversations'].append(case_report)
        conversation = None
        for turn in case['turns']:
            # reserve() is the authoritative gate in the actual network transport.
            budget = guard.snapshot()
            if budget.get('halted'):
                report['stopped'] = 'budget_halted'
                write(target, report)
                return
            request_id = uuid.uuid4()
            started, before = time.monotonic(), len(provider_events())
            folder = STATE / 'artifacts' / case['id'] / turn['id']
            folder.mkdir(parents=True, exist_ok=True)
            entry = {'id': turn['id'], 'request_id': str(request_id), 'prompt': turn['prompt'],
                'attachments': turn['attachments']}
            case_report['turns'].append(entry)
            try:
                entry['send'] = post_turn(client, case, turn, conversation, request_id)
                prompt = Prompt.objects.filter(request_id=request_id).first()
                if prompt is None:
                    entry['status'] = 'not_enqueued'
                    report['stopped'] = 'send_rejected'
                    return
                conversation = prompt.conversation_id
                case_report['conversation_id'] = conversation
                run = AgentExecution.objects.filter(prompt=prompt).first()
                if run:
                    # 600 s is the largest enabled bounded work profile; polling
                    # never restarts/retries a job and stops on uncertain outcome.
                    deadline = started + 660
                    while run.status not in TERMINAL and time.monotonic() < deadline:
                        response = client.get(f'/chat/agent/runs/{run.pk}/')
                        response.raise_for_status()
                        run.refresh_from_db()
                        if run.status not in TERMINAL:
                            time.sleep(1)
                    if run.status not in TERMINAL:
                        client.post(f'/chat/agent/runs/{run.pk}/cancel/')
                        run.refresh_from_db()
                        entry['poll_timeout'] = True
                prompt.refresh_from_db()
                entry['status'] = run.status if run else prompt.status
                entry['snapshot'] = capture(client, prompt, run)
                entry['downloads'] = download(client, entry['snapshot'], folder)
                if entry['status'] == 'completed' and case['preferred_entry'] not in replayed:
                    counts = (Prompt.objects.count(), AgentExecution.objects.count(), AgentArtifact.objects.count(), len(provider_events()))
                    replay = post_turn(client, case, turn, conversation, request_id)
                    after = (Prompt.objects.count(), AgentExecution.objects.count(), AgentArtifact.objects.count(), len(provider_events()))
                    check = {'entry': case['preferred_entry'], 'case': case['id'], 'turn': turn['id'],
                        'http_status': replay['http_status'], 'counts_before': counts, 'counts_after': after, 'passed': counts == after}
                    report['idempotency'].append(check)
                    if not check['passed']:
                        raise RuntimeError('Request replay caused a duplicate effect.')
                    replayed.add(case['preferred_entry'])
                for artifact in entry['downloads']:
                    status = outsider.get(artifact['download_url']).status_code
                    if status != 404:
                        raise RuntimeError('Other-tenant artifact access was not hidden.')
                    artifact['other_tenant_status'] = status
                if turn.get('rubric', {}).get('prior_revision_still_downloadable'):
                    prior = case_report['turns'][0].get('downloads', [])
                    entry['prior_revision_downloads'] = []
                    for artifact in prior:
                        response = client.get(artifact['download_url'])
                        entry['prior_revision_downloads'].append({'id': artifact['id'],
                            'http_status': response.status_code,
                            'sha256': hashlib.sha256(response.content).hexdigest(),
                            'same_bytes': response.status_code == 200 and hashlib.sha256(response.content).hexdigest() == artifact['download_sha256']})
                if entry['status'] == 'outcome_unknown':
                    report['stopped'] = 'execution_outcome_unknown'
            except Exception as error:
                entry['status'] = 'harness_error'
                entry['error_type'] = type(error).__name__
                entry['error'] = str(error)[:300]
                report['stopped'] = 'harness_error'
            finally:
                entry['wall_seconds'] = round(time.monotonic() - started, 3)
                entry['provider_events'] = provider_events()[before:]
                if entry.get('status') in ('failed', 'harness_error', 'not_enqueued') and not entry['provider_events']:
                    report['stopped'] = 'failure_before_provider'
                report['budget'] = guard.snapshot()
                write(target, report)
                print(json.dumps({'case': case['id'], 'turn': turn['id'], 'status': entry.get('status'),
                    'seconds': entry['wall_seconds'], 'provider_calls': len(entry['provider_events']),
                    'budget': {key: value for key, value in report['budget'].items() if key != 'reservations'}}, default=str), flush=True)
                connection.close()
            if report.get('stopped'):
                return
    if len(report['conversations']) == len(corpus['conversations']):
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    write(target, report)
    client.close()
    outsider.close()


if __name__ == '__main__':
    main()

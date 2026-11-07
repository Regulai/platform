"""Reproducible offline regression bank over the real chat use case."""
from collections import Counter
from datetime import date, datetime, timezone
from decimal import Decimal
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import uuid

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
import requests

from front.chat_service import send_chat_message
from front.connectors import ChatResponse
from front.documents import extract_document
from front.models import Company, CompanyEngine, Engine, EngineModel, ObfuscationConfig, Profile, RulesGroup, Rule


ROOT = Path(__file__).resolve().parents[4]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sha256(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode('utf-8')).hexdigest()


def load_bank(manifest_path):
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text(encoding='utf-8'))
    if manifest.get('mode') != 'offline' or manifest.get('configurations') != ['economy', 'strong', 'router']:
        raise CommandError('This command accepts only the three declared offline configurations.')
    dataset = (path.parent / manifest['dataset']).resolve()
    if not dataset.is_relative_to(path.parent):
        raise CommandError('Dataset must stay inside its manifest directory.')
    cases = [json.loads(line) for line in dataset.read_text(encoding='utf-8').splitlines() if line.strip()]
    if (len(cases) != 50 or len({case['id'] for case in cases}) != 50
            or Counter(case['group'] for case in cases) != manifest['group_counts']
            or Counter(case['split'] for case in cases) != manifest['split_counts']):
        raise CommandError('The frozen bank requires 50 unique cases and the declared group/split counts.')
    documents = {}
    for case in cases:
        if not all(case.get(key) for key in ('id', 'language', 'task', 'input', 'reason', 'expected_status')):
            raise CommandError('Cases need stable IDs, language, task, input, labels and rationale.')
        if case.get('policy') != manifest['policy_version']:
            raise CommandError('Each case must reference the frozen policy version.')
        if case.get('document_path'):
            document = (path.parent / case['document_path']).resolve()
            if not document.is_relative_to(path.parent):
                raise CommandError('Document must stay inside its manifest directory.')
            documents[case['document_path']] = sha256(document.read_bytes())
    return manifest, cases, dataset, documents


def observed_outcome(data, calls):
    """Translate execution state into documented human labels, retaining both."""
    state, code = data['status'], data.get('error_type')
    if code == 'clarification_required':
        return 'clarification_required'
    if code in {'classification_ambiguous', 'no_authorized_candidates', 'model_not_allowed'} and not any(
            call['purpose'] == 'generation' for call in calls):
        return 'blocked'
    if code in {'verification_failed', 'quality_unavailable'}:
        return 'not_verified'
    if state in {'failed', 'outcome_unknown'} and calls and calls[-1]['purpose'] == 'verification':
        return 'not_verified'
    return state


def summarize(rows):
    summaries = []
    for configuration in ('economy', 'strong', 'router'):
        for split in ('development', 'reserved', 'all'):
            selected = [row for row in rows if row['configuration'] == configuration
                        and (split == 'all' or row['split'] == split)]
            if not selected:
                continue
            known = sum((Decimal(row['known_cost']) for row in selected), Decimal(0))
            unknown = sum(row['unknown_cost_calls'] for row in selected)
            correct_answers = sum(row['exact_answer'] for row in selected)
            latencies = sorted(row['latency_ms'] for row in selected)
            summaries.append({
                'configuration': configuration, 'split': split, 'cases': len(selected),
                'control_passes': sum(row['control_pass'] for row in selected),
                'delivered': sum(row['delivered'] for row in selected),
                'exact_answers': correct_answers,
                'correct_abstentions': sum(row['correct_abstention'] for row in selected),
                'forbidden_egress': sum(row['forbidden_egress'] for row in selected),
                'invalid_displayed_citations': sum(row['invalid_displayed_citations'] for row in selected),
                'calls': sum(len(row['calls']) for row in selected),
                'provider_calls': sum(call.get('transport') != 'local' and call.get('status') != 'not_started'
                                      for row in selected for call in row['calls']),
                'local_transformations': sum(call.get('transport') == 'local' and call.get('status') != 'not_started'
                                             for row in selected for call in row['calls']),
                'generation_calls': sum(row['generation_calls'] for row in selected),
                'escalations': sum(row['generation_calls'] > 1 for row in selected),
                'errors_corrected': sum(row['errors_corrected'] for row in selected),
                'errors_introduced': sum(row['errors_introduced'] for row in selected),
                'security_false_negatives': sum(row['security_false_negative'] for row in selected),
                'security_false_positives': sum(row['security_false_positive'] for row in selected),
                'failed_cases': sum(row['execution_state'] in ('failed', 'outcome_unknown', 'validation_error') for row in selected),
                'unverified_cases': sum(row['observed_outcome'] == 'not_verified' for row in selected),
                'input_tokens': sum(row['input_tokens'] for row in selected),
                'output_tokens': sum(row['output_tokens'] for row in selected),
                'unknown_usage_calls': sum(row['unknown_usage_calls'] for row in selected),
                'known_cost': str(known), 'unknown_cost_calls': unknown,
                'total_cost': str(known) if unknown == 0 else None,
                'cost_per_exact_answer': str(known / correct_answers) if correct_answers and unknown == 0 else None,
                'currency': 'USD', 'median_latency_ms': statistics.median(latencies),
                'p95_latency_ms': latencies[math.ceil(len(latencies) * 0.95) - 1],
                'real_provider_cases': 0, 'real_quality': None, 'real_savings': None,
            })
    return summaries


class OfflineProviders:
    """Generation/judge fixtures; identity HTTP mask retained for remote compatibility tests."""
    def __init__(self, case, manifest):
        self.case, self.manifest, self.events = case, manifest, []
        self.last_correct = True

    def generate(self, messages, model, **kwargs):
        texts = [message.content for message in messages]
        self.events.append({'purpose': 'generation', 'content_hash': sha256(texts),
                            'forbidden': any('SYNTHETIC_SECRET' in text for text in texts)})
        fault = self.case.get('fault')
        if fault == 'timeout':
            raise TimeoutError('synthetic timeout with unknown result')
        answer = self.case.get('expected', 'Synthetic answer')
        if model == self.manifest['model_versions']['economy']:
            answer = self.case.get('economy_output', answer)
        self.last_correct = answer == self.case.get('expected', 'Synthetic answer')
        self.events[-1]['correct_answer'] = self.last_correct and fault not in {
            'false_citation', 'html_citation', 'foreign_citation', 'path_citation',
            'edited_quote', 'invalid_json', 'empty', 'truncated', 'refusal'}
        content, finish_reason = answer, 'stop'
        sources = []
        for text in texts:
            if '\n\nSources:\n' in text:
                sources = json.loads(text.split('\n\nSources:\n', 1)[1])
        if sources:
            quote = self.case.get('quote', sources[0]['text'])
            normalized = ' '.join(quote.split())
            source = next((fragment for fragment in sources if normalized in ' '.join(fragment['text'].split())), sources[0])
            if len(''.join(normalized.split())) < 12 and len(normalized.split()) < 3:
                literal = ' '.join(source['text'].split())
                position = literal.find(normalized)
                if position >= 0:
                    start = max(0, min(position, len(literal) - 1600))
                    quote = literal[start:start + 1600]
            source_id = source['id']
            source_id = {'false_citation': 'invented-source', 'html_citation': '<img src=x onerror=alert(1)>',
                         'foreign_citation': 'other-conversation-source', 'path_citation': 'C:/private/source.txt'}.get(fault, source_id)
            if fault == 'edited_quote':
                quote = 'Plazo inventado: 999 días.'
            content = canonical({'claims': [{'text': answer, 'citations': [{'id': source_id, 'quote': quote}]}]})
        if fault == 'invalid_json':
            content = '{broken-json'
        elif fault == 'empty':
            content = ''
        elif fault == 'truncated':
            finish_reason = 'length'
        elif fault == 'refusal':
            finish_reason = 'content_filter'
        usage = self.manifest['synthetic_usage']
        return ChatResponse(content=content, finish_reason=finish_reason, model=model,
                            input_tokens=usage['generation_input_tokens'], output_tokens=usage['generation_output_tokens'],
                            tokens_used=usage['generation_input_tokens'] + usage['generation_output_tokens'],
                            provider_request_id=f"synthetic-{self.case['id']}", usage={})

    def post(self, url, *, data=None, **kwargs):
        mask_payload = kwargs.pop('json', None)
        if mask_payload is not None:
            if url != 'https://mask.offline.invalid/api/mask':
                raise AssertionError('Unexpected synthetic masking destination')
            texts = json.loads(mask_payload['text'])
            if not isinstance(texts, list) or any(not isinstance(text, str) for text in texts):
                raise AssertionError('Mask contract requires a structured string batch')
            self.events.append({'purpose': 'obfuscation', 'content_hash': sha256(texts),
                                'forbidden': any('SYNTHETIC_SECRET' in text for text in texts)})
            response = requests.Response()
            response.status_code, response._content, response._content_consumed = 200, canonical({'masked': mask_payload['text']}).encode(), True
            return response
        return self.judge_response(data)

    def judge_response(self, data):
        payload = json.loads(data)
        questions = payload['questions']
        purpose = 'classification' if 'category' in questions else 'verification'
        self.events.append({'purpose': purpose, 'content_hash': sha256(payload['state']),
                            'forbidden': 'SYNTHETIC_SECRET' in canonical(payload['state'])})
        answers = {}
        for key, question in questions.items():
            if question['type'] == 'choice':
                choice = {'category': self.case.get('sensitivity', 'public'),
                          'task': self.case['task'], 'difficulty': self.case.get('difficulty', 'economy')}[key]
                answers[key] = {'type': 'choice', 'choice': choice, 'confidence': 1.0,
                                'probabilities': {option: float(option == choice) for option in question['criteria']}}
            else:
                failed = (key == 'ambiguous' and self.case.get('ambiguous')) or (
                    key == 'insufficient_evidence' and self.case.get('insufficient_evidence')) or (
                    purpose == 'verification' and not self.last_correct)
                answers[key] = {'type': 'noul', 'noul': float(bool(failed))}
        usage = self.manifest['synthetic_usage']
        body = canonical({'model': payload['model'], 'answers': answers,
                          'usage': {'input_tokens': usage['judge_input_tokens'], 'output_tokens': usage['judge_output_tokens']}}).encode()
        if self.case.get('fault') == 'judge_invalid_json' and purpose == 'verification':
            body = b'{invalid-judge-json'
        response = requests.Response()
        response.status_code, response._content, response._content_consumed = 200, body, True
        response.headers['x-request-id'] = f"synthetic-{self.case['id']}-{purpose}"
        return response


def policy_config(case, configuration, manifest, credential, models, mask=None):
    """Shared synthetic policy for regression runs and the isolated demo."""
    levels = ['economy', 'strong'] if configuration == 'router' else [configuration]
    generator_destinations = [] if case.get('deny_generation') else [f'engine:{credential.pk}']
    return {
        'version': 1, 'classification': manifest['classification_mode'], 'local_sensitivity': 'public', 'allow_empty_rules': False,
        'revision': manifest.get('policy_revision', 1),
        'classification_policy': manifest.get('classification_policy_override', {}),
        'destinations': {level: generator_destinations + ['jev'] + ([f'obfuscation:{mask.pk}'] if mask else [])
                         for level in ('public', 'internal', 'confidential')},
        'masking': {'max_call_cost': '0'},
        'jev': {'transport': 'typesafe', 'model': manifest['model_versions']['judge'],
                'input_price': manifest['prices_per_million']['judge']['input'],
                'output_price': manifest['prices_per_million']['judge']['output'],
                'price_date': manifest['price_date'], 'max_call_cost': manifest['jev_max_call_cost'],
                'threshold': manifest['thresholds']['classification']},
        'routing': {'mode': 'auto' if configuration == 'router' else 'manual',
                    'candidates': [{'company_engine_id': credential.pk, 'model_id': models[level].pk, 'level': level,
                                    'quality': {task: manifest['quality_by_task'][level]
                                                for task in ('general', 'extraction', 'summary', 'document_question')}} for level in levels],
                    'min_quality': manifest['minimum_quality'], 'max_output_tokens': manifest['limits']['max_output_tokens']},
        'verification': {'mode': manifest['verification_mode'], 'threshold': manifest['thresholds']['verification'],
                         'rubric_version': manifest['rubrics']['verification']},
        'limits': {'budget': manifest['limits']['budget'], 'deadline_seconds': manifest['limits']['deadline_seconds']},
    }


def run_case(case, configuration, manifest, root, engine, models, run_id):
    unique = uuid.uuid4().hex
    actor = User.objects.create(username=f'eval-{unique}')
    actor.set_unusable_password()
    actor.save(update_fields=['password'])
    company = Company.objects.create(name=f'eval-{unique}', jev_api_key='synthetic-offline-credential')
    credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic-offline-credential')
    selected = models['economy' if configuration == 'router' else configuration]
    Profile.objects.create(user=actor, company=company, default_engine=credential, default_model=selected)
    # Preserve the legacy bank's literal-output contract. The separate pilot path
    # exercises the real local detector, whose transformations can change labels.
    mask = ObfuscationConfig.objects.create(company=company, name='Synthetic offline mask',
                                            backend='http', api_url='https://mask.offline.invalid', active=True)
    company.ai_config = policy_config(case, configuration, manifest, credential, models, mask)
    company.save(update_fields=['ai_config'])
    group = RulesGroup.objects.create(company=company, name='Synthetic evaluation policy')
    Rule.objects.create(rules_group=group, name='Synthetic secret',
                        yara_rule='rule synthetic_secret { strings: $a = "SYNTHETIC_SECRET" condition: $a }')
    Rule.objects.create(rules_group=group, name='Synthetic consent', action='consent',
                        yara_rule='rule synthetic_consent { strings: $a = "SYNTHETIC_CONSENT" condition: $a }')
    if case.get('fault') == 'invalid_rule':
        Rule.objects.create(rules_group=group, name='Corrupt synthetic rule', yara_rule='rule broken {')
    original_model_values = {level: (model.input_price, model.output_price, model.context_window)
                             for level, model in models.items()}
    if case.get('fault') in {'missing_price', 'context_overflow'}:
        for model in models.values():
            if case['fault'] == 'missing_price':
                model.input_price = None
                model.save(update_fields=['input_price'])
            else:
                model.context_window = 10
                model.save(update_fields=['context_window'])
    document_bytes = ((root / case['document_path']).read_bytes() if case.get('document_path') else
                      case['document'].encode('utf-8') if 'document' in case else None)
    document_name = case.get('document_name', 'synthetic.txt')
    def command(content=None, **changes):
        values = {'content': case['input'] if content is None else content,
                  'request_id': str(uuid.uuid5(uuid.NAMESPACE_URL, f'{run_id}/{case["id"]}/{configuration}'))}
        if document_bytes is not None:
            values['file'] = SimpleUploadedFile(document_name, document_bytes)
        return {**values, **changes}
    providers = OfflineProviders(case, manifest)
    started = time.monotonic()
    try:
        with patch('front.chat_service.get_connector', return_value=SimpleNamespace(chat=providers.generate)), \
                patch('front.jev.requests.post', side_effect=providers.post), \
                patch('requests.sessions.Session.request', side_effect=AssertionError('Offline evaluation forbids HTTP')), \
                patch('socket.socket.connect', side_effect=AssertionError('Offline evaluation forbids network access')):
            scenario = case.get('scenario')
            conversation_id = None
            if scenario == 'blocked_history':
                previous = send_chat_message(actor, {'content': 'SYNTHETIC_SECRET_HISTORY'})
                conversation_id = previous.data['conversation_id']
            result = send_chat_message(actor, command(**({'conversation_id': conversation_id} if conversation_id else {})))
            if scenario in {'consent_accept', 'consent_change', 'cancel'}:
                changes = {'consent_token': result.data.get('consent_token')}
                if scenario == 'consent_change':
                    changes['content'] = case['input'] + ' modified'
                elif scenario == 'cancel':
                    changes['action'] = 'cancel'
                result = send_chat_message(actor, command(**changes))
            elif scenario == 'duplicate':
                result = send_chat_message(actor, command())
    finally:
        for level, model in models.items():
            model.input_price, model.output_price, model.context_window = original_model_values[level]
            model.save(update_fields=['input_price', 'output_price', 'context_window'])
    elapsed = round((time.monotonic() - started) * 1000, 3)
    data = result.data
    calls = [{key: value for key, value in call.items() if key not in ('duration_ms', 'provider')}
             for call in data.get('receipt', {}).get('calls', [])]
    state = observed_outcome(data, calls)
    expected = case.get('expected_by_configuration', {}).get(configuration, case['expected_status'])
    # Same configured floor applies to fixed baselines: insufficient capability abstains.
    if configuration == 'economy' and case.get('difficulty') == 'strong':
        expected = 'not_verified'
    delivered = bool(data.get('assistant_message'))
    content = data.get('assistant_message', {}).get('content', '')
    evidence = data.get('evidence', {}).get('items', [])
    if evidence:
        content = content.rsplit(' [', 1)[0]
    generation_calls = sum(event['purpose'] == 'generation' for event in providers.events)
    forbidden = sum(event['forbidden'] for event in providers.events)
    if case.get('expected_external_calls') == 0:
        forbidden = len(providers.events)
    elif case.get('expected_generation_calls') == 0:
        forbidden = max(forbidden, generation_calls)
    generations = [event for event in providers.events if event['purpose'] == 'generation']
    corrected = len(generations) > 1 and generations[0].get('correct_answer') is False and generations[-1].get('correct_answer') is True
    introduced = len(generations) > 1 and generations[0].get('correct_answer') is True and generations[-1].get('correct_answer') is False
    valid_sources = set()
    if document_bytes is not None:
        valid_sources = {fragment['id'] for fragment in extract_document(SimpleUploadedFile(document_name, document_bytes)).fragments}
    invalid_citations = sum(item['id'] not in valid_sources for item in evidence)
    passed = state == expected and not forbidden and not invalid_citations
    passed = passed and generation_calls <= manifest['max_generation_attempts'][configuration]
    if delivered and expected == 'completed' and 'expected' in case:
        passed = passed and content == case['expected']
    if 'expected_external_calls' in case:
        passed = passed and len(providers.events) == case['expected_external_calls']
    if 'expected_generation_calls' in case:
        passed = passed and generation_calls == case['expected_generation_calls']
    notices = data.get('receipt', {}).get('notices', [])
    sensitivity = data.get('decision', {}).get('sensitivity')
    if 'expected_notices' in case:
        passed = passed and set(case['expected_notices']).issubset(notices)
    if 'expected_sensitivity' in case:
        passed = passed and sensitivity == case['expected_sensitivity']
    known = sum((Decimal(call['cost']) for call in calls if call.get('cost') is not None), Decimal(0))
    row = {'case_id': case['id'], 'configuration': configuration, 'group': case['group'], 'split': case['split'],
           'mode': 'simulated', 'masking_backend': 'http', 'masking_execution': 'fixture',
           'execution_state': data['status'], 'error_type': data.get('error_type'),
           'observed_outcome': state, 'expected_outcome': expected, 'control_pass': bool(passed),
           'notices': notices, 'sensitivity': sensitivity,
           'delivered': delivered, 'exact_answer': delivered and content == case.get('expected'),
           'correct_abstention': not delivered and passed, 'forbidden_egress': forbidden,
           'invalid_displayed_citations': invalid_citations, 'generation_calls': generation_calls,
           'errors_corrected': corrected, 'errors_introduced': introduced,
           'security_false_negative': forbidden > 0,
           'security_false_positive': case['group'] == 'sensitivity' and expected == 'completed' and not delivered,
           'calls': calls, 'known_cost': str(known),
           'unknown_cost_calls': sum(call.get('cost') is None for call in calls),
           'input_tokens': sum(call.get('input_tokens') or 0 for call in calls),
           'output_tokens': sum(call.get('output_tokens') or 0 for call in calls),
           'unknown_usage_calls': sum(call.get('transport') != 'local' and call.get('status') != 'not_started'
               and (call.get('input_tokens') is None or call.get('output_tokens') is None) for call in calls),
           'answer_hash': sha256(content), 'evidence_ids': [item['id'] for item in evidence],
           'quality_status': data.get('receipt', {}).get('verification', {}).get('status', 'not_verified')}
    row['result_hash'] = sha256(row)
    row['latency_ms'] = elapsed
    return row


class Command(BaseCommand):
    help = 'Offline controls by default; real pilot runs require an explicit frozen authorization.'

    def add_arguments(self, parser):
        parser.add_argument('--output', required=True, help='New output directory; existing paths are never replaced.')
        parser.add_argument('--manifest', default=str(ROOT / 'evals' / 'manifest.json'))
        parser.add_argument('--split', choices=['all', 'development', 'reserved'], default='all')
        parser.add_argument('--real', action='store_true', help='Explicit opt-in; requires the pilot manifest and authorization.')
        parser.add_argument('--authorization', help='New explicit approval bound to the pilot manifest; never inferred from historical permission.')
        parser.add_argument('--max-usd', help='Must exactly match the new approved total ceiling.')
        parser.add_argument('--preflight', action='store_true', help='Read-only pilot checks; zero provider calls.')

    def handle(self, *args, **options):
        from front.evaluation import read_json, run_pilot
        if read_json(options['manifest']).get('bank_kind') == 'pilot':
            return run_pilot(options, self.stdout)
        if options['real']:
            raise CommandError('Real evaluation requires a pilot manifest and new explicit authorization.')
        if options.get('preflight'):
            raise CommandError('Preflight requires a pilot manifest.')
        database = connection.settings_dict
        name = str(database['NAME'])
        memory = name == ':memory:' or (name.startswith('file:') and parse_qs(urlsplit(name).query).get('mode') == ['memory'])
        if database['ENGINE'] != 'django.db.backends.sqlite3' or not memory:
            raise CommandError('Use isolated in-memory SQLite: --settings=regulai.test_settings. Existing databases are never modified.')
        manifest, cases, dataset, documents = load_bank(options['manifest'])
        output = Path(options['output']).resolve()
        if output.exists():
            raise CommandError('Output directory already exists; choose a new path to preserve earlier runs.')
        if 'front_company' not in connection.introspection.table_names():
            call_command('migrate', interactive=False, verbosity=0)
        output.mkdir(parents=True, exist_ok=False)
        run_id = uuid.uuid4().hex
        engine = Engine.objects.create(name=f'Synthetic evaluation {run_id}')
        models = {level: EngineModel.objects.create(engine=engine, name=f'Synthetic {level}',
                    model_id=manifest['model_versions'][level], max_tokens=manifest['limits']['max_output_tokens'],
                    context_window=manifest['context_window'],
                    supports_json=True, input_price=Decimal(manifest['prices_per_million'][level]['input']),
                    output_price=Decimal(manifest['prices_per_million'][level]['output']),
                    price_date=date.fromisoformat(manifest['price_date'])) for level in ('economy', 'strong')}
        selected = [case for case in cases if options['split'] == 'all' or case['split'] == options['split']]
        rows, order = [], []
        for index, case in enumerate(selected):
            configurations = manifest['configurations']
            offset = (index + manifest['seed']) % 3
            for configuration in configurations[offset:] + configurations[:offset]:
                order.append([case['id'], configuration])
                rows.append(run_case(case, configuration, manifest, dataset.parent, engine, models, run_id))
        summaries = summarize(rows)
        try:
            commit = subprocess.run(['rtk', 'git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            commit = 'unavailable'
        from front.evaluation import runtime_versions
        frozen = {**manifest, 'dataset_hash': sha256(dataset.read_bytes()), 'document_hashes': documents,
                  'masking_observed': {'backend': 'http', 'execution': 'fixture', 'api_url': 'https://mask.offline.invalid'},
                  'runtime_versions_observed': runtime_versions(),
                  'manifest_template_hash': sha256(Path(options['manifest']).read_bytes()),
                  'evaluator_source_hash': sha256(Path(__file__).read_bytes()),
                  'commit': commit, 'run_id': run_id, 'created_at': datetime.now(timezone.utc).isoformat(),
                  'selected_split': options['split'], 'execution_order': order,
                  'source_hashes': {name: sha256((ROOT / 'regulai' / 'front' / name).read_bytes())
                                    for name in ('chat_service.py', 'policy.py', 'routing.py', 'verification.py', 'jev.py', 'documents.py', 'masking.py', 'local_masking.py')},
                  'outcomes_hash': sha256([row['result_hash'] for row in rows]),
                  'label_normalization': 'Execution state is retained. Clarification error=>clarification; unavailable authorized routes=>blocked; rejected local/semantic checks and failed judge=>not_verified. Fixed economy below the shared strong floor correctly abstains.'}
        (output / 'manifest.json').write_text(json.dumps(frozen, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (output / 'results.jsonl').write_text(''.join(canonical(row) + '\n' for row in rows), encoding='utf-8')
        (output / 'summary.json').write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        with (output / 'summary.csv').open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
            writer.writeheader()
            writer.writerows(summaries)
        lines = ['# Offline evaluation', '', manifest['scope'], '',
                 f"Cases: {len(selected)}. Runs: {len(rows)}. Real provider cases: 0. Commit: `{commit}`.", '',
                 '| Configuration | Split | Controls passed | Delivered | Exact answers | Known simulated USD | Unknown cost calls | p95 ms |',
                 '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |']
        for summary in summaries:
            lines.append(f"| {summary['configuration']} | {summary['split']} | {summary['control_passes']}/{summary['cases']} | {summary['delivered']} | {summary['exact_answers']} | {summary['known_cost']} | {summary['unknown_cost_calls']} | {summary['p95_latency_ms']} |")
        lines.extend(['', 'Provider/judge answers and token usage are preprogrammed. Exact-answer counts exercise reference-label comparisons, not provider precision. Real quality and savings remain unmeasured.', '',
                      'This legacy regression bank uses an identity HTTP masking fixture to preserve its original literal-output contract. New pilot-real and pilot-human manifests use the real local CPU detector and report its transformations separately.', '',
                      'Unknown billed calls stay unknown and are excluded from any complete total or cost-per-correct calculation. Latencies are local observations, with the sample size shown; outcome hashes exclude clocks and run identities.', '',
                      'Failed controls (case ID / configuration / observed / expected):', ''])
        lines.extend(f"- {row['case_id']} / {row['configuration']} / {row['observed_outcome']} / {row['expected_outcome']}" for row in rows if not row['control_pass'])
        (output / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        failures = sum(not row['control_pass'] for row in rows)
        self.stdout.write(f'{len(rows)} simulated runs; {failures} failed controls; real calls 0. Reports: {output}')
        if failures:
            raise CommandError(f'{failures} failed controls. Reports: {output}')

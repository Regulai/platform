"""Safe failure diagnostics through HTTP adapters and the isolated budget harness."""
from decimal import Decimal
import json
from unittest.mock import patch
import uuid

import requests
from django.core.management.base import CommandError
from django.test import TestCase

from . import jev
from .models import Prompt, Rule
from .test_chat_flow import ChatFixture
from .test_pipeline import jev_http
from .test_smoke import SmokeHarness


SENSITIVE = 'SYNTHETIC_DIAGNOSTIC_SECRET_BODY'
FAULTS = (('timeout', 'timeout'), ('http-503', 'http_503'), ('invalid-json', 'invalid_response'))


def failed_judge(fault):
    if isinstance(fault, jev.JevError):
        raise fault
    if fault == 'timeout':
        raise requests.ReadTimeout(SENSITIVE)
    response = requests.Response()
    response.status_code = 503 if fault == 'http-503' else 200
    response._content = ('{"private_detail":"' + SENSITIVE + '"').encode('utf-8')
    response._content_consumed = True
    return response


class JevFailureDiagnosticTests(ChatFixture):
    def setUp(self):
        super().setUp()
        self.required_mask.backend = 'local'
        self.required_mask.api_url = ''
        self.required_mask.save()
        self.model.supports_json = True
        self.model.input_price, self.model.output_price = Decimal('.30'), Decimal('1.20')
        self.model.save()
        self.company.jev_api_key = 'synthetic-diagnostic-jev-key'
        self.company.ai_config.update(classification='required',
            jev={'transport': 'vercel', 'model': jev.VERCEL_MODEL, 'input_price': '.042',
                 'output_price': '0', 'max_call_cost': '.003'},
            verification={'mode': 'enforce', 'threshold': 0.8}, limits={'budget': '1'})
        self.company.ai_config['destinations']['internal'].append('jev')
        self.company.save()
        self.fault, self.failed_purpose = 'timeout', 'classification'
        self.http.side_effect = self.transport
        self.socket = self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('No network')))
        self.sdk = self.enterContext(patch('httpx.Client.send', side_effect=AssertionError('No SDK network')))

    def transport(self, url, *, data=None, **kwargs):
        self.assertEqual(url, jev.VERCEL_ENDPOINT)
        payload = json.loads(data)
        self.assertEqual(payload['providerOptions'], {'gateway': {'only': ['typesafe-ai']}})
        purpose = 'classification' if 'category' in payload['questions'] else 'verification'
        if purpose == self.failed_purpose:
            return failed_judge(self.fault)
        return jev_http()(url, data=data, **kwargs)

    def test_classification_failure_cause_survives_three_http_entries_without_retry_or_disclosure(self):
        for fault, expected in FAULTS:
            self.fault = fault
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(fault=fault, path=path):
                    request_id = str(uuid.uuid4())
                    before = self.http.call_count
                    with self.assertLogs('front.chat_service', level='WARNING') as logged:
                        response = self.send(path, request_id=request_id)
                    data = response.json()
                    self.assertEqual((response.status_code, data['status'], data['error_type']),
                                     (504, 'outcome_unknown', 'security_check_failed'))
                    call = data['receipt']['calls'][-1]
                    self.assertEqual(call.get('provider_error_code'), expected)
                    self.assertEqual((call['status'], call['cost'], call['cost_bound'], call['cost_kind']),
                                     ('outcome_unknown', None, '0.003', 'unknown'))
                    self.assertNotIn('no se ha enviado', data['error'])
                    self.assertIn('incierto', data['error'])
                    saved = Prompt.objects.get(user=self.user, request_id=request_id)
                    self.assertEqual(saved.decision['calls'][-1], call)
                    self.assertIn(expected, [getattr(record, 'code', None) for record in logged.records])
                    public = json.dumps([data, saved.decision, logged.output], ensure_ascii=False)
                    self.assertNotIn(SENSITIVE, public)
                    self.assertNotIn('synthetic-diagnostic-jev-key', public)
                    self.assertEqual(self.http.call_count, before + 1)
                    repeated = self.send(path, request_id=request_id).json()
                    self.assertEqual(repeated['receipt']['calls'], data['receipt']['calls'])
                    self.assertEqual(self.http.call_count, before + 1)
        self.provider.assert_not_called()
        self.socket.assert_not_called()
        self.sdk.assert_not_called()

    def test_unknown_or_nonstring_jev_codes_are_rejected_before_storage_and_logging(self):
        for unsafe in (SENSITIVE, {'private': SENSITIVE}, None):
            with self.subTest(code_type=type(unsafe).__name__):
                self.fault = jev.JevError(unsafe, outcome_unknown=True)
                with self.assertLogs('front.chat_service', level='WARNING') as logged:
                    data = self.send('/api/chat/send/').json()
                self.assertEqual(data['receipt']['calls'][-1].get('provider_error_code'), 'unknown_jev_error')
                self.assertEqual(data['error_type'], 'security_check_failed')
                self.assertIn('unknown_jev_error', [getattr(record, 'code', None) for record in logged.records])
                self.assertNotIn(SENSITIVE, json.dumps([data, logged.output], ensure_ascii=False))
        self.provider.assert_not_called()
        self.socket.assert_not_called()

    def test_verification_also_sanitizes_unknown_jev_codes(self):
        self.failed_purpose = 'verification'
        self.fault = jev.JevError(SENSITIVE, outcome_unknown=True)
        with self.assertLogs('front.chat_service', level='WARNING') as logged:
            data = self.send('/api/chat/send/').json()
        self.assertEqual((data['status'], data['error_type']), ('failed', 'verification_failed'))
        call = data['receipt']['calls'][-1]
        self.assertEqual((call['purpose'], call['status'], call['cost']), ('verification', 'outcome_unknown', None))
        self.assertEqual(call.get('provider_error_code'), 'unknown_jev_error')
        self.assertNotIn(SENSITIVE, json.dumps([data, logged.output], ensure_ascii=False))
        self.assertEqual(self.provider.call_count, 1)
        self.socket.assert_not_called()

    def test_local_security_failure_still_has_no_external_calls_or_provider_cause(self):
        Rule.objects.filter(pk=self.rule.pk).update(yara_rule='invalid YARA source')
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                response = self.send(path)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()['error_type'], 'security_check_failed')
                self.assertEqual(response.json()['receipt']['calls'], [])
        self.http.assert_not_called()
        self.provider.assert_not_called()
        self.socket.assert_not_called()


class PilotFailureDiagnosticTests(SmokeHarness, TestCase):
    def requests_transport(self, method, url, **kwargs):
        self.assertEqual((method, url), ('post', jev.ENDPOINT))
        self.assert_reserved('classification')
        return failed_judge(self.fault)

    def test_failure_cause_reaches_ledger_without_releasing_unknown_reservations(self):
        self.use_local_mask()
        for index, (fault, expected) in enumerate(FAULTS, 1):
            with self.subTest(fault=fault):
                self.fault = fault
                with self.assertRaises(CommandError):
                    self.run_smoke('diagnostic-' + fault)
                snapshot = self.ledger()
                call = snapshot['calls'][-1]
                self.assertEqual(call['metadata'].get('provider_error_code'), expected)
                self.assertEqual((call['status'], call['cost'], call['reserved']), ('outcome_unknown', None, '0.003'))
                self.assertEqual(Decimal(snapshot['uncertain_reservations_usd']), Decimal('.003') * index)
                self.assertEqual(Decimal(snapshot['budget_exposure_usd']), Decimal('.003') * index)
                self.assertNotIn(SENSITIVE, json.dumps(snapshot))
                report = json.loads((self.root / ('diagnostic-' + fault) / 'manifest.json').read_text(encoding='utf-8'))
                self.assertEqual(report['stop_reason'], 'failed_or_uncertain_provider_call')
        self.sdk.assert_not_called()
        self.socket.assert_not_called()

"""Offline provider fixtures emit meaningful quotes without changing case labels."""
import json

from django.test import SimpleTestCase

from front.connectors import ChatMessage
from front.management.commands.evaluate_ai import OfflineProviders
from front.verification import verify_response


class OfflineQuoteTests(SimpleTestCase):
    manifest = {'model_versions': {'economy': 'synthetic'}, 'synthetic_usage': {
        'generation_input_tokens': 20, 'generation_output_tokens': 10}}

    def test_short_fixture_quotes_expand_literally_and_remain_bounded(self):
        for text in ('Importe total: 30 euros.', 'Context. ' * 300 + 'Importe total: 30 euros.'):
            sources = [{'id': 'synthetic-source', 'locator': 'lines:1-3', 'text': text}]
            case = {'id': 'synthetic-quote', 'expected': '30 euros', 'quote': '30 euros.'}
            response = OfflineProviders(case, self.manifest).generate([
                ChatMessage('user', 'Question\n\nSources:\n' + json.dumps(sources))], 'synthetic')
            quote = json.loads(response.content)['claims'][0]['citations'][0]['quote']
            self.assertIn('30 euros.', quote)
            self.assertLessEqual(len(quote), 1600)
            self.assertEqual(verify_response(response.content, response.finish_reason,
                                            fragments=sources)['local_status'], 'passed')
            self.assertEqual(case['quote'], '30 euros.')

    def test_expanding_short_quotes_preserves_injected_faults(self):
        sources = [{'id': 'synthetic-source', 'locator': 'line:1', 'text': 'Importe total: 30 euros.'}]
        for fault, reason in (('false_citation', 'unknown_citation'), ('edited_quote', 'quote_not_found')):
            response = OfflineProviders({'id': 'synthetic-fault', 'expected': '30 euros',
                'quote': '30 euros.', 'fault': fault}, self.manifest).generate([
                    ChatMessage('user', 'Question\n\nSources:\n' + json.dumps(sources))], 'synthetic')
            checks = verify_response(response.content, response.finish_reason, fragments=sources)
            self.assertEqual(checks['checks'][-2]['reason'], reason)

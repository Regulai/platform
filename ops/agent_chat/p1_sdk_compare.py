"""Repeat the immutable E1 SDK fixture algorithm against P1, without provider network."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
E1 = ROOT / 'output/p1-20261016/e1'
E8 = ROOT / 'output/p1-20261016/e8'


def main():
    manifest = json.loads((E1 / 'p0-manifest.json').read_text(encoding='utf-8'))
    expected = next(row['sha256'] for row in manifest['files'] if row['path'] == 'regulai/front/connectors.py')
    assert hashlib.sha256((E1 / 'frozen/regulai/front/connectors.py').read_bytes()).hexdigest() == expected
    E8.mkdir(parents=True, exist_ok=True)
    os.environ.update(DJANGO_SETTINGS_MODULE='regulai.ci_settings', P1_BASELINE_EVIDENCE=str(E8))
    sys.path.insert(0, str(ROOT / 'regulai'))
    import django
    django.setup()
    from django.test import SimpleTestCase
    from front.test_agent_p1_baseline import P1SDKBaselineTests

    class CurrentSDKTests(SimpleTestCase):
        calls = 0

        def connector(self, handler):
            def counted(request):
                CurrentSDKTests.calls += 1
                return handler(request)
            return P1SDKBaselineTests.connector(self, counted)

        def test_same_twenty_samples_in_eight_contexts(self):
            P1SDKBaselineTests.test_local_sdk_overhead_distributions_record_all_twenty_samples(self)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CurrentSDKTests))
    if not result.wasSuccessful():
        return 1
    before = json.loads((E1 / 'sdk-overhead.json').read_text(encoding='utf-8'))
    after = json.loads((E8 / 'sdk-overhead.json').read_text(encoding='utf-8'))
    rows = []
    for old, new in zip(before['groups'], after['groups'], strict=True):
        key = ('context', 'warmth', 'concurrent_conversations', 'sample_count')
        assert all(old[name] == new[name] for name in key)
        first = sorted(max(call['first_provider_public_text_ms'] for call in sample['conversations']) for sample in new['samples'])
        rows.append({**{name: new[name] for name in key}, 'p0_p50_ms': old['median_ms'],
            'p0_p95_ms': old['p95_ms'], 'p1_p50_ms': new['median_ms'], 'p1_p95_ms': new['p95_ms'],
            'p1_first_sdk_text_p50_ms': (first[9]+first[10])/2, 'p1_first_sdk_text_p95_ms': first[18],
            'p50_difference_ms': new['median_ms']-old['median_ms']})
    summary = {'scope': 'Local SDK parsing with immediate synthetic HTTP chunks; no DB, ASGI, masking, worker or browser latency.',
        'limitations': ['No measurement of real provider latency, semantic quality or paid usage.',
            'Cold means a new SDK client per repetition; construction is outside the measured interval.',
            'Concurrent group sample is the maximum of its two request durations; samples are 20 per group.',
            'Windows scheduling and concurrent local work can affect tails; no claim of real-provider performance.'],
        'sample_batches': 160, 'synthetic_http_calls': CurrentSDKTests.calls, 'paid_calls': 0,
        'platform': platform.platform(), 'python': platform.python_version(), 'django': django.get_version(),
        'source_baseline_sha256': manifest['archive_sha256'], 'groups': rows}
    (E8 / 'sdk-comparison.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

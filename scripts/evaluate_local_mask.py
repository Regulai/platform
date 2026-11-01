"""Measure a frozen synthetic detector corpus; never claim complete PII detection."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'regulai'))
from front.local_masking import detector_metadata, mask_local_texts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    dataset = ROOT / 'evals/privacy/local-mask-v1/cases.json'
    plan = {'started_utc': datetime.now(timezone.utc).isoformat(),
        'dataset_sha256': sha256(dataset.read_bytes()).hexdigest(), 'detector': detector_metadata(),
        'source_sha256': sha256((ROOT / 'regulai/front/local_masking.py').read_bytes()).hexdigest(),
        'method': 'Exact synthetic value disappearance and preservation; not entity-level recall, anonymity, or human review.'}
    (output / 'plan.json').write_text(json.dumps(plan, indent=2), encoding='utf-8')
    cases = json.loads(dataset.read_text(encoding='utf-8'))
    observations = []
    with patch('socket.socket.connect', side_effect=AssertionError('No live network')) as sockets, \
            patch('socket.getaddrinfo', side_effect=AssertionError('No live DNS')) as dns:
        for case in cases:
            started = time.monotonic()
            masked = mask_local_texts([case['text']], timeout=30)[0]
            observations.append({**case, 'masked': masked,
                'retained_sensitive_values': [value for value in case['redact'] if value in masked],
                'lost_required_content': [value for value in case['preserve'] if value not in masked],
                'milliseconds': round((time.monotonic() - started) * 1000, 3)})
    matches = [row for row in observations if not row['retained_sensitive_values'] and not row['lost_required_content']]
    report = {'cases': len(cases), 'expectations_met': len(matches),
        'cases_with_remaining_sensitive_values': [row['id'] for row in observations if row['retained_sensitive_values']],
        'cases_with_lost_required_content': [row['id'] for row in observations if row['lost_required_content']],
        'network_attempts': sockets.call_count, 'dns_attempts': dns.call_count,
        'api_cost_usd': '0', 'human_review': 'pending', 'observations': observations}
    (output / 'results.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'observations'}, indent=2))
    # The exit code records execution integrity. All omissions remain explicit;
    # this is a measurement report, not a quality gate made green by exclusions.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

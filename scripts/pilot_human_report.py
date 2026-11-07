"""Merge independently completed reviews into NEW reports; no model calls or tuning."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.test_settings')
import django
django.setup()
from front.evaluation import attach_reviews, canonical, summarize_pilot

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--results', type=Path, required=True)
parser.add_argument('--reviews', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
rows = [json.loads(line) for line in args.results.read_text(encoding='utf-8').splitlines()]
rows = attach_reviews(rows, args.reviews)
args.output.mkdir(parents=True, exist_ok=False)
(args.output / 'results-reviewed.jsonl').write_text(''.join(canonical(row) + '\n' for row in rows), encoding='utf-8')
(args.output / 'summary-reviewed.json').write_text(json.dumps(summarize_pilot(rows), indent=2) + '\n', encoding='utf-8')
print('Human reviews merged; original results retained. No model calls, thresholds or reserved labels changed.')

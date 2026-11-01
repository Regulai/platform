"""Prepare a NEW reviewable manifest. Never grants approval or contacts a provider."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.test_settings')
import django
django.setup()
from front.evaluation import local_masking_manifest, runtime_versions, source_hashes

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--manifest', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True, help='New JSON file beside the dataset; never overwrites.')
args = parser.parse_args()
if args.output.resolve().parent != args.manifest.resolve().parent:
    parser.error('Keep the new manifest beside its frozen dataset and rubric.')
manifest = json.loads(args.manifest.read_text(encoding='utf-8'))
manifest['source_sha256'] = source_hashes()
manifest['runtime_versions'] = runtime_versions()
if manifest.get('masking', {}).get('backend') == 'local':
    manifest['masking'] = local_masking_manifest()
for key, source in [('dataset_sha256', 'dataset'), ('human_rubric_sha256', 'human_rubric')]:
    manifest[key] = hashlib.sha256((args.manifest.parent / manifest[source]).read_bytes()).hexdigest()
with args.output.open('x', encoding='utf-8') as output:
    output.write(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
print('Prepared new manifest; review the diff and obtain a new approval bound to SHA-256 ' + hashlib.sha256(args.output.read_bytes()).hexdigest())

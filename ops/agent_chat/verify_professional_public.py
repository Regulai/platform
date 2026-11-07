"""Free public HTTP/registry probe; does not instantiate paid search or a model."""
import os
from pathlib import Path
import sys
import json
import base64
from datetime import datetime, timezone
root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / 'regulai'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
import django
django.setup()
from front.agents.public_web import fetch
from front.agents.packages import prepare

destination = root / 'evals/reports/task56-professional-20261014'
destination.mkdir(exist_ok=True, parents=True)
downloads = root / '.claude/task56-downloads'
downloads.mkdir(exist_ok=True, parents=True)
results = []
for url in ['https://www.python.org/', 'https://www.eia.gov/', 'https://www.unwto.org/']:
    try:
        value = fetch(url, timeout=20, max_bytes=2000000)
        value.pop('raw')
        results.append({'succeeded': True, **value})
    except Exception as error:
        results.append({'url': url, 'succeeded': False, 'code': type(error).__name__})
manifest = []
for ecosystem, pins in [('pip', ['humanize==4.13.0']), ('npm', ['is-number@7.0.0'])]:
    value = prepare(ecosystem, pins, get=lambda url, metadata: fetch(url, timeout=25, max_bytes=2000000))
    for item in value['files']:
        (downloads / Path(item['path']).name).write_bytes(base64.b64decode(item['base64']))
    manifest.append({key: item for key, item in value.items() if key != 'files'})
(downloads / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
report = {'retrieved_at': datetime.now(timezone.utc).isoformat(), 'public_http': results,
    'packages': manifest, 'paid_search': 'not_run', 'model': 'not_run'}
(destination / 'public-network.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))

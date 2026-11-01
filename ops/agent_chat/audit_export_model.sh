set -euo pipefail
test "$(hostname)" = task48-e2b-vm
test "$#" = 1
case "$1" in task54-ui-before|task54-ui-final) ;; *) exit 2 ;; esac
docker exec -i task50-web python - "$1" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
root = Path('/evidence') / sys.argv[1]
root.mkdir(exist_ok=False)
source = Path('/evidence/task54-model.json')
raw = source.read_bytes()
values = json.loads(raw)
encoded = json.dumps(values)
for marker in ('original-private-id', 'synthetic-private-token', 'Private Synthetic Marker',
               'folder-one', 'person-one', 'export-folder', 'synthetic@example.invalid',
               'data:image/', 'iVBORw0KGgo'):
    assert marker not in encoded, 'Private fixture marker in model request'
(root / 'model.json').write_bytes(raw)
remote = json.loads(Path('/evidence/task54-drive.json').read_bytes())
report = {'requests': len(values), 'private_markers_absent': True,
          'model': 'simulated', 'paid_calls': 0, 'real_external_writes': 0,
          'model_sha256': hashlib.sha256(raw).hexdigest(),
          'simulated_uploads_total': remote['uploads']}
(root / 'report.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report))
PY

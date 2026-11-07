#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker exec task50-web python -c '
import json
from pathlib import Path
values = json.loads(Path("/evidence/task53-model.json").read_text())
encoded = json.dumps(values)
for marker in ("original-private-id", "synthetic-private-token", "Private Synthetic Marker", "folder-one", "person-one", "data:image/", "iVBORw0KGgo"):
    assert marker not in encoded, "Private fixture marker in model request"
print(json.dumps({"requests":len(values),"private_markers_absent":True,"paid_calls":0,"model":"simulated"}))
'

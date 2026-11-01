#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker exec -i task50-web python - <<'PY'
from ops.agent_chat.lab_server import prepare
prepare()
from front.models import AgentArtifact
from front.agents import jobs, document_contract as c
import base64, io, json, zipfile, traceback
from pathlib import Path
a = AgentArtifact.objects.filter(format='docx').order_by('-created_at').first()
data = base64.b64decode(a.content)
output = Path('/evidence/first-docx-draft')
output.mkdir(exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for name in z.namelist():
        if '/' not in name:
            (output/name).write_bytes(z.read(name))
    fields = c.fields(z.read('final.docx'))
    from pypdf import PdfReader
    pdf_root = PdfReader(io.BytesIO(z.read('final.pdf'))).trailer['/Root']
    print('PDF root keys:', list(pdf_root), 'OpenAction:', pdf_root.get('/OpenAction'))
try:
    print(c.verify_bundle(a.content, jobs._decode(a.source), a.source.kind, fields, format='docx')[1])
except Exception:
    traceback.print_exc()
PY

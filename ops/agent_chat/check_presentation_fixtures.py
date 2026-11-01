"""Independent trusted verifier over the already rendered synthetic corpus."""
import base64
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root/'regulai'))
from front.agents.presentation_contract import verify_bundle, expected_fields
source = 'item,amount_cents\nÁrea Norte,125\nPiñón español,250\nRevisión técnica,375\n'.encode()
folder = root/'evals/reports/task52-powerpoint-20261008/design-v3'
result = {}
for name in ('new', 'template', 'long', 'edit'):
    path = folder/name
    config = json.loads((folder/('new' if name == 'edit' else name)/'fields.json').read_text())
    expected = expected_fields(config['title'], config['section'])
    if name == 'edit':
        expected[2]['body'] = 'Revisión localizada: análisis de importes de España. Se conserva el resto de la presentación.'
    _, proof, _ = verify_bundle(base64.b64encode((path/'candidate.zip').read_bytes()).decode(), source, 'csv', expected,
        base=(folder/'new/final.pptx').read_bytes() if name == 'edit' else None,
        changed=(3, 'body') if name == 'edit' else None, template=config['template'])
    result[name] = proof
(folder/'independent-verification.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result))

"""Check frozen corpus hashes against Git's staged bytes, including CSV/JSON."""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
checked = 0
for folder in ('live/task54-corpus', 'final-live/task54-corpus2', 'ui-live/task54-corpus2'):
    relative = Path('evals/reports/task54-export-20261013') / folder
    report = json.loads((root / relative / 'report.json').read_text(encoding='utf-8'))
    assert len(report['cases']) == 16
    assert (report['passed'], report['failed'], report['not_supported']) == (7, 1, 8)
    for case in report['cases']:
        for name, expected in case['files'].items():
            file = (relative / case['id'] / name).as_posix()
            raw = subprocess.run(['rtk', 'proxy', 'git', 'cat-file', 'blob', ':' + file],
                                 cwd=root, capture_output=True, check=True).stdout
            assert hashlib.sha256(raw).hexdigest() == expected, 'Staged evidence changed: ' + file
            checked += 1
print(json.dumps({'passed': True, 'staged_file_hashes_verified': checked,
                  'scope': 'All three frozen corpus snapshots; byte-exact Git blobs'}))

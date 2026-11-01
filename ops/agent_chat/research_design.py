"""Read-only pinned public design references; never imported by runtime."""
import hashlib
import json
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[2]
target = root / 'docs/agent-assets/upstream/docx-report-design'
repo = 'drharunyuksel/docx-report-skill'
commit = json.load(urllib.request.urlopen(f'https://api.github.com/repos/{repo}/commits/main'))['sha']
tree = json.load(urllib.request.urlopen(f'https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1'))['tree']
files = [x for x in tree if x['type'] == 'blob' and (x['path'] in ('LICENSE', 'SKILL.md') or x['path'].endswith(('.md', 'brand-config.js', 'typography.js', 'page-setup.js', 'table-templates.js')))]
manifest = []
for item in files:
    raw = urllib.request.urlopen(f'https://raw.githubusercontent.com/{repo}/{commit}/{item["path"]}').read()
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == item['sha']
    path = target / item['path']
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    manifest.append({'path': item['path'], 'sha256': hashlib.sha256(raw).hexdigest()})
(target / 'source-manifest.json').write_text(json.dumps({'repo': repo, 'sha': commit, 'files': manifest}, indent=2))
print(commit, len(files))

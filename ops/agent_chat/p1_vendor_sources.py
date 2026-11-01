"""Reproduce the small, pinned P1 instruction bundles. Downloads are never executed."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'regulai/front/agents/runtime/skills'
SOURCES = [
    ('frontend-design/SKILL.md', 'anthropics/skills/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/frontend-design/SKILL.md',
     'd91970639e9f5c37682ac7ab60094d35f1c7c1f38d731bd56396563aee10c1d3'),
    ('frontend-design/LICENSE.txt', 'anthropics/skills/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/frontend-design/LICENSE.txt', None),
    ('web-design-guidelines/references/command.md', 'vercel-labs/web-interface-guidelines/434b7f91364665f2f733b310ec54809bf8f37937/command.md',
     'd246b026f4f29b5823a9cc857f9edf3d2507002e055e32040cadeaf3b38e0234'),
    ('web-design-guidelines/LICENSE.txt', 'vercel-labs/web-interface-guidelines/434b7f91364665f2f733b310ec54809bf8f37937/LICENSE', None),
]


def main():
    report = []
    for relative, source, expected in SOURCES:
        url = 'https://raw.githubusercontent.com/' + source
        with urllib.request.urlopen(url, timeout=25) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError('public_source_too_large')
        sha = hashlib.sha256(raw).hexdigest()
        if expected and expected != sha:
            raise ValueError('pinned_source_changed:' + relative)
        target = TARGET / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != raw:
            raise ValueError('refuse_overwrite:' + relative)
        target.write_bytes(raw)
        report.append({'path': relative, 'url': url, 'sha256': sha, 'bytes': len(raw)})
    output = ROOT / 'output/p1-20261016/sources.json'
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

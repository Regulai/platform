"""Fetch the pinned evaluation source; never called by the chat/runtime."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request

SHA = '97a6e384cb0664cd44ba8113c0b80c9761700670'
ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / '.task51-branddocs-source'


def main():
    with urllib.request.urlopen(
        f'https://api.github.com/repos/ferdinandobons/brand-docs/git/trees/{SHA}?recursive=1', timeout=30
    ) as response:
        manifest_tree = json.load(response)
    if manifest_tree.get('truncated'):
        raise ValueError('Incomplete upstream tree')
    tree = manifest_tree['tree']
    files = [row for row in tree if row['type'] == 'blob' and (
        row['path'].startswith(('scripts/brandkit/', 'skills/brand-docx/'))
        or row['path'] in ('LICENSE', 'NOTICE', 'requirements.txt'))]

    def fetch(row):
        path = DEST / row['path']
        data = urllib.request.urlopen(
            f'https://raw.githubusercontent.com/ferdinandobons/brand-docs/{SHA}/{row["path"]}', timeout=30).read()
        blob = b'blob ' + str(len(data)).encode() + b'\0' + data
        if hashlib.sha1(blob).hexdigest() != row['sha']:
            raise ValueError('Upstream blob digest mismatch: ' + row['path'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {'path': row['path'], 'sha256': hashlib.sha256(data).hexdigest()}

    with ThreadPoolExecutor(max_workers=6) as pool:
        manifest = list(pool.map(fetch, files))
    (DEST / 'source-manifest.json').write_text(json.dumps({'commit': SHA, 'files': manifest}, indent=2))
    print(f'Pinned evaluation source: {len(manifest)} verified blobs in {DEST}')


if __name__ == '__main__':
    main()

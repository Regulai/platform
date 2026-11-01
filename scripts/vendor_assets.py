"""Verify pinned UI assets offline, or restore them from their locked sources."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1] / 'regulai/static/vendor'


def icon_collection(content, names):
    collection = json.loads(content)
    selected = set(names)
    aliases = collection.get('aliases', {})
    for name in names:
        while name in aliases:
            name = aliases[name]['parent']
            selected.add(name)
    missing = selected - collection['icons'].keys() - aliases.keys()
    if missing:
        raise ValueError(f'Unknown pinned icons: {sorted(missing)}')
    collection['icons'] = {name: value for name, value in collection['icons'].items() if name in selected}
    collection['aliases'] = {name: value for name, value in aliases.items() if name in selected}
    # Disable Iconify's public API even for a missing or newly added icon.
    return ("{ const icons = customElements.get('iconify-icon');\n"
            "icons._api.setFetch(undefined);\n"
            "icons.addCollection(" + json.dumps(collection, separators=(',', ':')) + "); }\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify local hashes without network')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
    staged = {}
    for name, asset in manifest.items():
        if args.check:
            content = (ROOT / name).read_bytes()
        else:
            with urlopen(asset['source'], timeout=30) as response:
                content = response.read(32 * 1024 * 1024 + 1)
            if len(content) > 32 * 1024 * 1024:
                raise ValueError(f'Asset too large: {name}; retained existing assets.')
            if asset.get('format') == 'iconify':
                if hashlib.sha256(content).hexdigest() != asset['download_sha256']:
                    raise ValueError(f'Checksum mismatch for {name}; retained existing assets.')
                content = icon_collection(content, asset['icons'])
        if hashlib.sha256(content).hexdigest() != asset['sha256']:
            raise ValueError(f'Checksum mismatch for {name}; retained existing assets.')
        staged[name] = content
    if not args.check:
        # Validate every download before replacing any local file.
        for name, content in staged.items():
            target = ROOT / name
            temporary = target.with_suffix(target.suffix + '.tmp')
            temporary.write_bytes(content)
            temporary.replace(target)
    print(f'Verified {len(manifest)} local UI assets.')


if __name__ == '__main__':
    main()

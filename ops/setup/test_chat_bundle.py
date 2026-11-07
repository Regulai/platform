"""The installer ships the built chat island exactly as its manifest names it (task 81).

Host-side and offline: no Docker, Node or network. The VM serves these files through
Django's static files handler, so what the archive carries is what the page links.
"""
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('installer', ROOT / 'setup.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
BUILD = 'regulai/static/chat-app/'


class ChatBundleTests(unittest.TestCase):
    def test_the_archive_carries_the_whole_build_and_no_frontend_sources(self):
        manifest = json.loads((ROOT / BUILD / 'manifest.json').read_text(encoding='utf-8'))
        expected = {BUILD + 'manifest.json', BUILD + 'THIRD-PARTY-NOTICES.txt'} | {
            BUILD + name for chunk in manifest.values() for name in [chunk['file'], *chunk.get('css', [])]}
        with tempfile.TemporaryDirectory(prefix='regulai-chat-bundle-') as directory:
            destination = Path(directory) / 'source.tar.gz'
            installer.bundle(destination)
            with tarfile.open(destination) as archive:
                names = set(archive.getnames())
        # Exactly the files of this build: none missing, no leftovers from older builds.
        self.assertEqual({name for name in names if name.startswith(BUILD)}, expected)
        self.assertEqual([name for name in names if name.startswith('frontend/') or '/node_modules/' in name], [])


if __name__ == '__main__':
    unittest.main()

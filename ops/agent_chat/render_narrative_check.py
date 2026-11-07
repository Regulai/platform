"""Render only synthetic fixtures in the existing pinned offline document image.

No web/worker refresh, E2B creation, credentials or account data. The sole VM
directory is newly created under /tmp; results are copied back before cleanup.
"""
import io
import json
from pathlib import Path
import subprocess
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'evals/reports/task55-agent-documents-20261013'
REMOTE = '/tmp/regulay-task55-render-' + uuid.uuid4().hex
NAMES = ('report', 'report-edit', 'report-edit2', 'deck', 'deck-edit')
SSH = ['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm', 'ssh', '-i', '/vm/id_ed25519',
       '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/vm/known_hosts', '-p', '2222', 'probe@127.0.0.1']


def main():
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode='w') as archive:
        for source, target in [(ROOT/'regulai/front/agents/narrative_program.py', 'narrative_program.py'),
                *[(OUTPUT / (name + '-fields.json'), name + '-fields.json') for name in NAMES]]:
            archive.add(source, arcname=target)
    subprocess.run(SSH + [f'mkdir -m 777 {REMOTE} && tar -xf - -C {REMOTE}'], input=bundle.getvalue(), check=True)
    script = f'''set -eu
test -d {REMOTE}
sudo docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m --user 1000:1000 \
    --mount type=bind,src={REMOTE},dst=/check --workdir /check regulay-task50-spreadsheet:local \
    sh -ec 'python narrative_program.py build --fields report-fields.json --output report
python narrative_program.py render --output report
python narrative_program.py seal --output report
python narrative_program.py edit --source report/final.docx --fields report-edit-fields.json --output report-edit
python narrative_program.py render --output report-edit
python narrative_program.py seal --output report-edit
python narrative_program.py edit --source report-edit/final.docx --fields report-edit2-fields.json --output report-edit2
python narrative_program.py render --output report-edit2
python narrative_program.py seal --output report-edit2
python narrative_program.py build --fields deck-fields.json --extension pptx --output deck
python narrative_program.py render --extension pptx --output deck
python narrative_program.py seal --extension pptx --output deck
python narrative_program.py edit --source deck/final.pptx --fields deck-edit-fields.json --extension pptx --output deck-edit
python narrative_program.py render --extension pptx --output deck-edit
python narrative_program.py seal --extension pptx --output deck-edit'
'''
    result = subprocess.run(SSH + ['sh', '-se'], input=script.encode(), capture_output=True, timeout=300)
    (OUTPUT/'render.log').write_bytes(result.stdout+result.stderr)
    if result.returncode:
        raise RuntimeError('Offline render failed; see render.log. Retained ' + REMOTE)
    result = subprocess.run(SSH + ['tar', '--exclude=lo-profile', '-cf', '-', '-C', REMOTE, *NAMES], capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        archive.extractall(OUTPUT, filter='data')
    # Fixed-prefix UUID directory, never computed from source/archive input.
    subprocess.run(SSH + [f'test "{REMOTE}" != /tmp && case "{REMOTE}" in /tmp/regulay-task55-render-*) rm -rf -- "{REMOTE}";; *) exit 1;; esac'], check=True)
    print('Rendered DOCX/PDF and PPTX/PDF using the product image, offline. No provider call.')


if __name__ == '__main__':
    main()

"""Copy allowlisted synthetic evidence from the owned evaluation VM directory."""
import argparse
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', default='live')
    args = parser.parse_args()
    if not args.label.replace('-', '').isalnum():
        raise SystemExit('Label must contain letters, digits or hyphens.')
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('p0_installer', root / 'setup.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    destination = root / 'output/p0-real-20261016' / args.label
    destination.mkdir(parents=True, exist_ok=True)
    ssh = ['rtk', 'proxy', *installer.SSH]
    command = ('sudo tar -czf - --ignore-failed-read -C /opt/regulai-p0-eval-20261016/state '
               'initialized.json results.json provider.jsonl budget.json artifacts '
               'budget-reconciliation.json capacity-reconciliation.json integrated.json runtime-observation.json '
               'integrated-validator-issue.json')
    result = subprocess.run([*ssh, command], capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:gz') as archive:
        if any(item.name.split('/')[0] not in ('initialized.json', 'results.json', 'provider.jsonl', 'budget.json', 'artifacts',
                                              'budget-reconciliation.json', 'capacity-reconciliation.json',
                                              'integrated.json', 'runtime-observation.json', 'integrated-validator-issue.json')
               or not (item.isfile() or item.isdir()) for item in archive.getmembers()):
            raise RuntimeError('Evidence archive contains unexpected paths or links.')
        archive.extractall(destination, filter='data')
    print(destination)


if __name__ == '__main__':
    main()

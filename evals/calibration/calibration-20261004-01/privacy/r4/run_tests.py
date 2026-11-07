"""Record R4 focal tests with in-memory SQLite and no private settings import."""
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[5]
OWNER = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('labels', nargs='*', default=['front.test_calibration_manipulation'])
    args = parser.parse_args()
    output = (OWNER / args.output).resolve()
    if not output.is_relative_to(OWNER):
        raise ValueError('Evidence must remain within R4 ownership')
    output.mkdir(parents=True, exist_ok=False)
    sources = ['regulai/front/policy.py', 'regulai/front/classification.py',
               'regulai/front/test_calibration_manipulation.py', 'scripts/run_adversarial_community.py']
    hashes = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in sources}
    code = ('import os,sys,types; sys.path.insert(0,"regulai"); '
        'sys.modules["regulai.local_settings"]=types.ModuleType("regulai.local_settings"); '
        'os.environ["DJANGO_SETTINGS_MODULE"]="regulai.test_settings"; '
        'import django; django.setup(); from django.conf import settings; '
        'assert settings.DATABASES["default"]["NAME"]==":memory:"; '
        'from django.test.utils import get_runner; '
        f'sys.exit(bool(get_runner(settings)(verbosity=2,interactive=False).run_tests({args.labels!r})))')
    command = ['rtk', 'proxy', sys.executable, '-X', 'utf8', '-c', code]
    environment = dict(os.environ, REGULAI_R4_CAPTURE=str(output / 'transport.json'))
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, encoding='utf-8')
    (output / 'stdout.log').write_text(result.stdout, encoding='utf-8')
    (output / 'stderr.log').write_text(result.stderr, encoding='utf-8')
    report = dict(command=command, exit_code=result.returncode,
        completed_utc=datetime.now(timezone.utc).isoformat(), source_sha256=hashes,
        source_unchanged=all(sha256((ROOT / path).read_bytes()).hexdigest() == value
                             for path, value in hashes.items()),
        origin='synthetic_offline_tests_not_provider_quality', database='SQLite :memory:',
        private_settings_imported=False)
    (output / 'execution.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(result.stderr[-15000:])
    print(json.dumps(report, indent=2))
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())

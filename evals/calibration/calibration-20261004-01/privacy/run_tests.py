"""Run focused Django tests without importing private settings or opening user DB."""
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('labels', nargs='+')
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    if not output.is_relative_to(Path(__file__).resolve().parent):
        raise ValueError('Evidence must stay within privacy owner directory')
    output.mkdir(parents=True, exist_ok=False)
    code = ('import os,sys,types; sys.path.insert(0,"regulai"); '
        'sys.modules["regulai.local_settings"]=types.ModuleType("regulai.local_settings"); '
        'os.environ["DJANGO_SETTINGS_MODULE"]="regulai.test_settings"; '
        'import django; django.setup(); from django.conf import settings; '
        'assert settings.DATABASES["default"]["NAME"]==":memory:"; '
        'from django.test.utils import get_runner; '
        f'sys.exit(bool(get_runner(settings)(verbosity=2,interactive=False).run_tests({args.labels!r})))')
    command = ['rtk', 'proxy', sys.executable, '-X', 'utf8', '-c', code]
    environment = dict(os.environ)
    if args.capture:
        environment['REGULAI_PRIVACY_CAPTURE'] = str(output / 'transport.json')
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, encoding='utf-8')
    (output / 'stdout.log').write_text(result.stdout, encoding='utf-8')
    (output / 'stderr.log').write_text(result.stderr, encoding='utf-8')
    report = dict(command=command, exit_code=result.returncode,
        runtime_sha256=sha256((ROOT / 'regulai/front/local_masking.py').read_bytes()).hexdigest(),
        test_sha256=sha256((ROOT / 'regulai/front/test_calibration_privacy.py').read_bytes()).hexdigest())
    (output / 'execution.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(result.stderr[-12000:].encode('ascii', 'backslashreplace').decode('ascii'))
    print(json.dumps(report, indent=2))
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())

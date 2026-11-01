"""Run P1 tests only against the dedicated synthetic PostgreSQL container."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', default='test_regulai_p1_skills')
    parser.add_argument('tests', nargs='+')
    args = parser.parse_args()
    if not args.database.startswith('test_regulai_p1_') or not args.database.replace('_','').isalnum():
        parser.error('Only isolated P1 test databases are accepted')
    sys.path.insert(0, str(ROOT / 'regulai'))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
    from django.conf import settings
    settings.DATABASES['default'].update(HOST='127.0.0.1', PORT='55468')
    settings.DATABASES['default']['TEST']['NAME'] = args.database
    import django
    django.setup()
    from django.test.utils import get_runner
    runner = get_runner(settings)(verbosity=2, interactive=False)
    raise SystemExit(bool(runner.run_tests(args.tests)))


if __name__ == '__main__':
    main()

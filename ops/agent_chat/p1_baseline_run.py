"""Run frozen P0 fixtures against the exclusively owned P1/E1 PostgreSQL."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'output/p1-20261016/e1'
NAME = 'regulai-p1-e1-db-20261016'


def run(command, **kwargs):
    return subprocess.run(['rtk', 'proxy', *map(str, command)], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('tests', nargs='*')
    args = parser.parse_args()
    current = json.loads(run(['docker', 'inspect', NAME], text=True, capture_output=True).stdout)[0]
    assert current['Config']['Labels']['regulai.p1_e1'] == '20261016'
    assert current['NetworkSettings']['Ports']['5432/tcp'] == [{'HostIp': '127.0.0.1', 'HostPort': '55468'}]
    archive = EVIDENCE / 'p0-source.zip'
    manifest = json.loads((EVIDENCE / 'p0-manifest.json').read_text(encoding='utf-8'))
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest['archive_sha256']
    destination = EVIDENCE / 'frozen'
    if args.prepare:
        destination.mkdir(exist_ok=False)
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                assert (destination / info.filename).resolve().is_relative_to(destination.resolve())
            bundle.extractall(destination)
    assert destination.is_dir(), 'Run --prepare once.'
    for row in manifest['files']:
        assert hashlib.sha256((destination / row['path']).read_bytes()).hexdigest() == row['sha256'], row['path']
    settings = destination / 'regulai/regulai/p1_e1_settings.py'
    settings.write_text("from .ci_settings import *\nDATABASES['default']['PORT']='55468'\n"
                        "DATABASES['default']['TEST']['NAME']='test_regulai_p1_e1'\n", encoding='utf-8')
    baseline_test = ROOT / 'regulai/front/test_agent_p1_baseline.py'
    if baseline_test.exists():
        shutil.copyfile(baseline_test, destination / 'regulai/front/test_agent_p1_baseline.py')
    corpus = ROOT / 'evals/corpora/p1-harness'
    if corpus.exists():
        shutil.copytree(corpus, destination / 'evals/corpora/p1-harness', dirs_exist_ok=True)
    env = dict(os.environ)
    env.update(P1_BASELINE_EVIDENCE=str(EVIDENCE), P1_BASELINE_FROZEN='1', PYTHONIOENCODING='utf-8')
    for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DEEPSEEK_API_KEY', 'GOOGLE_API_KEY',
                'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY'):
        env.pop(key, None)
    stamp = str(time.time_ns())
    if args.worker:
        cmd = [ROOT / 'ops/agent_probe/.venv/Scripts/python.exe', '-m', 'unittest', 'discover',
               '-s', 'ops/agent_chat', '-p', args.tests[0] if args.tests else 'test_p0_runtime.py', '-v']
        label = 'worker'
    else:
        tests = args.tests or ['front.test_agent_p1_baseline', 'front.test_agent_continuity',
            'front.test_agent_history_window', 'front.test_agent_profiles', 'front.test_agent_work_limits',
            'front.test_agent_runtime_p0', 'front.test_agent_state', 'front.test_connectors']
        cmd = [ROOT / '.venv/Scripts/python.exe', destination / 'regulai/manage.py', 'test', *tests,
               '--settings=regulai.p1_e1_settings', '--noinput', '--verbosity=2',
               '--exclude-tag=namespace_integration', '--exclude-tag=capacity_benchmark']
        label = 'django'
    output = EVIDENCE / f'{label}-{stamp}.log'
    started = time.monotonic()
    with output.open('w', encoding='utf-8') as stream:
        result = subprocess.run(['rtk', 'proxy', *map(str, cmd)], cwd=destination, env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    summary = {'command': list(map(str, cmd)), 'source_archive_sha256': manifest['archive_sha256'],
               'exit_code': result.returncode, 'duration_seconds': round(time.monotonic() - started, 3),
               'log': str(output), 'provider': 'simulated', 'paid_calls': 0}
    (EVIDENCE / f'{label}-{stamp}.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()

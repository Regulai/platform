"""Run inside the fenced executor image, with real sockets and E2B/Firecracker."""
import importlib.util
import json
from pathlib import Path
import shlex
import sys

sys.path.insert(0, '/app/ops/agent_probe')
from runtime_checks import connect_probe
from front.agents.sandbox_pool import create_clean
from langchain_e2b import E2BSandbox


def probe(config, targets):
    assert importlib.util.find_spec('psycopg') is None
    assert importlib.util.find_spec('django') is None
    for name in ('aliases.py', 'service.py', 'jobs.py', 'records.py'):
        assert not (Path('/app/regulai/front/agents') / name).exists()
    assert not Path('/var/run/docker.sock').exists()
    denied = [connect_probe(t['address'], t['port'], denied=True) for t in targets]
    sandbox = create_clean(config)
    try:
        sandbox.files.write('/workspace/input/numbers.csv', b'item,amount_cents\na,125\nb,250\nc,375\n', user='root')
        sandbox.commands.run('chmod 0444 /workspace/input/* && chmod 0555 /workspace/input && '
            'mount --bind /workspace/input /workspace/input && mount -o remount,bind,ro /workspace/input', user='root')
        backend = E2BSandbox(sandbox=sandbox, workdir='/workspace/work', timeout=30)
        code = Path('/app/ops/agent_probe/runtime_checks.py').read_text().split('if __name__ == "__main__":')[0]
        code += '\nresults=[]\n'
        code += 'for target in ' + repr(targets) + ':\n'
        code += ' try:\n  results.append(connect_probe(target["address"],target["port"],denied=True))\n'
        code += ' except Exception as exc:\n  results.append({**target,"denied":False,"error":str(exc)})\n'
        code += 'print(json.dumps({"filesystem":filesystem_contract(),"sockets":results}))\n'
        result = backend.execute('python -I -c ' + shlex.quote(code), timeout=30)
        if result.exit_code:
            raise RuntimeError('Sandbox isolation probe failed: ' + result.output)
        versions = sandbox.commands.run('python -I -c \'import pandas,openpyxl,sys,json; '
            'print(json.dumps({"python":sys.version,"pandas":pandas.__version__,"openpyxl":openpyxl.__version__}))\' '
            '&& libreoffice --version')
        proof = json.loads(result.output)
        if not all(row['denied'] for row in proof['sockets']):
            raise RuntimeError('Sandbox socket denial failed: ' + json.dumps(proof['sockets']))
        return {'executor_sockets': denied, 'sandbox': proof,
            'sandbox_id': sandbox.sandbox_id, 'versions': versions.stdout,
            'executor_without_database_provider_keys_or_alias_modules': True}
    finally:
        sandbox.kill()


if __name__ == '__main__':
    print(json.dumps(probe(json.load(open('/run/task50/config.json')), json.loads(sys.argv[1]))))

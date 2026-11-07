"""Stop only the verified P1 UI processes and owned synthetic PostgreSQL.

Browser sessions must be closed separately. Never removes databases or volumes.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DATABASE = 'regulai-p1-e1-db-20261016'


def run(*args):
    return subprocess.run(['rtk', 'proxy', *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-pid', type=int, required=True)
    parser.add_argument('--launcher-pid', type=int, required=True)
    args = parser.parse_args()
    observed = []
    already_absent = []
    for pid in (args.server_pid, args.launcher_pid):
        value = run('powershell', '-NoProfile', '-Command',
            f"Get-CimInstance Win32_Process -Filter 'ProcessId={pid}' | "
            'Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json')
        if not value:
            already_absent.append(pid)
            continue
        item = json.loads(value)
        assert item['Name'] == 'python.exe'
        assert item['CommandLine'].endswith(' -X utf8 ops/agent_chat/p1_ui_lab.py') or \
            item['CommandLine'].endswith('  -X utf8 ops/agent_chat/p1_ui_lab.py')
        assert str(ROOT).lower() in item['CommandLine'].lower() or \
            'cpython-3.12-windows-x86_64-none' in item['CommandLine']
        observed.append(item)
    if len(observed) == 2:
        assert observed[0]['ParentProcessId'] == observed[1]['ProcessId']
    for item in observed:
        run('powershell', '-NoProfile', '-Command',
            f"$p = Get-Process -Id {item['ProcessId']} -ErrorAction SilentlyContinue; "
            'if ($null -ne $p) { Stop-Process -InputObject $p }; exit 0')
    db = json.loads(run('docker', 'inspect', DATABASE))[0]
    assert db['Config']['Labels'].get('regulai.p1_e1') == '20261016'
    assert db['HostConfig']['PortBindings'] == {
        '5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '55468'}]}
    run('docker', 'stop', DATABASE)
    after = json.loads(run('docker', 'inspect', DATABASE))[0]
    assert after['State']['Status'] == 'exited'
    ports = {}
    for port in (8871, 8872, 55468):
        with socket.socket() as sock:
            sock.settimeout(1)
            ports[str(port)] = sock.connect_ex(('127.0.0.1', port)) != 0
        assert ports[str(port)], f'P1 port remains active: {port}'
    receipt = {
        'completed_at': datetime.now(timezone.utc).isoformat(),
        'verified_processes_stopped': observed,
        'requested_processes_already_absent': already_absent,
        'browser': 'Playwright CLI session p1 closed separately; agent sessions closed by owner',
        'database': {'name': DATABASE, 'state': after['State']['Status'],
                     'container_and_synthetic_data_retained': True},
        'ports_closed': ports,
        'physical_cleanup': '../physical/cleanup.json',
        'unrelated_resources_modified': False,
    }
    (ROOT/'output/p1-20261016/e8/cleanup.json').write_text(
        json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()

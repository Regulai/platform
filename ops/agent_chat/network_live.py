"""Infrastructure-only positive/negative socket controls in the isolated 48 VM."""
import json
from pathlib import Path
import socket
import subprocess
import uuid

ROOT = Path('/home/probe/task50')


def main():
    assert socket.gethostname() == 'task48-e2b-vm'
    output = ROOT / 'evidence-live'
    report = {'passed': False}
    logs = []
    def run(*args, check=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        logs.append({'command': args, 'exit_code': result.returncode})
        if check and result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout.strip()
    flags = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '1000:1000', '--dns', '127.0.0.1']
    network, receiver = False, False
    try:
        run('docker', 'network', 'create', '--internal', '--ipv6', '--subnet', '172.30.51.0/24',
            '--subnet', 'fd50:51::/64', '--label', 'regulay.task=50', 'task50-receiver')
        network = True
        run('docker', 'run', '-d', '--name', 'task50-receiver', '--network', 'task50-receiver', *flags,
            'regulay-task48-sandbox:local', 'python', '-I', '/probe/runtime_checks.py', 'serve')
        receiver = True
        info = json.loads(run('docker', 'inspect', 'task50-receiver', '--format', '{{json .NetworkSettings.Networks}}'))['task50-receiver']
        targets = [{'address': info['IPAddress'], 'port': 8080}, {'address': info['GlobalIPv6Address'], 'port': 8080}]
        def positive():
            return [json.loads(run('docker', 'run', '--rm', '--network', 'task50-receiver', *flags,
                'regulay-task48-sandbox:local', 'python', '-I', '/probe/runtime_checks.py', 'allow', t['address'], str(t['port']))) for t in targets]
        report['positive_before'] = positive()
        probes = targets + [{'address': '172.30.50.1', 'port': 55450}, {'address': '169.254.169.254', 'port': 80}]
        report['negative'] = json.loads(run('docker', 'run', '--rm', '--network', 'task50-exec', *flags,
            '--mount', 'type=bind,src=/home/probe/task50/.runtime,dst=/run/task50,readonly',
            'regulay-task50-executor:local', 'python', '/app/ops/agent_chat/network_probe.py', json.dumps(probes)))
        report['positive_after'] = positive()
        report['passed'] = True
    finally:
        if receiver:
            run('docker', 'rm', '-f', 'task50-receiver', check=False)
        if network:
            run('docker', 'network', 'rm', 'task50-receiver', check=False)
        report['commands'] = logs
        with (output / ('network-' + uuid.uuid4().hex + '.json')).open('x') as target:
            json.dump(report, target, indent=2)
    print(json.dumps(report))


if __name__ == '__main__':
    main()

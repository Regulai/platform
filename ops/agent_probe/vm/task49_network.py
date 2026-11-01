"""Run only in the prepared task48 disposable VM; reuse its pinned SDK image."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
from datetime import datetime, timezone

ROOT = Path('/home/probe/task49')


def main():
    if socket.gethostname() != 'task48-e2b-vm' or os.geteuid() != 0:
        raise RuntimeError('This proof requires the prepared disposable task48 VM')
    output = ROOT / ('network-evidence-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    output.mkdir(exist_ok=False)
    logs = []

    def run(*args, check=True, input=None):
        result = subprocess.run(args, input=input, capture_output=True, timeout=120)
        logs.append({'command': list(args), 'exit_code': result.returncode})
        if check and result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result.stdout.decode().strip()

    files = {'Dockerfile': b'''FROM regulay-task48-executor:local
COPY adapter.py protocol.py /app/regulai/front/agents/
COPY network_governed.py /app/ops/agent_probe/
'''}
    for name in ('adapter.py', 'protocol.py'):
        files[name] = (ROOT / 'regulai/front/agents' / name).read_bytes()
    files['network_governed.py'] = (ROOT / 'ops/agent_probe/network_governed.py').read_bytes()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    report = {'passed': False}
    networks, firewall, control, receiver = [], False, None, False
    try:
        run('docker', 'build', '--network', 'none', '-t', 'regulay-task49-executor:local', '-', input=archive.getvalue())
        for name, subnet, ipv6 in [('task49-exec', '172.30.50.0/24', 'fd49:50::/64'),
                                  ('task49-receiver', '172.30.51.0/24', 'fd49:51::/64')]:
            options = ['--opt', 'com.docker.network.bridge.name=br-task49'] if name == 'task49-exec' else []
            run('docker', 'network', 'create', '--internal', '--ipv6', '--subnet', subnet, '--subnet', ipv6, *options, name)
            networks.append(name)
        run('iptables', '-N', 'TASK49_EXEC')
        firewall = True
        run('iptables', '-A', 'TASK49_EXEC', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
        run('iptables', '-A', 'TASK49_EXEC', '-p', 'tcp', '-m', 'multiport', '--dports', '3000,3002,31049', '-j', 'ACCEPT')
        run('iptables', '-A', 'TASK49_EXEC', '-j', 'REJECT', '--reject-with', 'icmp-admin-prohibited')
        run('iptables', '-I', 'INPUT', '1', '-i', 'br-task49', '-j', 'TASK49_EXEC')
        run('ip6tables', '-I', 'INPUT', '1', '-i', 'br-task49', '-j', 'REJECT')
        control = subprocess.Popen(['python3', str(ROOT / 'ops/agent_probe/network_governed.py'), 'serve'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if control.stdout.readline().strip() != 'ready':
            raise RuntimeError('Internal HTTP control failed to bind its dedicated port')
        flags = ['--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '1000:1000',
                 '--memory', '512m', '--pids-limit', '64', '--dns', '127.0.0.1']
        run('docker', 'run', '-d', '--name', 'task49-receiver', '--network', 'task49-receiver', *flags,
            'regulay-task48-sandbox:local', 'python', '-I', '/probe/runtime_checks.py', 'serve')
        receiver = True
        info = json.loads(run('docker', 'inspect', 'task49-receiver', '--format', '{{json .NetworkSettings.Networks}}'))['task49-receiver']
        targets = [{'address': info['IPAddress'], 'port': 8080}, {'address': info['GlobalIPv6Address'], 'port': 8080}]
        def positive():
            return [json.loads(run('docker', 'run', '--rm', '--network', 'task49-receiver', *flags,
                'regulay-task48-sandbox:local', 'python', '-I', '/probe/runtime_checks.py', 'allow', t['address'], str(t['port']))) for t in targets]
        report['positive_before'] = positive()
        probes = targets + [{'address': '172.30.50.1', 'port': 80}, {'address': '169.254.169.254', 'port': 80}]
        raw = run('docker', 'run', '--rm', '--network', 'task49-exec', *flags,
            'regulay-task49-executor:local', 'python', '/app/ops/agent_probe/network_governed.py', 'probe', json.dumps(probes))
        report['executor'] = json.loads(raw)
        report['positive_after'] = positive()
        report['image'] = run('docker', 'image', 'inspect', 'regulay-task49-executor:local', '--format', '{{.Id}}')
        report['passed'] = True
    finally:
        if control:
            control.terminate()
            control.wait(timeout=10)
        if receiver:
            run('docker', 'rm', '-f', 'task49-receiver', check=False)
        if firewall:
            for args in [('iptables', '-D', 'INPUT', '-i', 'br-task49', '-j', 'TASK49_EXEC'),
                         ('iptables', '-F', 'TASK49_EXEC'), ('iptables', '-X', 'TASK49_EXEC'),
                         ('ip6tables', '-D', 'INPUT', '-i', 'br-task49', '-j', 'REJECT')]:
                run(*args, check=False)
        for name in reversed(networks):
            run('docker', 'network', 'rm', name, check=False)
        report['commands'] = logs
        (output / 'report.json').write_text(json.dumps(report, indent=2))
        (output / 'commands.log').write_text(json.dumps(logs, indent=2))
    print(json.dumps(report))
    print('Evidence: ' + str(output))


if __name__ == '__main__':
    main()

"""Run only inside the disposable VM: real E2B plus a fenced executor.

Reuses run_e2b.live_probe and the original Deep Agents graph/CSV program.
The infrastructure administrator owns Docker; the executor receives no socket.
"""
from datetime import datetime, timezone
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

ROOT = Path('/home/probe/task48')
RUNTIME = ROOT / '.runtime'
EXECUTOR = 'regulay-task48-executor:local'
FIXTURE = 'regulay-task48-sandbox:local'
COMPOSE = ['compose', '--project-directory', '/home/probe/e2b']


def main():
    if socket.gethostname() != 'task48-e2b-vm' or os.geteuid() != 0:
        raise RuntimeError('Run only as infrastructure administrator in our disposable VM')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence')
    output = parser.parse_args().output
    output.mkdir(exist_ok=False)
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    report = {'scope': 'real self-hosted E2B/Firecracker inside disposable QEMU/KVM VM',
              'started_utc': datetime.now(timezone.utc).isoformat(), 'commands': []}
    networks, receiver_started, firewall = [], False, False

    def command(args, *, sensitive=False, check=True):
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=900)
        report['commands'].append({'command': args, 'exit_code': result.returncode})
        if not sensitive:
            with (output / 'commands.log').open('a') as log:
                log.write('\n$ ' + ' '.join(args) + '\n' + result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError('Infrastructure command failed; inspect VM evidence/commands.log')
        return result.stdout.strip()

    def docker(*args, **kwargs):
        return command(['docker', *args], **kwargs)

    def run(image, network, *args, detached=False, config=False):
        flags = ['-d', '--name', 'task48-receiver'] if detached else ['--rm']
        flags += ['--network', network, '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges', '--user', '1000:1000',
                  '--memory', '512m', '--cpus', '1', '--pids-limit', '64', '--dns', '127.0.0.1',
                  '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000',
                  '--tmpfs', '/workspace/work:rw,nosuid,nodev,size=32m,uid=1000,gid=1000',
                  '--tmpfs', '/workspace/output:rw,nosuid,nodev,size=32m,uid=1000,gid=1000']
        if config:
            flags += ['--mount', f'type=bind,src={RUNTIME},dst=/run/task48,readonly']
        return docker('run', *flags, image, *args)

    try:
        report['kernel'] = command(['uname', '-r'])
        report['docker_version'] = docker('version', '--format', '{{.Server.Version}}')
        report['e2b_preflight'] = docker(*COMPOSE, 'logs', '--no-color', 'preflight')
        for role in ('executor', 'sandbox'):
            print('Building ' + role, flush=True)
            docker('build', '--build-context', 'agents=' + str(ROOT / 'regulai/front/agents'),
                   '-t', 'regulay-task48-' + role + ':local', '-f',
                   str(ROOT / 'ops/agent_probe' / ('Dockerfile.' + role)), str(ROOT / 'ops/agent_probe'))
        # Fresh lab credential only; neither its value nor ready/sdk.env is logged.
        key = docker(*COMPOSE, 'exec', '-T', 'ready', 'cat', '/run/e2b/team-api-key', sensitive=True)
        key_file = RUNTIME / 'key'
        key_file.write_text(key)
        key_file.chmod(0o400)
        os.chown(key_file, 1000, 1000)
        template_config = {'api_url': 'http://127.0.0.1:3000', 'sandbox_url': 'http://127.0.0.1:3002',
                           'api_key_file': '/run/task48/key', 'template': 'task48-csv'}
        (RUNTIME / 'template.json').write_text(json.dumps(template_config))
        print('Building real E2B template', flush=True)
        run(EXECUTOR, 'host', 'python', '-c',
            "import sys,json; sys.path.insert(0,'/app/ops/agent_probe'); "
            "from run_e2b import build_template; build_template(json.load(open('/run/task48/template.json')))",
            config=True)
        for name, subnet, ipv6 in [('task48-exec', '172.30.48.0/24', 'fd48:48::/64'),
                                    ('task48-receiver', '172.30.49.0/24', 'fd48:49::/64')]:
            extra = ['--opt', 'com.docker.network.bridge.name=br-task48'] if name == 'task48-exec' else []
            docker('network', 'create', '--internal', '--ipv6', '--subnet', subnet, '--subnet', ipv6, *extra, name)
            networks.append(name)
        # Only API and sandbox proxy on the VM host are reachable by the executor.
        command(['iptables', '-N', 'TASK48_EXEC'])
        firewall = True
        command(['iptables', '-A', 'TASK48_EXEC', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
        command(['iptables', '-A', 'TASK48_EXEC', '-p', 'tcp', '-m', 'multiport', '--dports', '3000,3002', '-j', 'ACCEPT'])
        command(['iptables', '-A', 'TASK48_EXEC', '-j', 'REJECT', '--reject-with', 'icmp-admin-prohibited'])
        command(['iptables', '-I', 'INPUT', '1', '-i', 'br-task48', '-j', 'TASK48_EXEC'])
        command(['ip6tables', '-I', 'INPUT', '1', '-i', 'br-task48', '-j', 'REJECT'])
        run(FIXTURE, 'task48-receiver', 'python', '-I', '/probe/runtime_checks.py', 'serve', detached=True)
        receiver_started = True
        info = json.loads(docker('inspect', 'task48-receiver', '--format', '{{json .NetworkSettings.Networks}}'))['task48-receiver']
        targets = [{'address': info['IPAddress'], 'port': 8080}, {'address': info['GlobalIPv6Address'], 'port': 8080}]
        config = {**template_config, 'api_url': 'http://172.30.48.1:3000',
                  'sandbox_url': 'http://172.30.48.1:3002', 'controlled_targets': targets}
        (RUNTIME / 'live.json').write_text(json.dumps(config))

        def positive_controls():
            return [json.loads(run(FIXTURE, 'task48-receiver', 'python', '-I', '/probe/runtime_checks.py',
                                   'allow', target['address'], str(target['port']))) for target in targets]

        report['positive_controls_before'] = positive_controls()
        print('Running native SDK graph against real E2B (cold and prepared)', flush=True)
        raw = run(EXECUTOR, 'task48-exec', 'python', '-c',
            "import sys,json; sys.path.insert(0,'/app/ops/agent_probe'); from run_e2b import live_probe; "
            "print(json.dumps(live_probe(json.load(open('/run/task48/live.json')))))", config=True)
        report['live'] = json.loads(raw)
        report['positive_controls_after'] = positive_controls()
        report['passed'] = True
    finally:
        if receiver_started:
            docker('rm', '-f', 'task48-receiver', check=False)
        if firewall:
            command(['iptables', '-D', 'INPUT', '-i', 'br-task48', '-j', 'TASK48_EXEC'], check=False)
            command(['iptables', '-F', 'TASK48_EXEC'], check=False)
            command(['iptables', '-X', 'TASK48_EXEC'], check=False)
            command(['ip6tables', '-D', 'INPUT', '-i', 'br-task48', '-j', 'REJECT'], check=False)
        for name in reversed(networks):
            docker('network', 'rm', name, check=False)
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        (output / 'report.json').write_text(json.dumps(report, indent=2))
        print(f'Evidence: {output}', flush=True)
    print('Real E2B checks passed; evidence written inside the disposable VM')


if __name__ == '__main__':
    main()

"""Recover Javi's existing real local stack without seeding or copying credentials.

Run from the repository with: rtk proxy .venv/Scripts/python.exe
ops/agent_chat/start_real_local.py. Keep this process running for the loopback tunnel.
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

VM = 'regulay-task48-e2bvm'
SSH = ['rtk', 'proxy', 'docker', 'exec', '-i', VM, 'ssh', '-i', '/vm/id_ed25519',
       '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/vm/known_hosts',
       '-o', 'ConnectTimeout=5', '-p', '2222', 'probe@127.0.0.1']


def main():
    # Never replace an unknown service or accidentally route to the UI lab.
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 8800))
        except OSError:
            raise SystemExit('Port 8800 is occupied. Identify its process before starting the real stack.')
    subprocess.run(['rtk', 'proxy', 'docker', 'start', VM], check=True)
    for attempt in range(45):
        ready = subprocess.run([*SSH, 'true'], capture_output=True)
        if ready.returncode == 0:
            break
        time.sleep(2)
    else:
        raise SystemExit('The existing E2B VM did not become reachable. Inspect its Docker logs.')
    # A reboot restores the VM's old 1 GiB default, insufficient for its template.
    subprocess.run([*SSH, 'sudo sysctl -w vm.nr_hugepages=1536'], check=True)
    subprocess.run([*SSH, 'sudo bash -se'], input=Path(__file__).with_name('restore_real_network.sh').read_bytes(), check=True)
    subprocess.run([*SSH, 'sudo docker start regulai-javi-real-postgres regulai-javi-real-web'], check=True)
    for attempt in range(30):
        ready = subprocess.run([*SSH, 'curl --fail --silent --output /dev/null http://127.0.0.1:31049/login/'], capture_output=True)
        if ready.returncode == 0:
            break
        time.sleep(2)
    else:
        raise SystemExit('The real web service is unavailable; worker was not started.')
    subprocess.run([*SSH, 'sudo docker start regulai-javi-real-worker'], check=True)
    print('Real account service: http://127.0.0.1:8800/login/ (existing credentials).', flush=True)
    return subprocess.call(['rtk', 'proxy', sys.executable, str(Path(__file__).with_name('forward.py')), '--port', '8800'])


if __name__ == '__main__':
    raise SystemExit(main())

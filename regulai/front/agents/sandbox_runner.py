"""Trusted Linux runner installed read-only at /skills, never on the web host.

Untrusted programs run in a new user/mount/PID/network namespace with only
runtime libraries and this job's directories. No envd, host mounts or secrets.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time


def command_args(command, budget):
    args = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib']
    if Path('/lib64').exists():
        args += ['--ro-bind', '/lib64', '/lib64']
    for name in ('/etc/fonts', '/etc/alternatives', '/etc/libreoffice'):
        if Path(name).exists():
            args += ['--ro-bind', name, name]
    args += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/home',
        '--ro-bind', '/skills', '/skills', '--ro-bind', '/workspace/input', '/workspace/input',
        '--bind', '/workspace/work', '/workspace/work', '--bind', '/workspace/output', '/workspace/output',
        '--setenv', 'PATH', '/workspace/work/.venv/bin:/usr/local/bin:/usr/bin:/bin',
        '--setenv', 'HOME', '/workspace/work/.home', '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'TMPDIR', '/workspace/work/.tmp', '--setenv', 'PYTHONNOUSERSITE', '1',
        '--setenv', 'OPENBLAS_NUM_THREADS', '1', '--setenv', 'OMP_NUM_THREADS', '1',
        '--setenv', 'PIP_NO_INDEX', '1', '--setenv', 'NPM_CONFIG_OFFLINE', 'true',
        '--setenv', 'NODE_OPTIONS', '--jitless --max-semi-space-size=4 --max-old-space-size=' + str(max(64, min(256, budget['memory_mb'] // 4))),
        '--setenv', 'UV_THREADPOOL_SIZE', '2',
        '--setenv', 'MALLOC_ARENA_MAX', '2', '--setenv', 'NPM_CONFIG_UPDATE_NOTIFIER', 'false',
        '--chdir', '/workspace/work', '/bin/sh', '-c', command]
    return args


def run(command, budget, timeout):
    if os.getuid() != 1000:
        raise ValueError('Sandbox commands require UID 1000')
    for name in ('.home', '.tmp'):
        Path('/workspace/work', name).mkdir(exist_ok=True)
    timeout = min(max(1, timeout), budget['command_seconds'])

    def bound():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_NPROC, (budget['processes'], budget['processes']))
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget['file_bytes'], budget['file_bytes']))
        memory = budget['memory_mb'] * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))

    started = time.monotonic()
    process = subprocess.Popen(command_args(command, budget), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=bound, env={'PATH': '/usr/local/bin:/usr/bin:/bin'})
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    counts = {'stdout': 0, 'stderr': 0}
    timed_out = False
    with selectors.DefaultSelector() as selector:
        for name in streams:
            pipe = getattr(process, name)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                if time.monotonic() - started > timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(chunk)
                    room = max(0, budget['output_bytes'] - sum(len(v) for v in streams.values()))
                    streams[key.data].extend(chunk[:room])
                if timed_out and time.monotonic() - started > timeout + 3:
                    break
            process.wait(timeout=3)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            for name in streams:
                getattr(process, name).close()
    return {name: value.decode('utf-8', errors='replace') for name, value in streams.items()} | {
        'exit_code': 124 if timed_out else process.returncode, 'timed_out': timed_out,
        'duration_ms': round((time.monotonic() - started) * 1000),
        'truncated': any(counts[n] > len(streams[n]) for n in streams), 'output_bytes': counts,
        'command_sha256': hashlib.sha256(command.encode()).hexdigest()}


if __name__ == '__main__':
    payload = json.loads(base64.b64decode(sys.argv[1]))
    print(json.dumps(run(payload['command'], payload['limits'], payload['timeout']), ensure_ascii=False))

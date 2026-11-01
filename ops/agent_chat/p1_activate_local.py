"""Explicit local-v2 activation stages; never starts the older task-57 instance.

All subprocesses use RTK. Source comes from an immutable commit plus individually
named working files. No environment files, databases or credentials are bundled.
Prepare builds/validates privately; only the separate apply action changes the
live application. A tunnel action only exposes its existing web on loopback.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import socketserver
import subprocess
import sys
import tarfile
import threading
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VM = 'regulai-v2-vm'
SSH = ['rtk', 'proxy', 'docker', 'exec', '-i', VM, 'ssh', '-i', '/vm/id_ed25519',
    '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'UserKnownHostsFile=/vm/known_hosts', '-o', 'ConnectTimeout=5',
    '-p', '2222', 'probe@127.0.0.1']
ROOTS = ('.dockerignore', 'regulai', 'ops/agent_chat', 'ops/agent_probe', 'ops/setup')
TEXT_SUFFIXES = {'.py', '.js', '.mjs', '.cjs', '.ts', '.css', '.scss', '.html', '.json', '.md', '.txt', '.in', '.sh', '.yaml', '.yml'}


def git(*args):
    return subprocess.check_output(['rtk', 'proxy', 'git', *args], cwd=ROOT)


def safe_source(path):
    value = PurePosixPath(path)
    return (not value.is_absolute() and '..' not in value.parts and '\\' not in path
        and (path == '.dockerignore' or any(path.startswith(root + '/') for root in ROOTS[1:]))
        and value.name != 'local_settings.py' and not value.name.startswith('.env')
        and value.suffix not in {'.sqlite', '.sqlite3', '.db', '.dump', '.pem', '.key'}
        and not any(part in {'.git', '.venv', '__pycache__', '.runtime', 'private', 'media', 'node_modules'} for part in value.parts))


def archive_files(raw):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            if not member.isfile() or not safe_source(member.name):
                raise RuntimeError('unsafe_source_member:' + member.name)
            files[member.name] = (archive.extractfile(member).read(), member.mode & 0o777)
    return files


def normalized_hash(path, raw):
    name = PurePosixPath(path)
    if name.suffix in TEXT_SUFFIXES or name.name.startswith(('Dockerfile', 'LICENSE', 'NOTICE')):
        raw = raw.replace(b'\r\n', b'\n')
    return hashlib.sha256(raw).hexdigest()


def candidate_bundle(source_ref, overlays):
    commit = git('rev-parse', '--verify', source_ref + '^{commit}').decode().strip()
    files = archive_files(git('archive', '--format=tar', commit, *ROOTS))
    selected = [Path(path).as_posix() for path in overlays]
    for relative in selected:
        if not safe_source(relative):
            raise RuntimeError('unsafe_overlay:' + relative)
        source = ROOT / relative
        if not source.is_file() or source.is_symlink():
            raise RuntimeError('overlay_must_be_regular_file:' + relative)
        files[relative] = (source.read_bytes(), files.get(relative, (None, 0o644))[1])
    for path in ('ops/agent_chat/p1_activation_remote.py', 'ops/agent_chat/p1_activation_probe.cjs'):
        files[path] = ((ROOT / path).read_bytes(), 0o644)
    accepted = {}
    sources = [files, archive_files(git('archive', '--format=tar', 'HEAD', *ROOTS))]
    frozen = ROOT / 'output/p1-20261016/e1/p0-source.zip'
    with zipfile.ZipFile(frozen) as archive:
        sources.append({path: (archive.read(path), 0o644) for path in archive.namelist() if safe_source(path)})
    for source in sources:
        for path, (raw, _) in source.items():
            accepted.setdefault(path, set()).add(normalized_hash(path, raw))
    manifest = {'source_commit': commit, 'overlays': sorted(selected),
        'source_sha256': {path: hashlib.sha256(raw).hexdigest() for path, (raw, _) in files.items()},
        'accepted_live_hashes': {path: sorted(values) for path, values in accepted.items()}}
    files['activation-manifest.json'] = (json.dumps(manifest, sort_keys=True).encode(), 0o444)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for path, (raw, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(path)
            entry.size, entry.mode, entry.mtime = len(raw), mode, 0
            archive.addfile(entry, io.BytesIO(raw))
    return buffer.getvalue(), manifest


def owner_check():
    row = json.loads(subprocess.check_output(['rtk', 'proxy', 'docker', 'inspect', VM]))[0]
    if ((row['Config'].get('Labels') or {}).get('regulai.install') != 'v2'
            or not row['State']['Running']
            or not any(m.get('Name') == 'regulai-v2-state' and m['Destination'] == '/vm' for m in row['Mounts'])):
        raise RuntimeError('running_owned_v2_vm_required')


def remote(action, identity, bundle=b''):
    owner_check()
    source = (ROOT / 'ops/agent_chat/p1_activation_remote.py').read_bytes()
    arguments = ['activation', action] + (['--identity', identity] if identity else [])
    header = json.dumps({'argv': arguments, 'source': base64.b64encode(source).decode()}).encode() + b'\n'
    loader = ("import sys,json,base64; h=json.loads(sys.stdin.buffer.readline()); "
        "s=base64.b64decode(h['source']).decode(); sys.argv=h['argv']; "
        "exec(compile(s,'activation_remote.py','exec'),"
        "{'__name__':'__main__','__file__':'activation_remote.py','_ACTIVATION_SOURCE':s})")
    import shlex
    result = subprocess.run([*SSH, 'sudo python3 -c ' + shlex.quote(loader)], input=header + bundle,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        # Suppress unexpected private application tracebacks. Private VM logs and
        # the stage state identify the failed operation for deliberate recovery.
        raise RuntimeError('activation_stage_failed:' + action + ':exit=' + str(result.returncode))
    return json.loads(result.stdout)


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        connection = subprocess.Popen([*SSH[:-1], '-W', '127.0.0.1:31058', SSH[-1]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def upstream():
            try:
                while data := self.request.recv(65536):
                    connection.stdin.write(data)
                    connection.stdin.flush()
            except (OSError, BrokenPipeError):
                pass
            finally:
                try:
                    connection.stdin.close()
                except OSError:
                    pass
        thread = threading.Thread(target=upstream, daemon=True)
        thread.start()
        try:
            while data := connection.stdout.read1(65536):
                self.request.sendall(data)
        except OSError:
            pass
        finally:
            connection.terminate()
            connection.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'prepare', 'apply', 'rollback', 'tunnel'))
    parser.add_argument('--identity')
    parser.add_argument('--source-ref', default='codex/p1-skills-streaming-20261016')
    parser.add_argument('--overlay', action='append', default=[])
    parser.add_argument('--port', type=int, default=8800)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.action == 'tunnel':
        owner_check()
        with socketserver.ThreadingTCPServer(('127.0.0.1', args.port), Tunnel) as server:
            print('Existing v2 web only: http://127.0.0.1:' + str(args.port), flush=True)
            server.serve_forever()
        return
    if args.action != 'inspect' and not args.identity:
        parser.error('--identity is required for mutation stages')
    bundle = b''
    if args.action == 'prepare':
        bundle, manifest = candidate_bundle(args.source_ref, args.overlay)
        print('Candidate ' + manifest['source_commit'] + '; explicit overlays: ' + str(len(args.overlay)), file=sys.stderr)
    value = remote(args.action, args.identity, bundle)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(value, indent=2), encoding='utf-8')
    visible = {key: item for key, item in value.items() if key != 'source_hashes'}
    if 'source_hashes' in value:
        visible['source_files'] = len(value['source_hashes'])
    print(json.dumps(visible, indent=2))


if __name__ == '__main__':
    main()

"""Run a disposable Linux/PostgreSQL/HTTPS lab with synthetic data only.

Uses a new report directory and a new private .claude directory for every run.
No host database, settings, secrets or media are copied into the Docker build.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import traceback
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
import requests

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'Synthetic-lab-only-2026!'


class Lab:
    def __init__(self, output):
        self.output = Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.identity = 'regulai-lab-' + uuid.uuid4().hex[:12]
        self.work = ROOT / '.claude' / self.identity
        self.work.mkdir(parents=True, exist_ok=False)
        self.calls = []
        self.containers = []
        self.network_created = False
        self.ingress_created = False
        self.volume_created = False
        self.static_volume_created = False
        self.image = self.identity + ':local'
        self.images = json.loads((ROOT / 'ops/pilot/images.json').read_text(encoding='utf-8'))
        self.port = None
        self.checks = {}

    def run(self, *args, name=None, check=True, timeout=600):
        name = name or f'command-{len(self.calls) + 1:02}'
        started = time.monotonic()
        result = subprocess.run(['rtk', 'proxy', *map(str, args)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, encoding='utf-8', errors='replace')
        log = self.output / (name + '.log')
        log.write_text(result.stdout + result.stderr, encoding='utf-8')
        self.calls.append({'command': ['rtk', 'proxy', *map(str, args)], 'exit_code': result.returncode,
            'seconds': round(time.monotonic() - started, 3), 'log': log.name,
            'sha256': sha256(log.read_bytes()).hexdigest()})
        (self.output / 'commands.json').write_text(json.dumps(self.calls, indent=2), encoding='utf-8')
        print(f'{name}: exit {result.returncode}', flush=True)
        if check and result.returncode:
            raise RuntimeError(f'{name} failed; inspect its preserved log.')
        return result

    def prepare(self):
        for name in ('private', 'tls', 'media', 'static', 'provider', 'context'):
            (self.work / name).mkdir(mode=0o700 if name == 'private' else 0o755)
        keys = {'signing': secrets.token_urlsafe(64), 'encryption': Fernet.generate_key().decode(),
                'database': secrets.token_urlsafe(32)}
        for name, value in [('keys.json', json.dumps(keys)), ('db-password', keys['database'])]:
            target = self.work / 'private' / name
            with target.open('x', encoding='utf-8') as stream:
                stream.write(value)
            target.chmod(0o600)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost synthetic regulAI lab')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
        (self.work / 'tls' / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private = self.work / 'tls' / 'key.pem'
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        private.chmod(0o600)
        files = self.run('git', 'ls-files', '--cached', '--others', '--exclude-standard', name='source-list').stdout.splitlines()
        hashes_map = {}
        for rel in files:
            path = Path(rel)
            if (path.name in ('local_settings.py', '.env') or path.name.startswith('.env.')
                    or path.suffix in ('.sqlite3', '.pyc')
                    or any(part in ('.claude', '.venv', '__pycache__', 'media', 'staticfiles') for part in path.parts)):
                continue
            allowed = (path.parts[0] in ('regulai', 'ops', 'scripts', '.github')
                or rel in ('requirements.txt', 'gunicorn.conf.py', '.gitattributes')
                or (path.parts[0] == 'evals' and 'reports' not in path.parts))
            if not allowed:
                continue
            source = ROOT / path
            if not source.is_file() or source.is_symlink():
                continue
            target = self.work / 'context' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            hashes_map[path.as_posix()] = sha256(source.read_bytes()).hexdigest()
        head = self.run('git', 'rev-parse', 'HEAD', name='source-head').stdout.strip()
        (self.output / 'source-manifest.json').write_text(json.dumps({'head': head, 'files': hashes_map}, indent=2), encoding='utf-8')
        self.run('docker', 'build', '--file', str(self.work / 'context' / 'ops/pilot/Dockerfile'),
                 '--tag', self.image, str(self.work / 'context'), name='image-build', timeout=1200)
        for name, image in self.images.items():
            self.run('docker', 'pull', image, name='pull-' + name, timeout=300)
        for name, image in {'app': self.image, **self.images}.items():
            self.run('docker', 'image', 'inspect', image, '--format', '{{.Id}} {{json .RepoDigests}}',
                     name='image-' + name)

    def container(self, short, image, *args, extra=()):
        name = self.identity + '-' + short
        self.run('docker', 'run', '-d', '--name', name, '--label', 'regulai.synthetic-lab=' + self.identity,
            '--network', self.identity, '--network-alias', short, *extra, image, *args, name='start-' + short)
        self.containers.append(name)
        self.run('docker', 'inspect', name, '--format', '{{.Name}} {{json .Config.Cmd}}', name='process-' + short)
        return name

    def app_args(self):
        return ['--mount', f'type=bind,source={self.work},target=/lab',
            '--mount', f'type=volume,source={self.identity}-static,target=/lab/static',
            '-e', 'REGULAI_SYNTHETIC_LAB=1']

    def app(self, *args, name, database='regulai_lab', check=True):
        return self.run('docker', 'run', '--rm', '--network', self.identity, *self.app_args(),
            '-e', 'LAB_DATABASE=' + database, self.image, *args, name=name, check=check)

    def manage(self, *args, name, database='regulai_lab', check=True):
        return self.app('python', 'ops/pilot/manage_lab.py', *args, name=name, database=database, check=check)

    def start(self):
        self.run('docker', 'network', 'create', '--internal', '--label', 'regulai.synthetic-lab=' + self.identity,
                 self.identity, name='network-create')
        self.network_created = True
        self.run('docker', 'network', 'create', '--label', 'regulai.synthetic-lab=' + self.identity,
                 self.identity + '-ingress', name='ingress-network-create')
        self.ingress_created = True
        self.run('docker', 'volume', 'create', '--label', 'regulai.synthetic-lab=' + self.identity,
                 self.identity + '-db', name='volume-create')
        self.volume_created = True
        self.run('docker', 'volume', 'create', '--label', 'regulai.synthetic-lab=' + self.identity,
                 self.identity + '-static', name='static-volume-create')
        self.static_volume_created = True
        self.db = self.container('db', self.images['postgres'], extra=[
            '--mount', f'type=volume,source={self.identity}-db,target=/var/lib/postgresql/data',
            '--mount', f'type=bind,source={self.work / "private/db-password"},target=/run/db-password,readonly',
            '-e', 'POSTGRES_USER=lab', '-e', 'POSTGRES_DB=regulai_lab', '-e', 'POSTGRES_PASSWORD_FILE=/run/db-password'])
        for attempt in range(30):
            result = self.run('docker', 'exec', self.db, 'pg_isready', '-U', 'lab', '-d', 'regulai_lab',
                              name=f'db-ready-{attempt}', check=False)
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('PostgreSQL not ready.')
        self.app('python', 'regulai/manage.py', 'migrate', '--noinput', name='migrations')
        self.manage('seed', name='seed-two-companies')
        self.app('python', 'regulai/manage.py', 'collectstatic', '--noinput', name='static-collection')
        self.app('python', 'regulai/manage.py', 'check', '--deploy', '--fail-level', 'WARNING', name='deploy-check')
        self.provider = self.container('provider', self.image, 'python', 'ops/pilot/synthetic_provider.py', extra=[
            '--mount', f'type=bind,source={self.work / "provider"},target=/lab/provider'])
        self.web = self.container('app', self.image, extra=self.app_args())
        self.proxy = self.identity + '-https'
        self.run('docker', 'create', '--name', self.proxy, '--label', 'regulai.synthetic-lab=' + self.identity,
            '--network', self.identity + '-ingress',
            '-p', '127.0.0.1::8443', '--mount', f'type=bind,source={self.work / "tls"},target=/lab/tls,readonly',
            '--mount', f'type=volume,source={self.identity}-static,target=/lab/static,readonly',
            '--mount', f'type=bind,source={self.work / "context/ops/pilot/nginx.conf"},target=/etc/nginx/nginx.conf,readonly',
            self.images['nginx'], name='create-https')
        self.containers.append(self.proxy)
        self.run('docker', 'network', 'connect', self.identity, self.proxy, name='connect-https-backend')
        self.run('docker', 'start', self.proxy, name='start-https')
        binding = self.run('docker', 'port', self.proxy, '8443', name='loopback-binding').stdout.strip()
        assert binding.startswith('127.0.0.1:')
        self.port = int(binding.rsplit(':', 1)[1])
        self.base = f'https://localhost:{self.port}'
        self.ca = str(self.work / 'tls/cert.pem')
        (self.output / 'endpoint.json').write_text(json.dumps({'url': self.base,
            'certificate': self.ca, 'loopback_only': True, 'synthetic_only': True}, indent=2), encoding='utf-8')
        for attempt in range(30):
            try:
                response = requests.get(self.base + '/login/', verify=self.ca, timeout=2)
                if response.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(1)
        raise RuntimeError('HTTPS application not ready.')

    def session(self, username='lab-alpha-user'):
        session = requests.Session()
        session.verify = self.ca
        page = session.get(self.base + '/login/', timeout=10)
        assert page.status_code == 200
        csrf = session.cookies['regulai_lab_csrf']
        response = session.post(self.base + '/login/', data={'username': username, 'password': PASSWORD,
            'csrfmiddlewaretoken': csrf}, headers={'Referer': self.base + '/login/'}, timeout=10)
        assert response.status_code == 200 and '/login/' not in response.url
        return session

    def send(self, session, content, identity=None, _timeout=40, **extra):
        return session.post(self.base + '/api/chat/send/', json={'content': content,
            'request_id': identity or str(uuid.uuid4()), **extra}, headers={
                'X-CSRFToken': session.cookies['regulai_lab_csrf'], 'Referer': self.base + '/chat/'}, timeout=_timeout)

    def events(self):
        path = self.work / 'provider/events.jsonl'
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []

    def wait_provider(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if (self.work / 'provider/waiting').exists():
                return
            time.sleep(0.05)
        raise RuntimeError('Synthetic delayed transport was not reached.')

    def reset_wait(self):
        for name in ('waiting', 'release'):
            (self.work / 'provider' / name).unlink(missing_ok=True)

    def http_checks(self):
        alpha, beta = self.session(), self.session('lab-beta-user')
        page = alpha.get(self.base + '/chat/', timeout=10)
        assert page.status_code == 200 and page.headers['X-Content-Type-Options'] == 'nosniff'
        assert 'max-age=3600' in page.headers['Strict-Transport-Security']
        cookies = {cookie.name: cookie for cookie in alpha.cookies}
        assert cookies['regulai_lab_session'].secure and cookies['regulai_lab_csrf'].secure
        assert requests.get(self.base + '/login/', headers={'Host': 'unapproved.invalid'}, verify=self.ca, timeout=10).status_code == 400
        assert alpha.get(self.base + '/media/chat_responses/alpha.txt', timeout=10).status_code == 404
        file = json.loads((self.work / 'lab-files.json').read_text(encoding='utf-8'))[0]
        private_url = self.base + '/chat/download/' + str(file['message_id']) + '/'
        download = alpha.get(private_url, timeout=10)
        assert download.status_code == 200 and download.content == b'Synthetic private alpha'
        assert download.headers['X-Content-Type-Options'] == 'nosniff'
        assert beta.get(private_url, timeout=10).status_code == 404
        assert requests.get(private_url, verify=self.ca, allow_redirects=False, timeout=10).status_code == 302
        static_root = self.work / 'context/regulai/static'
        static = next((static_root / 'vendor').rglob('*.js'))
        served = alpha.get(self.base + '/static/' + static.relative_to(static_root).as_posix(), timeout=10)
        assert served.status_code == 200 and sha256(served.content).digest() == sha256(static.read_bytes()).digest(), {
            'static_status': served.status_code, 'expected_sha256': sha256(static.read_bytes()).hexdigest(),
            'served_sha256': sha256(served.content).hexdigest()}
        response = self.send(alpha, 'Hello synthetic.pilot@example.invalid').json()
        assert response['status'] == 'completed', response
        receipt_url = self.base + '/chat/requests/' + response['request_id'] + '/receipt/'
        assert alpha.get(receipt_url, timeout=10).status_code == 200
        assert beta.get(receipt_url, timeout=10).status_code == 404
        before = len(self.events())
        blocked = self.send(alpha, 'SYNTHETIC_BLOCK').json()
        assert blocked['status'] == 'blocked' and len(self.events()) == before
        assert not any(event['purpose'] == 'mask' for event in self.events())
        assert not any(event['contains_original_sentinel'] for event in self.events())
        local_calls = [call for call in response['receipt']['calls'] if call.get('transport') == 'local']
        assert len(local_calls) == 2 and all(call['cost'] == '0' and call['cost_kind'] == 'configured_zero'
                                           for call in local_calls)
        self.checks['https_cookies_hosts_static_private_files_and_tenants'] = True
        self.checks['real_local_detector_before_http_synthetic_transport_and_local_block'] = True
        self.reset_wait()
        identity = str(uuid.uuid4())
        before = sum(event['purpose'] == 'generation' for event in self.events())
        twin = requests.Session()
        twin.verify = self.ca
        twin.cookies.update(alpha.cookies)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future = executor.submit(self.send, alpha, 'lab_wait duplicate', identity)
            self.wait_provider()
            duplicate = self.send(twin, 'lab_wait duplicate', identity).json()
            assert duplicate['status'] == 'processing'
            (self.work / 'provider/release').write_text('release', encoding='utf-8')
            assert future.result().json()['status'] == 'completed'
        assert sum(event['purpose'] == 'generation' for event in self.events()) - before == 1
        self.checks['overlapping_http_requests_generate_once'] = True
        self.reset_wait()
        identity = str(uuid.uuid4())
        before = sum(event['purpose'] == 'generation' for event in self.events())
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.send, alpha, 'lab_wait disconnect', identity, _timeout=0.5)
            self.wait_provider()
            try:
                future.result()
            except requests.exceptions.ReadTimeout:
                pass
            else:
                raise AssertionError('The client must disconnect while the provider is pending.')
            (self.work / 'provider/release').write_text('release', encoding='utf-8')
        for attempt in range(40):
            recovered = self.send(alpha, 'lab_wait disconnect', identity).json()
            if recovered['status'] == 'completed':
                break
            assert recovered['status'] == 'processing'
            time.sleep(0.1)
        assert recovered['status'] == 'completed'
        assert sum(event['purpose'] == 'generation' for event in self.events()) - before == 1
        self.checks['disconnected_client_recovers_without_duplicate_generation'] = True
        self.reset_wait()
        identity = str(uuid.uuid4())
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.send, alpha, 'lab_wait restart', identity)
            self.wait_provider()
            self.run('docker', 'kill', self.web, name='kill-during-call')
            try:
                future.result()
            except requests.RequestException:
                pass
        self.run('docker', 'start', self.web, name='restart-application')
        time.sleep(2)
        (self.work / 'provider/release').write_text('release', encoding='utf-8')
        self.manage('expire', '--request-id', identity, name='age-only-synthetic-request')
        before = len(self.events())
        replay = self.send(alpha, 'lab_wait restart', identity).json()
        assert replay['status'] == 'outcome_unknown' and len(self.events()) == before
        assert replay['success'] is False
        assert any(call['purpose'] == 'generation' and call.get('cost') is None
                   for call in replay['receipt']['calls'])
        assert replay['receipt'].get('total', {}).get('cost') is None
        assert self.send(alpha, 'lab_wait restart', identity).json()['status'] == 'outcome_unknown'
        self.checks['killed_inflight_request_stays_unknown_without_resend'] = True
        (self.output / 'transport-events.json').write_text(json.dumps(self.events(), indent=2), encoding='utf-8')
        (self.output / 'restart-result.json').write_text(json.dumps(replay, indent=2), encoding='utf-8')

    def postgres_tests(self):
        self.app('python', 'regulai/manage.py', 'test', 'front.test_state', 'front.test_onboarding_migrations',
            'front.test_backend_hardening.SecretRotationTests', 'front.test_backend_hardening.BackendHardeningTests',
            'front.test_backend_hardening.LocalBootstrapTests', 'front.test_required_masking', 'front.test_pipeline_privacy',
            'front.test_local_masking', 'front.test_local_masking_integration',
            'front.test_operations', 'api.test_permissions', '--settings=regulai.pilot_postgres_test_settings',
            '--noinput', name='postgres-http-state-migration-security-tests')
        self.checks['postgres_http_state_migration_security_suite'] = True

    def serve(self, seconds):
        """Optional supervised session after all automated checks, still loopback only."""
        self.run('docker', 'start', self.web, name='supervised-session-start')
        for attempt in range(30):
            try:
                if requests.get(self.base + '/login/', verify=self.ca, timeout=2).status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Supervised session did not become ready.')
        print(f'SYNTHETIC ONLY: {self.base}/login/ for at most {seconds} seconds; Ctrl+C stops and cleans up.', flush=True)
        print('Public synthetic accounts: lab-alpha-user / lab-beta-user; password: ' + PASSWORD, flush=True)
        self.checks['supervised_session_endpoint_ready'] = True
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))

    def recovery(self):
        self.run('docker', 'stop', self.web, name='quiesce-before-backup')
        before = json.loads(self.manage('snapshot', name='snapshot-before').stdout)
        backup = self.work / 'private/backup'
        backup.mkdir()
        shutil.copyfile(self.work / 'private/keys.json', backup / 'keys.json')
        shutil.copytree(self.work / 'media', backup / 'media')
        self.run('docker', 'exec', self.db, 'pg_dump', '-U', 'lab', '-d', 'regulai_lab', '-Fc',
                 '-f', '/tmp/synthetic-backup.dump', name='database-backup')
        self.run('docker', 'cp', self.db + ':/tmp/synthetic-backup.dump', str(backup / 'database.dump'), name='backup-copy')
        self.run('docker', 'exec', self.db, 'createdb', '-U', 'lab', 'regulai_restored', name='isolated-restore-database')
        self.run('docker', 'exec', self.db, 'pg_restore', '-U', 'lab', '-d', 'regulai_restored', '--exit-on-error',
                 '/tmp/synthetic-backup.dump', name='database-restore')
        shutil.copytree(backup / 'media', self.work / 'restored-media')
        after = json.loads(self.manage('snapshot', name='snapshot-restored', database='regulai_restored').stdout)
        assert before == after
        self.checks['postgres_backup_restore_all_tables_media_keys'] = True
        self.manage('rotation-conflict', name='postgres-real-rotation-conflict', database='regulai_restored')
        key_path = self.work / 'private/keys.json'
        old = json.loads(key_path.read_text(encoding='utf-8'))
        new = {**old, 'encryption': Fernet.generate_key().decode(), 'encryption_fallbacks': [old['encryption']]}
        key_path.write_text(json.dumps(new), encoding='utf-8')
        self.app('python', 'regulai/manage.py', 'reencrypt_secrets', '--dry-run', name='rotation-dry-run', database='regulai_restored')
        self.app('python', 'regulai/manage.py', 'reencrypt_secrets', name='rotation-write', database='regulai_restored')
        new['encryption_fallbacks'] = []
        key_path.write_text(json.dumps(new), encoding='utf-8')
        self.app('python', 'regulai/manage.py', 'reencrypt_secrets', '--dry-run', name='rotation-new-key-only', database='regulai_restored')
        rotated = json.loads(self.manage('snapshot', name='rotated-readable', database='regulai_restored').stdout)
        assert rotated['credentials_readable'] and rotated['tables']['front_company']['count'] == 2
        # Roll back the restored copy and keys as a pair, never the source laboratory database.
        self.run('docker', 'exec', self.db, 'dropdb', '-U', 'lab', 'regulai_restored', name='discard-only-restored-copy')
        self.run('docker', 'exec', self.db, 'createdb', '-U', 'lab', 'regulai_restored', name='rollback-empty-target')
        self.run('docker', 'exec', self.db, 'pg_restore', '-U', 'lab', '-d', 'regulai_restored', '--exit-on-error',
                 '/tmp/synthetic-backup.dump', name='rollback-database')
        shutil.copyfile(backup / 'keys.json', key_path)
        rolled_back = json.loads(self.manage('snapshot', name='rollback-verified', database='regulai_restored').stdout)
        assert before == rolled_back
        self.checks['reencryption_new_key_only_concurrent_conflict_and_rollback'] = True

    def cleanup(self):
        for name in reversed(self.containers):
            self.run('docker', 'logs', name, name='logs-' + name.rsplit('-', 1)[1], check=False)
            label = self.run('docker', 'inspect', name, '--format',
                '{{index .Config.Labels "regulai.synthetic-lab"}}', name='verify-owned-' + name.rsplit('-', 1)[1], check=False)
            if label.stdout.strip() == self.identity:
                self.run('docker', 'rm', '--force', name, name='remove-owned-' + name.rsplit('-', 1)[1], check=False)
        if self.volume_created:
            self.run('docker', 'volume', 'rm', self.identity + '-db', name='remove-owned-volume', check=False)
        if self.static_volume_created:
            self.run('docker', 'volume', 'rm', self.identity + '-static', name='remove-owned-static-volume', check=False)
        if self.network_created:
            self.run('docker', 'network', 'rm', self.identity, name='remove-owned-network', check=False)
        if self.ingress_created:
            self.run('docker', 'network', 'rm', self.identity + '-ingress', name='remove-owned-ingress', check=False)
        self.run('docker', 'image', 'rm', self.image, name='remove-owned-image', check=False)
        (self.output / 'result.json').write_text(json.dumps({'checks': self.checks, 'private_work': str(self.work),
            'identity': self.identity, 'real_provider_calls': 0, 'public_deployment': False,
            'remote_ci_executed': False}, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New evidence directory; existing paths are rejected.')
    parser.add_argument('--serve-seconds', type=int, default=0,
        help='Optional supervised synthetic session after verification; maximum 7200 seconds, default 0.')
    options = parser.parse_args()
    if not 0 <= options.serve_seconds <= 7200:
        parser.error('--serve-seconds must be between 0 and 7200')
    lab = Lab(options.output)
    try:
        lab.prepare()
        lab.start()
        lab.http_checks()
        lab.postgres_tests()
        lab.recovery()
        if options.serve_seconds:
            lab.serve(options.serve_seconds)
    except BaseException:
        (lab.output / 'failure.txt').write_text(traceback.format_exc(), encoding='utf-8')
        raise
    finally:
        lab.cleanup()


if __name__ == '__main__':
    main()

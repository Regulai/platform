"""Finish only the interrupted, already-built P1 Taste a2 preparation.

Guest-only entry point: finish(remote_namespace, corrected_probe_bytes). The
caller loads this file with a non-main module name and explicitly invokes finish.
Nothing runs on import. No builds, template creation, migration, real-data
installation, service replacement or provider calls are performed here.
"""
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time

IDENTITY = 'p1-20261016-taste-a2'
COMMIT = 'ba2d6b2dbf1706ec3ca262988ee1658cab654ccc'
MANIFEST_SHA = '396cd6c1f675e9d4c8eae4aa66db08543c3ca8d09d16726a9b85b03950b0f0b8'
REMOTE_SHA = '4006b30ef759b98149fa0d0acd4e834f4fada94d85bd22060a5e8ebe4cfad8f9'
BACKEND_SHA = '0945e3a9489b0385e21aace83bb9b8de6f3e002c7597ca3aedfcd046135bdb94'
OLD_PROBE_SHA = '6e5c2b45401f6dbd1df2ce6417c1c41ca1f44ed91dd76ad2b7aa3b9179086239'
PROBE_SHA = '65876064c092fd3e0b91422e69997ba78db78a3d12929697df4ffe7d3dbb1a50'
PROBE_CODE_SHA = '1778a8b1e1782fb440341c0266b6752b2591d87595cc265f65f2495a0ed29fb5'
TEMPLATE_ALIAS = 'regulai-' + IDENTITY
TEMPLATE_ID = 'k07t82e4u9a30y71xa10'
BUILD_DIGESTS = {
    'web': ('3155460f1787c5a88fc5732ca6bb5afceb893bb53d9fa811fb7dc11d4104c8ed',
            '2939963da81afdb9465a3cbff8fb6e064b1cd1d55c5126446638620bb5bf8678'),
    'worker': ('83fc3da20a9c11d84e12398a0746c4c8e53dc4b293bd809c68d3549c41c3e69c',
               '8f1c0cd83a50178218c2f4395dc03a7fa0179d6b672c89c6fcc63de50acef6a1'),
    'sandbox': ('8f7d2c1213e60405a41923293f344b7586c7fe869510367cd7ea02454fe03bba',
                '375f5add9c03d73049db89b3077b04f16bb1471dd5e79abb59bdbcedabc1dfff'),
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, code):
    if not condition:
        raise RuntimeError('a2_continuation:' + code)


def _regular(path, stage):
    _require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(stage),
             'regular_stage_file_required')
    return path.read_bytes()


def _probe_code(source):
    tree = ast.parse(source)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'verify_template')
    values = [node.value.value for node in ast.walk(function) if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'code' for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    _require(len(values) == 1 and _sha(values[0].encode()) == PROBE_CODE_SHA, 'probe_code_changed')
    code = values[0]
    marker = 'try:\n backend=WorkspaceSandbox'
    _require(code.count(marker) == 1 and code.count("'template':config['template']") == 1,
             'probe_identity_guard_location_changed')
    # The SDK resolves this through the same local control endpoint used to
    # create the sandbox. Keep it inside finally: kill, including mismatch.
    code = code.replace(marker, 'try:\n info=sandbox.get_info()\n'
        + ' if info.template_id != ' + repr(TEMPLATE_ID) + ': raise RuntimeError("template_alias_changed")\n'
        + ' backend=WorkspaceSandbox', 1)
    return code.replace("'template':config['template']", "'template':config['template'],'template_id':info.template_id", 1)


def _build_evidence(kind, raw, image):
    text = raw.decode('utf-8', errors='replace')
    config = set(re.findall(r'exporting config sha256:([0-9a-f]{64})', text))
    manifests = set(re.findall(r'exporting manifest list sha256:([0-9a-f]{64})', text))
    expected_config, expected_manifest = BUILD_DIGESTS[kind]
    _require(config == {expected_config} and manifests == {expected_manifest}, 'build_log_identity_changed:' + kind)
    # Docker's classic store uses the config digest; its containerd store uses
    # the manifest-list digest. Both identities are pinned to the completed build.
    _require(image['Id'] in {'sha256:' + expected_config, 'sha256:' + expected_manifest},
             'built_image_identity_changed:' + kind)
    return {'log_sha256': _sha(raw), 'config_sha256': expected_config,
            'manifest_list_sha256': expected_manifest, 'image_id': image['Id']}


def finish(ns, probe_bytes):
    """Verify a2 artifacts, run its existing template once, prepare clone state.

    ns must be the loaded activation_remote namespace. Corrected probe bytes
    must match PROBE_SHA. Returns metadata-only state; all subprocess stderr is
    appended privately to the existing a2 stage. Any failed gate leaves no
    prepared state. A failed completed-proof/install boundary needs deliberate
    inspection, not an automatic second probe.
    """
    _require(os.geteuid() == 0 and Path(ns['ROOT']) == Path('/opt/regulai'), 'owned_guest_root_required')
    stage = ns['stage_path'](IDENTITY)
    _require(stage == Path('/opt/regulai/updates') / IDENTITY and stage.is_dir()
             and not stage.is_symlink() and stage.stat().st_uid == 0
             and stat.S_IMODE(stage.stat().st_mode) == 0o700, 'private_a2_stage_required')
    _require(isinstance(probe_bytes, bytes) and _sha(probe_bytes) == PROBE_SHA, 'corrected_probe_digest_mismatch')
    lock_fd = os.open(stage / 'continuation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _finish_locked(stage, probe_bytes)
    finally:
        os.close(lock_fd)


def _finish_locked(stage, probe_bytes):
    _require(not (stage / 'state.json').exists(), 'state_already_exists')
    manifest = json.loads(_regular(stage / 'source/activation-manifest.json', stage))
    _require(_sha(json.dumps(manifest, sort_keys=True).encode()) == MANIFEST_SHA
             and manifest['source_commit'] == COMMIT
             and manifest['overlays'] == ['regulai/front/agents/skill_backend.py'], 'candidate_manifest_changed')
    hashes = manifest['source_sha256']
    _require(hashes['regulai/front/agents/skill_backend.py'] == BACKEND_SHA
             and hashes['ops/agent_chat/p1_activation_remote.py'] == REMOTE_SHA
             and hashes['ops/agent_chat/p1_activation_probe.cjs'] == OLD_PROBE_SHA, 'candidate_code_identity_changed')
    for relative, expected in hashes.items():
        part = PurePosixPath(relative)
        _require(not part.is_absolute() and '..' not in part.parts and str(part) == relative,
                 'candidate_path_invalid')
        _require(_sha(_regular(stage / 'source' / relative, stage)) == expected, 'candidate_source_changed')
    remote_raw = _regular(stage / 'runtime/p1_activation_remote.py', stage)
    _require(_sha(remote_raw) == REMOTE_SHA, 'prepared_remote_changed')
    remote_source = remote_raw.decode('utf-8')
    code = _probe_code(remote_source)
    remote = {'__name__': 'p1_a2_prepared_remote', '__file__': str(stage / 'runtime/p1_activation_remote.py'),
              '_ACTIVATION_SOURCE': remote_source}
    exec(compile(remote_source, remote['__file__'], 'exec'), remote)
    stderr_path = stage / 'continuation-stderr.log'

    def private_command(args, *, data=None, output=None, timeout=None):
        fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'ab') as errors:
                result = subprocess.run(args, input=data, stdout=output or subprocess.PIPE,
                    stderr=errors, timeout=timeout or 180)
        except subprocess.TimeoutExpired:
            raise RuntimeError('a2_continuation:private_command_timeout') from None
        _require(result.returncode == 0, 'private_command_failed:' + str(result.returncode))
        return result.stdout if output is None else b''

    remote['command'] = private_command
    read_json, private_json, docker = remote['read_json'], remote['private_json'], remote['docker']
    original = read_json(stage / 'original-containers.json')
    expected_identity = remote['original_identity'](original)

    def live_unchanged():
        rows = {name: remote['inspect'](name) for name in remote['NAMES']}
        _require(remote['original_identity'](rows) == expected_identity, 'original_containers_changed')
        _require(remote['source_manifest']() == read_json(stage / 'original-source-hashes.json'), 'live_source_changed')
        _require(remote['private_configuration_digest']() == read_json(stage / 'original-configuration.json')['digest'],
                 'private_configuration_changed')
        return remote['require_idle'](current=True)

    metadata = live_unchanged()
    images = {kind: 'regulai-v2-' + kind + ':' + IDENTITY for kind in BUILD_DIGESTS}
    image_ids, builds = {}, {}
    for kind, image in images.items():
        inspected = json.loads(docker('image', 'inspect', image))[0]
        _require(image in inspected.get('RepoTags', []), 'candidate_image_tag_missing')
        builds[kind] = _build_evidence(kind, _regular(stage / ('build-' + kind + '.log'), stage), inspected)
        image_ids[kind] = inspected['Id']
    config = read_json(stage / 'worker/config.json')
    original_config = read_json(Path('/opt/regulai/worker/config.json'))
    _require(config == dict(original_config, template=TEMPLATE_ALIAS), 'prepared_worker_configuration_changed')
    for name in ('token', 'e2b-key'):
        _require(_regular(stage / 'worker' / name, stage) == (Path('/opt/regulai/worker') / name).read_bytes(),
                 'prepared_worker_credentials_changed')
    built_config = read_json(stage / 'worker/template.json')
    registry_digest = _regular(stage / 'image-manifest.sha256', stage).decode().strip()
    _require(re.fullmatch(r'[0-9a-f]{64}', registry_digest) is not None, 'registry_digest_invalid')
    _require(built_config == dict(config, api_url='http://127.0.0.1:3000', sandbox_url='http://127.0.0.1:3002',
             image='localhost:5000/task50-sheet@sha256:' + registry_digest), 'built_template_configuration_changed')
    template_log = _regular(stage / 'template-build.log', stage)
    _require(re.findall(rb'^Built spreadsheet template: ([a-z0-9]+)\r?$', template_log, re.M)
             == [TEMPLATE_ID.encode()], 'completed_template_identity_changed')
    previous_proof = read_json(stage / 'runtime/runtime.json')
    _require(previous_proof == {'verified': False, 'capabilities': {}}, 'runtime_proof_already_changed')
    clone = 'regulai_' + IDENTITY.replace('-', '_')
    parameters = {'stage': stage, 'image': images['web'], 'database': clone}
    before = read_json(stage / 'clone-invariants.json')
    clone_metadata = remote['require_idle'](**parameters)
    _require(clone_metadata['database']['basename'] == clone
             and all(name in clone_metadata['migrations'] for name in
                 ('0042_agent_artifact_metadata', '0043_p1_skills_and_events')), 'migrated_clone_required')
    remote['equal_fingerprints'](before, remote['web_exec']('fingerprint', payload=before, **parameters))
    backup_path = stage / 'before-prepare.dump'
    _require(backup_path.is_file() and not backup_path.is_symlink() and backup_path.stat().st_size > 0,
             'existing_backup_required')
    with backup_path.open('rb') as backup_stream:
        backup = {'file': backup_path.name, 'bytes': backup_path.stat().st_size,
                  'sha256': hashlib.file_digest(backup_stream, 'sha256').hexdigest()}

    # This is the only changed input to the already-built runtime. Keep source,
    # images, template and the prepared activation module byte-for-byte intact.
    probe_path = stage / 'runtime/p1_activation_probe.cjs'
    _require(_sha(_regular(probe_path, stage)) in {OLD_PROBE_SHA, PROBE_SHA}, 'runtime_probe_changed')
    temporary = stage / 'runtime/p1_activation_probe.cjs.continuation'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(probe_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, probe_path)
    proof = json.loads(docker('run', '--rm', '-i', '--network', 'regulai-v2-exec', '--user', '1000:1000',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--dns', '127.0.0.1',
        '--memory', '1024m', '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000',
        '--mount', f'type=bind,src={stage}/worker,dst=/run/task50,readonly',
        '--mount', f'type=bind,src={stage}/runtime,dst=/run/p1,readonly', images['worker'],
        'python', '-', data=code.encode(), timeout=300))
    _require(proof.get('verified') is True and proof.get('capabilities') == remote['CAPABILITY']
             and proof.get('helper_sha256') == hashes['regulai/front/agents/workspace_mutation.py']
             and proof.get('template') == TEMPLATE_ALIAS and proof.get('template_id') == TEMPLATE_ID
             and proof.get('provider_requests') == 0
             and proof.get('uid') == 1000 and proof.get('mutation_cas') is True
             and proof.get('run_hidden') is True and proof.get('egress_blocked') is True
             and proof.get('taste', {}).get('all_passed') is True
             and proof.get('taste', {}).get('node') == 'v24.21.0'
             and proof.get('taste', {}).get('provider_requests') == 0, 'runtime_proof_invalid')
    private_json(stage / 'runtime/runtime.json', proof)
    os.chmod(stage / 'runtime/runtime.json', 0o444)
    remote['equal_fingerprints'](before, remote['web_exec']('fingerprint', payload=before, **parameters))
    installation = remote['web_exec']('install', payload={'activation_id': IDENTITY}, **parameters)
    _require(installation.get('state') == 'installed', 'clone_installation_not_confirmed')
    remote['require_idle'](**parameters)
    # The explicit installation also writes its audit record in the clone.
    # Exact old-table fingerprints therefore apply up to that authorized write.
    live_unchanged()
    _require({kind: json.loads(docker('image', 'inspect', tag))[0]['Id']
              for kind, tag in images.items()} == image_ids, 'candidate_images_changed_during_probe')
    receipt = {'identity': IDENTITY, 'completed_at_unix': int(time.time()), 'template_alias': TEMPLATE_ALIAS,
        'template_id': TEMPLATE_ID, 'template_build_log_sha256': _sha(template_log), 'builds': builds,
        'prepared_remote_sha256': REMOTE_SHA, 'old_probe_sha256': OLD_PROBE_SHA, 'probe_sha256': PROBE_SHA,
        'probe_base_code_sha256': PROBE_CODE_SHA, 'probe_code_sha256': _sha(code.encode()),
        'template_id_verified_by_sdk': True, 'cloned_existing_data_unchanged_before_install': True,
        'builds_started': 0, 'templates_created': 0, 'real_database_writes': 0, 'provider_requests': 0}
    private_json(stage / 'continuation-receipt.json', receipt)
    state = {'identity': IDENTITY, 'phase': 'prepared', 'source_commit': COMMIT,
        'source_manifest_sha256': MANIFEST_SHA, 'original_identity': expected_identity,
        'images': images, 'image_ids': image_ids, 'clone_database': clone, 'backup': backup,
        'migration': {'applied': ['0042_agent_artifact_metadata', '0043_p1_skills_and_events'],
                      'verified_existing': True, 'executed_by_continuation': False},
        'runtime': proof, 'clone_installation': installation, 'provider_requests': 0,
        'original_metadata': metadata, 'continuation_receipt': receipt, 'probe_sha256': PROBE_SHA}
    private_json(stage / 'state.json.continuation', state)
    _require(not (stage / 'state.json').exists(), 'state_created_concurrently')
    os.replace(stage / 'state.json.continuation', stage / 'state.json')
    return state

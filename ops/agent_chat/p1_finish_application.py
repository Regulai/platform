"""Close the verified a2 application after its login health probe hit 429.

This performs read-only service/data/installation checks and publishes the
local activation receipt. It never migrates, installs or replaces services.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path

IDENTITY = 'p1-20261016-taste-a2'
WRAPPER_SHA = '4006b30ef759b98149fa0d0acd4e834f4fada94d85bd22060a5e8ebe4cfad8f9'
REPLACEMENTS = {
    'regulai-v2-web': '3ba89ccf96aae681ed6df8e6919220c2d7078b4265ea7bed7c732bbd1736325f',
    'regulai-v2-worker': '4db24e54101297114ab2a036fd16c20a0683b749f66b6aa7b3bb00ff5886fb36',
}


def finish(ns):
    stage = ns['stage_path'](IDENTITY)
    if os.geteuid() != 0 or stage != Path('/opt/regulai/updates') / IDENTITY:
        raise RuntimeError('owned_a2_stage_required')
    descriptor = os.open(stage / 'application-finalization.lock',
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = (stage / 'state.json').read_bytes()
        state = json.loads(raw)
        if state['phase'] != 'migrated' or not state['runtime']['verified']:
            raise RuntimeError('exact_post_apply_phase_required')
        if hashlib.sha256((stage / 'runtime/p1_activation_remote.py').read_bytes()).hexdigest() != WRAPPER_SHA:
            raise RuntimeError('prepared_runtime_wrapper_changed')
        original = ns['read_json'](stage / 'original-containers.json')
        for name, identity in REPLACEMENTS.items():
            new = ns['inspect'](name)
            old = ns['inspect'](name + '-before-' + IDENTITY)
            kind = 'web' if name.endswith('web') else 'worker'
            if (new['Id'] != identity or new['Image'] != state['image_ids'][kind]
                    or old['Id'] != original[name]['Id'] or old['State']['Running']):
                raise RuntimeError('replacement_or_rollback_identity_changed')
        if ns['inspect']('regulai-v2-postgres')['Id'] != original['regulai-v2-postgres']['Id']:
            raise RuntimeError('database_container_changed')
        if ns['private_configuration_digest']() != ns['read_json'](stage / 'original-configuration.json')['digest']:
            raise RuntimeError('private_configuration_changed')
        startup = ns['verify_started_services'](stage)
        parameters = {'stage': stage, 'image': state['images']['web'], 'database': 'regulai'}
        metadata = ns['require_idle'](**parameters)
        before = ns['read_json'](stage / 'real-before-invariants.json')
        script = ns['module_source']().replace("if __name__ == '__main__':\n    main()", '')
        script += '\n_before=' + repr(before) + '\n' + READ_ONLY_VERIFICATION
        proof = json.loads(ns['docker']('exec', '-i', 'regulai-v2-web', 'python', '-', data=script.encode()))
        if proof['tables_verified'] != len(before['tables']) or not proof['old_data_and_sequences_preserved']:
            raise RuntimeError('old_data_not_preserved')
        state.update(phase='applied', installation=proof['installation'],
            startup_verification=startup, final_metadata=metadata,
            applier_sha256=hashlib.sha256(ns['module_source']().encode()).hexdigest(),
            runtime_wrapper_sha256=WRAPPER_SHA,
            finalization={'reason': 'login_health_probe_rate_limited',
                          'health_url': '/static/js/skills.js', 'read_only_checks': proof,
                          'migrations_executed': 0, 'installations_executed': 0,
                          'service_replacements': 0, 'provider_requests': 0})
        if (stage / 'state.json').read_bytes() != raw:
            raise RuntimeError('activation_state_changed_during_finalization')
        ns['private_json'](stage / 'state.json.finalized', state)
        os.replace(stage / 'state.json.finalized', stage / 'state.json')
        return state
    finally:
        os.close(descriptor)


READ_ONLY_VERIFICATION = '''
settings=_configure('regulai')
from django.db import connection
from django.contrib.auth import get_user_model
from front.models import AgentSkillInstallation, AgentSkillInstallOperation
from front.agents import skills
quote=connection.ops.quote_name
audit_sequence='front_auditlog_id_seq'
audit_limit=_before['sequences'][audit_sequence] or 0
with connection.cursor() as cur:
 for table,names in sorted(_before['columns'].items()):
  fields=','.join(quote(name) for name in names)
  condition=' WHERE id <= %s' if table=='front_auditlog' else ''
  cur.execute('SELECT md5(row('+fields+')::text) FROM '+quote(table)+condition+' ORDER BY 1',
              [audit_limit] if condition else [])
  hashed,count=hashlib.sha256(),0
  while batch:=cur.fetchmany(1000):
   for row in batch:hashed.update(row[0].encode()+b'\\n');count+=1
  if {'count':count,'sha256':hashed.hexdigest()}!=_before['tables'][table]:
   raise RuntimeError('existing_table_changed:'+table)
 cur.execute("SELECT sequencename,last_value FROM pg_sequences WHERE schemaname='public'")
 sequences=dict(cur.fetchall())
 for name,value in _before['sequences'].items():
  if name!=audit_sequence and sequences.get(name)!=value:raise RuntimeError('existing_sequence_changed')
 cur.execute('SELECT action,count(*) FROM front_auditlog WHERE id > %s GROUP BY action',[audit_limit])
 audit_added=dict(cur.fetchall())
 if set(audit_added)-{'skill_install','rate_limit_exceeded'} or audit_added.get('skill_install')!=1:
  raise RuntimeError('unexpected_activation_audit_entries')
actor=get_user_model().objects.get(pk=settings.PLATFORM_ADMIN_USER_IDS[0],is_active=True)
entry=skills.candidate('design-taste-frontend')
row=AgentSkillInstallation.objects.select_related('current_revision').get(
 owner=actor,source_identity=entry['source_identity'],tombstoned_at__isnull=True)
_,profile=skills.actor_profile(actor)
view=skills.installation_view(row,profile)
if not view['enabled'] or not view['availability']['available']:
 raise RuntimeError('installed_taste_not_available')
if row.current_revision.folder_sha256!='b228fa2bd82974a046563b8d550c9e54b7f5a91cd5b194dd2c82dc806af75954':
 raise RuntimeError('installed_taste_revision_changed')
operation=AgentSkillInstallOperation.objects.get(pk=uuid.uuid5(uuid.NAMESPACE_URL,
 'regulai-v2:design-taste-frontend:p1-20261016-taste-a2'),owner=actor)
if operation.state!='installed' or operation.result_revision_id!=row.current_revision_id:
 raise RuntimeError('installation_operation_not_complete')
print(json.dumps({'tables_verified':len(_before['tables']),
 'rows_preserved':sum(x['count'] for x in _before['tables'].values()),
 'old_data_and_sequences_preserved':True,'new_audit_actions':audit_added,
 'installation':{'state':'installed','installation_id':str(row.pk),
 'revision_id':str(row.current_revision_id),'enabled':True,'available':True,
 'folder_sha256':row.current_revision.folder_sha256},'provider_requests':0}))
'''

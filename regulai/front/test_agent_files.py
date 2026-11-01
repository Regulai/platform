"""E2/E4 focused contracts: bytes, coverage, revisions, access and retention."""
import base64
from datetime import timedelta
import io
import json
import socket
import stat
import struct
import uuid
import zipfile
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from front.agents import file_continuity as files, professional_artifacts
from front.agents.artifact_formats import inspect_file, inspect_input, local_dependencies, safe_filename
from front.agents.capabilities import GENERAL
from front.agents.request_contract import interpret, delivery_problems
from front.agents.service import AgentDenied, _context
from front.models import AgentAccessGrant, AgentArtifact, AgentExecution, AgentInput, AgentInference, Conversation, Prompt, Rule, RulesGroup
from front.policy import digest
from front.test_agent_inference import AgentFixture
from front import test_agent_professional as professional_tests


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for name, raw in entries:
            zipped.writestr(name, raw)
    return output.getvalue()


class FormatTests(SimpleTestCase):
    def test_request_contract_actions_and_counterexamples(self):
        for text, expected in [('Crea un HTML de Madrid', 'html'), ('Crea una landing', 'html'),
                ('Genera un CSV', 'csv'), ('Crea un ZIP', 'zip'), ('Haz un CSS', 'css')]:
            with self.subTest(text=text):
                result = interpret(text, general=True)
                self.assertTrue(result['delivery_required'])
                self.assertEqual(result['formats'], [expected])
                self.assertEqual(result['operation'], 'create')
        for text in ('Explícame qué es HTML', '¿Qué es un ZIP?', 'Describe un CSV', 'Calcula 3 + 4'):
            self.assertFalse(interpret(text, general=True)['delivery_required'], text)
        self.assertTrue(interpret('Genera un archivo', general=True)['delivery_required'])
        self.assertEqual(interpret('Dámelo', general=True)['operation'], 'download')
        self.assertEqual(interpret('Cambia el color', general=True)['operation'], 'edit')
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            interpret('Crea un archivo malware.exe', general=True)
        self.assertIn('delivery_artifact_required', delivery_problems(interpret('Genera un archivo', general=True), []))

    def test_html_svg_include_full_source_without_execution(self):
        raw = b'<html><!-- secret --><script>fetch("https://remote.invalid")</script><p data-key="private">Madrid</p></html>'
        proof, text, _ = inspect_file(raw, 'html')
        self.assertEqual(text.encode(), raw)
        self.assertIn('private', text)
        self.assertEqual(proof['coverage']['status'], 'complete')
        self.assertEqual(inspect_input(raw, 'htm')['format'], 'html')
        with self.assertRaisesRegex(ValueError, 'xml_entities'):
            inspect_file(b'<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>', 'svg')
        proof, _, _ = inspect_file(b'<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA"/></svg>', 'svg')
        self.assertEqual(proof['coverage']['status'], 'partial')

    def test_zip_all_members_bounded_and_inspected(self):
        raw = archive([('index.html', b'<html><link href="styles.css"><img src="icon.svg"></html>'),
            ('styles.css', b'body { color: red; }'), ('icon.svg', b'<svg xmlns="http://www.w3.org/2000/svg"/>')])
        proof, text, _ = inspect_file(raw, 'zip')
        self.assertEqual(len(proof['members']), 3)
        self.assertIn('color: red', text)
        self.assertTrue(all(len(item['sha256']) == 64 for item in proof['members']))

    def test_zip_rejects_unsafe_paths_types_collisions_and_expansion(self):
        cases = [[('../a.txt', b'a')], [('/a.txt', b'a')], [('C:/a.txt', b'a')], [('a\\b.txt', b'a')],
            [('a.txt', b'a'), ('A.TXT', b'b')], [('a', b'a'), ('a/b.txt', b'b')],
            [('a/b.txt', b'a'), ('a', b'b')], [('nested.zip', archive([('x.txt', b'x')]))],
            [('image.png', b'opaque')], [('run.exe', b'opaque')], [('x.txt', b'a' * 100000)],
            [('a/' * 17 + 'x.txt', b'x')], [('e\u0301.txt', b'a'), ('é.txt', b'b')]]
        for entries in cases:
            with self.subTest(entries=[str(item[0]) for item in entries]), self.assertRaises((ValueError, OSError)):
                zipped = archive(entries)
                # Windows ZipInfo normalizes backslashes while constructing a fixture;
                # malicious archives arriving from elsewhere can retain them on the wire.
                if entries[0][0] == 'a\\b.txt':
                    zipped = zipped.replace(b'a/b.txt', b'a\\b.txt')
                inspect_file(zipped, 'zip')
        link = zipfile.ZipInfo('link.txt')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, 'entry_denied'):
            inspect_file(archive([(link, b'target.txt')]), 'zip')
        with self.assertRaisesRegex(ValueError, 'archive_limit'):
            inspect_file(archive([(f'{n}.txt', b'x') for n in range(201)]), 'zip')

    def test_static_dependencies_and_safe_unicode_names(self):
        raw = b'<link href="style.css"><img src="icon.svg"><script src="https://remote.invalid/x.js"></script>'
        proof = local_dependencies(raw, 'html', 'output/index.html', ['output/style.css', 'output/icon.svg'])
        self.assertEqual(proof['local_paths'], ['output/icon.svg', 'output/style.css'])
        self.assertEqual(proof['dynamic_resources'], 'not_inferred')
        with self.assertRaisesRegex(ValueError, 'dependency_missing'):
            local_dependencies(raw, 'html', 'output/index.html', [])
        with self.assertRaisesRegex(ValueError, 'path_denied'):
            local_dependencies(b'<link href="../secret.css">', 'html', 'output/index.html', ['secret.css'])
        self.assertEqual(safe_filename('/workspace/output/Madrid "azul"\r\n.htm', 'htm'), 'Madrid "azul".html')

    def test_zip_encryption_crc_and_embedded_coverage_fail_closed(self):
        raw = archive([('x.txt', b'synthetic fixture content')])
        encrypted = bytearray(raw)
        local = encrypted.index(b'PK\x03\x04')
        central = encrypted.index(b'PK\x01\x02')
        struct.pack_into('<H', encrypted, local + 6, struct.unpack_from('<H', encrypted, local + 6)[0] | 1)
        struct.pack_into('<H', encrypted, central + 8, struct.unpack_from('<H', encrypted, central + 8)[0] | 1)
        with self.assertRaisesRegex(ValueError, 'entry_denied'):
            inspect_file(bytes(encrypted), 'zip')
        corrupt = bytearray(raw)
        struct.pack_into('<I', corrupt, central + 16, 0)
        with self.assertRaises(zipfile.BadZipFile):
            inspect_file(bytes(corrupt), 'zip')
        with self.assertRaisesRegex(ValueError, 'coverage_incomplete'):
            inspect_file(archive([('index.html', b'<img src="data:image/png;base64,AAAA">')]), 'zip')


class FileFixture(AgentFixture):
    queued = professional_tests.ProfessionalTests.queued
    activate = professional_tests.ProfessionalTests.activate
    issue = professional_tests.ProfessionalTests.issue
    finish = professional_tests.ProfessionalTests.finish

    def setUp(self):
        super().setUp()
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('Unexpected network')))
        self.agent.professional, self.agent.tools = True, sorted(GENERAL)
        self.agent.save()
        self.grant = AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.client.force_login(self.user)

    def make_artifact(self, run=None, raw=b'<html>Madrid</html>', path='output/madrid.html', purpose='deliverable', base=None):
        run = run or self.queued('Crea un HTML de Madrid')
        proof, _, _ = inspect_file(raw, path.rsplit('.', 1)[1])
        artifact = files.persist_revision(run, path, raw, proof, purpose=purpose,
            status='verified' if purpose == 'deliverable' else 'draft', base=base)
        files.write_manifest(run, [(artifact, path, [])])
        if purpose == 'deliverable':
            run.prompt.refresh_from_db()
            run.prompt.decision['delivery'] = {'status': 'complete', 'artifacts': [{'artifact_id': str(artifact.pk), 'sha256': artifact.sha256}]}
            run.prompt.save(update_fields=['decision'])
        run.status, run.finished_at = 'completed', timezone.now()
        run.save(update_fields=['status', 'finished_at'])
        return artifact


@override_settings(REGULAY_AGENT_ENABLED=True, DEBUG=False)
class ContinuityTests(FileFixture, TestCase):
    def test_revision_replay_promotion_and_immutable_bytes(self):
        run = self.queued('Crea un HTML de Madrid')
        first = self.make_artifact(run, purpose='working')
        promoted = self.make_artifact(run)
        self.assertEqual(first.pk, promoted.pk)
        self.assertEqual(AgentArtifact.objects.filter(execution=run).count(), 1)
        run2 = self.queued('Crea un HTML de Madrid')
        # Synthetic same conversation for the focused revision invariant.
        run2.conversation = run.conversation
        run2.save(update_fields=['conversation'])
        edited = self.make_artifact(run2, raw=b'<html style="color:blue">Madrid</html>', base=promoted)
        self.assertEqual(edited.base_id, promoted.pk)
        self.assertEqual(edited.logical_id, promoted.logical_id)
        self.assertEqual(edited.revision, 2)
        promoted.refresh_from_db()
        self.assertEqual(base64.b64decode(promoted.content), b'<html>Madrid</html>')
        self.assertEqual(files.expires_at(promoted), files.expires_at(edited))

    def test_authorization_reference_resolution_and_working_is_private(self):
        artifact = self.make_artifact()
        raw = files.authorize_artifact(self.user, artifact.pk)[1]
        self.assertEqual(raw, b'<html>Madrid</html>')
        self.assertEqual(files.resolve_reference(self.user, artifact.execution.conversation, {}, 'Dámelo').pk, artifact.pk)
        other = Conversation.objects.create(user=self.user, mode='agent')
        with self.assertRaisesRegex(AgentDenied, 'not_found'):
            files.authorize_artifact(self.user, artifact.pk, conversation=other)
        artifact.verification['purpose'] = 'working'
        artifact.save(update_fields=['verification'])
        with self.assertRaisesRegex(AgentDenied, 'not_delivered'):
            files.authorize_artifact(self.user, artifact.pk)
        self.grant.enabled = False
        self.grant.save(update_fields=['enabled'])
        with self.assertRaises(AgentDenied):
            files.authorize_artifact(self.user, artifact.pk, deliverable=False)

    def test_policy_reads_attributes_and_comments_and_rejects_blocked(self):
        artifact = self.make_artifact(raw=b'<html><!-- INTERNAL_SECRET --></html>')
        group = RulesGroup.objects.create(name='Files', company=self.company)
        Rule.objects.create(name='Secret', rules_group=group, action='block',
            yara_rule='rule Secret { strings: $x = "INTERNAL_SECRET" condition: $x }')
        with self.assertRaisesRegex(AgentDenied, 'policy_denied'):
            files.authorize_artifact(self.user, artifact.pk)

    def test_restore_exact_selected_set_after_new_run_and_expiry(self):
        base = self.make_artifact(raw=b'<link href="style.css">Madrid')
        origin = base.execution
        proof, _, _ = inspect_file(b'body {color:red}', 'css')
        dependency = files.persist_revision(origin, 'output/style.css', b'body {color:red}', proof)
        files.write_manifest(origin, [(base, 'output/madrid.html', [(dependency, 'output/style.css')]),
            (dependency, 'output/style.css', [])])
        # A later unrelated capture must not change the base's immutable set.
        other = files.persist_revision(origin, 'work/script.py', b'print(1)', inspect_file(b'print(1)', 'py')[0])
        files.write_manifest(origin, [(other, 'work/script.py', [])])
        run = self.queued('Crea un HTML de Madrid')
        run.conversation = origin.conversation
        run.prompt.conversation = origin.conversation
        run.prompt.save(update_fields=['conversation'])
        run.job['base'] = str(base.pk)
        run.save()
        context = _context(run.prompt, run.profile_id)
        self.assertEqual(files.bind_references(run, base, context), 2)
        run = AgentExecution.objects.get(pk=run.pk)
        restored = files.restore_references(run, _context(run.prompt, run.profile_id))
        self.assertEqual(len(restored), 2)
        self.assertEqual({entry['sha256'] for entry in restored}, {base.sha256, dependency.sha256})
        self.assertTrue(all('/workspace/input/refs/' in entry['path'] for entry in restored))
        self.assertNotIn('madrid.html', json.dumps(run.job))
        dependency.verification['origin_expires_at'] = (timezone.now() - timedelta(seconds=1)).isoformat()
        dependency.save(update_fields=['verification'])
        with self.assertRaisesRegex(AgentDenied, 'expired'):
            files.restore_references(run, context)

    def test_selective_checkpoint_import_is_idempotent_without_inference(self):
        run = self.queued('Crea un HTML de Madrid')
        run.status, run.finished_at = 'failed', timezone.now()
        packed = json.dumps({'archive': base64.b64encode(archive([
            ('output/madrid_landing.html', b'<html>Madrid</html>'), ('output/other.txt', b'not imported')])).decode(),
            'messages': ['untrusted not read'], 'watermark': {'old': True}})
        checkpoint = AgentInput.objects.create(execution=run, kind='checkpoint', path='checkpoint/latest', original=packed, digest=digest(packed))
        run.job['checkpoint'] = str(checkpoint.pk)
        run.save()
        before = AgentInference.objects.count()
        preview = files.recover_member(self.user, run, 'output/madrid_landing.html')
        self.assertNotIn('artifact_id', preview)
        first = files.recover_member(self.user, run, 'output/madrid_landing.html', apply=True)
        second = files.recover_member(self.user, run, 'output/madrid_landing.html', apply=True)
        self.assertEqual(first['artifact_id'], second['artifact_id'])
        self.assertEqual(run.artifacts.count(), 1)
        self.assertEqual(AgentInference.objects.count(), before)
        self.assertEqual(files.authorize_artifact(self.user, first['artifact_id'])[1], b'<html>Madrid</html>')
        self.assertEqual(self.requests, [])

    def test_purge_erases_inherited_bytes_names_and_extracts_preserving_lineage(self):
        base = self.make_artifact()
        child_run = self.queued('Crea HTML')
        child_run.conversation = base.execution.conversation
        child_run.save(update_fields=['conversation'])
        child = self.make_artifact(child_run, raw=b'<html>Madrid azul</html>', base=base)
        deadline = (timezone.now() - timedelta(days=1)).isoformat()
        for item in (base, child):
            item.verification['origin_expires_at'] = deadline
            item.save(update_fields=['verification'])
        extract = AgentInput.objects.create(execution=child_run, kind='policy_text', path='policy/old',
            original=json.dumps({'artifact_id': str(base.pk), 'text': 'Madrid'}), digest='a' * 64)
        AgentExecution.objects.filter(pk=base.execution_id).update(finished_at=timezone.now() - timedelta(days=31))
        inference = AgentInference.objects.create(execution=base.execution, call_id=uuid.uuid4(), attempt=base.execution.attempt,
            request_digest='a' * 64, status='outcome_unknown', response={'content': 'private original',
                '_capacity': {'status': 'uncertain', 'destination': 'synthetic-digest'}})
        call_command('purge_agent_data', apply=True, stdout=io.StringIO())
        base.refresh_from_db(); child.refresh_from_db(); extract.refresh_from_db()
        inference.refresh_from_db()
        self.assertEqual(inference.response, {'_capacity': {'status': 'uncertain', 'destination': 'synthetic-digest'}})
        self.assertEqual((base.content, child.content, child.filename, extract.original), ('', '', '', ''))
        self.assertEqual(child.base_id, base.pk)
        self.assertEqual(child.sha256, child.verification['sha256'])

    def test_publish_html_metadata_and_draft_promotion(self):
        self.activate(self.queued('Crea un HTML de Madrid'))
        raw = b'<html>Madrid</html>'
        proof, _, _ = inspect_file(raw, 'html')
        draft = files.persist_revision(self.execution, '/workspace/output/madrid.html', raw, proof)
        call = self.issue('publish_artifact', {'file_path': '/workspace/output/madrid.html', 'title': 'Madrid'})
        result = professional_artifacts.candidate(self.token, self.execution.attempt,
            {'call': call, 'files': {'/workspace/output/madrid.html': base64.b64encode(raw).decode()}})
        self.assertEqual(result['reference'], str(draft.pk))
        artifact = AgentArtifact.objects.get(pk=result['reference'])
        self.assertEqual(artifact.filename, 'madrid.html')
        self.assertEqual(artifact.size_bytes, len(raw))
        self.assertEqual(artifact.verification['purpose'], 'deliverable')
        self.assertEqual(professional_artifacts.candidate(self.token, self.execution.attempt,
            {'call': call, 'files': {'/workspace/output/madrid.html': base64.b64encode(raw).decode()}}), result)
        with self.assertRaisesRegex(AgentDenied, 'publication_conflict'):
            professional_artifacts.candidate(self.token, self.execution.attempt,
                {'call': call, 'files': {'/workspace/output/madrid.html': base64.b64encode(b'<html>changed</html>').decode()}})
        self.assertEqual(self.execution.artifacts.count(), 1)


@override_settings(REGULAY_AGENT_ENABLED=True, DEBUG=False)
class MetadataMigrationTests(FileFixture, TransactionTestCase):
    def test_additive_migration_preserves_old_bytes_and_grants(self):
        artifact = self.make_artifact()
        artifact_id, sha, content, source_id, owner_id = artifact.pk, artifact.sha256, artifact.content, str(artifact.source_id), self.user.pk
        executor = MigrationExecutor(connection)
        executor.migrate([('front', '0041_agent_professional')])
        old_apps = executor.loader.project_state([('front', '0041_agent_professional')]).apps
        old = old_apps.get_model('front', 'AgentArtifact').objects.get(pk=artifact_id)
        self.assertEqual((old.sha256, old.content, str(old.source_id)), (sha, content, source_id))
        try:
            MigrationExecutor(connection).migrate([('front', '0042_agent_artifact_metadata')])
            restored = AgentArtifact.objects.get(pk=artifact_id)
            self.assertEqual((restored.sha256, restored.content, str(restored.source_id)), (sha, content, source_id))
            self.assertIsNone(restored.size_bytes)
            self.assertEqual(restored.filename, '')
            self.assertEqual(AgentAccessGrant.objects.get(user_id=owner_id).enabled, True)
        finally:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())

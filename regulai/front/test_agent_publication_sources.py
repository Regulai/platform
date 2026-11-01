"""Keep uploaded-input provenance separate from opened web evidence IDs."""
import base64
import hashlib
import json

from django.core.files.uploadedfile import SimpleUploadedFile

from front import test_agent_professional as fixtures
from front.agents import professional_artifacts
from front.agents.protocol import tool_schema
from front.agents.service import AgentDenied
from front.models import AgentArtifact, AgentInput


class PublicationSourcesTests(fixtures.ProfessionalTests):
    def test_uploaded_input_publishes_without_web_sources_and_retains_provenance(self):
        raw = b'region,net_revenue_eur\nNorte,110.00\nSur,130.00\nEste,16.00\n'
        run = self.activate(self.queued('Analiza el adjunto y crea resumen.csv con una fila TOTAL.',
            file=SimpleUploadedFile('sales.csv', raw)))
        output = raw + b'TOTAL,256.00\n'
        path = '/workspace/output/resumen.csv'
        call = self.issue('publish_artifact', {'file_path': path, 'title': 'Ingresos netos'})
        payload = {'call': call, 'files': {path: base64.b64encode(output).decode()}}
        result = professional_artifacts.candidate(self.token, run.attempt, payload)
        artifact = AgentArtifact.objects.select_related('source').get(pk=result['reference'])
        self.assertEqual(artifact.verification['source_ids'], [])
        self.assertEqual(json.loads(artifact.source.original)['input_sha256'], hashlib.sha256(raw).hexdigest())
        source = AgentInput.objects.get(pk=run.job['source'], execution=run, kind='private_file')
        self.assertEqual(base64.b64decode(source.original), raw)
        self.assertEqual(source.digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(professional_artifacts.candidate(self.token, run.attempt, payload)['reference'], str(artifact.pk))
        self.assertEqual(AgentArtifact.objects.filter(execution=run, status='verified').count(), 1)

    def test_unopened_web_source_and_local_path_are_not_web_evidence(self):
        run = self.activate(self.queued('Crea resumen.csv.', file=SimpleUploadedFile('sales.csv', b'a,b\n1,2\n')))
        path = '/workspace/output/resumen.csv'
        for source in ('web-unopened', '/workspace/input/source.csv'):
            with self.subTest(source=source):
                call = self.issue('publish_artifact', {'file_path': path, 'title': 'Resumen', 'sources': [source]})
                with self.assertRaisesRegex(AgentDenied, 'artifact_source_not_opened'):
                    professional_artifacts.candidate(self.token, run.attempt,
                        {'call': call, 'files': {path: base64.b64encode(b'a,b\n1,2\n').decode()}})
                self.finish(call, 'artifact_source_not_opened', failed=True)
        self.assertFalse(AgentArtifact.objects.filter(execution=run).exists())
        description = tool_schema('publish_artifact')['function']['parameters']['properties']['sources']['description']
        self.assertIn('uploaded inputs', description)
        self.assertIn('never file paths', description)


# Reuse only the fixture helpers, without rediscovering the prior delivery suite.
for _name in dir(fixtures.ProfessionalTests):
    if _name.startswith('test_') and _name not in PublicationSourcesTests.__dict__:
        setattr(PublicationSourcesTests, _name, None)

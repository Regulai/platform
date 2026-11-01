"""Regressions observed before provider dispatch in the ten-conversation corpus."""
import io
import uuid
import zipfile

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings

from front.agents.capabilities import GENERAL
from front.agents.request_contract import interpret
from front.models import AgentAccessGrant, AgentExecution, AgentInference
from front.test_agent_inference import AgentFixture


PACKAGE_EDIT = ('Modifica el paquete adjunto: cambia solamente el fondo del botón a #147d45. '
    'Genera un ZIP con la estructura y los nombres originales. Conserva el título, el texto y la imagen.')
RECONCILE = ('Reconcílialo todo con el ZIP adjunto, que contiene orders.csv y reconciliation.json. '
    'Lee ambos archivos. Elimina duplicados idénticos, excluye cancelados de ventas y cobros válidos, '
    'y no elijas arbitrariamente un importe contradictorio. Indica ventas y cobros válidos que sí son ciertos, '
    'saldo pendiente cierto y errores detectados. Separa lo que no puedes resolver. '
    'Responde breve, sin crear archivos.')
UPDATE_TOTALS = ('Confirmo que el importe correcto de O5 es 40,00 EUR y que no tiene ningún cobro. '
    'Actualiza las ventas válidas totales y el saldo pendiente total. No cambies ninguna otra regla.')


def upload():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('orders.csv', 'id,amount\nO5,40.00\n')
        archive.writestr('reconciliation.json', '{"payments": []}')
    return SimpleUploadedFile('inputs.zip', stream.getvalue(), content_type='application/zip')


class RequestIntentTests(SimpleTestCase):
    def test_negated_format_aliases_do_not_become_required_outputs(self):
        original = ('Crea un HTML autónomo llamado nebula.html para el evento ficticio Nébula. '
            'Debe mostrar Bilbao, sábado 18:30 y un botón Reservar con fondo #2457d6. '
            'Todo el estilo dentro del archivo, sin JavaScript ni recursos externos.')
        for text, expected in (
                (original, {'html'}),
                ('Crea HTML sin JS.', {'html'}),
                ('Crea HTML sin JavaScript ni CSS.', {'html'}),
                ('Crea HTML sin CSS ni Python.', {'html'}),
                ('Create HTML without JavaScript or CSS.', {'html'}),
                ('Crea un Word, no PDF.', {'docx'}),
                ('Crea PDF sin Word.', {'pdf'}),
                ('Crea HTML sin CSS pero con JS.', {'html', 'js'}),
                ('Crea HTML y CSS.', {'html', 'css'})):
            with self.subTest(text=text):
                request = interpret(text, general=True)
                self.assertEqual(set(request['formats']), expected)
                self.assertEqual(set(request['requirements']['formats']), expected)
                self.assertTrue(request['delivery_required'])
        self.assertEqual(interpret('Crea un Word, no PDF.')['formats'], ['docx'])

    def test_source_formats_do_not_override_no_file_delivery(self):
        request = interpret(RECONCILE, uploaded=True, general=True)
        self.assertEqual(request['operation'], 'chat')
        self.assertEqual(request['formats'], [])
        self.assertFalse(request['delivery_required'])
        self.assertEqual(request['requirements']['minimum_files'], 0)

    def test_update_numbers_is_chat_but_visual_file_edit_remains_edit(self):
        self.assertEqual(interpret(UPDATE_TOTALS, general=True)['operation'], 'chat')
        self.assertEqual(interpret('Cambia el color a azul', general=True)['operation'], 'edit')
        self.assertEqual(interpret('Actualiza el CSV con los totales', general=True)['operation'], 'edit')
        self.assertEqual(interpret('Dámelo', general=True)['operation'], 'download')

    def test_uploaded_edit_does_not_require_a_published_revision(self):
        request = interpret(PACKAGE_EDIT, uploaded=True, general=True)
        self.assertEqual(request['operation'], 'edit')
        self.assertEqual(request['formats'], ['zip'])
        self.assertTrue(request['delivery_required'])
        self.assertEqual(request['ambiguities'], [])


@override_settings(REGULAY_AGENT_ENABLED=True)
class InputEntryTests(AgentFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.professional = True
        self.agent.tools = sorted(GENERAL)
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.client.force_login(self.user)

    def send(self, text, *, url='/chat/', file=None, identity=None):
        identity = str(identity or uuid.uuid4())
        payload = {'content': text, 'prompt': text, 'mode': 'agent', 'request_id': identity}
        if file:
            payload['file'] = file
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 202, response.content)
        return AgentExecution.objects.get(prompt__request_id=identity)

    def test_uploaded_edit_and_idempotency_at_three_http_entries(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(url=url):
                identity = uuid.uuid4()
                run = self.send(PACKAGE_EDIT, url=url, file=upload(), identity=identity)
                duplicate = self.send(PACKAGE_EDIT, url=url, file=upload(), identity=identity)
                self.assertEqual(run.pk, duplicate.pk)
                self.assertEqual(run.job['request']['formats'], ['zip'])
                self.assertIsNone(run.job['base'])
                self.assertTrue(run.job['source'])
                self.assertEqual(run.job['request']['ambiguities'], [])
        self.assertEqual(AgentInference.objects.count(), 0)
        self.assertEqual(self.requests, [])

    def test_analysis_then_update_does_not_require_a_prior_artifact(self):
        run = self.send(RECONCILE, file=upload())
        self.assertFalse(run.job['request']['delivery_required'])
        self.assertEqual(run.job['request']['formats'], [])
        # Reproduce the observed failed preflight without fabricating a model reply.
        run.status = 'failed'
        run.save(update_fields=['status'])
        followup = self.send(UPDATE_TOTALS, url=f'/chat/{run.conversation_id}/send/')
        self.assertEqual(followup.job['request']['operation'], 'chat')
        self.assertFalse(followup.job['request']['delivery_required'])
        self.assertEqual(AgentInference.objects.count(), 0)
        self.assertEqual(self.requests, [])

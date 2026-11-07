"""The chat page's scripts against rendered pages and synthetic server replies (offline).

Every check runs the real templates and the real chat-markdown.js, chat.js and
agent-chat.js in front/offline_browser.cjs; the network is scripted per test.
"""
import json
import uuid

from django.test import SimpleTestCase, override_settings

from front import test_pipeline, test_pipeline_privacy
from front.models import Conversation, EngineModel, Message, Prompt
from front.offline_browser import OfflineBrowser
from front.test_chat_flow import ChatFixture
from front.test_chat_streaming import parse_sse

# A turn appended to the rendered log, as chat.js builds one for a new command.
TURN = r"""
const turnFor = (requestId, command = {}) => {
  const turn = document.createElement('article'), ai = document.createElement('div');
  turn.className = 'rg-turn';
  turn.dataset.requestId = requestId;
  ai.className = 'rg-msg rg-msg-ai';
  turn.appendChild(ai);
  $('#chatContainer').appendChild(turn);
  return regulayChat.createLive({turn, ai}, {requestId, ...command});
};
const openDetails = async live => {
  await click($('[data-action=details]', live.ai));
  return $('.rg-receipt', live.ai);
};
const buttonNamed = (name, root = document) => $$('button', root).find(item => item.textContent.trim() === name);
const completed = (requestId, content, extra = {}) => ({status: 'completed', success: true, request_id: requestId,
  receipt: {verification: {status: 'passed'}, calls: []}, assistant_message: {content}, ...extra});
"""


class ChatPageScriptTests(OfflineBrowser, ChatFixture):
    def chat(self, checks, path='/chat/', **options):
        return self.browse(TURN + checks, self.client.get(path), **options)

    def test_reading_above_counts_updated_messages_once_and_returning_clears_count(self):
        self.chat(r'''
const scroller=$('#chatScroll'),jump=$('#jumpToEnd');
scroller.scrollHeight=5000;scroller.clientHeight=500;scroller.scrollTop=400;
scroller.dispatchEvent(new Event('scroll'));
regulayChat.follow('request-one');regulayChat.follow('request-one');regulayChat.follow();
assert.equal(scroller.scrollTop,400);
assert.equal(jump.hidden,false);
assert.match(text(jump),/1 mensaje actualizado/);
regulayChat.follow('request-two');
assert.match(text(jump),/2 mensajes actualizados/);
await click(jump);
assert.equal(jump.hidden,true);
assert.equal(text($('.rg-jump-count',jump)),'');
regulayChat.follow('request-three');
assert.equal(text($('.rg-jump-count',jump)),'');
''')

    def test_historical_receipt_explains_judge_rejection_without_candidate_text(self):
        self.chat(r"""
const output = document.createElement('div');
regulayChat.renderReceipt(output, {verification: {status: 'failed'}, calls: [{purpose: 'verification', status: 'completed', threshold: 0.8,
  signals: {failure_omission: {type: 'noul', noul: 0.2}, failure_contradiction: {type: 'noul', noul: 0.72}}}]}, 'failed');
assert.match(text(output), /Verificación\nEstado\nNo superada/);
assert.match(text(output), /Señal de Jev · contradicción o afirmación sin respaldo\n0\.72/);
assert.match(text(output), /Umbral máximo de fallo admitido\n0\.2/);
""")

    def test_provider_limits_receipt_explains_null_limits(self):
        self.chat(r"""
const output = document.createElement('div');
regulayChat.renderReceipt(output, {limits: {provider_managed: true, response_bytes: null,
  max_output_tokens: null, call_timeout_seconds: null, deadline_seconds: null}}, 'completed');
assert.match(text(output), /Límites de generación\nGestionados por el proveedor/);
assert.doesNotMatch(text(output), /Límite de respuesta|Límite de salida|Tiempo máximo por llamada|Plazo de la petición|null/);
""")

    def test_answer_text_and_file_names_are_never_parsed_as_markup(self):
        self.chat(r"""
const live = turnFor('markup', {prompt: 'Genera un script'});
regulayChat.renderOutcome(live, completed('markup', '<img src=x onerror=alert(1)> **bien** <script>alert(2)</script>',
  {assistant_message: {content: '<img src=x onerror=alert(1)> **bien**', file_name: 'a"b\'<c>.py', file_url: '/chat/download/7/', file_size: 3}}));
assert.equal($$('img, script', live.ai).length, 0);
assert.match(text(live.ai), /<img src=x onerror=alert\(1\)> bien/);
const link = $('a.rg-file-chip', live.ai);
assert.equal(link.getAttribute('download'), 'a"b\'<c>.py');
assert.equal(link.getAttribute('href'), '/chat/download/7/');
for (const url of ['javascript:alert(1)', 'https://outside.invalid/chat/download/7/', '/chat/download/7/?x=1']) {
  const other = turnFor('markup-' + url.length, {prompt: 'x'});
  regulayChat.renderOutcome(other, completed('markup', 'Hecho', {assistant_message: {content: 'Hecho', file_name: 'x.py', file_url: url}}));
  assert.equal($('a.rg-file-chip', other.ai), null, url);
}
""")

    def test_finished_receipt_does_not_request_confirmation_for_historical_reason(self):
        self.chat(r"""
for (const status of ['completed', 'cancelled', 'blocked', 'failed', 'outcome_unknown']) {
  for (const reason of ['consent_expired', 'consent_context_changed']) {
    const output = document.createElement('div');
    regulayChat.renderReceipt(output, {consent_reason: reason}, status);
    assert.match(text(output), /Aviso de confirmación anterior\n/);
    assert.doesNotMatch(text(output), /confirma de nuevo|Revísal/i);
  }
}
const pending = document.createElement('div');
regulayChat.renderReceipt(pending, {consent_reason: 'consent_expired'}, 'pending_consent');
assert.match(text(pending), /Confirmación\nLa confirmación caducó\. Revísala y confirma de nuevo\./);
""")

    def test_unknown_outcome_without_total_never_renders_zero_cost_or_success(self):
        self.chat(r"""
const live = turnFor('synthetic-interrupted', {prompt: 'Resume'});
regulayChat.renderOutcome(live, {status: 'outcome_unknown', success: false, request_id: 'synthetic-interrupted', error_type: 'outcome_unknown',
  error: 'No se pudo confirmar el resultado del proveedor.', receipt: {calls: [{purpose: 'generation', status: 'started', provider: 'engine:1', cost: null}]}});
assert.equal($('.rg-md', live.ai), null);
assert.match(text(live.ai), /Resultado desconocido\nNo se pudo confirmar el resultado del proveedor\./);
assert.ok(buttonNamed('Comprobar estado', live.ai));
assert.ok(buttonNamed('Volver a enviar', live.ai));
const receipt = text(await openDetails(live));
assert.match(receipt, /Estado\nResultado desconocido/);
assert.match(receipt, /Llamada 1\nGeneración · iniciada, sin resultado · engine:1\nCoste\nNo disponible/);
assert.match(receipt, /Coste total\nNo disponible/);
assert.doesNotMatch(receipt, /Coste total\n0|Superada|Completada/);
const legacy = document.createElement('div');
regulayChat.renderReceipt(legacy, {policy: {status: 'allow'}}, 'completed');
assert.match(text(legacy), /Coste total\nNo disponible/);
const blocked = document.createElement('div');
regulayChat.renderReceipt(blocked, {policy: {status: 'block'}, calls: []}, 'blocked');
assert.match(text(blocked), /Coste total\n0 \(sin llamadas\)/);
""")

    def test_escalated_destination_survives_send_export_and_history_restore(self):
        test_pipeline.PipelineTests.configure(self)
        first = self.send('/api/chat/send/', 'Previous synthetic turn').json()
        self.assertEqual(first['status'], 'completed')
        other = test_pipeline_privacy.PipelinePrivacyTests.fallback(self, cross_engine=True, allow=True)
        EngineModel.objects.filter(engine=other.engine).update(model_id=self.model.model_id)
        self.http.side_effect = test_pipeline.jev_http(failures={'failure_contradiction': 1})
        history_path = '/chat/' + str(first['conversation_id']) + '/'
        for path in (history_path + 'send/', '/api/chat/send/', history_path):
            with self.subTest(path=path):
                self.provider.reset_mock()
                result = self.send(path, 'Next synthetic turn', conversation_id=first['conversation_id']).json()
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(self.provider.call_count, 2)
                self.assertEqual(result['receipt']['route']['company_engine_id'], other.pk)
                self.assertEqual(result['receipt']['history']['sent_turns'], 1)
                generations = [call for call in result['receipt']['calls'] if call['purpose'] == 'generation']
                self.assertEqual([call['provider'] for call in generations],
                                 [f'engine:{self.credential.pk}', f'engine:{other.pk}'])
                receipt_url = '/chat/requests/' + result['request_id'] + '/receipt/'
                exported = self.client.get(receipt_url)
                self.assertEqual(exported.status_code, 200)
                self.assertIn('attachment;', exported['Content-Disposition'])
                saved = exported.json()
                page = self.client.get(history_path)
                self.assertContains(page, 'data-receipt-url="' + receipt_url + '"')
                values = {'result': result, 'saved': saved, 'receiptUrl': receipt_url,
                          'expected': f'engine:{other.pk}', 'original': f'engine:{self.credential.pk}'}
                self.browse(TURN + 'const {result, saved, receiptUrl, expected, original} = ' + json.dumps(values) + ';' + r"""
function checkDestination(node) {
  const value = text(node);
  assert.ok(value.includes('Destino\n' + expected + '\n'), value);
  assert.ok(value.includes('Ruta efectiva\n' + expected + ' / synthetic-v1'), value);
  const generations = value.split('\n').filter(line => line.startsWith('Generación · '));
  assert.equal(generations.length, 2, value);
  assert.ok(generations[0].endsWith(original + ' · synthetic-v1'), generations[0]);
  assert.ok(generations[1].endsWith(expected + ' · synthetic-v1'), generations[1]);
  assert.match(value, /Turnos enviados \/ omitidos\n1 \/ 0/);
  assert.doesNotMatch(value, /Second engine|synthetic-key|synthetic-other|https?:\/\//);
}
// Restored from the history page: its Details control loads the stored record once.
net.on('GET ' + receiptUrl, () => net.json(saved));
const stored = $(`.rg-turn[data-request-id="${result.request_id}"]`);
await click($('[data-action=details]', stored));
const restored = $('#receipt-' + result.request_id);
assert.equal(restored.hidden, false);
assert.equal(restored.dataset.loaded, 'true');
checkDestination(restored);
assert.equal($('a[download]', restored).getAttribute('href'), receiptUrl);
assert.equal(net.find('GET', receiptUrl).length, 1);
stored.remove();
// The exported file renders the same destination.
const exported = document.createElement('div');
regulayChat.renderReceipt(exported, saved.receipt, saved.status);
checkDestination(exported);
// The live reply renders it without a request.
const live = turnFor(result.request_id, {prompt: 'Next synthetic turn'});
regulayChat.renderOutcome(live, result, 200);
const panel = await openDetails(live);
checkDestination(panel);
assert.equal($('a[download]', panel).getAttribute('href'), receiptUrl);
assert.equal(net.find('GET', receiptUrl).length, 1);
""", page)

    def test_pending_consent_shows_omissions_and_preserves_request_and_file(self):
        self.chat(r"""
const file = window.file('synthetic.docx', 2048);
const live = turnFor('same-request', {file, fileName: 'synthetic.docx', prompt: 'same-input', token: 'old-token'});
regulayChat.renderOutcome(live, {status: 'pending_consent', success: false, request_id: 'same-request', consent_token: 'renewed-token',
  consent_reason: 'consent_expired', receipt: {coverage: {status: 'complete_text_only',
    disclosures: [{code: 'images_unread', count: 2, locators: ['paragraph:1']}]},
    notices: ['classification_ambiguous'], history: {sent_turns: 3, omitted_turns: 4, sent_bytes: 100, omitted_bytes: 200},
    limits: {jev_state_bytes: 131072, max_output_tokens: 4000}, route: {model_effective: 'effective-model'}}});
assert.equal(live.command.requestId, 'same-request');
assert.equal(live.command.file, file);
assert.equal(live.command.token, 'renewed-token');
const notice = $('.rg-notice.is-consent', live.ai);
assert.match(text(notice), /La confirmación caducó\. Revísala y confirma de nuevo\./);
assert.match(text(notice), /Imágenes no analizadas ni enviadas \(2\): paragraph:1/);
assert.match(text(notice), /classification_ambiguous/);
const receipt = text(await openDetails(live));
assert.match(receipt, /Aviso del documento\nImágenes no analizadas ni enviadas \(2\): paragraph:1/);
assert.match(receipt, /Turnos enviados \/ omitidos\n3 \/ 4/);
assert.match(receipt, /Entrada máxima del evaluador \(bytes\)\n131072/);
assert.match(receipt, /Modelo\neffective-model/);
let sent;
net.on('POST /chat/send/', request => { sent = request; return net.json(completed('same-request', 'Enviado tras confirmar.')); });
await click(buttonNamed('Confirmar envío', notice));
assert.equal(sent.body.get('request_id'), 'same-request');
assert.equal(sent.body.get('consent_token'), 'renewed-token');
assert.equal(sent.body.get('file'), file);
assert.equal(sent.body.get('prompt'), 'same-input');
assert.equal(sent.body.get('action'), null);
assert.match(text(live.ai), /Enviado tras confirmar\./);
assert.equal($('.rg-notice', live.ai), null);
""")

    def test_informational_disclosures_are_not_reported_as_omitted_content(self):
        self.chat(r"""
const output = document.createElement('div');
regulayChat.renderDisclosures(output, {disclosures: [{code: 'tracked_changes_present', count: 1, locators: ['paragraph:1']},
  {code: 'encoding_assumed', count: 1, locators: ['document']}, {code: 'blank_page', count: 1, locators: ['page:2']}]});
assert.match(text(output), /cambios aceptados/);
assert.match(text(output), /Windows-1252/);
assert.match(text(output), /Página en blanco/);
assert.doesNotMatch(text(output), /no analizad|no enviad/i);
const receipt = document.createElement('div');
regulayChat.renderReceipt(receipt, {limits: {response_bytes: 12345, history_max_bytes: 32768, history_max_turns: 20}}, 'completed');
assert.match(text(receipt), /Límite de respuesta \(bytes\)\n12345/);
assert.match(text(receipt), /Límite del historial \(bytes\)\n32768/);
assert.match(text(receipt), /Límite del historial \(turnos\)\n20/);
const withoutLimits = document.createElement('div');
regulayChat.renderReceipt(withoutLimits, {}, 'completed');
assert.doesNotMatch(text(withoutLimits), /Límites|Límite del historial/);
""")

    def test_advisory_answer_is_labelled_and_retains_no_verified_evidence(self):
        self.chat(r"""
const advisory = turnFor('advisory', {prompt: 'p'});
regulayChat.renderOutcome(advisory, {status: 'completed', success: true, request_id: 'advisory', receipt: {verification: {status: 'failed'}},
  assistant_message: {content: 'No verificado\n\nA synthetic claim'},
  evidence: {items: [{claim_index: 1, locator: 'line:1', excerpt: 'UNVERIFIED_EXCERPT'}]}});
assert.equal((text(advisory.ai).match(/No verificado/g) || []).length, 1);
assert.match(text($('.rg-md', advisory.ai)), /^A synthetic claim$/);
assert.doesNotMatch(text(advisory.ai), /UNVERIFIED_EXCERPT|Citas del documento/);
const verified = turnFor('verified', {prompt: 'p'});
regulayChat.renderOutcome(verified, completed('verified', 'El plazo acordado es de diecisiete días [1].',
  {evidence: {items: [{claim_index: 1, locator: 'line:1', excerpt: 'verified source'}]}}));
assert.doesNotMatch(text(verified.ai), /No verificado/);
assert.match(text(verified.ai), /Citas del documento · 1\n1\nline:1\nverified source/);
const evidence = $('.rg-evidence', verified.ai);
assert.equal(evidence.open, false);
await click($('.rg-cite', verified.ai));
assert.equal(evidence.open, true);
assert.ok(scrolledIntoView.includes($('#cite-verified-1')));
""")

    def test_pending_consent_after_reload_confirms_the_same_request_and_selection(self):
        self.rule.action = 'consent'
        self.rule.save()
        first = self.send('/chat/send/', 'SYNTHETIC_SECRET', engine_id=str(self.credential.pk), model_id=str(self.model.pk)).json()
        self.assertEqual(first['status'], 'pending_consent')
        prompt = Prompt.objects.get(request_id=first['request_id'])
        self.assertEqual(prompt.decision['requested'], {'engine_id': self.credential.pk, 'model_id': self.model.pk})
        page = self.client.get(f"/chat/{first['conversation_id']}/")
        self.assertContains(page, f'data-engine="{self.credential.pk}" data-model="{self.model.pk}"')
        # The browser sends the stored selection, not the one currently chosen in the picker.
        session = self.client.session
        session['selected_engine_id'], session['selected_model_id'] = 99999, 99999
        session.save()
        result = self.chat(r"""
const turn = $(`.rg-turn[data-request-id="${REQUEST}"]`);
assert.match(text(turn), /Requiere tu confirmación/);
let sent;
net.on(`POST /chat/${CONVERSATION}/send/`, request => { sent = request; return net.json(completed(REQUEST, 'Confirmado.')); });
await click($('[data-action=consent-confirm]', turn));
assert.equal(sent.body.get('request_id'), REQUEST);
assert.equal(sent.body.get('consent_token'), TOKEN);
assert.equal(sent.body.get('engine_id'), ENGINE);
assert.equal(sent.body.get('model_id'), MODEL);
assert.equal(sent.body.get('auto_route'), 'false');
assert.equal(sent.body.get('prompt'), 'SYNTHETIC_SECRET');
assert.match(text(turn), /Confirmado\./);
console.log(JSON.stringify(Object.fromEntries(sent.body.entries())));
""".replace('REQUEST', json.dumps(first['request_id'])).replace('CONVERSATION', str(first['conversation_id']))
            .replace('TOKEN', json.dumps(first['consent_token'])).replace('ENGINE', json.dumps(str(self.credential.pk)))
            .replace('MODEL', json.dumps(str(self.model.pk))), path=f"/chat/{first['conversation_id']}/")
        # The server accepts exactly what the page sends as the same request.
        sent = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(sent['stream'], '1')
        with override_settings(CHAT_STREAM_THREADS=False):
            response = self.client.post(f"/chat/{first['conversation_id']}/send/", sent)
            events = parse_sse(b''.join(response.streaming_content).decode())
        self.assertEqual(events[-1]['result']['status'], 'completed')
        self.assertEqual(events[-1]['result']['request_id'], first['request_id'])
        self.assertEqual(Prompt.objects.count(), 1)
        self.assertEqual(self.provider.call_count, 1)

    def test_conversation_list_and_mobile_drawer_keep_accessible_state(self):
        self.chat(r"""
const app = $('#chatApp');
const hide = $('.rg-threads-head [data-action=threads-toggle]');
assert.equal(hide.getAttribute('aria-expanded'), 'true');
await click(hide);
assert.ok(app.classList.contains('is-threads-hidden'));
for (const control of $$('[data-action=threads-toggle]')) {
  assert.equal(control.getAttribute('aria-expanded'), 'false');
  assert.equal(control.getAttribute('aria-label'), 'Mostrar conversaciones');
}
assert.equal(localStorage.getItem('regulai.chat.threads'), 'hidden');
await click($('.rg-head [data-action=threads-toggle]'));
assert.ok(!app.classList.contains('is-threads-hidden'));
assert.equal(hide.getAttribute('aria-label'), 'Ocultar conversaciones');
""")
        self.chat(r"""
assert.ok($('#chatApp').classList.contains('is-threads-hidden'));
""", storage={'regulai.chat.threads': 'hidden'})
        self.chat(r"""
const app = $('#chatApp'), menu = $('[data-action=nav-open]');
await click(menu);
assert.ok(app.classList.contains('is-drawer-open'));
assert.equal($('.rg-scrim').hidden, false);
assert.equal(menu.getAttribute('aria-expanded'), 'true');
assert.equal(document.activeElement, $('.rg-new'));
assert.equal($('#chatMain').hasAttribute('inert'), true);
await press(document.activeElement, 'Escape');
assert.ok(!app.classList.contains('is-drawer-open'));
assert.equal($('.rg-scrim').hidden, true);
assert.equal($('#chatMain').hasAttribute('inert'), false);
assert.equal(document.activeElement, menu);
await click(menu);
await click($('.rg-scrim'));
assert.ok(!app.classList.contains('is-drawer-open'));
""", media={'desktop': False})


@override_settings(CHAT_STREAM_THREADS=False)
class ChatStreamClientTests(OfflineBrowser, ChatFixture):
    """Streamed replies in the page: order, retraction, reattach and stop."""

    def chat(self, checks, path='/chat/', **options):
        return self.browse(TURN + checks, self.client.get(path), **options)

    def test_server_frames_are_parsed_like_event_source(self):
        self.chat(r"""
const parse = regulayChat.parseFrame;
assert.deepEqual(parse('id: 3\nevent: delta\ndata: {"seq":3,"type":"delta","text":"Hola"}'), {seq: 3, type: 'delta', text: 'Hola'});
assert.deepEqual(parse('event: stage\ndata: {"seq":1,\ndata: "stage":"protecting"}'), {seq: 1, stage: 'protecting', type: 'stage'});
assert.equal(parse(': keepalive'), null);
assert.equal(parse('event: delta\ndata: no-json'), null);
""")

    def test_events_apply_once_in_order_and_withdrawn_text_disappears(self):
        self.chat(r"""
const live = turnFor('ordered', {prompt: 'Hola'});
const apply = event => regulayChat.handleEvent(live, event);
assert.equal(apply({seq: 1, type: 'accepted', conversation_id: null}), true);
apply({seq: 2, type: 'stage', stage: 'protecting'});
assert.match(text(live.ai), /Protegiendo datos sensibles/);
apply({seq: 3, type: 'delivery', mode: 'streamed', reason: null});
apply({seq: 4, type: 'stage', stage: 'generating', attempt: 1, model: 'Lab Rápido'});
assert.match(text(live.ai), /Generando · Lab Rápido/);
assert.equal(apply({seq: 5, type: 'delta', attempt: 1, text: 'Hola '}), true);
assert.equal(apply({seq: 5, type: 'delta', attempt: 1, text: 'Hola '}), false);
assert.equal(apply({seq: 4, type: 'stage', stage: 'protecting'}), false);
apply({seq: 6, type: 'delta', attempt: 1, text: 'mundo'});
await tick(20);
assert.equal(text($('.rg-md', live.ai)), 'Hola mundo');
assert.equal($('.rg-md', live.ai).getAttribute('aria-busy'), 'true');
assert.doesNotMatch(text(live.ai), /Generando/);
apply({seq: 7, type: 'retract', reason: 'retry', attempt: 1});
assert.equal($('.rg-md', live.ai), null);
assert.match(text(live.ai), /Reintentando\n· el texto anterior no superó las comprobaciones y se ha retirado/);
apply({seq: 8, type: 'stage', stage: 'generating', attempt: 2, model: 'Lab Preciso'});
apply({seq: 9, type: 'delta', attempt: 2, text: 'Segundo intento. '});
await tick(20);
const second = $('.rg-md', live.ai);
assert.equal(text(second), 'Segundo intento.');
apply({seq: 10, type: 'final', result: completed('ordered', 'Segundo intento. Completo.')});
assert.equal(live.done, true);
assert.equal($('.rg-md', live.ai), second);
assert.equal($$('.rg-md', live.ai).length, 1);
assert.equal(text(second), 'Segundo intento. Completo.');
assert.equal(second.hasAttribute('aria-busy'), false);
assert.doesNotMatch(text(live.ai), /Reintentando|Hola mundo/);
const complete = turnFor('whole', {prompt: 'Resume el acta'});
regulayChat.handleEvent(complete, {seq: 1, type: 'stage', stage: 'generating', attempt: 1, model: 'Lab'});
regulayChat.handleEvent(complete, {seq: 2, type: 'delivery', mode: 'complete', reason: 'document_citations'});
assert.match(text(complete.ai), /Generando · Lab\n· Se mostrará completa, con las citas comprobadas\./);
""")

    def test_send_streams_rejoins_after_a_dropped_connection_and_never_resends(self):
        self.chat(r"""
const input = $('#prompt');
await typeInto(input, 'Resume la política');
const first = net.sse();
let posted;
net.on('POST /chat/send/', request => { posted = request; return first; });
await click($('#sendButton'));
assert.equal(navigations.length, 0);
assert.equal(posted.body.get('stream'), '1');
assert.equal(posted.headers.accept, 'text/event-stream');
assert.equal(posted.body.get('prompt'), 'Resume la política');
const requestId = posted.body.get('request_id');
assert.match(requestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
assert.equal(input.value, '');
assert.equal($('#stopButton').hidden, false);
assert.equal($('#sendButton').hidden, true);
const turn = $(`.rg-turn[data-request-id="${requestId}"]`);
assert.equal(text($('.rg-bubble', turn)), 'Resume la política');
first.send({seq: 1, type: 'accepted', request_id: requestId, conversation_id: 41},
  {seq: 2, type: 'stage', stage: 'protecting'}, {seq: 3, type: 'delivery', mode: 'streamed', reason: null},
  {seq: 4, type: 'stage', stage: 'generating', attempt: 1, model: 'Lab'},
  {seq: 5, type: 'delta', attempt: 1, text: 'La política fija '});
await tick(20);
assert.equal(text($('.rg-md', turn)), 'La política fija');
assert.equal(history.entries.at(-1).url, '/chat/41/');
assert.equal($('#chatApp').dataset.conversation, '41');
const rest = net.sse();
let rejoined;
net.on(`GET /chat/requests/${requestId}/stream/?after=5`, request => { rejoined = request; return rest; });
first.fail();
await flush();
assert.ok(rejoined, 'the client did not rejoin after the last applied event');
rest.send({seq: 5, type: 'delta', attempt: 1, text: 'La política fija '}, {seq: 6, type: 'delta', attempt: 1, text: 'límites claros.'});
await tick(20);
assert.equal(text($('.rg-md', turn)), 'La política fija límites claros.');
rest.send({seq: 7, type: 'final', result: completed(requestId, 'La política fija límites claros.', {conversation_id: 41})});
rest.close();
await flush();
assert.equal($$('.rg-md', turn).length, 1);
assert.ok($('[data-action=copy]', turn));
assert.equal($('#sendButton').hidden, false);
assert.equal($('#stopButton').hidden, true);
assert.equal(net.find('POST', '/chat/send/').length, 1);
assert.equal(net.find('POST', '/chat/41/send/').length, 0);
""")

    def test_stop_asks_the_server_and_shows_the_withdrawn_answer_state(self):
        self.chat(r"""
await typeInto($('#prompt'), 'Escribe un informe largo');
const stream = net.sse();
net.on('POST /chat/send/', () => stream);
let cancel;
net.on(request => request.method === 'POST' && request.url.endsWith('/cancel/'),
  request => { cancel = request; return net.json({cancelling: true}, {status: 202}); });
await click($('#sendButton'));
const requestId = net.find('POST', '/chat/send/')[0].body.get('request_id');
const turn = $(`.rg-turn[data-request-id="${requestId}"]`);
stream.send({seq: 1, type: 'accepted', request_id: requestId, conversation_id: 7}, {seq: 2, type: 'delta', attempt: 1, text: 'Primer párrafo. '});
await tick(20);
await click($('#stopButton'));
assert.equal(cancel.url, `/chat/requests/${requestId}/cancel/`);
assert.ok(cancel.headers['x-csrftoken']);
assert.match(text(turn), /Deteniendo/);
stream.send({seq: 3, type: 'retract', reason: 'cancelled_by_user', attempt: 1},
  {seq: 4, type: 'final', result: {status: 'cancelled', success: false, request_id: requestId, error_type: 'cancelled_by_user',
    error: 'Respuesta detenida. No se ha guardado el texto parcial.', receipt: {calls: [{purpose: 'generation', status: 'cancelled', cost: null}]}}});
stream.close();
await flush();
assert.equal($('.rg-md', turn), null);
assert.match(text(turn), /Respuesta detenida\. No se ha guardado el texto parcial\./);
assert.doesNotMatch(text(turn), /Primer párrafo/);
assert.equal($('#stopButton').hidden, true);
""")

    def test_unregistered_request_is_retried_as_the_same_request(self):
        self.chat(r"""
await typeInto($('#prompt'), 'Hola');
net.on('POST /chat/send/', () => new TypeError('offline'), {once: true});
net.on(/\/stream\/\?after=0$/, () => net.json({error: 'not_found'}, {status: 404}));
await click($('#sendButton'));
const requestId = net.find('POST', '/chat/send/')[0].body.get('request_id');
const turn = $(`.rg-turn[data-request-id="${requestId}"]`);
assert.match(text(turn), /No se pudo obtener el resultado\nReintentar consulta esta misma petición; no crea un envío nuevo\./);
assert.doesNotMatch(text(turn), /sigue registrada/);
net.on('POST /chat/send/', () => net.json(completed(requestId, 'Hola, ¿en qué te ayudo?')));
await click(buttonNamed('Reintentar', turn));
const posts = net.find('POST', '/chat/send/');
assert.equal(posts.length, 2);
assert.equal(posts[1].body.get('request_id'), requestId);
assert.match(text(turn), /Hola, ¿en qué te ayudo\?/);
""")

    def test_reload_rejoins_a_running_request_from_the_start_without_sending(self):
        conversation = Conversation.objects.create(user=self.user, title='En curso')
        message = Message.objects.create(conversation=conversation, role='user', content='Resume la política')
        prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=conversation, user_message=message,
                                       content=message.content, request_id=uuid.uuid4(), status='processing',
                                       decision={'schema_version': 1, 'calls': []})
        path = f'/chat/{conversation.pk}/'
        self.assertContains(self.client.get(path), 'data-live="true"')
        self.chat(r"""
const requestId = REQUEST;
const turn = $(`.rg-turn[data-request-id="${requestId}"]`);
assert.match(text(turn), /Reconectando/);
assert.equal($('#stopButton').hidden, false);
assert.equal($('#sendButton').disabled, true);
const stream = net.sse();
net.on(`GET /chat/requests/${requestId}/stream/?after=0`, () => stream);
await tick(600);
stream.send({seq: 1, type: 'accepted', request_id: requestId, conversation_id: CONVERSATION},
  {seq: 2, type: 'stage', stage: 'generating', attempt: 1, model: 'Lab'},
  {seq: 3, type: 'delta', attempt: 1, text: 'Texto ya generado. '});
await tick(20);
assert.equal(text($('.rg-md', turn)), 'Texto ya generado.');
stream.send({seq: 4, type: 'final', result: completed(requestId, 'Texto ya generado. Fin.')});
stream.close();
await flush();
assert.equal(text($('.rg-md', turn)), 'Texto ya generado. Fin.');
assert.equal(net.requests.filter(request => request.method === 'POST').length, 0);
assert.ok(net.requests.every(request => request.url === `/chat/requests/${requestId}/stream/?after=0`));
assert.equal($('#stopButton').hidden, true);
""".replace('REQUEST', json.dumps(str(prompt.request_id))).replace('CONVERSATION', str(conversation.pk)), path=path)


class MarkdownTests(OfflineBrowser, SimpleTestCase):
    def test_markup_is_text_links_are_safe_and_markers_become_labels(self):
        self.browse(r"""
const md = document.createElement('div');
RegulayMarkdown.render(md, ['<script>alert(1)</script> <img src=x onerror=alert(1)>', '',
  '[uno](javascript:alert(1)) [dos](https://example.org/a_(b)) <https://ok.example/x> https://es.wikipedia.org/wiki/Euro_(moneda). ' +
  '[tres](data:text/html,x) [cuatro](mailto:equipo@example.org)', '',
  'Contacto: [[REGULAI_EMAIL]] y [[REGULAI_PHONE]] · **[[REGULAI_PERSON]]**'].join('\n'));
assert.equal($$('script, img', md).length, 0);
assert.match(text(md), /<script>alert\(1\)<\/script> <img src=x onerror=alert\(1\)>/);
assert.deepEqual($$('a', md).map(link => link.getAttribute('href')),
  ['https://example.org/a_(b)', 'https://ok.example/x', 'https://es.wikipedia.org/wiki/Euro_(moneda)', 'mailto:equipo@example.org']);
for (const link of $$('a', md)) {
  assert.equal(link.getAttribute('target'), '_blank');
  assert.match(link.getAttribute('rel'), /noopener/);
}
assert.match(text(md), /uno/);
assert.match(text(md), /tres/);
assert.match(text(md), /Euro_\(moneda\)\./);
assert.deepEqual($$('.rg-redacted', md).map(chip => chip.textContent), ['correo protegido', 'teléfono protegido', 'nombre protegido']);
assert.equal(RegulayMarkdown.plain('a [[REGULAI_EMAIL]] b [[REGULAI_PHONE]] c'), 'a [correo protegido] b [teléfono protegido] c');
// A label that is itself a URL (or emphasis around a URL) gives one anchor, never a nested one.
const nested = document.createElement('div');
RegulayMarkdown.render(nested, 'Ver **https://example.org/x** y [https://a.example](https://a.example) o <https://b.example>.');
assert.deepEqual($$('a', nested).map(link => link.textContent), ['https://example.org/x', 'https://a.example', 'https://b.example']);
assert.equal($$('a a', nested).length, 0);
assert.equal($('strong a', nested).getAttribute('href'), 'https://example.org/x');
const code = document.createElement('div');
RegulayMarkdown.render(code, '```python\nprint("<b>hola</b>")\n```');
assert.equal($$('b', code).length, 0);
assert.equal($('pre code', code).textContent, 'print("<b>hola</b>")');
assert.equal($('.rg-code-copy', code).dataset.copy, 'print("<b>hola</b>")');
assert.equal($('.rg-code-lang', code).textContent, 'python');
""")

    def test_streaming_holds_partial_table_rows_and_reuses_finished_blocks(self):
        self.browse(r"""
const md = document.createElement('div');
RegulayMarkdown.render(md, 'Resumen:\n\n| Concepto | Importe |', {streaming: true});
assert.equal($$('table', md).length, 0);
assert.doesNotMatch(text(md), /\|/);
assert.equal(text(md), 'Resumen:');
RegulayMarkdown.render(md, 'Resumen:\n\n| Concepto | Importe |\n|---|---:|\n| Hotel | 120 € |', {streaming: true});
// Finished blocks are kept as they are while later text arrives.
const first = md.firstElementChild;
assert.equal($$('table', md).length, 1);
assert.equal($('tbody td:last-child', md).style.textAlign, 'right');
RegulayMarkdown.render(md, 'Resumen:\n\n| Concepto | Importe |\n|---|---:|\n| Hotel | 120 € |\n\nTexto **importan', {streaming: true});
assert.equal(md.firstElementChild, first);
assert.equal(md.lastElementChild.querySelector('strong').textContent, 'importan');
RegulayMarkdown.render(md, 'Respuesta con `codigo', {streaming: true});
assert.equal($('code', md).textContent, 'codigo');
// Lists and headings that are still arriving never show a raw marker either.
const list = document.createElement('div');
RegulayMarkdown.render(list, '## Puntos **cla', {streaming: true});
assert.equal($('h3 strong', list).textContent, 'cla');
RegulayMarkdown.render(list, '## Puntos **clave**\n\n1. Primero.\n2. Las reservas se hacen con al menos **15', {streaming: true});
assert.doesNotMatch(text(list), /\*\*/);
assert.equal($('h3 strong', list).textContent, 'clave');
assert.equal($('li:last-child strong', list).textContent, '15');
RegulayMarkdown.render(md, 'Resumen:\n\n| Concepto | Importe |\n|---|---:|\n| Hotel | 120 € |\n\nTexto **importante**.');
assert.equal($$('table', md).length, 1);
assert.equal($$('p', md).length, 2);
assert.equal((text(md).match(/Resumen:/g) || []).length, 1);
assert.equal(md.lastElementChild.querySelector('strong').textContent, 'importante');
""")

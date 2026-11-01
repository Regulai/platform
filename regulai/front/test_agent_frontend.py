"""Agent runs inside the conversation: activity, deliverables, review and export (offline).

agent-chat.js runs against rendered pages in front/offline_browser.cjs. Run
snapshots and progress events are synthetic or come from the server's own
projections (run_data, _events); no worker, sandbox or provider is involved.
"""
from datetime import datetime, timedelta
import json
import re
import uuid

from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from front.agents.jobs import event, run_data
from front.agents.views import _events
from front.models import AgentAccessGrant, AgentExecution, AgentModelProfile, Conversation, Message, Prompt
from front.offline_browser import OfflineBrowser
from front.test_chat_flow import ChatFixture

AGENT = r"""
const RUN = {id: 'run-a', status: 'completed', status_url: '/chat/agent/runs/run-a/', events_url: '/chat/agent/runs/run-a/events/',
  cancel_url: '/chat/agent/runs/run-a/cancel/', request: {}};
const RECEIPT = {policy: {status: 'allowed', reason_codes: ['local_policy_allowed']}, jev: {status: 'not_consulted'}, calls: [], total: {cost: null}};
const runAt = (id, extra = {}) => ({...RUN, id, status_url: `/chat/agent/runs/${id}/`, events_url: `/chat/agent/runs/${id}/events/`,
  cancel_url: `/chat/agent/runs/${id}/cancel/`, ...extra});
const snapshot = (run, extra = {}) => {
  const result = extra.result || {receipt: RECEIPT};
  return {run, result, receipt: result.receipt || {}, events: [], artifacts: [], current_revision: null, export_enabled: false, ...extra};
};
const hostFor = run => {
  const turn = document.createElement('article'), ai = document.createElement('div'), host = document.createElement('div');
  turn.className = 'rg-turn';
  turn.dataset.run = run.id;
  ai.className = 'rg-msg rg-msg-ai';
  host.className = 'rg-agent';
  host.dataset.agentRun = run.id;
  ai.appendChild(host);
  turn.appendChild(ai);
  $('#chatContainer').appendChild(turn);
  return host;
};
const mount = async (run, data) => {
  if (data) net.on('GET ' + run.status_url, () => net.json(data));
  const host = hostFor(run);
  const watcher = regulayAgent.mount(host, run);
  await flush();
  return {host, watcher};
};
const buttonNamed = (name, root = document) => $$('button', root).find(item => item.textContent.trim() === name);
const title = host => text($('.rg-activity-title', host));
"""


class AgentPageScriptTests(OfflineBrowser, ChatFixture):
    def agent(self, checks, path='/chat/', **options):
        return self.browse(AGENT + checks, self.client.get(path), **options)

    def agent_conversation(self, professional=False):
        profile = AgentModelProfile.objects.create(company=self.company, name='Documentos', enabled=True,
            connection=self.credential, model=self.model, tools=['build_document'], professional=professional)
        return profile, Conversation.objects.create(user=self.user, mode='agent', title='Informe trimestral')

    def agent_turn(self, conversation, text, status, profile=None, run_status=None, request=None):
        message = Message.objects.create(conversation=conversation, role='user', content=text)
        prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=conversation, user_message=message,
            content=text, request_id=uuid.uuid4(), status=status, decision={'schema_version': 1, 'calls': []})
        if profile is None:
            return prompt, None
        now = timezone.now()
        run = AgentExecution.objects.create(prompt=prompt, profile=profile, token_digest=uuid.uuid4().hex * 2,
            authorization_digest='0' * 64, expires_at=now + timedelta(hours=1), conversation=conversation, status=run_status,
            started_at=now - timedelta(seconds=75), finished_at=None if run_status in ('queued', 'active') else now,
            job={'kind': 'create', 'logical_id': str(uuid.uuid4()),
                 'request': request or {'formats': ['docx', 'pdf'], 'pages': 3, 'language': 'es'}})
        return prompt, run

    def stored_snapshot(self, run, **extra):
        """The status endpoint's shape, built from the server's own projections."""
        return {'run': run_data(run), 'result': {'receipt': {}}, 'receipt': {}, 'events': _events(run.events.all()),
                'artifacts': [], 'current_revision': None, 'export_enabled': False, **extra}

    def test_restored_agent_omits_only_the_receipt_already_shown_in_its_panel(self):
        profile, conversation = self.agent_conversation()
        previous, _ = self.agent_turn(conversation, 'Pregunta anterior sin ejecución', 'completed')
        current, run = self.agent_turn(conversation, 'Crea un informe de tres páginas', 'processing', profile, 'active')
        for kind in ('queued', 'claimed', 'compose'):
            event(run, kind)
        page = self.client.get(f'/chat/{conversation.pk}/')
        previous_url = reverse('front:chat_request_receipt', args=[previous.request_id])
        current_url = reverse('front:chat_request_receipt', args=[current.request_id])
        self.assertContains(page, f'data-receipt-url="{previous_url}"')
        self.assertNotContains(page, current_url)
        self.assertContains(page, f'data-agent-run="{run.pk}"', count=1)
        runs = json.loads(re.search(r'<script id="agent-runs" type="application/json">(.*?)</script>', page.content.decode(), re.S)[1])
        self.assertEqual(list(runs), [str(run.pk)])
        self.assertEqual(runs[str(run.pk)]['created_at'], run.created_at.isoformat())
        self.assertIsNone(runs[str(run.pk)]['finished_at'])
        self.browse(AGENT + r"""
const host = $('[data-agent-run="RUN_ID"]');
assert.equal($$('.rg-activity').length, 1);
assert.equal($('[data-action=details]', host.closest('.rg-turn')), null);
assert.equal($$('[data-receipt-url]').length, 1);
assert.equal(title(host), 'Redactando el documento');
assert.match(text(host), /Petición interpretada: Crear DOCX y PDF · 3 páginas · en español/);
assert.deepEqual($$('.rg-step', host).map(step => step.dataset.kind), ['queued', 'claimed', 'compose']);
assert.deepEqual($$('.rg-step', host).map(step => step.dataset.state), ['done', 'done', 'active']);
assert.match(text($('.rg-step[data-kind=compose]', host)), /Componiendo el documento con el contenido autorizado\./);
assert.doesNotMatch(text($('.rg-step[data-kind=queued]', host)), /Petición aceptada/);
assert.ok(buttonNamed('Detener', host));
assert.equal(sources.at(-1).url, '/chat/agent/runs/RUN_ID/events/?cursor=' + CURSOR);
assert.equal($('#stopButton').hidden, false);
""".replace('RUN_ID', str(run.pk)).replace('CURSOR', str(run.events.order_by('-id').first().pk)), page,
            routes=[{'url': f'/chat/agent/runs/{run.pk}/', 'json': self.stored_snapshot(run)}])

    def test_jev_states_do_not_turn_local_policy_into_jev_approval(self):
        self.agent(r"""
for (const [status, expected] of [['not_consulted', 'No consultado'], ['disabled', 'Deshabilitado'],
  ['failed', 'Falló'], ['no_response', 'Sin respuesta'], ['consulted', 'Consultado']]) {
  const output = document.createElement('div');
  regulayAgent.renderReceipt(output, {policy: {reason_codes: ['local_policy_allowed']},
    jev: {status, decision: {category: 'ordinary', task: 'report', difficulty: 'high'}, reasons: [],
      recommendations: [], applied: {sensitivity: 'ordinary', task: 'report', difficulty: 'high'},
      effect: 'continue', signals: {difficulty: {noul: 0.7}}, policy: {source: 'regulay_policy', revision: 3}}, calls: []});
  assert.match(text(output), new RegExp('Estado de Jev\n' + expected));
  assert.match(text(output), /Jev no ha proporcionado motivos textuales/);
  assert.match(text(output), /Decisión aplicada por Regulay\nordinary · report · high/);
  assert.match(text(output), /Una autorización local no es una aprobación de Jev/);
  assert.doesNotMatch(text(output), /Jev aprobado|Jev: Permitido|\[object Object\]/);
}
""")

    def test_full_call_sequence_preserves_requested_effective_fallback_and_unknown_cost(self):
        self.agent(r"""
const output = document.createElement('div');
regulayAgent.renderReceipt(output, {calls: [
  {sequence: 1, purpose: 'classification', provider_name: 'Jev gateway', model_requested: 'jev-requested',
   model_effective: 'jev-effective', route: {mode: 'policy', destination: 'gateway'}, fallback: {status: 'not_used'}, cost: null},
  {sequence: 2, purpose: 'generation', provider: 'synthetic', model_requested: 'requested-a', model_effective: 'effective-b',
   route: {mode: 'agent_profile', destination: 'engine:9'}, fallback: {status: 'used', reason: 'test fallback'},
   duration_ms: 42, cost: '0.0012', cost_kind: 'tariff_estimate', currency: 'USD'}]});
for (const value of ['jev-requested', 'jev-effective', 'requested-a', 'effective-b', 'engine:9', '42 ms', '0.0012 USD',
  'Estimación con las tarifas configuradas', 'Motivo de fallback\ntest fallback']) assert.ok(text(output).includes(value), value);
assert.match(text(output), /Coste\nNo disponible/);
assert.match(text(output), /Fallback\nSin fallback de Regulay/);
const sequence = $$('details', output).find(item => text($('summary', item)).startsWith('Secuencia de llamadas'));
assert.equal(text($('summary', sequence)), 'Secuencia de llamadas · 2 llamadas');
assert.equal(sequence.open, false);
assert.equal($('ol', sequence).children.length, 2);
""")

    def test_long_call_sequence_is_built_only_when_opened(self):
        self.agent(r"""
const calls = Array.from({length: 60}, (_, index) => ({sequence: index + 1, status: 'completed', cost: '0', currency: 'USD',
  purpose: index % 2 ? 'generation' : 'obfuscation', model_effective: index % 2 ? 'model-a' : null,
  ...(index % 2 ? {protection: {reused: index, protected: 1}} : {})}));
const output = document.createElement('div');
regulayAgent.renderReceipt(output, {calls});
const sequence = $('.rg-sequence', output);
assert.equal(text($('summary', sequence)), 'Secuencia de llamadas · 60 llamadas');
assert.equal($('.rg-calls', sequence), null);
await click($('summary', sequence));
assert.equal($('.rg-calls', sequence).children.length, 60);
assert.match(text(sequence), /Protección del historial\n1 mensaje reutilizado · 1 protegido en esta llamada/);
assert.match(text(sequence), /Protección del historial\n59 mensajes reutilizados · 1 protegido en esta llamada/);
await click($('summary', sequence));
await click($('summary', sequence));
assert.equal($$('.rg-calls', sequence).length, 1);
""")

    def test_refresh_keeps_an_unchanged_receipt_and_the_sections_the_reader_opened(self):
        self.agent(r"""
const run = {...RUN, status: 'active'};
const call = sequence => ({sequence, purpose: 'generation', status: 'completed', model_effective: 'model-a'});
const {host, watcher} = await mount(run, snapshot(run, {result: {receipt: {...RECEIPT, calls: [call(1)]}}}));
const tech = $('.rg-receipt', host), built = tech.children[0];
await watcher.refresh();
assert.equal(tech.children[0], built);
await click($('summary', $('.rg-sequence', tech)));
net.on('GET ' + run.status_url, () => net.json(snapshot(run, {result: {receipt: {...RECEIPT, calls: [call(1), call(2)]}}})));
await watcher.refresh();
assert.notEqual(tech.children[0], built);
assert.equal($('.rg-sequence', tech).open, true);
assert.equal($('.rg-calls', tech).children.length, 2);
""")

    def test_primary_source_read_does_not_claim_an_inference_or_missing_model(self):
        self.agent(r"""
const output = document.createElement('div');
regulayAgent.renderReceipt(output, {calls: [{sequence: 1, purpose: 'research',
  provider_name: 'public_https', route: {mode: 'primary_source_read'},
  model_requested: null, model_effective: null, cost: '0', currency: 'USD', cost_kind: 'no_api_charge'}]});
assert.match(text(output), /Secuencia de llamadas · 1 llamada/);
assert.match(text(output), /1\. Consulta de fuentes · Lectura sin modelo/);
assert.match(text(output), /Ruta\nConsulta de fuente primaria/);
assert.match(text(output), /Modelo solicitado\nLectura sin modelo/);
assert.match(text(output), /Modelo efectivo\nLectura sin modelo/);
assert.match(text(output), /Origen del coste\nSin cargo de API/);
assert.doesNotMatch(text(output), /Secuencia de inferencia|Modelo efectivo\nNo disponible/);
""")

    def test_document_card_has_companion_downloads_and_separate_honest_checks(self):
        self.agent(r"""
const base = '/chat/agent/artifacts/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/';
const artifact = {id: 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb', logical_id: 'logical-a', revision: 2, format: 'docx', status: 'verified',
  preview: {title: '<img src=x onerror=alert(1)> Informe largo', page_count: 5, pages: []},
  download_url: base + 'download/',
  downloads: [{format: 'DOCX', url: base + 'download/?format=docx'}, {format: 'pdf', url: base + 'download/?format=pdf'},
    {format: 'pdf', url: 'https://outside.invalid/document'}, {format: 'pdf', url: 'javascript:alert(1)'}],
  verification_checks: {integrity: {status: 'passed', detail: 'Archivo abre'}, instructions: {status: 'failed', detail: 'No cumple el idioma'}}};
const {host} = await mount(RUN, snapshot(RUN, {artifacts: [artifact], current_revision: artifact}));
const card = $('.rg-deliverable', host);
assert.match(text(card), /DOCX · 5 páginas · Revisión 2/);
assert.equal($('h3', card).textContent, artifact.preview.title);
assert.equal($$('img', card).length, 0);
const downloads = $$('a[download]', card);
assert.deepEqual(downloads.map(link => link.getAttribute('aria-label')), ['Descargar DOCX', 'Descargar PDF']);
assert.deepEqual(downloads.map(link => link.getAttribute('href')), [base + 'download/', base + 'download/?format=pdf']);
assert.match(text(card), /Integridad del archivo\nSuperada\nArchivo abre/);
assert.match(text(card), /Formato e instrucciones\nFallida\nNo cumple el idioma/);
assert.equal((text(card).match(/\nNo realizada\n/g) || []).length, 3);
assert.match(text(card), /Comprobaciones técnicas · 1 superada, 1 fallida, 3 no realizadas/);
assert.ok($('details.has-failed', card));
assert.doesNotMatch(text(card), /Verificado y revisado|Fórmulas y totales verificados/);
const details = buttonNamed('Detalles', host), tech = $('.rg-receipt', host);
assert.equal(tech.hidden, true);
await click(details);
assert.equal(tech.hidden, false);
assert.equal(details.getAttribute('aria-expanded'), 'true');
assert.match(text(tech), /Coste\nNo disponible/);
assert.match(text(tech), /Seguridad local\nPermitido\nJev\nNo consultado/);
""")

    def test_v2_file_card_uses_receipt_name_size_and_coverage_without_active_preview(self):
        self.agent(r"""
const id = 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb', base = '/chat/agent/artifacts/' + id + '/';
const artifact = {id, logical_id: 'logical-a', revision: 2, format: 'html', status: 'verified', sha256: 'a'.repeat(64),
  filename: 'Madrid "azul" <img onerror=alert(1)>.html', size_bytes: 13269,
  preview: {title: 'Modelo', pages: [base + 'pages/1/']}, download_url: base + 'download/',
  verification_checks: {coverage: {status: 'complete', scope: 'full_source_text_not_execution_safety'}}};
const receipt = {version: 2, status: 'partial', artifacts: [{artifact_id: id, sha256: artifact.sha256}]};
const {host} = await mount({...RUN, status: 'failed', professional: true}, snapshot({...RUN, status: 'failed', professional: true},
  {delivery: receipt, artifacts: [artifact]}));
assert.equal(title(host), 'Entrega parcial');
const card = $('.rg-deliverable', host);
assert.equal($('h3', card).textContent, artifact.filename);
assert.match(text(card), /13[.\s]?269 bytes/);
assert.match(text(card), /Revisión 2/);
assert.match(text(card), /Cobertura completa/);
assert.equal($$('img,iframe,object', card).length, 0);
assert.equal(buttonNamed('Vista previa', card), undefined);
assert.equal($('a[download]', card).getAttribute('download'), artifact.filename);
const pending = runAt('pending-file', {status: 'active', professional: true});
const waiting = await mount(pending, snapshot(pending, {delivery: {version: 2, status: 'pending', artifacts: []}, artifacts: [artifact]}));
assert.equal(title(waiting.host), 'Archivo generado, pendiente de entrega');
assert.equal($$('a[download]', waiting.host).length, 0);
const noFiles = runAt('text-finished');
const textResult = await mount(noFiles, snapshot(noFiles, {delivery: {version: 2, status: 'not_required', artifacts: []}}));
assert.equal(title(textResult.host), 'Respuesta completada');
""")

    def test_sandbox_intervals_stop_before_provider_and_unmeasured_gaps_are_blank(self):
        self.agent(r"""
const run = runAt('timed', {status: 'active', professional: true});
const at = seconds => new Date(Date.parse('2026-10-16T10:00:00Z') + seconds * 1000).toISOString();
const {host} = await mount(run, snapshot(run, {events: [
 {id: 1, kind: 'claimed', created_at: at(0), data: {}},
 {id: 2, kind: 'sandbox_waiting', created_at: at(1), data: {}},
 {id: 3, kind: 'sandbox_acquired', created_at: at(2), data: {duration_ms: 1200}},
 {id: 4, kind: 'sandbox_prepared', created_at: at(3), data: {duration_ms: 2000}},
 {id: 5, kind: 'provider_started', created_at: at(90), data: {}}
]}));
assert.equal(title(host), 'Generando la respuesta');
assert.equal(text($('.rg-step[data-kind=claimed] .rg-step-label', host)), 'Ejecución iniciada');
assert.equal(text($('.rg-step[data-kind=sandbox_waiting] .rg-step-time', host)), '');
assert.equal(text($('.rg-step[data-kind=sandbox_acquired] .rg-step-time', host)), '1 s');
assert.equal(text($('.rg-step[data-kind=sandbox_prepared] .rg-step-time', host)), '2 s');
assert.doesNotMatch(text(host), /87 s|1 min 27 s|Entorno aislado reservado/);
""")

    def test_visual_review_requires_all_pages_and_only_confirms_visual_checks(self):
        self.agent(r"""
const base = '/chat/agent/artifacts/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/';
const artifact = {id: 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb', revision: 1, format: 'pdf', status: 'candidate',
  preview: {title: 'Informe', pages: [base + 'pages/1/', base + 'pages/2/']}, review_url: base + 'review/',
  download_url: base + 'download/', sha256: 'safe-digest', page_sha256: ['a', 'b'], review_checks: ['legibility']};
const run = {...RUN, status: 'active'};
const {host} = await mount(run, snapshot(run, {artifacts: [artifact],
  events: [{id: 1, kind: 'visual_pending', data: {text: 'Comprobaciones automáticas completadas. Revisa todas las páginas antes de publicar.'}}]}));
assert.equal(title(host), 'Revisión visual pendiente');
assert.equal($('.rg-activity-body', host).hidden, true);
assert.equal($('#composerHint').textContent, 'Pendiente de tu revisión visual');
const card = $('.rg-deliverable', host);
const control = buttonNamed('Confirmar revisión visual', card);
const images = $$('.rg-pages img', card);
assert.equal(images.length, 2);
assert.equal(control.disabled, true);
images[0].onload();
assert.equal(control.disabled, true);
images[1].onload();
assert.equal(control.disabled, false);
assert.match(text(card), /Revisa las 2 páginas antes de publicar/);
assert.match(text(card), /únicamente la revisión visual/);
assert.equal($$('a[download]', card).length, 0);
let review;
net.on('POST ' + base + 'review/', request => { review = request; return net.json({status: 'reviewed'}); });
await click(control);
assert.deepEqual(JSON.parse(review.body), {sha256: 'safe-digest', page_sha256: ['a', 'b'], checks: ['legibility']});
assert.ok(review.headers['x-csrftoken']);
assert.equal(review.headers['content-type'], 'application/json');
""")

    def test_terminal_error_is_visible_once_and_the_next_run_starts_clean(self):
        self.agent(r"""
const error = 'La investigación está deshabilitada. No se han consultado fuentes.';
const failed = runAt('run-f', {status: 'failed'});
const {host} = await mount(failed, snapshot(failed, {result: {receipt: RECEIPT, error},
  events: [{id: 1, kind: 'queued', data: {text: 'En cola'}}, {id: 2, kind: 'failed', data: {text: error}}]}));
assert.equal((text(host).match(/La investigación está deshabilitada/g) || []).length, 1);
assert.equal($('.rg-agent-message', host).hidden, false);
assert.equal(text($('.rg-agent-message', host)), error);
assert.equal(title(host), 'No completado');
const next = runAt('run-g', {status: 'active'});
const second = await mount(next, snapshot(next));
assert.equal($('.rg-agent-message', second.host).hidden, true);
assert.equal(text($('.rg-agent-message', second.host)), '');
assert.equal(text($('.rg-agent-message', host)), error);
""")

    def test_error_box_stays_hidden_until_the_snapshot_reports_a_failure(self):
        self.agent(r"""
const run = runAt('run-wait', {status: 'failed'});
const held = net.hold();
net.on('GET ' + run.status_url, () => held.promise);
const host = hostFor(run);
regulayAgent.mount(host, run);
await flush();
assert.equal($('.rg-agent-message', host).hidden, true);
assert.equal($('.rg-limits', host).hidden, true);
held.resolve(net.json(snapshot(run, {result: {receipt: RECEIPT, error: 'Sin fuentes.'}})));
await flush();
assert.equal($('.rg-agent-message', host).hidden, false);
assert.equal(text($('.rg-agent-message', host)), 'Sin fuentes.');
""")

    def test_summary_identifies_estimated_subtotal_without_claiming_complete_cost(self):
        self.agent(r"""
const {host} = await mount(RUN, snapshot(RUN, {result: {receipt: {calls: [{model_effective: 'model-a', cost_kind: 'tariff_estimate'}],
  total: {cost: null, known_cost: '0.004', currency: 'USD'}}}}));
assert.match(text($('.rg-receipt', host)), /Coste\n0\.004 USD conocido · incluye estimación · total no disponible/);
assert.match(text($('.rg-receipt', host)), /Modelo efectivo\nmodel-a/);
""")

    def test_stale_snapshot_cannot_replace_a_newer_one(self):
        self.agent(r"""
const run = {...RUN, status: 'active'};
const held = net.hold();
let first = true;
net.on('GET ' + run.status_url, () => first ? (first = false, held.promise) :
  net.json(snapshot({...run, status: 'cancelled'}, {events: [{id: 2, kind: 'cancelled', data: {text: 'Ejecución cancelada'}}]})));
const host = hostFor(run);
const watcher = regulayAgent.mount(host, run);
await flush();
await watcher.refresh();
assert.equal(title(host), 'Cancelado');
held.resolve(net.json(snapshot(run, {events: [{id: 1, kind: 'compose', data: {text: 'Respuesta anterior'}}]})));
await flush();
assert.equal(title(host), 'Cancelado');
assert.doesNotMatch(text(host), /Respuesta anterior|Redactando/);
// Runs are separate: another run's late reply never touches this one.
const other = runAt('run-b', {status: 'active'});
const late = net.hold();
net.on('GET ' + other.status_url, () => late.promise);
const otherHost = hostFor(other);
regulayAgent.mount(otherHost, other);
await flush();
late.resolve(net.json(snapshot({...other, status: 'completed'}, {events: [{id: 9, kind: 'completed', data: {text: 'Otra'}}]})));
await flush();
assert.equal(title(otherHost), 'Listo');
assert.equal(title(host), 'Cancelado');
assert.doesNotMatch(text(host), /Otra/);
""")

    def test_failed_old_request_does_not_clear_newer_state(self):
        self.agent(r"""
const run = {...RUN, status: 'active'};
const held = net.hold();
let first = true;
net.on('GET ' + run.status_url, () => first ? (first = false, held.promise) : net.json(snapshot({...run, status: 'completed'})));
const host = hostFor(run);
const watcher = regulayAgent.mount(host, run);
await flush();
await watcher.refresh();
held.reject(new TypeError('Old network failure'));
await flush();
assert.equal(title(host), 'Listo');
assert.equal(watcher.unavailable, false);
assert.ok($('.rg-receipt', host).children.length);
""")

    def test_real_events_are_deduplicated_and_unavailable_state_removes_private_projection(self):
        self.agent(r"""
const base = '/chat/agent/artifacts/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/';
const run = {...RUN, status: 'active'};
const artifact = {id: 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb', revision: 1, format: 'pdf', status: 'candidate',
  preview: {title: 'Privado', pages: [base + 'pages/1/']}, review_url: base + 'review/'};
const {host} = await mount(run, snapshot(run, {artifacts: [artifact], events: [{id: 1, kind: 'compose', data: {text: 'Componiendo el informe'}}]}));
const source = sources.at(-1);
assert.equal(source.url, run.events_url + '?cursor=1');
source.emit('progress', {id: 1, kind: 'compose', data: {text: 'Componiendo el informe'}});
source.emit('progress', {id: 2, kind: 'render', data: {text: 'Renderizando cinco páginas'}});
assert.deepEqual($$('.rg-step', host).map(step => step.dataset.kind), ['compose', 'render']);
assert.equal(title(host), 'Renderizando páginas');
assert.match(text(host), /Renderizando cinco páginas/);
assert.doesNotMatch(text(host), /Excel|fórmulas/);
source.emit('revoked', '');
assert.equal(source.closed, true);
assert.equal(buttonNamed('Detener', host), undefined);
assert.equal($$('.rg-deliverable', host).length, 0);
assert.equal($('.rg-receipt', host).children.length, 0);
assert.doesNotMatch(text(host), /Privado/);
assert.equal(title(host), 'Estado no disponible');
assert.ok(buttonNamed('Actualizar estado', host));
assert.equal($('#stopButton').hidden, true);
""")

    def test_activity_shows_recorded_steps_tools_and_measured_time_only(self):
        self.agent(r"""
const run = runAt('run-p', {professional: true, created_at: '2026-10-14T10:00:00+00:00', finished_at: '2026-10-14T10:02:05+00:00',
  request: {formats: ['xlsx'], language: 'es', research_required: true}});
const at = seconds => new Date(Date.parse('2026-10-14T10:00:00+00:00') + seconds * 1000).toISOString();
const events = [
  {id: 1, kind: 'queued', created_at: at(0), data: {text: 'Petición aceptada.', duration_ms: 3000}},
  {id: 2, kind: 'claimed', created_at: at(3), data: {text: 'Ejecución iniciada.'}},
  {id: 3, kind: 'searching', created_at: at(5), data: {text: 'Buscando fuentes en la web pública.', tool: 'web_search'}},
  {id: 4, kind: 'reading', created_at: at(20), data: {text: 'Leyendo una fuente.', tool: 'web_open', duration_ms: 20000}},
  {id: 5, kind: 'reading', created_at: at(40), data: {text: 'Leyendo otra fuente.', tool: 'web_find', duration_ms: 20000}},
  {id: 6, kind: 'executing', created_at: at(60), data: {text: 'Trabajando con archivos.', tool: 'execute'}},
  {id: 7, kind: 'completed', created_at: at(125), data: {text: 'Entregable disponible.'}}];
const {host} = await mount(run, snapshot(run, {events,
  sources: [{title: 'Red Eléctrica', url: 'https://www.ree.es/es/datos', opened: true, reading: 'complete', retrieved_at: at(30), publication_date: '2026-09-30'},
    {title: 'Resultado', url: 'javascript:alert(1)', opened: false, snippet: 'Sin abrir'}],
  operations: [{name: 'web_search', status: 'completed'},
    {name: 'execute', status: 'completed', details_url: '/chat/agent/runs/aaaaaaaa-0000-0000-0000-000000000000/operations/3/'}]}));
assert.equal(title(host), 'Listo');
assert.equal(text($('.rg-activity-meta', host)), '6 pasos · 1 fuente · 2 min 5 s');
const steps = $$('.rg-step', host);
assert.deepEqual(steps.map(step => step.dataset.kind), ['queued', 'claimed', 'searching', 'reading', 'executing', 'completed']);
assert.ok(steps.every(step => step.dataset.state === 'done'));
assert.equal(text($('.rg-step-count', steps[3])), '×2');
assert.equal(text($('.rg-step-time', steps[0])), '3 s');
assert.equal(text($('.rg-step-time', steps[3])), '40 s');
assert.equal(text($('.rg-step-text', steps[2])), 'búsqueda web');
assert.equal(text($('.rg-step-text', steps[3])), 'abrir página, buscar en la página');
assert.equal(text($('.rg-step-text', steps[5])), 'Entregable disponible.');
assert.equal(steps[3].title, 'Leyendo otra fuente.');
assert.doesNotMatch(text(host), /%|Paso \d+ de|restante|estimad/);
assert.match(text(host), /Fuentes · 1 consultada/);
const links = $$('.rg-sources a', host);
assert.equal(links[0].getAttribute('href'), 'https://www.ree.es/es/datos');
assert.equal(links[1].hasAttribute('href'), false);
assert.match(text(host), /Resultado del buscador · no abierto/);
assert.match(text(host), /Herramientas · 2\nbúsqueda web · completada|Herramientas · 2/);
assert.equal($$('.rg-ops button', host).length, 1);
const bare = runAt('run-q');
const second = await mount(bare, snapshot(bare, {events: [{id: 1, kind: 'queued', data: {text: 'x'}}, {id: 2, kind: 'completed', data: {text: 'y'}}]}));
assert.equal(text($('.rg-activity-meta', second.host)), '2 pasos');
assert.ok($$('.rg-step-time', second.host).every(node => node.textContent === ''));
""")

    def test_interrupted_run_time_ends_at_its_last_recorded_step(self):
        self.agent(r"""
const at = seconds => new Date(Date.parse('2026-10-14T21:54:53+00:00') + seconds * 1000).toISOString();
// The interruption is recorded when the abandoned lease is noticed, here ten hours later.
const run = runAt('run-i', {status: 'interrupted', professional: true, created_at: at(0), finished_at: at(36000)});
const events = [
  {id: 1, kind: 'queued', created_at: at(0), data: {text: 'Petición aceptada.'}},
  {id: 2, kind: 'executing', created_at: at(20), data: {text: 'Trabajando con archivos.', tool: 'execute'}},
  {id: 3, kind: 'reading', created_at: at(60), data: {text: 'Leyendo una fuente.', tool: 'web_open'}},
  {id: 4, kind: 'reading', created_at: at(140), data: {text: 'Leyendo otra fuente.', tool: 'web_open'}},
  {id: 5, kind: 'interrupted', created_at: at(36000), data: {text: 'Ejecución interrumpida.'}}];
const {host} = await mount(run, snapshot(run, {events}));
assert.equal(title(host), 'Interrumpido');
assert.equal(text($('.rg-activity-meta', host)), '4 pasos · 2 min 20 s');
const steps = $$('.rg-step', host);
assert.equal(text($('.rg-step-time', steps[1])), '');
assert.equal(text($('.rg-step-time', steps[2])), '');
assert.doesNotMatch(text(host), /\d h /);
""")

    def test_activity_is_open_while_working_and_respects_the_reader(self):
        self.agent(r"""
const run = {...RUN, status: 'active'};
const {host} = await mount(run, snapshot(run, {events: [{id: 1, kind: 'queued', data: {text: 'q'}}]}));
const head = $('.rg-activity-head', host), body = $('.rg-activity-body', host);
assert.equal(head.getAttribute('aria-expanded'), 'true');
assert.equal(head.getAttribute('aria-controls'), body.id);
assert.equal(body.hidden, false);
await click(head);
assert.equal(body.hidden, true);
assert.equal(head.getAttribute('aria-expanded'), 'false');
sources.at(-1).emit('progress', {id: 2, kind: 'compose', data: {text: 'c'}});
assert.equal(body.hidden, true);
await click(head);
assert.equal(body.hidden, false);
const done = runAt('run-d');
const finished = await mount(done, snapshot(done, {events: [{id: 1, kind: 'completed', data: {text: 'ok'}}]}));
assert.equal($('.rg-activity-body', finished.host).hidden, true);
assert.equal($('.rg-activity-head', finished.host).getAttribute('aria-expanded'), 'false');
""")

    def test_export_needs_explicit_approval_and_uncertain_results_are_reconciled(self):
        self.agent(r"""
const run = runAt('run-e', {status: 'active'});
const proposal = {account: 'drive@empresa.example', folder: 'Informes', name: 'informe-r2.xlsx', revision: 2, bytes: 1024,
  sha256: 'f'.repeat(64), status: 'pending', binding: 'binding-1', expires_at: new Date(Date.now() + 3600e3).toISOString(),
  decision_url: '/chat/agent/exports/e1/decision/', preview_url: '/chat/agent/artifacts/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/download/'};
const {host} = await mount(run, snapshot(run, {export: proposal, events: [{id: 1, kind: 'approval_pending', data: {text: 'Exportación preparada.'}}]}));
const card = $('.rg-export', host);
assert.match(text(card), /Cuenta\ndrive@empresa\.example\nCarpeta\nInformes\nNombre\ninforme-r2\.xlsx\nRevisión\n2\nEfecto\nCrear un archivo nuevo/);
assert.match(text(card), /Estado\nEsperando aprobación/);
assert.equal($('a', card).getAttribute('href'), proposal.preview_url);
assert.equal(title(host), 'Exportación pendiente de aprobación');
assert.equal($('#composerHint').textContent, 'Pendiente de tu aprobación');
let decision;
net.on('POST /chat/agent/exports/e1/decision/', request => { decision = request; return net.json({status: 'approved'}); });
await click(buttonNamed('Aprobar esta exportación', card));
assert.deepEqual(JSON.parse(decision.body), {binding: 'binding-1', decision: 'approve'});
const expired = runAt('run-x', {status: 'active'});
const stale = await mount(expired, snapshot(expired, {export: {...proposal, expires_at: new Date(Date.now() - 1000).toISOString()}}));
assert.equal(buttonNamed('Aprobar esta exportación', stale.host), undefined);
const interrupted = runAt('run-u', {status: 'interrupted'});
const second = await mount(interrupted, snapshot(interrupted, {export: {...proposal, status: 'uncertain'}}));
assert.equal(buttonNamed('Aprobar esta exportación', second.host), undefined);
assert.match(text(second.host), /Estado\nResultado por confirmar/);
let recover;
net.on('POST /chat/agent/runs/run-u/recover-export/', request => { recover = request; return net.json({status: 'authorized'}); });
await click(buttonNamed('Reconciliar el resultado de la exportación', second.host));
assert.ok(recover);
assert.equal(net.find('POST', '/chat/agent/exports/e1/decision/').length, 1);
""")

    @override_settings(REGULAY_AGENT_ENABLED=True)
    def test_agent_send_names_the_revision_it_changes_and_mounts_its_own_activity(self):
        profile, conversation = self.agent_conversation()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=profile, enabled=True)
        _, run = self.agent_turn(conversation, 'Crea un informe', 'completed', profile, 'completed')
        revision = {'id': 'aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb', 'logical_id': run.job['logical_id'], 'revision': 2, 'format': 'docx',
                    'status': 'verified', 'preview': {'title': 'Informe trimestral', 'page_count': 3, 'pages': []}}
        path = f'/chat/{conversation.pk}/'
        self.agent(r"""
const context = $('#composerContext');
assert.equal(context.hidden, false);
assert.equal(text(context), 'Los cambios se aplicarán a «Informe trimestral», revisión 2');
assert.equal(regulayAgent.capture(null).artifactId, LOGICAL);
assert.equal(regulayAgent.capture(null).baseRevision, 'aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb');
assert.equal(regulayAgent.capture(file('datos.csv')).artifactId, false);
assert.equal($('#fileInput').accept, '.csv,.xlsx');
let posted;
net.on('POST /chat/CONVERSATION/send/', request => { posted = request; return net.json({status: 'accepted', success: true, mode: 'agent',
  request_id: request.body.get('request_id'), conversation_id: CONVERSATION, agent: {id: 'run-new', status: 'queued',
  status_url: '/chat/agent/runs/run-new/', events_url: '/chat/agent/runs/run-new/events/', cancel_url: '/chat/agent/runs/run-new/cancel/',
  request: {formats: ['docx'], operation: 'edit', language: 'es'}}}, {status: 202}); });
net.on('GET /chat/agent/runs/run-new/', () => net.json(snapshot(runAt('run-new', {status: 'queued', request: {formats: ['docx'], operation: 'edit'}}),
  {events: [{id: 1, kind: 'queued', data: {text: 'Petición aceptada.'}}]})));
await typeInto($('#prompt'), 'Añade un resumen ejecutivo');
await click($('#sendButton'));
assert.equal(posted.body.get('mode'), 'agent');
assert.equal(posted.body.get('artifact_id'), LOGICAL);
assert.equal(posted.body.get('base_revision'), 'aaaaaaaa-2222-3333-4444-bbbbbbbbbbbb');
assert.equal(posted.body.get('stream'), null);
assert.equal(context.hidden, true);
const created = $('[data-agent-run="run-new"]');
assert.ok(created);
assert.equal(title(created), 'En cola');
assert.match(text(created), /Petición interpretada: Editar DOCX/);
assert.equal($$('.rg-activity').length, 2);
assert.equal($('#stopButton').hidden, false);
""".replace('LOGICAL', json.dumps(run.job['logical_id'])).replace('CONVERSATION', str(conversation.pk)), path,
            routes=[{'url': f'/chat/agent/runs/{run.pk}/', 'json': self.stored_snapshot(run, current_revision=revision)}])

    def test_run_projection_and_events_carry_server_times(self):
        profile, conversation = self.agent_conversation()
        _, run = self.agent_turn(conversation, 'Crea un informe', 'completed', profile, 'completed')
        event(run, 'queued')
        event(run, 'completed')
        data = run_data(run)
        self.assertEqual(data['created_at'], run.created_at.isoformat())
        self.assertEqual(data['started_at'], run.started_at.isoformat())
        self.assertEqual(data['finished_at'], run.finished_at.isoformat())
        rows = _events(run.events.all())
        self.assertEqual([row['kind'] for row in rows], ['queued', 'completed'])
        for row in rows:
            self.assertEqual(datetime.fromisoformat(row['created_at']), run.events.get(pk=row['id']).created_at)
        self.assertEqual([row['kind'] for row in _events(run.events.all(), limit=1)], ['queued'])
        queued = AgentExecution.objects.filter(pk=run.pk)
        queued.update(started_at=None, finished_at=None)
        self.assertEqual((run_data(queued.get())['started_at'], run_data(queued.get())['finished_at']), (None, None))

    @override_settings(REGULAY_AGENT_ENABLED=True)
    def test_drive_picker_appears_only_for_agent_requests_with_the_connector(self):
        profile, conversation = self.agent_conversation()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=profile, enabled=True)
        chat = Conversation.objects.create(user=self.user, title='Chat normal')
        for path in ('/chat/', f'/chat/{conversation.pk}/', f'/chat/{chat.pk}/'):
            self.assertNotContains(self.client.get(path), 'id="drivePanel"')
        with override_settings(REGULAY_AGENT_MCP_ENABLED=True):
            self.assertContains(self.client.get(f'/chat/{conversation.pk}/'), 'id="drivePanel"')
            self.assertNotContains(self.client.get(f'/chat/{chat.pk}/'), 'id="drivePanel"')
            page = self.client.get('/chat/')
            self.assertContains(page, 'id="drivePanel"')
            self.browse(r"""
const button = $('#driveButton'), panel = $('#drivePanel');
assert.equal(button.hidden, true);
await click($('input[name=conversation_mode][value=agent]'));
assert.equal(button.hidden, false);
await click(button);
assert.equal(panel.hidden, false);
assert.equal(button.getAttribute('aria-expanded'), 'true');
assert.equal(document.activeElement, $('#agentDocumentQuery'));
net.on('POST /chat/agent/documents/search/', () => net.json({documents: [{reference: 'ref-1', label: 'ventas.xlsx'}]}));
await typeInto($('#agentDocumentQuery'), 'ventas');
await click($('#agentDocumentSearch'));
await click($$('#agentDocumentResults button')[0]);
assert.equal(text($('#composerContext')), 'Archivo de Drive: ventas.xlsx');
assert.equal(regulayAgent.capture(null).documentReference, 'ref-1');
await click($('input[name=conversation_mode][value=chat]'));
assert.equal(button.hidden, true);
assert.equal(panel.hidden, true);
assert.equal($('#composerContext').hidden, true);
assert.deepEqual(regulayAgent.capture(null), {});
""", page)

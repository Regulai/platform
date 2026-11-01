/* Agent runs inside the conversation: one activity component per request.
 * It shows registered events, the server's interpretation of the request,
 * recorded tool operations, sources and checks. Nothing is inferred: no plan,
 * percentage, time or verification is shown unless the server recorded it.
 * Document and inference content is only ever inserted as text. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const list = value => Array.isArray(value) ? value : [];
  const present = value => value !== null && value !== undefined && value !== '';
  const csrf = () => document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
  const LIVE = ['queued', 'active', 'outcome_unknown'];
  const live = status => LIVE.includes(status);
  const SVG = 'http://www.w3.org/2000/svg';
  const chat = () => window.regulayChat || null;

  const labels = {
    queued: 'En cola', active: 'En curso', outcome_unknown: 'Resultado por confirmar',
    completed: 'Finalizado', failed: 'No completado', interrupted: 'Interrumpido', cancelled: 'Cancelado',
    expired: 'Caducado', pending: 'Pendiente', passed: 'Superada', not_performed: 'No realizada',
    consulted: 'Consultado', not_consulted: 'No consultado', disabled: 'Deshabilitado', no_response: 'Sin respuesta',
    allow: 'Permitido', allowed: 'Permitido', block: 'Bloqueado', blocked: 'Bloqueado', unavailable: 'No disponible',
    continue: 'Continuar', not_required: 'No requerido', required: 'Requerido', automatic: 'Automática',
    agent_profile: 'Perfil del agente', classification: 'Clasificación', generation: 'Generación',
    research: 'Consulta de fuentes', primary_source_read: 'Consulta de fuente primaria', no_api_charge: 'Sin cargo de API',
    verification: 'Comprobación', not_used: 'Sin fallback de Regulay', used: 'Utilizado', unknown: 'No disponible',
    reviewed: 'Revisada por el modelo', web_search: 'Búsqueda web', web_read: 'Lectura web',
    web_browser_resource: 'Recurso del navegador', package_download: 'Descarga de dependencia',
    configured_upper_bound_estimate: 'Estimación máxima configurada', started: 'Iniciada', partial: 'Parcial',
  };
  const label = value => labels[value] || (present(value) ? String(value) : 'No disponible');
  // Short names for registered event kinds; the server sentence stays available on the step.
  const STEP = {
    queued: 'En cola', claimed: 'Ejecución iniciada', recovered: 'Recuperación solicitada',
    sandbox_waiting: 'Esperando un entorno disponible', sandbox_preparing: 'Preparando el entorno',
    sandbox_acquired: 'Entorno reservado', sandbox_prepared: 'Entorno preparado', provider_waiting: 'Esperando capacidad del proveedor',
    provider_started: 'Generando la respuesta', provider_completed: 'Generación terminada',
    generation: 'Generando la respuesta', capacity_waiting: 'Esperando capacidad disponible',
    input: 'Leyendo el archivo', calculate: 'Calculando con Python', recalculate: 'Recalculando fórmulas',
    rename: 'Renombrando la revisión', compose: 'Redactando el documento', render: 'Renderizando páginas',
    verify: 'Comprobando el archivo final', searching: 'Buscando fuentes', reading: 'Leyendo fuentes',
    executing: 'Trabajando con archivos y código', installing: 'Preparando dependencias', verifying: 'Comprobando el resultado',
    visual_pending: 'Revisión visual pendiente', visual_reviewed: 'Revisión visual registrada',
    draft: 'Comprobación no superada', verified: 'Comprobaciones técnicas superadas',
    approval_pending: 'Exportación pendiente de aprobación', export_intent: 'Exportando a Google Drive',
    export_completed: 'Exportación confirmada', export_uncertain: 'Exportación por confirmar',
    export_recovery: 'Recuperación de la exportación', completed: 'Finalizado', cancelled: 'Cancelado',
    interrupted: 'Interrumpido', failed: 'No completado',
    'inference.started': 'Generando', 'inference.finished': 'Generación terminada',
    'inference.delivery': 'Comprobando antes de mostrar', 'tool.started': 'Ejecutando herramienta',
    'tool.finished': 'Herramienta terminada', 'skill.activated': 'Skill activada',
    'artifact.available': 'Archivo disponible', 'run.finished': 'Ejecución terminada', interval: 'Tiempo registrado',
  };
  const TOOLS = {web_search: 'búsqueda web', web_open: 'abrir página', web_find: 'buscar en la página',
    web_download: 'descarga', web_browse: 'navegador', ls: 'listar archivos', read_file: 'leer archivo',
    write_file: 'escribir archivo', edit_file: 'editar archivo', glob: 'buscar archivos', grep: 'buscar texto',
    execute: 'ejecutar código', install_packages: 'instalar dependencias', publish_artifact: 'publicar entregable',
    inspect_image: 'revisar imagen', read_output: 'leer salida'};
  const WAITING = new Set(['visual_pending', 'approval_pending']);
  const FAILED = new Set(['draft', 'failed']);
  const UNCERTAIN = new Set(['interrupted', 'export_uncertain']);
  const REFRESH = new Set(['claimed', 'input', 'calculate', 'compose', 'render', 'verify', 'recalculate', 'rename',
    'visual_pending', 'verified', 'draft', 'approval_pending', 'export_completed', 'export_uncertain', 'inference_completed',
    'visual_reviewed', 'searching', 'reading', 'executing', 'installing', 'verifying',
    'sandbox_waiting', 'sandbox_preparing', 'sandbox_acquired', 'sandbox_prepared', 'provider_waiting', 'provider_started', 'provider_completed',
    'tool.finished', 'artifact.available', 'run.finished']);

  function node(tag, value, parent, className = '') {
    const element = document.createElement(tag);
    if (value != null) element.textContent = String(value);
    if (className) element.className = className;
    if (parent) parent.appendChild(element);
    return element;
  }
  function icon(name, parent, className = 'rg-i') {
    const svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('class', className);
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    if (parent) parent.appendChild(svg);
    return svg;
  }
  function button(value, parent, action, className = 'rg-btn', iconName = null) {
    const element = node('button', null, parent, className);
    element.type = 'button';
    if (iconName) icon(iconName, element);
    element.appendChild(document.createTextNode(value));
    element.addEventListener('click', action);
    return element;
  }
  function detail(parent, name, value) {
    if (!present(value)) return;
    node('dt', name, parent);
    node('dd', value, parent);
  }
  function details(parent, title, className = 'rg-disclosure') {
    const element = node('details', null, parent, className);
    node('summary', title, element);
    return element;
  }
  function amount(value, currency) {
    return present(value) && Number.isFinite(Number(value)) ? `${value} ${currency || ''}`.trim() : 'No disponible';
  }
  function timestamp(value) {
    if (!value || !Number.isFinite(Date.parse(value))) return 'No disponible';
    return new Date(value).toLocaleString('es-ES');
  }
  function duration(ms) {
    if (!Number.isFinite(ms) || ms < 1000) return '';
    const seconds = Math.round(ms / 1000);
    if (seconds < 60) return `${seconds} s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return seconds % 60 ? `${minutes} min ${seconds % 60} s` : `${minutes} min`;
    return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
  }
  const time = value => (value && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null);
  function artifactUrl(value, action) {
    const query = action === 'download' ? '(?:\\?format=(?:docx|pdf))?' : '';
    return typeof value === 'string' && new RegExp('^/chat/agent/artifacts/[0-9a-f-]+/' + action + '/' + query + '$').test(value);
  }
  async function post(url, body) {
    const options = {method: 'POST', headers: {'X-CSRFToken': csrf()}};
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    const response = await fetch(url, options);
    if (!response.ok) throw new Error('unavailable');
    return response.json();
  }

  /* ------------------------------------------------------------ records */
  function checkRows(parent, checks) {
    const names = {integrity: 'Integridad del archivo', instructions: 'Formato e instrucciones',
      layout: 'Maquetación y paginación', sources: 'Fuentes y respaldo factual', security: 'Seguridad y políticas'};
    const area = node('ul', null, parent, 'rg-checks');
    const counts = {passed: 0, failed: 0, reviewed: 0, partial: 0, not_performed: 0};
    Object.entries(names).forEach(([key, title]) => {
      const check = checks?.[key] || {};
      const status = ['passed', 'failed', 'reviewed', 'partial'].includes(check.status) ? check.status : 'not_performed';
      counts[status]++;
      const item = node('li', null, area, 'rg-check');
      item.dataset.status = status;
      node('span', title, item, 'rg-check-label');
      node('span', status === 'failed' ? 'Fallida' : label(status), item, 'rg-check-status');
      node('small', check.detail || 'No hay una comprobación registrada para esta categoría.', item);
    });
    return counts;
  }
  function checkSummary(counts) {
    const parts = [];
    const add = (count, one, many) => { if (count) parts.push(`${count} ${count === 1 ? one : many}`); };
    add(counts.passed, 'superada', 'superadas');
    add(counts.reviewed, 'revisada por el modelo', 'revisadas por el modelo');
    add(counts.failed, 'fallida', 'fallidas');
    add(counts.partial, 'parcial', 'parciales');
    add(counts.not_performed, 'no realizada', 'no realizadas');
    return 'Comprobaciones técnicas · ' + parts.join(', ');
  }
  function renderJev(parent, jev = {}) {
    jev = jev && typeof jev === 'object' ? jev : {};
    const area = node('dl', null, parent, 'rg-facts');
    detail(area, 'Estado de Jev', jev.status === 'failed' ? 'Falló' : label(jev.status || 'unknown'));
    detail(area, 'Propósito', label(jev.purpose));
    detail(area, 'Consulta', jev.consulted_at ? timestamp(jev.consulted_at) : 'No consta una consulta');
    if (jev.completed_at) detail(area, 'Fin', timestamp(jev.completed_at));
    if (jev.decision && typeof jev.decision === 'object') {
      Object.entries({category: 'Categoría', task: 'Tarea', difficulty: 'Dificultad'}).forEach(([key, name]) => detail(area, name, jev.decision[key]));
    } else if (typeof jev.decision === 'string') detail(area, 'Decisión', jev.decision);
    detail(area, 'Motivos devueltos', list(jev.reasons).join(' · ') || 'Jev no ha proporcionado motivos textuales.');
    detail(area, 'Recomendaciones devueltas', list(jev.recommendations).join(' · ') || 'Jev no ha proporcionado recomendaciones textuales.');
    const policy = jev.policy || {};
    detail(area, 'Política aplicada', [policy.source, present(policy.revision) ? `revisión ${policy.revision}` : null].filter(Boolean).join(' · ') || 'No disponible');
    detail(area, 'Clasificación exigida', policy.classification);
    detail(area, 'Umbral de la política', policy.threshold);
    detail(area, 'Efecto sobre la ejecución', label(jev.effect));
    if (jev.applied && typeof jev.applied === 'object') {
      detail(area, 'Decisión aplicada por Regulay', [jev.applied.sensitivity, jev.applied.task, jev.applied.difficulty].filter(present).join(' · '));
    }
    detail(area, 'Motivos locales del efecto', list(jev.reason_codes).join(' · '));
    if (jev.signals && typeof jev.signals === 'object' && Object.keys(jev.signals).length) {
      node('pre', JSON.stringify(jev.signals, null, 2), details(parent, 'Señales estructuradas devueltas por Jev'), 'rg-signals');
    }
    node('p', 'La decisión de enrutamiento se muestra en cada llamada. Una autorización local no es una aprobación de Jev.', parent, 'rg-explain');
  }
  // Long runs record hundreds of calls: build their rows when the reader opens the list.
  const EAGER_CALLS = 40;
  function renderCalls(parent, calls) {
    if (!calls.length) { node('p', 'No hay llamadas registradas.', parent, 'rg-explain'); return; }
    if (calls.length > EAGER_CALLS && parent.localName === 'details' && !parent.open) {
      const build = () => {
        if (!parent.open || parent.querySelector('.rg-calls')) return;
        parent.removeEventListener('toggle', build);
        callRows(parent, calls);
      };
      parent.addEventListener('toggle', build);
      return;
    }
    callRows(parent, calls);
  }
  function callRows(parent, calls) {
    const area = node('ol', null, parent, 'rg-calls');
    calls.forEach((call, index) => {
      const noModel = call.purpose === 'research' ? 'Lectura sin modelo' : 'No disponible';
      const row = details(node('li', null, area), `${call.sequence || index + 1}. ${label(call.purpose)} · ${call.model_effective || noModel}`);
      const values = node('dl', null, row, 'rg-facts');
      detail(values, 'Estado', label(call.status));
      detail(values, 'Proveedor', call.provider_name || call.provider || 'No disponible');
      detail(values, 'Modelo solicitado', call.model_requested || call.model || noModel);
      detail(values, 'Modelo efectivo', call.model_effective || noModel);
      detail(values, 'Propósito', label(call.purpose));
      if (call.route && typeof call.route === 'object') {
        detail(values, 'Ruta', label(call.route.mode)); detail(values, 'Destino', call.route.destination);
        detail(values, 'Conector', call.route.connector); detail(values, 'Proveedor de destino', call.route.upstream_provider);
      } else detail(values, 'Ruta', call.route || 'No disponible');
      const fallback = call.fallback;
      detail(values, 'Fallback', typeof fallback === 'object' && fallback ? label(fallback.status) : fallback === true ? 'Utilizado' : fallback === false ? 'No utilizado' : 'No disponible');
      if (fallback && typeof fallback === 'object') detail(values, 'Motivo de fallback', fallback.reason);
      detail(values, 'Inicio', call.started_at ? timestamp(call.started_at) : null);
      detail(values, 'Duración', present(call.duration_ms) ? `${call.duration_ms} ms` : 'No disponible');
      detail(values, 'Coste', amount(call.cost, call.currency));
      detail(values, 'Origen del coste', ({provider_reported: 'Informado por el proveedor', tariff_estimate: 'Estimación con las tarifas configuradas',
        no_api_charge: labels.no_api_charge, configured_upper_bound_estimate: labels.configured_upper_bound_estimate, unknown: 'No disponible'})[call.cost_kind] || 'No disponible');
      if (call.protection && typeof call.protection === 'object') {
        const reused = Number(call.protection.reused) || 0, fresh = Number(call.protection.protected) || 0;
        detail(values, 'Protección del historial', `${reused} ${reused === 1 ? 'mensaje reutilizado' : 'mensajes reutilizados'} · ` +
          `${fresh} ${fresh === 1 ? 'protegido' : 'protegidos'} en esta llamada`);
      }
      if (call.jev) renderJev(details(row, 'Consulta Jev de esta llamada'), call.jev);
    });
  }
  function renderReceipt(parent, receipt = {}, opened = {}) {
    parent.replaceChildren();
    receipt = receipt && typeof receipt === 'object' ? receipt : {};
    const jevArea = details(parent, 'Consulta y decisión de Jev', 'rg-disclosure rg-jev');
    jevArea.open = Boolean(opened.jev);
    renderJev(jevArea, receipt.jev);
    const calls = list(receipt.calls);
    const sequence = details(parent, `Secuencia de llamadas · ${calls.length} ${calls.length === 1 ? 'llamada' : 'llamadas'}`, 'rg-disclosure rg-sequence');
    sequence.open = Boolean(opened.calls);
    renderCalls(sequence, calls);
    return parent;
  }
  function oversight(parent, receipt = {}, data = {}) {
    // A refresh during a live run must not close what the reader opened.
    const opened = {jev: Boolean(parent.querySelector('.rg-jev')?.open), calls: Boolean(parent.querySelector('.rg-sequence')?.open)};
    parent.replaceChildren();
    const calls = list(receipt.calls), total = receipt.total || {};
    const models = [...new Set(calls.map(call => call.model_effective).filter(Boolean))], cost = amount(total.cost, total.currency);
    const estimated = calls.some(call => ['tariff_estimate', 'configured_upper_bound_estimate'].includes(call.cost_kind)) ? ' · incluye estimación' : '';
    const summary = node('dl', null, parent, 'rg-facts rg-oversight');
    [['Seguridad local', label(receipt.policy?.status)],
      ['Jev', receipt.jev?.status === 'failed' ? 'Falló' : receipt.jev?.status ? label(receipt.jev.status) : 'Sin registro'],
      ['Modelo efectivo', models.length > 1 ? `${models.length} modelos · ${calls.length} llamadas` : models[0] || 'Sin dato efectivo'],
      ['Coste', cost === 'No disponible' && present(total.known_cost) ? `${amount(total.known_cost, total.currency)} conocido${estimated} · total no disponible` : cost + (cost === 'No disponible' ? '' : estimated)],
    ].forEach(([name, value]) => detail(summary, name, value));
    if (data.infrastructure) node('p', 'El coste mostrado corresponde a APIs. El coste del sandbox y del tráfico no está disponible.', parent, 'rg-explain');
    renderReceipt(parent.appendChild(document.createElement('div')), receipt, opened);
    if (list(receipt.policy?.reason_codes).length) node('p', receipt.policy.reason_codes.join(' · '), details(parent, 'Decisión de la política local'), 'rg-explain');
  }

  /* ------------------------------------------------------------ steps */
  function recordedDuration(event) {
    if (Number.isFinite(event.data?.duration_ms) && event.data.duration_ms >= 0) return event.data.duration_ms;
    const interval = event.data?.interval;
    const start = time(interval?.started_at), end = time(interval?.completed_at);
    return start !== null && end !== null && end >= start ? end - start : null;
  }
  function groupSteps(events) {
    const steps = [];
    events.forEach(event => {
      const last = steps[steps.length - 1];
      if (last && last.kind === event.kind) {
        last.count++;
        last.end = event;
        if (event.data?.text) last.text = event.data.text;  // The latest sentence describes the step now.
        if (event.data?.tool) last.tools.add(event.data.tool);
        const elapsed = recordedDuration(event);
        last.duration = last.duration === null || elapsed === null ? null : last.duration + elapsed;
        return;
      }
      steps.push({kind: event.kind, count: 1, start: event, end: event, text: event.data?.text || '',
        duration: recordedDuration(event),
        tools: new Set(event.data?.tool ? [event.data.tool] : [])});
    });
    return steps;
  }
  function stepState(step, index, steps, status) {
    if (FAILED.has(step.kind)) return 'failed';
    if (step.kind === 'cancelled') return 'cancelled';
    const last = index === steps.length - 1;
    if ((WAITING.has(step.kind) || UNCERTAIN.has(step.kind)) && last) return 'waiting';
    if (last && live(status)) return 'active';
    return 'done';
  }
  function headline(watcher) {
    const {status} = watcher.run;
    const steps = watcher.steps;
    const last = steps[steps.length - 1];
    if (watcher.unavailable) return {text: 'Estado no disponible', tone: 'bad', icon: 'alert'};
    const delivery = watcher.data?.delivery;
    if (delivery?.status === 'partial') return {text: 'Entrega parcial', tone: 'warn', icon: 'alert'};
    if (delivery?.status === 'failed') return {text: 'No se pudo entregar el archivo', tone: 'bad', icon: 'alert'};
    if (status === 'completed' && delivery?.status === 'complete') return {text: 'Archivo disponible', tone: 'ok', icon: 'check'};
    if (status === 'completed' && delivery?.status === 'not_required') return {text: 'Respuesta completada', tone: 'ok', icon: 'check'};
    if (live(status) && delivery?.status === 'pending' && list(watcher.data?.artifacts).length)
      return {text: 'Archivo generado, pendiente de entrega', tone: 'live', icon: null};
    if (status === 'completed') return {text: 'Listo', tone: 'ok', icon: 'check'};
    if (status === 'failed') return {text: 'No completado', tone: 'bad', icon: 'alert'};
    if (status === 'cancelled') return {text: 'Cancelado', tone: 'muted', icon: 'x'};
    if (status === 'interrupted') return {text: 'Interrumpido', tone: 'warn', icon: 'alert'};
    if (status === 'outcome_unknown') return {text: 'Resultado por confirmar', tone: 'warn', icon: 'clock'};
    if (!live(status)) return {text: label(status), tone: 'muted', icon: 'info'};
    if (watcher.generating) return {text: watcher.generating.mode === 'complete' ?
      'Generando · el texto se mostrará tras comprobarlo' : 'Generando', tone: 'live', icon: null};
    if (last && WAITING.has(last.kind)) return {text: STEP[last.kind], tone: 'warn', icon: last.kind === 'visual_pending' ? 'eye' : 'shield'};
    if (!watcher.loaded) return {text: 'Consultando el estado', tone: 'live', icon: null};
    return {text: last ? STEP[last.kind] || label(last.kind) : 'Preparando', tone: 'live', icon: null};
  }
  function brief(request) {
    if (!request || typeof request !== 'object') return '';
    if (!list(request.formats).length) return request.delivery_required ? 'Petición interpretada: Entregar un archivo' : '';
    const operation = {create: 'Crear', transform: 'Transformar', edit: 'Editar', download: 'Descargar'}[request.operation] || 'Crear';
    const parts = [`${operation} ${list(request.formats).map(value => String(value).toUpperCase()).join(' y ')}`];
    if (Number.isInteger(request.pages)) parts.push(`${request.pages} ${list(request.formats).includes('pptx') ? 'diapositivas' : 'páginas'}`);
    if (request.language) parts.push(request.language === 'en' ? 'en inglés' : 'en español');
    if (request.research_required) parts.push('con fuentes actuales');
    if (request.allow_mock) parts.push('datos ficticios solicitados');
    return 'Petición interpretada: ' + parts.join(' · ');
  }

  /* ------------------------------------------------------------ preview dialog */
  function dialogParts() {
    const dialog = byId('previewDialog');
    return dialog ? {dialog, title: byId('previewTitle'), meta: byId('previewMeta'), body: byId('previewBody'), foot: byId('previewFoot')} : null;
  }
  function openDialog(title, meta, fill, trigger) {
    const parts = dialogParts();
    if (!parts) return;
    parts.title.textContent = title;
    parts.meta.textContent = meta;
    parts.body.replaceChildren();
    parts.foot.replaceChildren();
    fill(parts.body, parts.foot);
    if (typeof parts.dialog.showModal === 'function') {
      if (!parts.dialog.open) parts.dialog.showModal();
    } else parts.dialog.setAttribute('open', '');
    parts.dialog.addEventListener('close', () => trigger?.focus?.(), {once: true});
  }
  function sheetTables(parent, preview) {
    if (Array.isArray(preview.sheets)) {
      preview.sheets.forEach(sheet => {
        const block = node('section', null, parent, 'rg-sheet');
        node('h4', `${sheet.name} · ${sheet.rows} filas · ${sheet.columns} columnas`, block);
        const table = node('table', null, node('div', null, block, 'rg-table'));
        const body = node('tbody', null, table);
        list(sheet.preview).forEach(row => { const tr = node('tr', null, body); list(row).forEach(value => node('td', value, tr)); });
      });
      return;
    }
    const table = node('table', null, node('div', null, parent, 'rg-table'));
    node('caption', 'Muestra del archivo generado', table).className = 'rg-sr';
    const header = node('tr', null, node('thead', null, table));
    list(preview.headers).forEach(value => { node('th', value, header).scope = 'col'; });
    const body = node('tbody', null, table);
    list(preview.rows).forEach(row => { const tr = node('tr', null, body); list(row).forEach(value => node('td', value, tr)); });
    if (present(preview.total_euros)) node('p', `Total del archivo: ${preview.total_euros} €`, parent, 'rg-explain');
    if (present(preview.rows_total)) node('p', `${preview.rows_total} filas en el archivo.`, parent, 'rg-explain');
  }

  /* ------------------------------------------------------------ one run */
  const watchers = new Map();
  let latest = null;
  let documentReference = null, documentLabel = '', pendingExport = null, chosenRevision = null;

  class Watcher {
    constructor(host, run) {
      this.host = host;
      this.run = {...run};
      this.events = [];
      this.steps = [];
      this.cursor = 0;
      this.version = 0;
      this.stream = null;
      this.timer = null;
      this.ticker = null;
      this.userOpen = null;
      this.loaded = false;
      this.unavailable = false;
      this.data = null;
      this.artifactKey = '';
      this.reviews = new Map();
      this.skew = null;
      this.failure = '';
      this.segments = new Map();
      this.dirtySegments = new Set();
      this.renderFrame = null;
      this.snapshotPending = false;
      this.generating = null;
      this.skillActivationKeys = new Set();
      this.receiptTimer = null;
      this.receiptPoll = 0;
      // A professional run's stored answer is rendered by the page; keep it inside the run.
      const next = host.nextElementSibling;
      this.answerNode = next?.classList?.contains('rg-md') ? next : null;
      this.build();
      this.paint();
    }
    build() {
      const {host, run} = this;
      host.replaceChildren();
      host.dataset.state = run.status;
      this.activity = node('section', null, host, 'rg-activity');
      this.activity.setAttribute('aria-label', 'Actividad del agente');
      this.head = node('button', null, this.activity, 'rg-activity-head');
      this.head.type = 'button';
      this.head.setAttribute('aria-controls', 'activity-' + run.id);
      this.iconSlot = node('span', null, this.head, 'rg-activity-icon');
      this.title = node('span', null, this.head, 'rg-activity-title');
      this.title.setAttribute('aria-live', 'polite');
      this.meta = node('span', null, this.head, 'rg-activity-meta');
      icon('chevron', this.head, 'rg-i rg-activity-chevron');
      this.body = node('div', null, this.activity, 'rg-activity-body');
      this.body.id = 'activity-' + run.id;
      this.brief = node('p', null, this.body, 'rg-brief');
      this.list = node('ol', null, this.body, 'rg-steps');
      this.extra = node('div', null, this.body);
      this.publicActivity = node('div', null, this.body, 'rg-public-activity');
      this.timings = node('p', null, this.body, 'rg-timing');
      this.skillActivations = node('div', null, host, 'rg-skill-activations');
      this.skillActivations.setAttribute('role', 'status');
      this.skillActivations.setAttribute('aria-live', 'polite');
      this.skillActivations.setAttribute('aria-label', 'Skills activadas');
      this.limits = node('ul', null, host, 'rg-limits');
      this.limits.hidden = true;
      // Empty until the first snapshot; visible, its tinted box flashes before any text.
      this.message = node('div', null, host, 'rg-agent-message');
      this.message.hidden = true;
      this.answerSlot = node('div', null, host, 'rg-agent-answer');
      if (this.answerNode) this.answerSlot.appendChild(this.answerNode);
      this.deliverables = node('div', null, host, 'rg-deliverables');
      this.exportArea = node('div', null, host);
      this.actions = node('div', null, host, 'rg-agent-actions');
      this.tech = node('div', null, host, 'rg-receipt');
      this.tech.id = 'agent-details-' + run.id;
      this.tech.hidden = true;
      this.head.addEventListener('click', () => {
        this.userOpen = !this.isOpen();
        this.paintOpen();
      });
    }
    isOpen() {
      if (this.userOpen !== null) return this.userOpen;
      // Open while work is visible and running; summarized afterwards.
      return live(this.run.status) && !this.unavailable && !WAITING.has(this.steps[this.steps.length - 1]?.kind);
    }
    paintOpen() {
      const open = this.isOpen();
      this.activity.dataset.open = String(open);
      this.head.setAttribute('aria-expanded', String(open));
      this.body.hidden = !open;
    }
    addEvent(event) {
      if (!event || typeof event.id !== 'number' || event.id <= this.cursor) return false;
      this.cursor = event.id;
      if (event.kind === 'text.delta' || event.kind === 'text.snapshot') {
        this.textEvent(event.data, event.kind === 'text.snapshot');
        return false; // No activity/receipt/history rebuild on text batches.
      }
      if (event.kind === 'inference.started' || event.kind === 'inference.delivery') this.generating = event.data;
      if (event.kind === 'inference.finished') {
        this.generating = null;
        const segment = this.segments.get(event.data?.message_id);
        if (segment) {
          segment.done = true;
          segment.incomplete = Boolean(event.data.incomplete);
          segment.tools = event.data.tool_count || 0;
          if (segment.tools) this.publicActivity.appendChild(segment.host);
          this.queueText(segment);
        }
      }
      this.showSkillActivation(event);
      this.events.push(event);
      return true;
    }
    showSkillActivation(event) {
      if (event?.kind !== 'skill.activated' || typeof event.id !== 'number') return;
      const value = event.data || {};
      const key = value.revision_id || value.installation_id || value.alias || value.name || event.id;
      if (this.skillActivationKeys.has(key)) return;
      this.skillActivationKeys.add(key);
      node('span', `${value.display_name || value.name || value.alias || 'Skill'} · activada`,
        this.skillActivations, 'rg-skill-activation');
    }
    textEvent(data, snapshot = false) {
      if (snapshot && data?.snapshot_required) { this.recoverText(); return; }
      if (!data || typeof data.message_id !== 'string' || typeof data.text !== 'string' || !Number.isSafeInteger(data.offset) || data.offset < 0) return;
      let segment = this.segments.get(data.message_id);
      if (!segment) {
        const host = node('section', null, this.answerSlot, 'rg-stream-segment');
        host.dataset.segment = data.message_id;
        segment = {host, status: node('p', null, host, 'rg-stream-status'), body: node('div', null, host, 'rg-md'), text: '', offset: 0, done: false};
        this.segments.set(data.message_id, segment);
      }
      const bytes = new TextEncoder().encode(data.text);
      if (snapshot) {
        segment.text = data.text; segment.offset = bytes.length;
      } else if (data.offset < segment.offset && data.offset + bytes.length <= segment.offset) return;
      else if (data.offset !== segment.offset) {
        this.recoverText();
        return;
      } else { segment.text += data.text; segment.offset += bytes.length; }
      this.queueText(segment);
    }
    recoverText() {
      if (this.snapshotPending) return;
      this.snapshotPending = true;
      this.snapshot().catch(() => this.revoke()).finally(() => { this.snapshotPending = false; });
    }
    queueText(segment) {
      segment.unread = segment.unread || !this.applyingInitialSnapshot;
      this.dirtySegments.add(segment);
      if (this.renderFrame !== null) return;
      this.renderFrame = requestAnimationFrame(() => {
        this.renderFrame = null;
        const unread = [...this.dirtySegments].some(value => value.unread);
        this.dirtySegments.forEach(value => {
          value.unread = false;
          value.status.textContent = value.incomplete ? 'Respuesta incompleta · texto autorizado recibido' : value.tools ? 'Nota pública del modelo' : '';
          value.status.hidden = !value.status.textContent;
          if (window.RegulayMarkdown) window.RegulayMarkdown.render(value.body, value.text, {streaming: !value.done});
          else value.body.textContent = value.text;
        });
        this.dirtySegments.clear();
        chat()?.follow(unread ? this.run.id : null);
      });
    }
    paint() {
      const {run} = this;
      this.host.dataset.state = this.unavailable ? 'unavailable' : run.status;
      this.steps = groupSteps(this.events);
      const head = headline(this);
      this.activity.dataset.tone = head.tone;
      this.title.textContent = head.text;
      this.iconSlot.replaceChildren();
      if (head.icon) icon(head.icon, this.iconSlot);
      else node('span', null, this.iconSlot, 'rg-pulse').setAttribute('aria-hidden', 'true');
      this.paintMeta();
      this.brief.textContent = brief(run.request);
      this.brief.hidden = !this.brief.textContent;
      this.paintSteps();
      this.paintTimings();
      this.paintOpen();
      const running = live(run.status) && !this.unavailable;
      if (running && !this.ticker) this.ticker = window.setInterval(() => this.paintMeta(), 1000);
      if (!running && this.ticker) { window.clearInterval(this.ticker); this.ticker = null; }
      if (this === latest) {
        const waiting = this.steps[this.steps.length - 1]?.kind;
        chat()?.busy(running, running ? () => this.cancel() : null, waiting === 'visual_pending' ? 'Pendiente de tu revisión visual' :
          waiting === 'approval_pending' ? 'Pendiente de tu aprobación' : 'El agente está trabajando');
      }
    }
    finishedAt() {
      // An interruption is recorded when the abandoned lease is noticed, possibly
      // hours later (a host restart): the work ended at the last recorded step.
      if (this.run.status === 'interrupted') {
        const last = [...this.events].reverse().find(event => event.kind !== 'interrupted');
        if (time(last?.created_at) !== null) return time(last.created_at);
      }
      return time(this.run.finished_at) ?? time(this.events[this.events.length - 1]?.created_at);
    }
    paintMeta() {
      const count = this.steps.length;
      const start = time(this.run.created_at) ?? time(this.events[0]?.created_at);
      // Running time uses the server clock (Date header), never a client guess.
      const end = live(this.run.status) ? (this.skew === null ? null : Date.now() + this.skew) : this.finishedAt();
      const parts = [];
      if (count) parts.push(`${count} ${count === 1 ? 'paso' : 'pasos'}`);
      const sources = list(this.data?.sources).filter(source => source.opened).length;
      if (sources) parts.push(`${sources} ${sources === 1 ? 'fuente' : 'fuentes'}`);
      const spent = start && end ? duration(end - start) : '';
      if (spent) parts.push(spent);
      this.meta.textContent = parts.join(' · ');
    }
    paintTimings() {
      const totals = new Map();
      this.events.filter(event => event.kind === 'interval').forEach(event => {
        const elapsed = recordedDuration(event), scope = event.data?.category;
        if (elapsed !== null && scope) totals.set(scope, (totals.get(scope) || 0) + elapsed);
      });
      const names = {queue: 'Cola', provider: 'Modelo', tool: 'Herramientas', protection: 'Controles',
        preparation: 'Preparación', checkpoint: 'Checkpoint', network: 'Red'};
      this.timings.textContent = [...totals].map(([scope, value]) => `${names[scope] || scope}: ${duration(value)}`).join(' · ');
      this.timings.title = 'Duraciones registradas por ámbito. Los intervalos pueden solaparse; no se suman como tiempo total.';
      this.timings.hidden = !totals.size;
    }
    paintSteps() {
      const {steps} = this;
      const previous = this.list.children.length;
      this.list.replaceChildren();
      steps.forEach((step, index) => {
        const state = stepState(step, index, steps, this.run.status);
        const item = node('li', null, this.list, 'rg-step' + (index >= previous && this.loaded ? ' rg-enter' : ''));
        item.dataset.state = state;
        item.dataset.kind = step.kind;
        const dot = node('span', null, item, 'rg-step-dot');
        if (state === 'done') icon('check', dot);
        else if (state === 'failed' || state === 'cancelled') icon('x', dot);
        else if (state === 'waiting') icon('clock', dot);
        const text = node('span', null, item);
        node('span', STEP[step.kind] || label(step.kind), text, 'rg-step-label');
        if (step.count > 1) node('span', `×${step.count}`, text, 'rg-step-count');
        node('span', duration(step.duration), item, 'rg-step-time');
        const tools = [...step.tools].map(name => TOOLS[name] || name);
        const last = index === steps.length - 1;
        // The failure message is shown once, below the activity.
        const sentence = last && step.text && step.text.trim() !== this.failure ? step.text : '';
        const extra = [tools.join(', '), sentence].filter(Boolean).join(' — ');
        if (extra) node('p', extra, item, 'rg-step-text');
        if (step.text) item.title = step.text;
      });
    }
    showFailure(data) {
      const error = this.run.status === 'failed' && typeof data?.result?.error === 'string' ? data.result.error.trim() : '';
      this.failure = error;
      this.message.replaceChildren();
      this.message.hidden = !error;
      this.message.className = 'rg-agent-message';
      if (!error) return;
      icon('alert', this.message);
      node('p', error, this.message);
    }
    showLimits(run) {
      this.limits.replaceChildren();
      list(run.limitations).forEach(value => node('li', value, this.limits));
      this.limits.hidden = !this.limits.children.length;
    }
    showActions() {
      const {run} = this;
      const key = JSON.stringify([run.status, run.resumable, this.unavailable, Boolean(this.data)]);
      if (key === this.actionsKey) return;
      this.actionsKey = key;
      this.actions.replaceChildren();
      if (live(run.status) && !this.unavailable) button('Detener', this.actions, () => this.cancel(), 'rg-link-btn', 'stop');
      if (run.resumable) button('Reanudar', this.actions, event => this.resume(event.currentTarget), 'rg-link-btn', 'play');
      if (this.unavailable) button('Actualizar estado', this.actions, () => this.refresh(), 'rg-link-btn', 'refresh');
      if (this.data && !this.unavailable) {
        const toggle = button('Detalles', this.actions, () => {
          const open = toggle.getAttribute('aria-expanded') !== 'true';
          toggle.setAttribute('aria-expanded', String(open));
          this.tech.hidden = !open;
          if (open) this.pollReceipt();
        }, 'rg-link-btn');
        icon('chevron', toggle);
        toggle.setAttribute('aria-controls', this.tech.id);
        toggle.setAttribute('aria-expanded', String(!this.tech.hidden));
      }
      this.actions.hidden = !this.actions.children.length;
    }
    pollReceipt() {
      window.clearTimeout(this.receiptTimer);
      if (this.tech.hidden || live(this.run.status) || this.data?.receipt?.total?.complete !== false || this.receiptPoll >= 5) return;
      this.receiptTimer = window.setTimeout(async () => {
        this.receiptPoll++;
        try { await this.snapshot(); this.pollReceipt(); } catch (_) { this.revoke(); }
      }, Math.min(30000, 2000 * 2 ** this.receiptPoll));
    }
    showSources(sources) {
      if (!sources.length) return;
      const opened = sources.filter(source => source.opened).length;
      node('p', `Fuentes · ${opened} ${opened === 1 ? 'consultada' : 'consultadas'}`, this.extra, 'rg-subhead');
      const items = node('ol', null, this.extra, 'rg-sources');
      sources.forEach(source => {
        const item = node('li', null, items);
        const url = source.final_url || source.url;
        const title = node('a', source.title || url, item);
        if (typeof url === 'string' && /^https?:\/\/[^\s]+$/i.test(url)) { title.href = url; title.target = '_blank'; title.rel = 'noopener noreferrer'; }
        node('span', source.opened ? (source.reading === 'complete' ? 'Lectura completa' : 'Lectura parcial') : 'Resultado del buscador · no abierto', item, 'rg-meta');
        if (source.excerpt || source.snippet) node('p', source.excerpt || source.snippet, item);
        if (source.opened) node('span', `Consulta: ${timestamp(source.retrieved_at)} · Publicación: ${source.publication_date || 'fecha desconocida'}`, item, 'rg-meta');
      });
    }
    showOperations(operations) {
      if (!operations.length) return;
      node('p', `Herramientas · ${operations.length}`, this.extra, 'rg-subhead');
      const items = node('ul', null, this.extra, 'rg-ops');
      operations.forEach(operation => {
        const item = node('li', null, items);
        const head = node('div', null, item, 'rg-op-head');
        node('span', `${TOOLS[operation.name] || label(operation.name)} · ${label(operation.status)}`, head);
        if (typeof operation.details_url !== 'string' || !/^\/chat\/agent\/runs\/[0-9a-f-]+\/operations\/\d+\/$/.test(operation.details_url)) return;
        const control = button('Ver resultado y duración', head, async () => {
          control.disabled = true;
          try {
            const response = await fetch(operation.details_url, {headers: {Accept: 'application/json'}});
            if (!response.ok) throw new Error('unavailable');
            node('pre', JSON.stringify(await response.json(), null, 2), item, 'rg-op-output');
            control.remove();
          } catch (_) {
            node('p', 'El detalle ya no está disponible con tus permisos actuales.', item, 'rg-meta');
            control.disabled = false;
          }
        }, 'rg-link-btn');
      });
    }
    async snapshot() {
      const expected = this.run.id, version = ++this.version;
      let data;
      try {
        const response = await fetch(this.run.status_url, {headers: {Accept: 'application/json'}});
        if (!response.ok) throw new Error('unavailable');
        const served = Date.parse(response.headers?.get?.('Date') || '');
        if (Number.isFinite(served)) this.skew = served - Date.now();
        data = await response.json();
      } catch (error) {
        if (this.run.id !== expected || version !== this.version) return null;
        throw error;
      }
      if (this.run.id !== expected || version !== this.version || !data?.run) return null;
      this.apply(data);
      return data.run;
    }
    apply(data) {
      this.applyingInitialSnapshot = !this.loaded;
      this.loaded = true;
      this.unavailable = false;
      this.data = data;
      this.run = {...this.run, ...data.run};
      list(data.text_segments).forEach(segment => this.textEvent({...segment, offset: 0}, true));
      list(data.events).forEach(event => {
        this.addEvent(event);
        // An authorized snapshot restores badges cleared by revoke without
        // replaying activity or moving the event cursor backwards.
        this.showSkillActivation(event);
      });
      if (Number.isSafeInteger(data.high_watermark)) this.cursor = Math.max(this.cursor, data.high_watermark);
      if (!live(this.run.status)) this.segments.forEach(segment => {
        segment.done = true;
        if (this.run.status !== 'completed') segment.incomplete = true;
        this.queueText(segment);
      });
      this.showFailure(data);
      this.showLimits(data.run);
      const extraKey = JSON.stringify([data.sources, data.operations]);
      if (this.extraKey !== extraKey) {
        this.extraKey = extraKey;
        this.extra.replaceChildren();
        this.showSources(list(data.sources));
        this.showOperations(list(data.operations));
      }
      // Every event refreshes the run; rebuild its receipt only when the server's copy changed.
      const receipt = data.receipt || data.result?.receipt || {};
      const receiptKey = JSON.stringify([receipt, Boolean(data.infrastructure)]);
      if (receiptKey !== this.receiptKey || !this.tech.children.length) {
        this.receiptKey = receiptKey;
        oversight(this.tech, receipt, data);
      }
      showExport(this, data.export, data.run);
      const visible = list(data.artifacts).length ? data.artifacts : (data.current_revision ? [data.current_revision] : []);
      const key = JSON.stringify([visible, data.export_enabled, live(data.run.status)]);
      if (key !== this.artifactKey) {
        this.artifactKey = key;
        this.deliverables.replaceChildren();
        this.reviews.clear();
        visible.forEach(artifact => this.deliverables.appendChild(this.card(artifact, data.export_enabled && !live(data.run.status))));
      }
      if (this === latest) updateContext();
      this.answer(data);
      this.paint();
      this.showActions();
      if (!live(data.run.status)) this.close();
      chat()?.follow(this.applyingInitialSnapshot ? null : this.run.id);
      this.applyingInitialSnapshot = false;
    }
    answer(data) {
      // Professional runs answer in text as well; the stored message is shown once.
      const message = data.result?.assistant_message;
      if (!this.run.professional || live(this.run.status) || !message?.content) return;
      const candidates = [...this.segments.values()].filter(segment => !segment.tools);
      const segment = candidates[candidates.length - 1];
      const body = segment?.body || this.answerSlot.querySelector('.rg-md') || node('div', null, this.answerSlot, 'rg-md');
      if (segment && this.answerNode && this.answerNode !== body) { this.answerNode.remove(); this.answerNode = null; }
      if (segment) { segment.text = message.content; segment.done = true; segment.incomplete = false; this.queueText(segment); }
      if (window.RegulayMarkdown) window.RegulayMarkdown.render(body, message.content);
      else body.textContent = message.content;
    }
    card(artifact, canExport) {
      const preview = artifact.preview || {}, format = String(artifact.format || '').toLowerCase();
      const delivery = this.data?.delivery;
      const receiptAllows = !delivery || ['complete', 'partial'].includes(delivery.status) && list(delivery.artifacts).some(
        reference => (reference.artifact_id || reference.id) === artifact.id && reference.sha256 === artifact.sha256);
      const verified = artifact.status === 'verified' && receiptAllows;
      const pageUrls = list(preview.pages), pages = pageUrls.filter(url => artifactUrl(url, 'pages/\\d+'));
      const document_ = ['docx', 'pdf', 'pptx'].includes(format);
      const unit = format === 'pptx' ? 'diapositivas' : 'páginas';
      const count = format === 'xlsx' ? (present(preview.sheet_count) ? `${preview.sheet_count} hojas` : 'Hojas: sin dato') :
        document_ ? `${preview.page_count ?? pageUrls.length} ${unit}` : 'Archivo';
      const size = Number.isSafeInteger(artifact.size_bytes) && artifact.size_bytes >= 0 ? ` · ${artifact.size_bytes.toLocaleString('es-ES')} bytes` : '';
      const meta = `${format.toUpperCase() || 'ARCHIVO'} · ${count} · Revisión ${artifact.revision}${size}`;
      const title = artifact.filename || preview.title || 'Entregable';
      const card = node('article', null, null, 'rg-deliverable');
      card.dataset.status = artifact.status || '';
      const head = node('div', null, card, 'rg-deliverable-head');
      const canPreview = artifactUrl(artifact.preview_url, 'preview') || (document_ ? pages.length > 0 && pages.length === pageUrls.length : format === 'xlsx' && (Array.isArray(preview.sheets) || list(preview.rows).length));
      const open = trigger => this.preview(artifact, title, meta, trigger);
      if (verified && document_ && canPreview) {
        const thumb = node('button', null, head, 'rg-thumb');
        thumb.type = 'button';
        thumb.setAttribute('aria-label', `Vista previa de ${title}`);
        const img = node('img', null, thumb);
        img.alt = '';
        img.loading = 'lazy';
        img.src = pages[0];
        thumb.addEventListener('click', () => open(thumb));
      } else {
        const mark = node('span', format.toUpperCase() || 'ARCHIVO', head, 'rg-file-mark');
        mark.dataset.format = format;
      }
      const titleArea = node('div', null, head, 'rg-deliverable-title');
      node('h3', title, titleArea);
      node('p', meta, titleArea);
      const actions = node('div', null, head, 'rg-deliverable-actions');
      if (canPreview && verified) button('Vista previa', actions, event => open(event.currentTarget), 'rg-btn', 'eye');
      if (verified) {
        const seen = new Set();
        [{format: artifact.format, url: artifact.download_url}, ...list(artifact.downloads)].forEach(download => {
          const downloadFormat = String(download.format || artifact.format || '').toLowerCase();
          if (!artifactUrl(download.url, 'download') || seen.has(downloadFormat)) return;
          const first = !seen.size;
          seen.add(downloadFormat);
          const link = node('a', null, actions, first ? 'rg-btn rg-btn-primary' : 'rg-btn');
          icon('download', link);
          link.appendChild(document.createTextNode(downloadFormat.toUpperCase()));
          link.setAttribute('aria-label', `Descargar ${downloadFormat.toUpperCase()}`);
          link.title = `Descargar ${downloadFormat.toUpperCase()}`;
          link.href = download.url;
          link.setAttribute('download', artifact.filename || '');
        });
      }
      if (this.run.professional && verified && !live(this.run.status)) {
        button('Editar', actions, () => {
          chosenRevision = {...artifact, title};
          updateContext();
          byId('prompt')?.focus();
        }, 'rg-btn', 'pencil');
      }
      const foot = node('div', null, card, 'rg-deliverable-foot');
      const coverage = artifact.coverage || artifact.verification_checks?.coverage;
      const coverageText = {complete: 'Cobertura completa del texto inspeccionable', partial: 'Cobertura parcial',
        legacy: 'Cobertura del lector histórico'}[coverage?.status] || 'Cobertura no disponible';
      node('span', coverageText, foot, 'rg-chip');
      if (artifact.data_mode === 'mock' || preview.data_mode === 'mock') node('span', 'Datos ficticios solicitados expresamente', foot, 'rg-chip is-warn');
      if (!verified && document_ && artifact.review_url) this.review(artifact, card, title, meta);
      else if (!verified) node('p', 'Archivo pendiente de entrega verificada.', foot, 'rg-meta');
      const checks = details(foot, '');
      const counts = checkRows(checks, artifact.verification_checks);
      checks.querySelector('summary').textContent = checkSummary(counts);
      if (counts.failed) checks.classList.add('has-failed');
      if (verified && canExport) {
        const area = details(foot, 'Guardar una copia en Google Drive');
        const formRow = node('div', null, area, 'rg-export-form');
        const nameLabel = node('label', 'Nombre del archivo', formRow);
        const name = node('input', null, nameLabel);
        name.maxLength = 120;
        name.value = `informe-r${artifact.revision}.${artifact.format || 'xlsx'}`;
        button('Preparar exportación', formRow, () => {
          pendingExport = {artifactId: artifact.logical_id, baseRevision: artifact.id, exportName: name.value};
          const prompt = byId('prompt');
          if (!prompt) return;
          prompt.value = 'Guarda la revisión verificada en la carpeta autorizada de Drive.';
          prompt.dispatchEvent(new Event('input', {bubbles: true}));
          byId('chatForm')?.requestSubmit();
        }, 'rg-btn', 'cloud');
      }
      return card;
    }
    review(artifact, card, title, meta) {
      const preview = artifact.preview || {}, urls = list(preview.pages), valid = urls.filter(url => artifactUrl(url, 'pages/\\d+'));
      const pageName = artifact.format === 'pptx' ? 'Diapositiva' : 'Página';
      const state = {loaded: new Set(), total: urls.length, controls: [], valid: valid.length === urls.length && urls.length > 0};
      this.reviews.set(artifact.id, state);
      const box = node('div', null, card, 'rg-review');
      const plural = artifact.format === 'pptx' ? 'diapositivas' : 'páginas';
      node('strong', `Revisa ${urls.length === 1 ? (artifact.format === 'pptx' ? 'la diapositiva' : 'la página') : `las ${urls.length} ${plural}`} antes de publicar`, box);
      node('p', `Comprueba la legibilidad, las tablas, los símbolos y los cortes de todas las ${plural}. Tu confirmación registra únicamente la revisión visual.`, box);
      const strip = node('div', null, box, 'rg-pages');
      valid.forEach((url, index) => {
        const page = node('button', null, strip, 'rg-pagethumb');
        page.type = 'button';
        page.dataset.format = artifact.format;
        page.setAttribute('aria-label', `${pageName} ${index + 1} de ${urls.length}: abrir a tamaño completo`);
        const img = node('img', null, page);
        img.alt = `${pageName} ${index + 1}: ${preview.title || 'documento'}.`;
        img.onload = () => this.pageLoaded(artifact.id, index);
        img.onerror = () => {
          page.classList.add('is-error');
          node('p', `No se ha podido cargar la ${pageName.toLowerCase()} ${index + 1}. Recarga antes de aprobar la revisión.`, box, 'rg-meta');
        };
        img.src = url;
        node('span', String(index + 1), page);
        page.addEventListener('click', () => this.preview(artifact, title, meta, page, index));
      });
      const row = node('div', null, box, 'rg-btn-row');
      this.reviewButton(artifact, row);
      button('Ver a tamaño completo', row, event => this.preview(artifact, title, meta, event.currentTarget), 'rg-btn', 'eye');
    }
    reviewButton(artifact, parent) {
      const state = this.reviews.get(artifact.id);
      const control = button('Confirmar revisión visual', parent, async () => {
        if (!artifactUrl(artifact.review_url, 'review')) return;
        state.controls.forEach(item => { item.disabled = true; });
        try {
          await post(artifact.review_url, {sha256: artifact.sha256, page_sha256: artifact.page_sha256, checks: artifact.review_checks});
          chat()?.announce('Revisión visual registrada');
          byId('previewDialog')?.open && byId('previewDialog').close();
          await this.snapshot();
        } catch (_) {
          this.note('No se pudo registrar la revisión visual. Recarga el estado para comprobar los permisos y la ejecución.');
          state.controls.forEach(item => { item.disabled = state.loaded.size !== state.total; });
        }
      }, 'rg-btn rg-btn-primary', 'check');
      control.disabled = !state.valid || state.loaded.size !== state.total;
      state.controls.push(control);
      return control;
    }
    pageLoaded(id, index) {
      const state = this.reviews.get(id);
      if (!state) return;
      state.loaded.add(index);
      state.controls.forEach(control => { control.disabled = !state.valid || state.loaded.size !== state.total; });
    }
    preview(artifact, title, meta, trigger, focusIndex = 0) {
      if (artifactUrl(artifact.preview_url, 'preview') && window.RegulayArtifactViewer) {
        window.RegulayArtifactViewer.open(artifact, trigger, list(this.data?.artifacts));
        return;
      }
      const preview = artifact.preview || {};
      const verified = artifact.status === 'verified';
      openDialog(title, meta, (body, foot) => {
        if (artifact.format === 'xlsx') {
          sheetTables(body, preview);
        } else {
          const urls = list(preview.pages), valid = urls.filter(url => artifactUrl(url, 'pages/\\d+'));
          const pageName = artifact.format === 'pptx' ? 'Diapositiva' : 'Página';
          const view = node('div', null, body, 'rg-pageview');
          valid.forEach((url, index) => {
            const figure = node('figure', null, view);
            const caption = node('figcaption', null, figure);
            node('span', `${pageName} ${index + 1} de ${urls.length}`, caption);
            const link = node('a', 'Abrir en una pestaña', caption);
            link.href = url; link.target = '_blank'; link.rel = 'noopener';
            const img = node('img', null, figure);
            img.alt = `${pageName} ${index + 1}: ${preview.title || 'documento'}.`;
            if (!verified) img.onload = () => this.pageLoaded(artifact.id, index);
            img.src = url;
            if (index === focusIndex && focusIndex) window.setTimeout(() => figure.scrollIntoView({block: 'start'}), 60);
          });
        }
        if (!verified && this.reviews.has(artifact.id)) {
          node('p', 'Tu confirmación registra únicamente la revisión visual; la exportación se autoriza aparte.', foot, 'rg-meta');
          this.reviewButton(artifact, foot);
        } else if (verified) {
          const seen = new Set();
          [{format: artifact.format, url: artifact.download_url}, ...list(artifact.downloads)].forEach(download => {
            const downloadFormat = String(download.format || artifact.format || '').toLowerCase();
            if (!artifactUrl(download.url, 'download') || seen.has(downloadFormat)) return;
            seen.add(downloadFormat);
            const link = node('a', null, foot, seen.size === 1 ? 'rg-btn rg-btn-primary' : 'rg-btn');
            icon('download', link);
            link.appendChild(document.createTextNode(`Descargar ${downloadFormat.toUpperCase()}`));
            link.href = download.url;
            link.setAttribute('download', '');
          });
        }
      }, trigger);
    }
    note(text) {
      this.message.replaceChildren();
      this.message.className = 'rg-agent-message is-info';
      icon('info', this.message);
      node('p', text, this.message);
      this.message.hidden = false;
    }
    async start() {
      try {
        const state = await this.snapshot();
        if (!state || !live(state.status)) return;
        this.listen();
      } catch (_) {
        this.revoke();
      }
    }
    listen() {
      this.close();
      if (typeof EventSource !== 'function') { this.poll(); return; }
      const source = new EventSource(this.run.events_url + '?cursor=' + this.cursor);
      this.stream = source;
      const current = () => this.stream === source;
      let pending = null;
      const refresh = () => {
        if (pending) return;
        pending = window.setTimeout(() => { pending = null; this.snapshot().catch(() => this.revoke()); }, 16);
      };
      source.addEventListener('progress', message => {
        if (!current()) return;
        try {
          const event = JSON.parse(message.data);
          if (this.addEvent(event)) this.paint();
          if (REFRESH.has(event.kind)) refresh();
        } catch (_) {
          this.note('Se recibió un evento que no se pudo leer. Actualiza el estado para continuar.');
        }
      });
      source.addEventListener('terminal', () => { if (current()) { this.close(); this.snapshot().catch(() => this.revoke()); } });
      source.addEventListener('revoked', () => { if (current()) this.revoke(); });
      source.onerror = () => {
        if (!current()) return;
        // EventSource reconnects with Last-Event-ID; a closed source (no SSE here) falls back to polling.
        if (source.readyState === 2) { this.close(); this.poll(); }
      };
    }
    poll() {
      window.clearTimeout(this.timer);
      this.timer = window.setTimeout(async () => {
        try {
          const state = await this.snapshot();
          if (state && live(state.status)) this.poll();
        } catch (_) {
          this.revoke();
        }
      }, 2500);
    }
    close() {
      this.stream?.close();
      this.stream = null;
      window.clearTimeout(this.timer);
      this.timer = null;
    }
    revoke() {
      this.close();
      this.unavailable = true;
      this.data = null;
      this.artifactKey = '';
      this.deliverables.replaceChildren();
      this.exportArea.replaceChildren();
      this.extra.replaceChildren();
      this.tech.replaceChildren();
      this.tech.hidden = true;
      this.limits.replaceChildren();
      this.limits.hidden = true;
      this.reviews.clear();
      window.clearTimeout(this.receiptTimer);
      if (this.renderFrame !== null) cancelAnimationFrame(this.renderFrame);
      this.renderFrame = null;
      this.dirtySegments.clear();
      this.segments.clear();
      this.answerSlot.replaceChildren();
      this.answerNode = null;
      this.publicActivity.replaceChildren();
      this.skillActivations.replaceChildren();
      this.skillActivationKeys.clear();
      window.RegulayArtifactViewer?.close();
      if (this === latest) { chosenRevision = null; updateContext(); }
      this.note('El estado no está autorizado o no está disponible. Actualiza el estado para comprobar el acceso.');
      this.paint();
      this.showActions();
      if (this === latest) chat()?.busy(false);
    }
    async refresh() {
      try {
        const state = await this.snapshot();
        if (state && live(state.status)) this.listen();
      } catch (_) {
        this.revoke();
      }
    }
    async cancel() {
      if (!live(this.run.status) || !this.run.cancel_url) return;
      try {
        await post(this.run.cancel_url);
        await this.snapshot();
      } catch (_) {
        this.revoke();
      }
    }
    async resume(control) {
      if (!this.run.resumable) return;
      if (control) control.disabled = true;
      try {
        const value = await post(this.run.resume_url);
        if (value?.run) {
          this.run = {...this.run, ...value.run};
          this.events = [];
          this.cursor = 0;
          this.artifactKey = '';
          await this.start();
        }
      } catch (_) {
        this.note('No se puede reanudar: el punto guardado, los permisos o el presupuesto ya no son válidos.');
      } finally {
        if (control) control.disabled = false;
      }
    }
  }

  function showExport(watcher, proposal, state) {
    const area = watcher.exportArea;
    area.replaceChildren();
    if (!proposal) return;
    const card = node('article', null, area, 'rg-export');
    const heading = node('h3', null, card);
    icon('cloud', heading);
    heading.appendChild(document.createTextNode('Guardar revisión en Google Drive'));
    const values = node('dl', null, card, 'rg-facts');
    const statuses = {pending: 'Esperando aprobación', approved: 'Aprobado', rejected: 'Rechazado', intent: 'Guardando; resultado pendiente',
      uncertain: 'Resultado por confirmar', completed: 'Guardado confirmado'};
    [['Cuenta', proposal.account], ['Carpeta', proposal.folder], ['Nombre', proposal.name], ['Revisión', proposal.revision],
      ['Efecto', 'Crear un archivo nuevo'], ['Contenido', `${proposal.bytes} bytes`], ['SHA-256 del contenido', proposal.sha256],
      ['Estado', statuses[proposal.status] || proposal.status], ['Caduca', timestamp(proposal.expires_at)]].forEach(([name, value]) => detail(values, name, value));
    if (artifactUrl(proposal.preview_url, 'download')) {
      const content = node('a', 'Revisar el contenido exacto antes de aprobar', card, 'rg-meta');
      content.href = proposal.preview_url;
    }
    const row = node('div', null, card, 'rg-btn-row');
    if (proposal.status === 'pending' && state.status === 'active' && Date.parse(proposal.expires_at) > Date.now()) {
      [['approve', 'Aprobar esta exportación', 'rg-btn rg-btn-primary'], ['reject', 'Rechazar', 'rg-btn']].forEach(([decision, title, className]) => {
        const control = button(title, row, async () => {
          control.disabled = true;
          try {
            await post(proposal.decision_url, {binding: proposal.binding, decision});
            await watcher.snapshot();
          } catch (_) {
            watcher.note('La propuesta ha caducado o sus permisos han cambiado. Actualiza para comprobar el estado.');
            control.disabled = false;
          }
        }, className);
      });
    }
    if (proposal.status === 'uncertain' && state.status === 'interrupted') {
      const recover = button('Reconciliar el resultado de la exportación', row, async () => {
        recover.disabled = true;
        try {
          await post(`/chat/agent/runs/${state.id}/recover-export/`);
          await watcher.start();
        } catch (_) {
          watcher.note('No se pudo recuperar el resultado. Comprueba los permisos y la aprobación.');
          recover.disabled = false;
        }
      }, 'rg-btn', 'refresh');
    }
    if (!row.children.length) row.remove();
  }

  /* ------------------------------------------------------------ composer context */
  const professional = () => latest?.run?.professional || byId('chatApp')?.dataset.professional === 'true';
  function updateContext() {
    const area = byId('composerContext');
    if (!area) return;
    area.replaceChildren();
    let text = '', clear = null;
    if (documentReference) {
      text = `Archivo de Drive: ${documentLabel}`;
      clear = () => { documentReference = null; documentLabel = ''; updateContext(); };
    } else if (professional() && chosenRevision) {
      text = `Editando «${chosenRevision.title || chosenRevision.preview?.title || 'Archivo'}», revisión ${chosenRevision.revision}`;
      clear = () => { chosenRevision = null; updateContext(); };
    } else if (!professional() && latest?.data?.current_revision && !live(latest.run.status)) {
      const revision = latest.data.current_revision;
      text = `Los cambios se aplicarán a «${revision.preview?.title || 'Entregable'}», revisión ${revision.revision}`;
    }
    area.hidden = !text;
    if (!text) return;
    icon(documentReference ? 'cloud' : 'pencil', area);
    node('span', text, area);
    if (clear) {
      const control = node('button', null, area, 'rg-icon-btn rg-sm');
      control.type = 'button';
      control.setAttribute('aria-label', 'Quitar selección');
      icon('x', control);
      control.addEventListener('click', clear);
    }
  }

  function mount(host, run, {fresh = false} = {}) {
    if (!host || !run?.id) return null;
    watchers.get(run.id)?.close();
    const watcher = new Watcher(host, run);
    watchers.set(run.id, watcher);
    latest = watcher;
    if (fresh) {
      documentReference = null; documentLabel = ''; pendingExport = null; chosenRevision = null;
      updateContext();
    }
    watcher.start();
    return watcher;
  }

  window.regulayAgent = {
    capture(file) {
      const app = byId('chatApp');
      const mode = app?.dataset.conversation ? app.dataset.mode : document.querySelector('input[name=conversation_mode]:checked')?.value;
      if (mode !== 'agent') return {};
      if (pendingExport) return {mode: 'agent', ...pendingExport};
      const selected = professional() ? chosenRevision : latest?.data?.current_revision;
      return {mode: 'agent', documentReference: !file && documentReference,
        artifactId: !file && !documentReference && selected?.logical_id, baseRevision: !file && !documentReference && selected?.id};
    },
    consumed() {
      pendingExport = null; documentReference = null; documentLabel = ''; chosenRevision = null;
      updateContext();
    },
    modeChanged(agent) {
      // A Drive file is only an agent input: leaving agent mode drops the selection.
      if (!agent) { documentReference = null; documentLabel = ''; }
      updateContext();
    },
    mount, renderReceipt,
    watchers,
  };

  function init() {
    let runs = {};
    try { runs = JSON.parse(byId('agent-runs')?.textContent || '{}') || {}; } catch (_) { runs = {}; }
    const hosts = Array.from(document.querySelectorAll('[data-agent-run]'));
    const lazy = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      lazy.unobserve(entry.target);
      watchers.get(entry.target.dataset.agentRun)?.start();
    }), {rootMargin: '600px 0px'}) : null;
    hosts.forEach((host, index) => {
      const run = runs[host.dataset.agentRun];
      if (!run) return;
      const watcher = new Watcher(host, run);
      watchers.set(run.id, watcher);
      const last = index === hosts.length - 1;
      if (last) latest = watcher;
      if (last || live(run.status) || !lazy) watcher.start();
      else lazy.observe(host);
    });
    byId('agentDocumentSearch')?.addEventListener('click', async () => {
      const area = byId('agentDocumentResults'), control = byId('agentDocumentSearch');
      control.disabled = true; documentReference = null; area.replaceChildren(); updateContext();
      try {
        const data = await post('/chat/agent/documents/search/', {query: byId('agentDocumentQuery').value});
        if (!list(data.documents).length) node('p', 'No hay archivos compatibles en la carpeta autorizada.', area);
        list(data.documents).forEach(doc => {
          button(doc.label, area, () => {
            documentReference = doc.reference; documentLabel = doc.label;
            area.replaceChildren();
            byId('drivePanel').hidden = true;
            updateContext();
            byId('prompt')?.focus();
          }, 'rg-btn', 'file');
        });
      } catch (_) {
        node('p', 'Conector no disponible. Requiere una cuenta autorizada por el administrador.', area);
      } finally {
        control.disabled = false;
      }
    });
  }
  window.addEventListener('pagehide', () => watchers.forEach(watcher => watcher.close()));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

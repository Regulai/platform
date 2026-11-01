/* regulAI chat client: layout, composer, streamed answers and request records.
 * Inference and document content is only ever inserted as text nodes
 * (RegulayMarkdown builds DOM nodes; it never parses HTML). */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const list = value => Array.isArray(value) ? value : [];
  const present = value => value !== null && value !== undefined && value !== '';
  const SVG = 'http://www.w3.org/2000/svg';
  const LIVE = ['processing', 'received'];

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function icon(name) {
    const svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('class', 'rg-i');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }
  function button(label, className, action, iconName) {
    const node = el('button', className);
    node.type = 'button';
    if (iconName) node.appendChild(icon(iconName));
    node.appendChild(document.createTextNode(label));
    if (action) node.addEventListener('click', action);
    return node;
  }
  const csrf = () => document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
  function requestUUID() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  function fileSize(bytes) {
    if (!Number.isFinite(bytes)) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1).replace('.', ',') + ' KB';
    return (bytes / 1024 / 1024).toFixed(1).replace('.', ',') + ' MB';
  }
  const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------------------------------------ records */
  const STATUS = {completed: 'Completada', blocked: 'Bloqueada', pending_consent: 'Pendiente de confirmación',
    processing: 'En curso', received: 'Recibida', accepted: 'Aceptada', failed: 'No completada',
    validation_error: 'No completada', outcome_unknown: 'Resultado desconocido', cancelled: 'Cancelada'};
  const POLICY = {allow: 'Permitida', allowed: 'Permitida', block: 'Bloqueada', blocked: 'Bloqueada',
    consent: 'Requiere confirmación', consent_required: 'Requiere confirmación', confirmed: 'Confirmada por el usuario'};
  const PURPOSE = {generation: 'Generación', verification: 'Verificación', classification: 'Clasificación',
    difficulty: 'Dificultad', masking: 'Enmascarado', obfuscation: 'Enmascarado', research: 'Consulta de fuentes'};
  const CALL_STATUS = {completed: 'completada', failed: 'fallida', started: 'iniciada, sin resultado',
    stopped: 'detenida', cancelled: 'cancelada', outcome_unknown: 'resultado desconocido'};
  const VERIFICATION = {passed: 'Superada', failed: 'No superada', not_verified: 'No realizada (servicio no disponible)'};
  const ROUTE = {auto: 'Automática', manual: 'Elegida por el usuario', fallback: 'Escalada a otro modelo'};
  const DELIVERY = {
    document_citations: 'Se mostrará completa, con las citas comprobadas.',
    response_verification: 'Se mostrará completa tras la verificación.',
    remote_masking: 'Se mostrará completa tras enmascararla.',
    policy_needs_complete_text: 'Las reglas de salida necesitan el texto completo.',
    structured_answer: 'Respuesta estructurada: se mostrará completa.',
    provider_streaming_unverified: 'Este proveedor no tiene entrega progresiva verificada.',
    streaming_disabled: 'La entrega progresiva está desactivada.',
  };
  const DISCLOSURES = {
    images_unread: 'Imágenes no analizadas ni enviadas', images_omitted: 'Imágenes no analizadas ni enviadas',
    attachments_unread: 'Adjuntos no analizados ni enviados', charts_unread: 'Gráficos no analizados ni enviados',
    comments_unread: 'Comentarios no analizados ni enviados', equations_unread: 'Ecuaciones no analizadas ni enviadas',
    symbols_unread: 'Símbolos no analizados ni enviados', form_fields_unread: 'Campos de formulario no analizados ni enviados',
    annotations_unread: 'Anotaciones no analizadas ni enviadas', external_content_unread: 'Contenido externo no analizado ni enviado',
    page_without_text: 'Página sin texto extraíble; su contenido visual no se ha analizado ni enviado',
    tracked_changes_present: 'Se ha usado la vista con los cambios aceptados',
    encoding_assumed: 'Se ha interpretado la codificación como Windows-1252', blank_page: 'Página en blanco',
    formula_expression_security_only: 'La fórmula se comprueba para seguridad; se envía su valor en caché',
    formula_coverage_unknown: 'El valor actual de la fórmula no se ha podido comprobar',
    numbering_unsupported: 'No se ha podido representar esta numeración',
  };
  const LIMITS = {jev_state_bytes: 'Entrada máxima del evaluador (bytes)', response_bytes: 'Límite de respuesta (bytes)',
    max_output_tokens: 'Límite de salida (tokens)', call_timeout_seconds: 'Tiempo máximo por llamada (s)',
    deadline_seconds: 'Plazo de la petición (s)', history_max_bytes: 'Límite del historial (bytes)',
    history_max_turns: 'Límite del historial (turnos)', judge_input_bytes_bound: 'Entrada máxima del juez (bytes)'};
  const SIGNALS = {failure_omission: 'Señal de Jev · requisitos omitidos',
    failure_contradiction: 'Señal de Jev · contradicción o afirmación sin respaldo'};
  const ERROR_TITLES = {verification_failed: 'Respuesta no entregada', provider_failed: 'Error del proveedor',
    outcome_unknown: 'Resultado desconocido', security_check_failed: 'Comprobación de seguridad no superada',
    deadline_exceeded: 'Tiempo agotado', budget_exhausted: 'Presupuesto insuficiente', unknown_price: 'Coste no acotado',
    context_overflow: 'Contenido demasiado largo', evaluation_input_too_large: 'Contenido demasiado largo',
    input_unreadable: 'Documento no legible', authorization_changed: 'Permisos cambiados',
    consent_invalid: 'Confirmación caducada', internal_error: 'Error interno'};
  const SETUP_CODES = ['masking_required', 'policy_configuration_invalid', 'jev_unavailable', 'no_api_key',
    'model_not_allowed', 'no_authorized_candidates', 'empty_policy_not_authorized', 'destination_not_allowed',
    'quality_unavailable', 'capability_unavailable'];

  function consentReason(reason, pending = true) {
    if (!pending) return ({consent_expired: 'Una confirmación anterior caducó.',
      consent_context_changed: 'La política o el contexto cambiaron durante la petición.',
      coverage_incomplete: 'Parte del documento no se analizó ni se envió.'})[reason] || reason;
    return ({consent_expired: 'La confirmación caducó. Revísala y confirma de nuevo.',
      consent_context_changed: 'La política o el contexto cambiaron. Revísalo y confirma de nuevo.',
      coverage_incomplete: 'Parte del documento no se ha podido analizar y no se enviará.'})[reason] || reason;
  }
  function facts(parent) { return parent.appendChild(el('dl', 'rg-facts')); }
  function fact(area, name, value) {
    area.appendChild(el('dt', null, name));
    area.appendChild(el('dd', null, present(value) ? value : 'No disponible'));
  }
  function section(parent, title) {
    parent.appendChild(el('p', 'rg-section-title', title));
    return facts(parent);
  }
  function disclosureText(item) {
    const locators = list(item.locators).join(', ');
    return (DISCLOSURES[item.code] || item.code) + ' (' + (item.count ?? 'No disponible') + ')' + (locators ? ': ' + locators : '');
  }
  function renderDisclosures(parent, coverage) {
    const items = list(coverage?.disclosures).filter(item => item && typeof item.code === 'string');
    if (!items.length) return null;
    const area = parent.appendChild(el('ul', 'rg-disclosures'));
    items.forEach(item => area.appendChild(el('li', null, disclosureText(item))));
    return area;
  }
  function amount(value, currency) {
    return present(value) && Number.isFinite(Number(value)) ? `${value} ${currency || ''}`.trim() : 'No disponible';
  }
  function renderReceipt(parent, receipt = {}, status) {
    parent.replaceChildren();
    receipt = receipt && typeof receipt === 'object' ? receipt : {};
    const request = section(parent, 'Petición');
    fact(request, 'Estado', STATUS[status] || status);
    fact(request, 'Política local', POLICY[receipt.policy?.status] || receipt.policy?.status);
    if (list(receipt.policy?.reason_codes).length) fact(request, 'Motivos', receipt.policy.reason_codes.join(', '));
    list(receipt.policy?.rules).forEach(rule => fact(request, 'Regla coincidente', rule?.name || rule?.id));
    list(receipt.notices).forEach(notice => fact(request, 'Aviso', notice));
    if (receipt.consent_reason) fact(request, status === 'pending_consent' ? 'Confirmación' : 'Aviso de confirmación anterior',
      consentReason(receipt.consent_reason, status === 'pending_consent'));
    const coverage = receipt.coverage;
    if (coverage) {
      const area = section(parent, 'Documento');
      fact(area, 'Cobertura', coverage.status);
      fact(area, 'Unidades leídas / total', `${coverage.units_read ?? 'No disponible'} / ${coverage.units_total ?? 'No disponible'}`);
      if (list(coverage.warnings).length) fact(area, 'Advertencias', coverage.warnings.join(', '));
      list(coverage.disclosures).filter(item => item && typeof item.code === 'string')
        .forEach(item => fact(area, 'Aviso del documento', disclosureText(item)));
    }
    if (receipt.history) {
      const area = section(parent, 'Historial enviado');
      fact(area, 'Turnos enviados / omitidos', `${receipt.history.sent_turns ?? 'No disponible'} / ${receipt.history.omitted_turns ?? 'No disponible'}`);
      fact(area, 'Bytes enviados / omitidos', `${receipt.history.sent_bytes ?? 'No disponible'} / ${receipt.history.omitted_bytes ?? 'No disponible'}`);
    }
    const limits = Object.entries(LIMITS).filter(([key]) => receipt.limits?.[key] != null);
    if (limits.length || receipt.limits?.provider_managed) {
      const area = section(parent, 'Límites');
      limits.forEach(([key, name]) => fact(area, name, receipt.limits[key]));
      if (receipt.limits?.provider_managed) fact(area, 'Límites de generación', 'Gestionados por el proveedor');
    }
    if (receipt.route) {
      const area = section(parent, 'Ruta');
      fact(area, 'Selección', ROUTE[receipt.route.mode] || receipt.route.mode);
      if (receipt.route.company_engine_id != null) fact(area, 'Destino', 'engine:' + receipt.route.company_engine_id);
      fact(area, 'Modelo', receipt.route.model_effective || receipt.route.model || receipt.route.model_requested || receipt.route.model_id);
      if (receipt.route.task) fact(area, 'Tarea', receipt.route.task);
      if (receipt.route.level || receipt.route.tier) fact(area, 'Nivel', receipt.route.level || receipt.route.tier);
      if (list(receipt.route.reason_codes).length) fact(area, 'Motivos de la ruta', receipt.route.reason_codes.join(', '));
    }
    if (receipt.delivery) {
      const area = section(parent, 'Entrega');
      fact(area, 'Modo', receipt.delivery.mode === 'streamed' ? 'Progresiva, comprobada por fragmentos' : 'Al completar las comprobaciones');
      if (receipt.delivery.reason) fact(area, 'Motivo', DELIVERY[receipt.delivery.reason] || receipt.delivery.reason);
      list(receipt.delivery.withdrawn).forEach(item => fact(area, 'Texto retirado', `Intento ${item.attempt}: ${item.reason}`));
    }
    if (receipt.jev && window.regulayAgent?.renderReceipt) {
      const trace = parent.appendChild(el('div'));
      window.regulayAgent.renderReceipt(trace, receipt);
      const area = section(parent, 'Coste');
      fact(area, 'Coste total', receipt.total?.cost ?? 'No disponible');
      if (receipt.total?.cost == null && receipt.total?.known_cost != null) fact(area, 'Subtotal conocido (incompleto)', receipt.total.known_cost);
      if (receipt.total?.currency) fact(area, 'Moneda', receipt.total.currency);
      return parent;
    }
    const verification = section(parent, 'Verificación');
    fact(verification, 'Estado', VERIFICATION[receipt.verification?.status] || receipt.verification?.status || 'No realizada');
    if (list(receipt.verification?.reason_codes).length) fact(verification, 'Motivos', receipt.verification.reason_codes.join(', '));
    const calls = list(receipt.calls);
    const judge = calls.filter(call => call.purpose === 'verification' && call.status === 'completed').slice(-1)[0];
    if (judge?.signals) {
      Object.entries(SIGNALS).forEach(([key, name]) => {
        const value = judge.signals[key]?.noul;
        if (typeof value === 'number' && Number.isFinite(value)) fact(verification, name, value);
      });
      if (typeof judge.threshold === 'number') fact(verification, 'Umbral máximo de fallo admitido', Number((1 - judge.threshold).toFixed(10)));
    }
    parent.appendChild(el('p', 'rg-section-title', `Llamadas · ${calls.length}`));
    if (calls.length) {
      const items = parent.appendChild(el('ol', 'rg-calls'));
      calls.forEach((call, index) => {
        const item = items.appendChild(el('li'));
        const area = facts(item);
        fact(area, `Llamada ${index + 1}`, [PURPOSE[call.purpose] || call.purpose, CALL_STATUS[call.status] || call.status,
          call.provider, call.model_effective || call.model].filter(Boolean).join(' · '));
        fact(area, 'Coste', amount(call.cost, call.currency));
        if (call.duration_ms != null) fact(area, 'Duración', `${call.duration_ms} ms`);
      });
    }
    const generation = calls.filter(call => call.purpose === 'generation').slice(-1)[0];
    const total = receipt.total;
    const cost = section(parent, 'Coste');
    if (generation) fact(cost, 'Ruta efectiva', [generation.provider, generation.model_effective || generation.model].filter(Boolean).join(' / '));
    // Zero only when the record lists its calls and there were none (e.g. blocked locally).
    fact(cost, 'Coste total', total?.cost != null ? amount(total.cost, total.currency) :
      (Array.isArray(receipt.calls) && !calls.length ? '0 (sin llamadas)' : 'No disponible'));
    if (total?.cost == null && total?.known_cost != null) fact(cost, 'Subtotal conocido (incompleto)', amount(total.known_cost, total.currency));
    if (total) {
      fact(cost, 'Integridad del coste', ({estimated: 'Estimado con las tarifas configuradas', incomplete: 'Incompleto'})[total.cost_status || total.status] ||
        (total.complete === false ? 'Incompleto' : 'No disponible'));
      if (total.duration_ms != null) fact(cost, 'Duración total', `${total.duration_ms} ms`);
    }
    return parent;
  }
  function exportLink(parent, url) {
    const head = el('div', 'rg-receipt-head');
    head.appendChild(el('span', 'rg-meta', 'Registro de la decisión'));
    const link = head.appendChild(el('a', null, 'Exportar JSON'));
    link.href = url;
    link.setAttribute('download', '');
    parent.prepend(head);
  }
  async function toggleDetails(control) {
    const panel = byId(control.getAttribute('aria-controls'));
    if (!panel) return;
    const open = control.getAttribute('aria-expanded') !== 'true';
    control.setAttribute('aria-expanded', String(open));
    panel.hidden = !open;
    if (!open || panel.dataset.loaded) return;
    if (panel._rgData) {
      renderReceipt(panel, panel._rgData.receipt || {}, panel._rgData.status);
      exportLink(panel, control.dataset.receiptUrl);
      panel.dataset.loaded = 'true';
      return;
    }
    panel.replaceChildren(el('p', 'rg-meta', 'Cargando…'));
    try {
      const response = await fetch(control.dataset.receiptUrl, {headers: {Accept: 'application/json'}});
      if (!response.ok) throw new Error('unavailable');
      const data = await response.json();
      renderReceipt(panel, data.receipt || {}, data.status);
      exportLink(panel, control.dataset.receiptUrl);
      panel.dataset.loaded = 'true';
    } catch (_) {
      panel.replaceChildren(el('p', 'rg-meta', 'No se ha podido cargar el registro con tus permisos actuales.'));
    }
  }

  /* ------------------------------------------------------------ status line */
  function statusLine(text, live = true) {
    const line = el('div', 'rg-status');
    if (live) line.appendChild(el('span', 'rg-pulse')).setAttribute('aria-hidden', 'true');
    const label = line.appendChild(el('span', 'rg-status-text' + (live ? ' is-live' : ''), text));
    label.dataset.role = 'label';
    return line;
  }
  function stageText(event) {
    const retry = event.attempt > 1;
    switch (event.stage) {
      case 'protecting': return 'Protegiendo datos sensibles';
      case 'classifying': return 'Clasificando la petición';
      case 'generating': return (retry ? 'Reintentando' : 'Generando') + (event.model ? ' · ' + event.model : '');
      case 'verifying': return 'Verificando la respuesta';
      case 'waiting': return 'Esperando el resultado';
      default: return 'Procesando';
    }
  }

  /* ------------------------------------------------------------ app */
  const app = byId('chatApp');
  const state = {conversationId: app?.dataset.conversation || null, busy: null, sending: false};

  function announce(text) {
    const region = byId('chatStatus');
    if (!region) return;
    region.textContent = '';
    window.setTimeout(() => { region.textContent = text; }, 30);
  }
  function toast(text, error = false) {
    document.querySelector('.rg-toast')?.remove();
    const node = document.body.appendChild(el('div', 'rg-toast' + (error ? ' is-error' : ''), text));
    node.setAttribute('role', 'status');
    window.setTimeout(() => node.remove(), 3200);
  }

  /* Scroll: follow new content only while the reader is at the end. */
  const scroller = byId('chatScroll');
  const jump = byId('jumpToEnd');
  const unseen = new Set();
  const jumpCount = jump?.appendChild(el('span', 'rg-jump-count'));
  let stuck = true;
  function resetUnseen() {
    unseen.clear();
    if (jumpCount) { jumpCount.textContent = ''; jumpCount.hidden = true; }
  }
  resetUnseen();
  const atEnd = () => !scroller || scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 72;
  function toEnd(smooth = false) {
    if (!scroller) return;
    stuck = true;
    resetUnseen();
    if (jump) jump.hidden = true;
    scroller.scrollTo({top: scroller.scrollHeight, behavior: smooth && !reducedMotion() ? 'smooth' : 'auto'});
  }
  function follow(updateKey) {
    if (!scroller) return;
    if (stuck) scroller.scrollTop = scroller.scrollHeight;
    else if (jump && scroller.scrollHeight > scroller.clientHeight + 72) {
      jump.hidden = false;
      if (typeof updateKey === 'string' && updateKey && !unseen.has(updateKey)) {
        unseen.add(updateKey);
        jumpCount.textContent = ` · ${unseen.size} ${unseen.size === 1 ? 'mensaje actualizado' : 'mensajes actualizados'}`;
        jumpCount.hidden = false;
      }
    }
  }

  /* Markdown */
  const sources = new WeakMap();
  function renderMarkdown(node, source, options = {}) {
    sources.set(node, source);
    if (window.RegulayMarkdown) window.RegulayMarkdown.render(node, source, options);
    else node.textContent = source;
  }
  function hydrate(root) {
    root.querySelectorAll('[data-md]').forEach(node => {
      if (sources.has(node)) return;
      const source = node.textContent;
      node.textContent = '';
      renderMarkdown(node, source);
    });
  }
  async function copy(text, control) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      const area = document.body.appendChild(el('textarea'));
      area.value = text; area.select();
      try { document.execCommand('copy'); } catch (__) { /* Clipboard unavailable. */ }
      area.remove();
    }
    if (!control) return;
    const label = control.getAttribute('aria-label');
    control.classList.add('is-done');
    if (control.classList.contains('rg-code-copy')) control.textContent = 'Copiado';
    else control.setAttribute('aria-label', 'Copiado');
    announce('Copiado');
    window.setTimeout(() => {
      control.classList.remove('is-done');
      if (control.classList.contains('rg-code-copy')) control.textContent = 'Copiar';
      else if (label) control.setAttribute('aria-label', label);
    }, 1600);
  }

  /* ------------------------------------------------------------ turns */
  const container = byId('chatContainer');
  function leaveEmptyState() {
    app?.classList.remove('is-empty');
    byId('welcome')?.remove();
  }
  function userTurn(command) {
    const turn = el('article', 'rg-turn rg-enter');
    turn.dataset.requestId = command.requestId;
    const user = turn.appendChild(el('div', 'rg-msg rg-msg-user'));
    if (command.prompt) user.appendChild(el('div', 'rg-bubble', command.prompt));
    if (command.file) {
      const chip = user.appendChild(el('div', 'rg-attachment'));
      chip.appendChild(icon('file'));
      chip.appendChild(el('span', 'rg-attachment-name', command.file.name));
      chip.appendChild(el('span', 'rg-meta', fileSize(command.file.size)));
    }
    const ai = turn.appendChild(el('div', 'rg-msg rg-msg-ai'));
    return {turn, ai};
  }
  function turnFromArticle(article) {
    const ai = article.querySelector('.rg-msg-ai');
    const prompt = article.querySelector('.rg-bubble')?.textContent || '';
    const command = {...settings(), requestId: article.dataset.requestId, prompt};
    const consent = article.querySelector('[data-consent]');
    if (consent && 'engine' in consent.dataset) {
      // The same request must be confirmed with the selection it was sent with.
      command.engineId = consent.dataset.engine || null;
      command.modelId = consent.dataset.model || null;
      command.autoRoute = !command.engineId && !command.modelId;
    }
    return {turn: article, ai, command};
  }

  function answerBlock(target, data, command, body) {
    const message = data.assistant_message;
    const agentResult = command?.mode === 'agent' || Boolean(data.receipt?.jev && data.agent);
    const verified = data.receipt?.verification?.status === 'passed';
    let text = message.content || '';
    if (!verified && !agentResult) {
      const chip = target.appendChild(el('span', 'rg-chip is-warn', 'No verificado'));
      chip.title = 'La respuesta no superó la verificación configurada y se entrega en modo informativo';
      chip.setAttribute('role', 'status');
      if (text.startsWith('No verificado\n\n')) text = text.slice('No verificado\n\n'.length);
    }
    body = target.appendChild(body || el('div', 'rg-md'));
    body.classList.remove('is-streaming');
    body.dataset.md = '';
    renderMarkdown(body, text, {animate: !body._rgBlocks});
    if (message.file_name && message.file_url && /^\/chat\/download\/\d+\/$/.test(message.file_url)) {
      const link = target.appendChild(el('a', 'rg-file-chip'));
      link.href = message.file_url;
      link.setAttribute('download', message.file_name);
      link.appendChild(icon('file'));
      link.appendChild(el('span', null, message.file_name));
      if (message.file_size) link.appendChild(el('span', 'rg-meta', fileSize(message.file_size)));
      link.appendChild(icon('download'));
    }
    const items = list(data.evidence?.items || data.evidence).filter(item => item && typeof item === 'object' && typeof item.locator === 'string');
    if (verified && items.length && !agentResult) target.appendChild(evidenceBlock(items, data.request_id));
  }
  function evidenceBlock(items, requestId) {
    const details = el('details', 'rg-disclosure rg-evidence');
    details.appendChild(el('summary', null, `Citas del documento · ${items.length}`));
    const cites = details.appendChild(el('ol', 'rg-cites'));
    items.forEach(item => {
      const row = cites.appendChild(el('li'));
      row.id = `cite-${requestId}-${item.claim_index}`;
      row.appendChild(el('span', 'rg-cite-index', item.claim_index ?? '·'));
      const body = row.appendChild(el('div'));
      body.appendChild(el('span', 'rg-meta', item.locator));
      body.appendChild(el('blockquote', null, item.excerpt || item.text || ''));
    });
    details.appendChild(el('p', 'rg-meta', 'Vuelve a adjuntar el original para comprobarlas de nuevo.'));
    return details;
  }
  function noticeBlock(kind, title, text, iconName) {
    const notice = el('div', 'rg-notice is-' + kind);
    notice.appendChild(icon(iconName));
    const body = notice.appendChild(el('div'));
    body.appendChild(el('strong', null, title));
    if (text) body.appendChild(el('p', null, text));
    return {notice, body};
  }
  function actionsRow(target, data, hasAnswer) {
    if (!data.request_id) return;
    const row = target.appendChild(el('div', 'rg-actions'));
    if (hasAnswer) {
      const copyButton = row.appendChild(el('button', 'rg-icon-btn rg-sm'));
      copyButton.type = 'button';
      copyButton.dataset.action = 'copy';
      copyButton.setAttribute('aria-label', 'Copiar respuesta');
      copyButton.title = 'Copiar';
      copyButton.appendChild(icon('copy'));
    }
    const details = row.appendChild(el('button', 'rg-link-btn', 'Detalles'));
    details.type = 'button';
    details.dataset.action = 'details';
    details.dataset.receiptUrl = '/chat/requests/' + data.request_id + '/receipt/';
    details.setAttribute('aria-expanded', 'false');
    details.setAttribute('aria-controls', 'receipt-' + data.request_id);
    details.appendChild(icon('chevron'));
    const panel = target.appendChild(el('div', 'rg-receipt'));
    panel.id = 'receipt-' + data.request_id;
    panel.dataset.receipt = '';
    panel.hidden = true;
    panel._rgData = {receipt: data.receipt || {}, status: data.status};
  }

  /* Outcome of one request, from a stream's final event or a JSON reply. */
  function renderOutcome(live, data, httpStatus) {
    const {ai, command} = live;
    data = data && typeof data === 'object' ? data : {};
    live.done = true;
    live.status = data.status || 'validation_error';
    if (command) {
      command.status = live.status;
      command.token = data.consent_token || command.token;
    }
    if (data.conversation_id) adoptConversation(data.conversation_id);
    live.turn.dataset.status = live.status;
    delete live.turn.dataset.live;
    // A streamed answer keeps its node: the final text extends what was shown.
    const keep = data.assistant_message && live.status === 'completed' && live.body?.isConnected ? live.body : null;
    ai.replaceChildren();
    live.body = null;
    live.line = null;
    if (data.agent && window.regulayAgent?.mount) {
      window.regulaySkills?.accepted?.();
      const host = ai.appendChild(el('div', 'rg-agent'));
      host.dataset.agentRun = data.agent.id;
      live.turn.dataset.run = data.agent.id;
      window.regulayAgent.mount(host, data.agent, {fresh: true, command});
      return;
    }
    const status = live.status;
    if (status === 'completed' && data.assistant_message) {
      answerBlock(ai, data, command, keep);
      announce('Respuesta lista');
    } else if (status === 'blocked') {
      const rules = list(data.blocked_rules).map(rule => rule?.name).filter(Boolean);
      ai.appendChild(noticeBlock('blocked', 'Bloqueado por la política',
        (rules.length ? `Coincide con ${rules.join(', ')}. ` : '') + 'No se ha enviado a ningún proveedor.', 'shield').notice);
      announce('Bloqueado por la política');
    } else if (status === 'pending_consent') {
      ai.appendChild(consentNotice(live, data));
      announce('Requiere tu confirmación');
    } else if (status === 'cancelled') {
      const own = data.error_type === 'cancelled_by_user';
      ai.appendChild(el('p', 'rg-quiet-note', own ? data.error || 'Respuesta detenida.' : 'Petición cancelada. No se ha enviado.'));
      announce(own ? 'Respuesta detenida' : 'Petición cancelada');
    } else if (LIVE.includes(status) || status === 'accepted') {
      ai.appendChild(statusLine('Sin resultado todavía', false));
      const row = ai.appendChild(el('div', 'rg-notice-actions'));
      row.appendChild(button('Comprobar estado', 'rg-btn', () => attach(live), 'refresh'));
      live.done = false;
    } else {
      const code = data.error_type;
      const title = SETUP_CODES.includes(code) ? 'Configuración incompleta' : ERROR_TITLES[code] || 'No se pudo completar';
      const {notice, body} = noticeBlock('error', title, data.error || 'La petición no se pudo completar.', 'alert');
      if (live.retracted) body.appendChild(el('p', 'rg-meta', 'El texto parcial se retiró y no se ha guardado.'));
      const row = body.appendChild(el('div', 'rg-notice-actions'));
      if (status === 'outcome_unknown') row.appendChild(button('Comprobar estado', 'rg-btn', () => attach(live), 'refresh'));
      if (['failed', 'outcome_unknown'].includes(status) && command && (command.prompt || command.file)) {
        row.appendChild(button('Volver a enviar', 'rg-btn', () => resend(command), 'refresh'));
      }
      if (!row.children.length) row.remove();
      ai.appendChild(notice);
      announce(title);
    }
    actionsRow(ai, data, status === 'completed' && Boolean(data.assistant_message));
    follow(live.requestId);
  }

  function consentNotice(live, data) {
    const {command} = live;
    const rules = list(data.consent_rules).map(rule => rule?.name).filter(Boolean);
    const reason = data.consent_reason || data.receipt?.consent_reason;
    const {notice, body} = noticeBlock('consent', 'Requiere tu confirmación',
      (rules.length ? `Coincide con ${rules.join(', ')}. ` : '') + (reason ? consentReason(reason) : 'Revisa el aviso antes de enviar este mismo contenido.'), 'shield');
    renderDisclosures(body, data.receipt?.coverage);
    list(data.receipt?.notices).forEach(item => body.appendChild(el('p', 'rg-meta', item)));
    const row = body.appendChild(el('div', 'rg-notice-actions'));
    const token = data.consent_token || command?.token;
    if (command && token && (!command.fileName || command.file)) {
      row.appendChild(button('Confirmar envío', 'rg-btn rg-btn-primary', () => {
        command.token = token;
        submit(command, live);
      }));
    } else if (command?.fileName) {
      row.appendChild(el('p', 'rg-meta', `Para confirmar, vuelve a enviar la petición con «${command.fileName}» adjunto.`));
    }
    row.appendChild(button('Cancelar', 'rg-btn', () => submit(command, live, 'cancel')));
    return notice;
  }

  /* ------------------------------------------------------------ transport */
  function parseFrame(frame) {
    const data = [];
    let type = 'message';
    frame.split('\n').forEach(line => {
      if (!line || line.startsWith(':')) return;
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') type = value;
      else if (field === 'data') data.push(value);
    });
    if (!data.length) return null;
    try {
      const event = JSON.parse(data.join('\n'));
      if (!event.type) event.type = type;
      return event;
    } catch (_) {
      return null;
    }
  }
  async function readStream(response, onEvent) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer = (buffer + decoder.decode(value, {stream: true})).replace(/\r\n?/g, '\n');
      let index;
      while ((index = buffer.indexOf('\n\n')) >= 0) {
        const event = parseFrame(buffer.slice(0, index));
        buffer = buffer.slice(index + 2);
        if (event) onEvent(event);
      }
    }
  }

  /* One request's live view. Events are applied once, in order, by sequence. */
  function createLive(parts, command) {
    return {...parts, command, requestId: command?.requestId || parts.turn.dataset.requestId,
      seq: 0, attempt: 0, text: '', done: false, retracted: false, status: null, body: null, line: null, frame: 0};
  }
  function ensureLine(live, text) {
    if (!live.line || !live.line.isConnected) {
      live.line = statusLine(text);
      live.ai.prepend(live.line);
    } else live.line.querySelector('[data-role=label]').textContent = text;
    return live.line;
  }
  function setNote(live, text) {
    const line = ensureLine(live, live.line?.querySelector('[data-role=label]')?.textContent || 'Procesando');
    let note = line.querySelector('.rg-status-note');
    if (!text) { note?.remove(); return; }
    if (!note) note = line.appendChild(el('span', 'rg-status-note'));
    note.textContent = '· ' + text;
  }
  function paint(live) {
    live.frame = 0;
    if (!live.body) return;
    renderMarkdown(live.body, live.text, {streaming: true, animate: true});
    follow(live.requestId);
  }
  function handleEvent(live, event) {
    if (!event || typeof event.seq !== 'number' || event.seq <= live.seq) return false;
    live.seq = event.seq;
    switch (event.type) {
      case 'accepted':
        if (event.conversation_id) adoptConversation(event.conversation_id);
        break;
      case 'stage':
        ensureLine(live, stageText(event));
        if (event.stage === 'generating' && event.attempt > 1) announce('Reintentando con otro modelo');
        break;
      case 'delivery':
        setNote(live, event.mode === 'complete' ? DELIVERY[event.reason] || '' : '');
        break;
      case 'delta':
        if (event.attempt !== live.attempt) { live.attempt = event.attempt; live.text = ''; }
        live.text += event.text || '';
        if (!live.body || !live.body.isConnected) {
          live.body = live.ai.appendChild(el('div', 'rg-md is-streaming'));
          live.body.setAttribute('aria-busy', 'true');
        }
        live.line?.remove();
        live.line = null;
        if (!live.frame) live.frame = (window.requestAnimationFrame || (fn => window.setTimeout(fn, 16)))(() => paint(live));
        break;
      case 'retract':
        live.retracted = true;
        live.text = '';
        live.body?.remove();
        live.body = null;
        ensureLine(live, event.reason === 'retry' ? 'Reintentando' : 'Comprobando');
        setNote(live, event.reason === 'retry' ? 'el texto anterior no superó las comprobaciones y se ha retirado' : 'el texto mostrado se ha retirado');
        break;
      case 'final':
        if (live.frame) { (window.cancelAnimationFrame || window.clearTimeout)(live.frame); live.frame = 0; }
        live.body?.removeAttribute('aria-busy');
        renderOutcome(live, event.result || {}, event.http_status);
        break;
      default:
        return false;
    }
    return true;
  }

  async function attach(live, {reportMissing = true} = {}) {
    // Rejoin a request: replays from the last applied event and never starts work.
    if (!live.requestId) return false;
    live.done = false;
    let missing = false;
    if (!live.ai.querySelector('.rg-md')) ensureLine(live, 'Reconectando');
    for (let attempt = 0; attempt < 6 && !live.done; attempt++) {
      if (attempt) await new Promise(resolve => window.setTimeout(resolve, Math.min(8000, 500 * 2 ** (attempt - 1))));
      try {
        const response = await fetch(`/chat/requests/${live.requestId}/stream/?after=${live.seq}`,
          {headers: {Accept: 'text/event-stream'}, cache: 'no-store'});
        if (response.status === 404) { missing = true; break; }
        if (!response.ok || !response.body) continue;
        await readStream(response, event => handleEvent(live, event));
      } catch (_) { /* Retry with backoff. */ }
    }
    if (!live.done) {
      live.line?.remove();
      live.line = null;
      if (missing) {
        // Not registered for this account: never claim that it is still running.
        if (reportMissing) live.ai.appendChild(noticeBlock('error', 'Petición no disponible',
          'No consta con tus permisos actuales.', 'alert').notice);
        return false;
      }
      const {notice, body} = noticeBlock('error', 'Conexión interrumpida',
        'La petición sigue registrada; reconectar no la repite.', 'alert');
      body.appendChild(el('div', 'rg-notice-actions')).appendChild(button('Comprobar estado', 'rg-btn', () => {
        notice.remove();
        attach(live);
      }, 'refresh'));
      live.ai.appendChild(notice);
    }
    return live.done;
  }

  function formData(command, action, stream) {
    const form = new FormData();
    form.append('prompt', command.prompt || '');
    form.append('request_id', command.requestId);
    form.append('auto_route', String(Boolean(command.autoRoute)));
    if (command.mode) form.append('mode', command.mode);
    if (command.inferenceProfile) form.append('inference_profile', command.inferenceProfile);
    if (command.skills) form.append('skills', JSON.stringify(command.skills));
    if (command.artifactId) form.append('artifact_id', command.artifactId);
    if (command.baseRevision) form.append('base_revision', command.baseRevision);
    if (command.documentReference) form.append('document_reference', command.documentReference);
    if (command.exportName) form.append('export_name', command.exportName);
    if (command.file) form.append('file', command.file);
    if (command.engineId) form.append('engine_id', command.engineId);
    if (command.modelId) form.append('model_id', command.modelId);
    if (command.token) form.append('consent_token', command.token);
    if (action) form.append('action', action);
    if (stream) form.append('stream', '1');
    form.append('csrfmiddlewaretoken', csrf());
    return form;
  }

  async function submit(command, live, action = '') {
    if (state.sending) return;
    state.sending = true;
    const streamed = !action && command.mode !== 'agent' && window.ReadableStream && window.TextDecoder;
    live.done = false;
    live.retracted = false;
    live.ai.replaceChildren();
    live.body = null;
    live.line = null;
    ensureLine(live, action === 'cancel' ? 'Cancelando' : command.mode === 'agent' ? 'Enviando al agente' : 'Enviando');
    setBusy('request', streamed ? () => stopRequest(live) : null);
    const url = command.conversationId ? `/chat/${command.conversationId}/send/` : '/chat/send/';
    try {
      const response = await fetch(url, {method: 'POST', body: formData(command, action, streamed),
        headers: {Accept: streamed ? 'text/event-stream' : 'application/json'}});
      if (streamed && response.body && (response.headers.get('Content-Type') || '').includes('text/event-stream')) {
        await readStream(response, event => handleEvent(live, event));
        if (!live.done) await attach(live);
      } else {
        // Blocked and unavailable replies carry useful JSON even with 403/503.
        renderOutcome(live, await response.json(), response.status);
      }
    } catch (_) {
      // The request may have started before the connection failed: rejoin it.
      // If it was never registered, retrying sends this same request again.
      if (streamed) await attach(live, {reportMissing: false});
      if (!live.done && !live.ai.querySelector('.rg-notice')) {
        live.ai.replaceChildren();
        const {notice, body} = noticeBlock('error', 'No se pudo obtener el resultado',
          'Reintentar consulta esta misma petición; no crea un envío nuevo.', 'alert');
        body.appendChild(el('div', 'rg-notice-actions')).appendChild(button('Reintentar', 'rg-btn', () => submit(command, live, action), 'refresh'));
        live.ai.appendChild(notice);
      }
    } finally {
      state.sending = false;
      if (busyOwner === 'request') setBusy(null);
      follow(live.requestId);
    }
  }

  async function stopRequest(live) {
    if (!live.requestId || live.done) return;
    ensureLine(live, 'Deteniendo');
    try {
      await fetch(`/chat/requests/${live.requestId}/cancel/`, {method: 'POST', headers: {'X-CSRFToken': csrf()}});
    } catch (_) {
      toast('No se pudo detener. La respuesta sigue en curso.', true);
    }
  }

  /* ------------------------------------------------------------ composer */
  const form = byId('chatForm');
  const input = byId('prompt');
  const fileInput = byId('fileInput');
  const sendButton = byId('sendButton');
  const stopButton = byId('stopButton');
  const hint = byId('composerHint');
  let stopAction = null;
  let busyOwner = null;

  function setBusy(owner, onStop = null) {
    busyOwner = owner;
    stopAction = onStop;
    if (stopButton) stopButton.hidden = !onStop;
    if (sendButton) sendButton.hidden = Boolean(onStop);
    updateSend();
  }
  function updateSend() {
    if (!sendButton) return;
    sendButton.disabled = Boolean(busyOwner) || (!input?.value.trim() && !fileInput?.files?.length);
  }
  function autosize() {
    if (!input) return;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, Math.round(window.innerHeight * 0.4)) + 'px';
  }
  function setHint(text = '', error = false) {
    if (!hint) return;
    hint.textContent = text;
    hint.classList.toggle('is-error', error);
  }
  function accepted(file) {
    const allowed = (fileInput?.accept || '').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
    const name = file.name.toLowerCase();
    return !allowed.length || allowed.some(extension => name.endsWith(extension));
  }
  function showFile(file) {
    const area = byId('filePreview');
    if (!area) return;
    area.replaceChildren();
    area.hidden = !file;
    if (!file) return;
    const chip = area.appendChild(el('div', 'rg-file'));
    chip.appendChild(el('span', 'rg-file-icon')).appendChild(icon('file'));
    const text = chip.appendChild(el('span', 'rg-file-text'));
    text.appendChild(el('strong', null, file.name));
    text.appendChild(el('span', null, fileSize(file.size)));
    const remove = chip.appendChild(el('button', 'rg-icon-btn rg-sm'));
    remove.type = 'button';
    remove.setAttribute('aria-label', `Quitar ${file.name}`);
    remove.appendChild(icon('x'));
    remove.addEventListener('click', () => { clearFile(); input?.focus(); });
  }
  function setFile(file) {
    if (!fileInput) return;
    if (file && !accepted(file)) {
      clearFile();
      setHint(`Formato no admitido aquí: ${fileInput.accept.replaceAll(',', ', ')}`, true);
      return;
    }
    if (file && fileInput.files?.[0] !== file && typeof DataTransfer === 'function') {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      fileInput.files = transfer.files;
    }
    setHint();
    showFile(file || null);
    updateSend();
  }
  function clearFile() {
    if (fileInput) fileInput.value = '';
    showFile(null);
    updateSend();
  }
  function currentMode() {
    if (app?.dataset.conversation) return app.dataset.mode;
    return document.querySelector('input[name=conversation_mode]:checked')?.value || app?.dataset.mode || 'chat';
  }
  function setMode(mode) {
    if (!app) return;
    app.dataset.mode = mode;
    const agent = mode === 'agent';
    const professional = app.dataset.professional === 'true';
    if (input) input.placeholder = agent ? (professional ? 'Describe qué quieres investigar, calcular o crear…' :
      'Describe el documento: formato, idioma y extensión…') : 'Escribe un mensaje…';
    if (fileInput) fileInput.accept = agent && !professional ? '.csv,.xlsx' : '.txt,.pdf,.docx,.pptx,.csv,.json,.py,.js,.md,.xlsx' + (agent && professional ? ',.html,.htm,.css,.svg,.zip,.png,.jpg,.jpeg,.sh' : '');
    document.querySelectorAll('[data-for]').forEach(node => { node.hidden = node.dataset.for !== mode; });
    if (!agent && byId('drivePanel')) {
      byId('drivePanel').hidden = true;
      byId('driveButton')?.setAttribute('aria-expanded', 'false');
    }
    if (fileInput?.files?.[0] && !accepted(fileInput.files[0])) clearFile();
    window.regulayAgent?.modeChanged?.(agent);
  }

  function selectedOption(groupId, attribute) {
    return document.querySelector(`#${groupId} [aria-checked="true"]`)?.dataset[attribute] || null;
  }
  function settings() {
    return {conversationId: state.conversationId, autoRoute: byId('automaticRouting')?.checked || false,
      engineId: selectedOption('engineOptions', 'engineId'), modelId: selectedOption('modelOptions', 'modelId'),
      ...(currentMode() === 'agent' ? {mode: 'agent', inferenceProfile: byId('inferenceProfile')?.value || 'legacy'} : {})};
  }
  function buildCommand() {
    const prompt = input?.value.trim() || '';
    const file = fileInput?.files?.[0] || null;
    if (!prompt && !file) return null;
    const command = {requestId: requestUUID(), prompt, file, fileName: file?.name || null, ...settings()};
    if (command.mode === 'agent') Object.assign(command, window.regulayAgent?.capture(file) || {});
    if (command.mode === 'agent' && window.regulaySkills) command.skills = window.regulaySkills.capture();
    return command;
  }
  function send() {
    if (busyOwner || state.sending) return;
    const command = buildCommand();
    if (!command) return;
    leaveEmptyState();
    form?.querySelector('.rg-mode')?.remove();
    const parts = userTurn(command);
    container.appendChild(parts.turn);
    const live = createLive(parts, command);
    input.value = '';
    autosize();
    clearFile();
    window.regulayAgent?.consumed?.();
    toEnd();
    submit(command, live);
  }
  function resend(previous) {
    if (busyOwner || state.sending) return;
    if (previous.fileName && !previous.file) return;
    const command = {...previous, ...settings(), requestId: requestUUID(), token: null, status: null};
    const parts = userTurn(command);
    container.appendChild(parts.turn);
    toEnd();
    submit(command, createLive(parts, command));
  }

  function adoptConversation(id) {
    if (!id || String(state.conversationId) === String(id)) return;
    state.conversationId = String(id);
    if (app) app.dataset.conversation = String(id);
    window.history.replaceState({}, '', `/chat/${id}/`);
    const listNode = byId('threadList');
    if (listNode && !listNode.querySelector(`a[href="/chat/${id}/"]`)) {
      listNode.querySelectorAll('.rg-thread.is-active').forEach(item => item.classList.remove('is-active'));
      listNode.querySelector('.rg-threads-empty:not(#threadsNone)')?.remove();
      let group = listNode.querySelector('.rg-thread-group');
      if (!group || group.querySelector('h2')?.textContent !== 'Hoy') {
        group = el('section', 'rg-thread-group');
        group.appendChild(el('h2', null, 'Hoy'));
        group.appendChild(el('ul'));
        listNode.prepend(group);
      }
      const item = el('li', 'rg-thread is-active');
      item.dataset.title = 'nueva conversación';
      const link = item.appendChild(el('a'));
      link.href = `/chat/${id}/`;
      link.setAttribute('aria-current', 'page');
      if (currentMode() === 'agent') link.appendChild(icon('spark'));
      link.appendChild(el('span', null, 'Nueva conversación'));
      group.querySelector('ul').prepend(item);
    }
  }

  /* ------------------------------------------------------------ model picker */
  function initModelPicker() {
    const picker = byId('modelPicker');
    if (!picker) return;
    const trigger = byId('modelButton');
    const menu = byId('modelMenu');
    const automatic = byId('automaticRouting');
    const name = byId('currentModelName');
    let modelName = name?.textContent || 'Modelo';
    const label = () => { if (name) name.textContent = automatic?.checked ? 'Automático' : modelName; };
    const open = value => {
      menu.hidden = !value;
      trigger.setAttribute('aria-expanded', String(value));
      if (value) (menu.querySelector('[aria-checked="true"]') || menu.querySelector('button, input'))?.focus();
    };
    trigger.addEventListener('click', event => { event.stopPropagation(); open(menu.hidden); });
    document.addEventListener('click', event => { if (!picker.contains(event.target)) open(false); });
    picker.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !menu.hidden) { event.stopPropagation(); open(false); trigger.focus(); }
    });
    automatic?.addEventListener('change', label);
    const check = (group, chosen) => group.querySelectorAll('[role=radio]').forEach(option =>
      option.setAttribute('aria-checked', String(option === chosen)));
    async function choose(option, url, field, value) {
      const form = new FormData();
      form.append(field, value);
      form.append('csrfmiddlewaretoken', csrf());
      option.disabled = true;
      try {
        const response = await fetch(url, {method: 'POST', body: form});
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || 'unavailable');
        return data;
      } catch (_) {
        toast('No se pudo cambiar la selección.', true);
        return null;
      } finally {
        option.disabled = false;
      }
    }
    byId('engineOptions')?.addEventListener('click', async event => {
      const option = event.target.closest('[data-engine-id]');
      if (!option) return;
      const data = await choose(option, picker.dataset.engineUrl, 'engine_id', option.dataset.engineId);
      if (!data) return;
      check(byId('engineOptions'), option);
      const models = list(data.available_models);
      const group = byId('modelOptions');
      group.replaceChildren(...models.map((model, index) => {
        const item = el('button', 'rg-option');
        item.type = 'button';
        item.setAttribute('role', 'radio');
        item.setAttribute('aria-checked', String(index === 0));
        item.dataset.modelId = model.id;
        item.dataset.name = model.name;
        item.appendChild(el('span', null, model.name));
        item.appendChild(el('small', null, model.model_id + (model.supports_vision ? ' · imágenes' : '')));
        return item;
      }));
      modelName = models[0]?.name || 'Modelo';
      if (automatic) automatic.checked = false;
      label();
      toast(`Proveedor: ${option.dataset.name}`);
    });
    byId('modelOptions')?.addEventListener('click', async event => {
      const option = event.target.closest('[data-model-id]');
      if (!option) return;
      const data = await choose(option, picker.dataset.modelUrl, 'model_id', option.dataset.modelId);
      if (!data) return;
      check(byId('modelOptions'), option);
      modelName = option.dataset.name;
      if (automatic) automatic.checked = false;
      label();
      open(false);
      trigger.focus();
    });
    menu.addEventListener('keydown', event => {
      if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
      const options = Array.from(menu.querySelectorAll('button:not(:disabled), input'));
      const index = options.indexOf(document.activeElement);
      options[(index + (event.key === 'ArrowDown' ? 1 : -1) + options.length) % options.length]?.focus();
      event.preventDefault();
    });
    label();
  }

  /* ------------------------------------------------------------ layout */
  const THREADS_KEY = 'regulai.chat.threads';
  const desktop = () => window.matchMedia?.('(min-width: 992px)').matches ?? true;
  function setDrawer(open) {
    if (!app) return;
    app.classList.toggle('is-drawer-open', open);
    document.querySelector('.rg-scrim').hidden = !open;
    // Behind the scrim nothing is reachable by keyboard while the drawer is open.
    byId('chatMain')?.toggleAttribute('inert', open);
    document.querySelectorAll('[data-action="nav-open"]').forEach(node => node.setAttribute('aria-expanded', String(open)));
    if (open) (document.querySelector('.rg-thread.is-active a') || document.querySelector('.rg-new'))?.focus({preventScroll: true});
  }
  function setThreads(visible) {
    if (!app) return;
    app.classList.toggle('is-threads-hidden', !visible);
    document.querySelectorAll('[data-action="threads-toggle"]').forEach(node => {
      node.setAttribute('aria-expanded', String(visible));
      const text = visible ? 'Ocultar conversaciones' : 'Mostrar conversaciones';
      node.setAttribute('aria-label', text);
      node.title = text;
    });
    try { window.localStorage.setItem(THREADS_KEY, visible ? 'shown' : 'hidden'); } catch (_) { /* Optional. */ }
  }
  function filterThreads(query) {
    const value = query.trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll('.rg-thread-group').forEach(group => {
      let visible = 0;
      group.querySelectorAll('.rg-thread').forEach(item => {
        const match = !value || (item.dataset.title || '').includes(value);
        item.hidden = !match;
        visible += match ? 1 : 0;
      });
      group.hidden = !visible;
      shown += visible;
    });
    const none = byId('threadsNone');
    if (none) none.hidden = !value || shown > 0;
  }

  function busyFromAgent(active, onStop, text = 'El agente está trabajando') {
    if (active) {
      setBusy('agent', onStop || null);
      setHint(text);
    } else if (busyOwner === 'agent') {
      setBusy(null);
      setHint();
    }
  }

  function initEvents() {
    document.addEventListener('click', event => {
      const target = event.target.closest('[data-action], .rg-code-copy, .rg-cite, [data-suggestion]');
      if (!target) return;
      if (target.classList.contains('rg-code-copy')) { copy(target.dataset.copy || '', target); return; }
      if (target.classList.contains('rg-cite')) { openCitation(target); return; }
      if (target.dataset.suggestion) {
        input.value = target.dataset.suggestion;
        autosize();
        updateSend();
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
        return;
      }
      const article = target.closest('.rg-turn');
      switch (target.dataset.action) {
        case 'threads-toggle':
          if (desktop()) setThreads(app.classList.contains('is-threads-hidden'));
          else setDrawer(false);
          break;
        case 'nav-open': setDrawer(!app.classList.contains('is-drawer-open')); break;
        case 'drawers-close': setDrawer(false); break;
        case 'copy': {
          const body = article?.querySelector('.rg-md');
          if (body) copy(window.RegulayMarkdown?.plain(sources.get(body) ?? body.textContent) ?? body.textContent, target);
          break;
        }
        case 'details': toggleDetails(target); break;
        case 'consent-confirm':
        case 'consent-cancel': {
          if (!article) break;
          const parts = turnFromArticle(article);
          const live = createLive(parts, parts.command);
          if (target.dataset.action === 'consent-confirm') {
            parts.command.token = target.closest('[data-token]')?.dataset.token;
            if (!parts.command.token) break;
          }
          submit(parts.command, live, target.dataset.action === 'consent-cancel' ? 'cancel' : '');
          break;
        }
        case 'check': if (article) attach(createLive(turnFromArticle(article))); break;
        case 'resend': if (article) resend(turnFromArticle(article).command); break;
        case 'dialog-close': target.closest('dialog')?.close(); break;
        default: break;
      }
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && app?.classList.contains('is-drawer-open')) {
        setDrawer(false);
        document.querySelector('[data-action="nav-open"]')?.focus();
      }
    });
    window.matchMedia?.('(min-width: 992px)').addEventListener?.('change', () => setDrawer(false));
    byId('threadSearch')?.addEventListener('input', event => filterThreads(event.target.value));
    byId('threadList')?.addEventListener('click', event => {
      if (event.target.closest('a') && !desktop()) setDrawer(false);
    });
    // A smooth target becomes stale when lazy historical cards hydrate on the
    // way down. Jump immediately, then normal follow keeps the latest end.
    jump?.addEventListener('click', () => toEnd());
    scroller?.addEventListener('scroll', () => {
      stuck = atEnd();
      if (stuck && jump) { jump.hidden = true; resetUnseen(); }
      byId('chatMain')?.classList.toggle('is-scrolled', scroller.scrollTop > 4);
    }, {passive: true});
    if (window.ResizeObserver && container) new ResizeObserver(() => follow()).observe(container);
    if (window.ResizeObserver && form) new ResizeObserver(() => {
      byId('chatMain')?.style.setProperty('--rg-composer-h', form.offsetHeight + 'px');
    }).observe(form);

    // A fragment link does not move keyboard focus in every browser: do it explicitly.
    document.querySelector('.rg-skip')?.addEventListener('click', event => { event.preventDefault(); input?.focus(); });
    form?.addEventListener('submit', event => { event.preventDefault(); send(); });
    input?.addEventListener('input', () => { autosize(); updateSend(); });
    input?.addEventListener('keydown', event => {
      if (event.key !== 'Enter' || event.shiftKey || event.isComposing || event.keyCode === 229) return;
      event.preventDefault();
      send();
    });
    byId('attachButton')?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', () => setFile(fileInput.files?.[0] || null));
    stopButton?.addEventListener('click', () => stopAction?.());
    const box = byId('composerBox');
    if (box && fileInput) {
      ['dragenter', 'dragover'].forEach(name => box.addEventListener(name, event => {
        if (!event.dataTransfer?.types?.includes('Files')) return;
        event.preventDefault();
        box.classList.add('is-dragging');
      }));
      ['dragleave', 'drop'].forEach(name => box.addEventListener(name, () => box.classList.remove('is-dragging')));
      box.addEventListener('drop', event => {
        const file = event.dataTransfer?.files?.[0];
        if (!file) return;
        event.preventDefault();
        setFile(file);
        input?.focus();
      });
    }
    document.querySelectorAll('input[name=conversation_mode]').forEach(radio =>
      radio.addEventListener('change', () => { if (radio.checked) setMode(radio.value); }));
    byId('driveButton')?.addEventListener('click', () => {
      const panel = byId('drivePanel');
      if (!panel) return;
      panel.hidden = !panel.hidden;
      byId('driveButton').setAttribute('aria-expanded', String(!panel.hidden));
      if (!panel.hidden) byId('agentDocumentQuery')?.focus();
    });
  }

  function openCitation(cite) {
    const article = cite.closest('.rg-turn');
    const details = article?.querySelector('.rg-evidence');
    if (!details) return;
    details.open = true;
    const row = byId(`cite-${article.dataset.requestId}-${cite.dataset.cite}`);
    row?.scrollIntoView({block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth'});
    if (row) {
      row.style.background = 'var(--rg-accent-soft)';
      window.setTimeout(() => { row.style.background = ''; }, 1400);
    }
  }

  function init() {
    if (!app) return;
    let threads = 'shown';
    try { threads = window.localStorage.getItem(THREADS_KEY) || 'shown'; } catch (_) { /* Optional. */ }
    if (desktop()) setThreads(threads !== 'hidden');
    hydrate(document);
    initEvents();
    initModelPicker();
    if (!app.dataset.conversation) setMode(currentMode());
    autosize();
    updateSend();
    toEnd();
    // Requests still running after a reload rejoin their events (agent runs are watched by agent-chat.js).
    document.querySelectorAll('.rg-turn[data-live="true"]:not([data-run])').forEach(article => {
      const parts = turnFromArticle(article);
      const live = createLive(parts, parts.command);
      parts.ai.replaceChildren();
      setBusy('request', () => stopRequest(live));
      attach(live).finally(() => { if (busyOwner === 'request' && !state.sending) setBusy(null); });
    });
    if (window.matchMedia?.('(pointer: fine)').matches && input && !app.querySelector('.rg-turn[data-live="true"]')) input.focus({preventScroll: true});
  }

  window.regulayChat = {renderReceipt, renderDisclosures, consentReason, parseFrame, handleEvent, createLive,
    renderOutcome, stageText, el, icon, button, announce, toast, follow, copy, busy: busyFromAgent,
    composer: {setMode, focus: () => input?.focus(), setContext: null}};
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

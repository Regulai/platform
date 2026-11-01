/* Static artifact projection. Source is text; only server-sanitized HTML enters an opaque iframe. */
(() => {
  'use strict';
  const make = (tag, text, parent, className = '') => {
    const value = document.createElement(tag);
    if (text != null) value.textContent = text;
    if (className) value.className = className;
    parent?.appendChild(value);
    return value;
  };
  const valid = value => typeof value === 'string' && /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/preview\/$/.test(value);
  let dialog, title, meta, content, notice, footer, controller, previousFocus, currentVersion = 0;
  const desktop = matchMedia('(min-width: 1100px)');
  let modal = false;
  function cleanup() {
    if (dialog?.open) return; // A breakpoint switch closes and reopens the same view.
    controller?.abort();
    document.documentElement.classList.remove('rg-artifact-open');
    content?.replaceChildren();
    previousFocus?.focus?.();
  }
  function show() {
    modal = !desktop.matches;
    document.documentElement.classList.toggle('rg-artifact-open', !modal);
    if (modal) dialog.showModal(); else dialog.show();
  }
  desktop.addEventListener('change', () => {
    if (!dialog?.open || modal === !desktop.matches) return;
    const focused = dialog.contains(document.activeElement) ? document.activeElement : dialog.querySelector('button');
    dialog.close();
    show();
    focused?.focus();
  });
  function ensure() {
    if (dialog) return;
    dialog = make('dialog', null, document.body, 'rg-artifact-drawer');
    dialog.setAttribute('aria-labelledby', 'artifactViewerTitle');
    const header = make('header', null, dialog, 'rg-artifact-header');
    const headings = make('div', null, header);
    title = make('h2', '', headings); title.id = 'artifactViewerTitle';
    meta = make('p', '', headings);
    const close = make('button', 'Volver al chat', header, 'rg-btn'); close.type = 'button';
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', cleanup);
    dialog.addEventListener('keydown', event => {
      if (event.key === 'Escape') { event.preventDefault(); dialog.close(); }
    });
    notice = make('p', '', dialog, 'rg-artifact-notice'); notice.setAttribute('role', 'status');
    content = make('div', null, dialog, 'rg-artifact-content');
    footer = make('footer', null, dialog, 'rg-artifact-footer');
  }
  async function open(artifact, trigger, revisions = []) {
    ensure();
    controller?.abort();
    controller = new AbortController();
    const version = ++currentVersion;
    previousFocus = trigger || document.activeElement;
    title.textContent = artifact.filename || 'Archivo';
    meta.textContent = `${String(artifact.format).toUpperCase()} · Revisión ${artifact.revision}`;
    notice.textContent = 'Comprobando acceso a esta revisión…';
    content.replaceChildren(); footer.replaceChildren();
    if (!dialog.open) show();
    dialog.querySelector('button').focus();
    try {
      if (!valid(artifact.preview_url)) throw new Error('La vista previa no está disponible para este archivo.');
      const response = await fetch(artifact.preview_url, {headers: {Accept: 'application/json'}, signal: controller.signal, cache: 'no-store'});
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'No se pudo abrir esta revisión. Consulta el estado del chat.');
      if (data.artifact_id !== artifact.id || data.sha256 !== artifact.sha256 || data.revision !== artifact.revision) throw new Error('La revisión ha cambiado. Actualiza el estado del chat.');
      if (version !== currentVersion || !dialog.open) return;
      meta.textContent = `${data.format.toUpperCase()} · ${data.size_bytes.toLocaleString('es-ES')} bytes · Revisión ${data.revision}`;
      notice.textContent = data.notice || '';
      const tabs = make('div', null, content, 'rg-artifact-tabs'); tabs.setAttribute('role', 'tablist');
      const panes = make('div', null, content, 'rg-artifact-panes');
      const code = make('pre', null, panes, 'rg-artifact-code'); code.id = 'artifactCode';
      make('code', data.code || '', code);
      let preview = null;
      if (typeof data.html === 'string') {
        preview = make('iframe', null, panes, 'rg-artifact-frame'); preview.id = 'artifactPreview';
        preview.title = `Vista estática de ${data.filename}`;
        preview.setAttribute('sandbox', '');
        preview.setAttribute('referrerpolicy', 'no-referrer');
        preview.srcdoc = data.html;
      }
      const tabButtons = [];
      const select = selected => tabButtons.forEach(({button, pane}) => {
        const active = selected === button;
        button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1; pane.hidden = !active;
      });
      [[preview, 'Vista previa'], [code, 'Código']].filter(([pane]) => pane).forEach(([pane, label], index) => {
        pane.setAttribute('role', 'tabpanel'); pane.tabIndex = 0;
        const button = make('button', label, tabs, 'rg-btn'); button.type = 'button';
        button.setAttribute('role', 'tab'); button.setAttribute('aria-controls', pane.id);
        button.addEventListener('click', () => select(button));
        button.addEventListener('keydown', event => {
          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
          event.preventDefault();
          const target = event.key === 'Home' ? 0 : event.key === 'End' ? tabButtons.length-1 : (index+1)%tabButtons.length;
          select(tabButtons[target].button); tabButtons[target].button.focus();
        });
        tabButtons.push({button, pane});
      });
      select(tabButtons[0].button);
      const download = make('a', 'Descargar original', footer, 'rg-btn rg-btn-primary');
      if (/^\/chat\/agent\/artifacts\/[0-9a-f-]+\/download\/$/.test(data.download_url)) download.href = data.download_url;
      download.setAttribute('download', data.filename || '');
      const available = revisions.filter(value => value.logical_id === artifact.logical_id && valid(value.preview_url));
      if (available.length > 1) {
        const label = make('label', 'Revisión ', footer);
        const selectRevision = make('select', null, label);
        available.forEach(value => { const option = make('option', `v${value.revision}`, selectRevision); option.value = value.id; option.selected = value.id === artifact.id; });
        selectRevision.addEventListener('change', () => open(available.find(value => value.id === selectRevision.value), previousFocus, available));
      }
      const widthLabel = make('label', 'Ancho del visor ', footer, 'rg-artifact-width');
      const width = make('input', null, widthLabel); width.type = 'range'; width.min = '480'; width.max = '640'; width.value = '560';
      width.addEventListener('input', () => document.documentElement.style.setProperty('--rg-artifact-width', `${width.value}px`));
    } catch (error) {
      if (error.name !== 'AbortError' && version === currentVersion) notice.textContent = error.message;
    }
  }
  window.RegulayArtifactViewer = {open, close: () => dialog?.close()};
})();

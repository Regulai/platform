/* Lab-only browser verification of the chat and agent interface (Playwright, loopback).
 * Each check prints PASS/FAIL with what was observed and the run ends with a JSON summary.
 *
 * Usage: node ops/chat_ui_lab/verify.cjs <output-dir>
 * Env: LAB_URL (lab server), LAB_DRIVE_URL (same lab with REGULAI_UI_LAB_DRIVE=1, optional),
 *      LAB_PROVIDER (simulated provider), PLAYWRIGHT_MODULE (installed playwright package).
 * Synthetic lab accounts only; the simulated provider's "pausa" keyword holds a stream
 * until /control/release, so partial delivery, stop and rejoin are observable. */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const BASE = process.env.LAB_URL || 'http://127.0.0.1:8800';
const DRIVE = process.env.LAB_DRIVE_URL || '';
const PROVIDER = process.env.LAB_PROVIDER || 'http://127.0.0.1:8790';
const PASSWORD = 'lab-ui-synthetic-2026';
const outDir = process.argv[2] || 'verify-output';
const DESKTOP = { width: 1440, height: 900 };
const MOBILE = { width: 390, height: 844 };
const results = [];
const consoleErrors = [];
const out = name => path.join(outDir, name);
const release = () => fetch(PROVIDER + '/control/release', { method: 'POST' });
const SEND = /\/chat\/(\d+\/)?send\/$/;

async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail: detail || '' });
    console.log(`PASS ${name}${detail ? ' — ' + detail : ''}`);
  } catch (error) {
    results.push({ name, ok: false, detail: String(error.message || error).split('\n')[0] });
    console.log(`FAIL ${name} — ${String(error.message || error).split('\n')[0]}`);
  }
  await release().catch(() => {});
}
function expect(condition, message) { if (!condition) throw new Error(message); }

const states = {};
async function signIn(browser, base, user) {
  const key = base + user;
  if (states[key]) return states[key];
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(base + '/login/');
  await page.fill('input[name="username"]', user);
  await page.fill('input[name="password"]', PASSWORD);
  await Promise.all([page.waitForNavigation(), page.click('button[type="submit"]')]);
  if (page.url().includes('/login/')) throw new Error('Lab sign-in failed for ' + user);
  states[key] = await context.storageState();
  await context.close();
  return states[key];
}
async function open(browser, { base = BASE, user = 'lab-user', viewport = DESKTOP, reducedMotion = false } = {}) {
  const context = await browser.newContext({ viewport, deviceScaleFactor: viewport.width < 600 ? 2 : 1, locale: 'es-ES',
    reducedMotion: reducedMotion ? 'reduce' : 'no-preference', storageState: await signIn(browser, base, user) });
  const page = await context.newPage();
  page.on('console', message => {
    if (message.type() !== 'error') return;
    // Expected: the lab has no Drive grant, so the document search answers 403 (handled in the page).
    if (/\/chat\/agent\/documents\/search\/$/.test(message.location()?.url || '')) return;
    consoleErrors.push(`${page.url()}: ${message.text()} ${message.location()?.url || ''}`);
  });
  page.on('pageerror', error => consoleErrors.push(`${page.url()}: ${error.message}`));
  page.sends = [];
  page.on('request', request => { if (request.method() === 'POST' && SEND.test(new URL(request.url()).pathname)) page.sends.push(request.url()); });
  return page;
}
async function ask(page, text) {
  await page.fill('#prompt', text);
  await page.keyboard.press('Enter');
}
const lastTurn = page => page.locator('.rg-turn').last();

// Text/background pairs below WCAG AA among visible text (text drawn as a gradient is skipped).
const CONTRAST = () => {
  const parse = value => {
    const match = /rgba?\(([^)]+)\)/.exec(value);
    if (!match) return null;
    const parts = match[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };
  const channel = value => { value /= 255; return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4; };
  const luminance = color => 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b);
  const background = element => {
    for (let node = element; node; node = node.parentElement) {
      const color = parse(getComputedStyle(node).backgroundColor);
      if (color && color.a > 0.5) return color;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  };
  const issues = [], seen = new Set();
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let count = 0;
  while (walker.nextNode()) {
    const element = walker.currentNode.parentElement;
    if (!walker.currentNode.textContent.trim() || !element || seen.has(element)) continue;
    seen.add(element);
    const style = getComputedStyle(element), box = element.getBoundingClientRect();
    if (!box.width || !box.height || style.visibility === 'hidden' || element.closest('[hidden], .rg-sr, svg, button:disabled, .dropdown-menu:not(.show)')) continue;
    const color = parse(style.color);
    if (!color || color.a < 0.5) continue;
    count++;
    const a = luminance(color), b = luminance(background(element));
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const size = parseFloat(style.fontSize), large = size >= 24 || (parseInt(style.fontWeight, 10) >= 700 && size >= 18.66);
    if (ratio < (large ? 3 : 4.5)) issues.push(`${ratio.toFixed(2)}:1 <${element.tagName.toLowerCase()} class="${element.className}"> «${walker.currentNode.textContent.trim().slice(0, 40)}»`);
  }
  return { count, issues };
};

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
  await release().catch(() => {});

  await check('Streaming: texto comprobado antes de que termine la generación, y parada', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    await ask(page, 'Explica la pausa de la política de viajes');
    const body = page.locator('.rg-md.is-streaming').last();
    await body.waitFor({ timeout: 15000 });
    await page.waitForTimeout(1500);  // The simulated provider holds at one third of the answer.
    const shown = (await body.innerText()).trim();
    expect(shown.length > 20, 'casi sin texto parcial: ' + shown.length);
    expect(await page.locator('#stopButton').isVisible(), 'el botón Detener no está visible');
    expect(await page.locator('#sendButton').isHidden(), 'Enviar sigue visible durante la respuesta');
    await page.screenshot({ path: out('desktop-18-streaming-mid.png') });
    await page.click('#stopButton');
    await lastTurn(page).locator('.rg-quiet-note', { hasText: 'Respuesta detenida' }).waitFor({ timeout: 10000 });
    expect(await lastTurn(page).locator('.rg-md').count() === 0, 'el texto parcial sigue visible tras detener');
    await page.screenshot({ path: out('desktop-19-stopped.png') });
    await page.context().close();
    return `${shown.length} caracteres visibles con el proveedor en pausa; tras Detener se retira y queda «Respuesta detenida»`;
  });

  await check('Recarga durante la generación: se reengancha sin volver a enviar', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    await ask(page, 'Otra pausa para probar la reconexión');
    await page.locator('.rg-md.is-streaming').last().waitFor({ timeout: 15000 });
    await page.waitForURL(/\/chat\/\d+\/$/, { timeout: 5000 });
    const sent = page.sends.length;
    await page.reload();
    await page.locator('.rg-md.is-streaming').last().waitFor({ timeout: 15000 });
    await page.screenshot({ path: out('desktop-20-rejoined-after-reload.png') });
    await release();
    await lastTurn(page).locator('.rg-actions').waitFor({ timeout: 30000 });
    const answers = await lastTurn(page).locator('.rg-md').count();
    expect(page.sends.length === sent && sent === 1, `envíos: ${page.sends.length}`);
    expect(answers === 1, `respuesta mostrada ${answers} veces`);
    await page.context().close();
    return 'el texto parcial se repite desde el registro en memoria; 1 envío en total; respuesta única al terminar';
  });

  await check('Cambio de conversación durante la generación: al volver, la respuesta está guardada', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    await ask(page, 'Una pausa antes de cambiar de conversación');
    await page.locator('.rg-md.is-streaming').last().waitFor({ timeout: 15000 });
    await page.waitForURL(/\/chat\/\d+\/$/, { timeout: 5000 });
    const url = page.url();
    await page.goto(BASE + '/chat/1/');
    await release();
    await page.waitForTimeout(1500);
    await page.goto(url);
    const live = await page.locator('.rg-turn[data-live="true"]').count();
    await lastTurn(page).locator('.rg-actions').waitFor({ timeout: 30000 });
    const answers = await lastTurn(page).locator('.rg-md').count();
    expect(answers === 1, `respuesta mostrada ${answers} veces`);
    expect(page.sends.length === 1, `envíos: ${page.sends.length}`);
    await page.context().close();
    return live ? 'aún en curso al volver: se reenganchó y terminó' : 'ya terminada al volver: respuesta guardada';
  });

  await check('Móvil: generación progresiva', async () => {
    const page = await open(browser, { viewport: MOBILE });
    await page.goto(BASE + '/chat/');
    await ask(page, 'Explica la pausa en móvil');
    await page.locator('.rg-md.is-streaming').last().waitFor({ timeout: 15000 });
    await page.waitForTimeout(1200);
    await page.screenshot({ path: out('mobile-06-streaming-mid.png') });
    await release();
    await lastTurn(page).locator('.rg-actions').waitFor({ timeout: 30000 });
    await page.context().close();
  });

  await check('Teclado: salto al compositor, selector de modelo, actividad y vista previa', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/1/');
    expect(await page.evaluate(() => document.activeElement.id) === 'prompt', 'al cargar, el foco no está en el compositor');
    await page.focus('.rg-skip');
    await page.waitForTimeout(300);  // Its slide-in transition lasts 120 ms.
    expect(await page.evaluate(() => getComputedStyle(document.querySelector('.rg-skip')).transform === 'none'), 'el enlace de salto no se ve al enfocarlo');
    await page.keyboard.press('Enter');
    expect(await page.evaluate(() => document.activeElement.id) === 'prompt', 'el enlace de salto no lleva al compositor');
    await page.focus('#modelButton');
    await page.keyboard.press('Enter');
    await page.locator('#modelMenu').waitFor({ state: 'visible' });
    expect(await page.evaluate(() => document.getElementById('modelMenu').contains(document.activeElement)), 'al abrir, el foco no entra en el menú');
    const first = await page.evaluate(() => document.activeElement.textContent.trim());
    await page.keyboard.press('ArrowDown');
    const second = await page.evaluate(() => document.activeElement.textContent.trim());
    await page.keyboard.press('Escape');
    expect(await page.locator('#modelMenu').isHidden(), 'Escape no cierra el menú');
    expect(await page.evaluate(() => document.activeElement.id) === 'modelButton', 'el foco no vuelve al botón del menú');
    await page.goto(BASE + '/chat/9/');
    await page.locator('.rg-activity-head').first().waitFor();
    await page.waitForTimeout(1500);
    const head = page.locator('.rg-activity-head').first();
    const before = await head.getAttribute('aria-expanded');
    await head.focus();
    await page.keyboard.press('Enter');
    const after = await head.getAttribute('aria-expanded');
    expect(before !== after, 'Enter no despliega la actividad');
    const trigger = page.locator('.rg-deliverable-actions button', { hasText: 'Vista previa' }).first();
    await trigger.focus();
    await page.keyboard.press('Enter');
    await page.locator('#previewDialog[open]').waitFor({ timeout: 5000 });
    expect(await page.evaluate(() => document.getElementById('previewDialog').contains(document.activeElement)), 'el foco no entra en el diálogo');
    await page.screenshot({ path: out('desktop-21-preview-keyboard.png') });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
    expect(!(await page.evaluate(() => document.getElementById('previewDialog').open)), 'Escape no cierra el diálogo');
    expect(await page.evaluate(() => /Vista previa/.test(document.activeElement.textContent)), 'el foco no vuelve al botón Vista previa');
    await page.context().close();
    return `menú: ${first} → ${second}; actividad ${before} → ${after}; diálogo abre con foco dentro y Escape devuelve el foco`;
  });

  await check('Teclado móvil: cajón con foco dentro, fondo inerte y Escape', async () => {
    const page = await open(browser, { viewport: MOBILE });
    await page.goto(BASE + '/chat/1/');
    await page.click('[data-action=nav-open]');
    await page.waitForTimeout(450);
    expect(await page.evaluate(() => Boolean(document.activeElement.closest('.rg-thread.is-active'))), 'el foco no va a la conversación activa');
    expect(await page.evaluate(() => document.getElementById('chatMain').hasAttribute('inert')), 'el contenido de fondo sigue accesible');
    await page.screenshot({ path: out('mobile-07-drawer.png') });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(400);
    expect(await page.evaluate(() => document.activeElement.dataset.action === 'nav-open'), 'el foco no vuelve al botón de menú');
    expect(!(await page.evaluate(() => document.getElementById('chatMain').hasAttribute('inert'))), 'el fondo sigue inerte');
    await page.context().close();
  });

  await check('Movimiento reducido: animaciones anuladas y sin brillo animado', async () => {
    const page = await open(browser, { reducedMotion: true });
    await page.goto(BASE + '/chat/12/');
    await page.waitForTimeout(1500);
    const agent = await page.evaluate(() => ({
      reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
      durations: [...document.querySelectorAll('.rg-step, .rg-activity-body, .rg-deliverable, .rg-step-dot')]
        .map(node => parseFloat(getComputedStyle(node).animationDuration) || 0),
      ping: getComputedStyle(document.querySelector('.rg-pulse') || document.body, '::after').display,
    }));
    expect(agent.reduced, 'la preferencia no se aplica');
    expect(agent.durations.every(value => value <= 0.002), 'animaciones largas: ' + agent.durations.join(','));
    await page.screenshot({ path: out('desktop-22-reduced-motion-agent.png') });
    await page.goto(BASE + '/chat/');
    await ask(page, 'Explica la pausa con movimiento reducido');
    await page.locator('.rg-md.is-streaming').last().waitFor({ timeout: 15000 });
    const stream = await page.evaluate(() => [...document.querySelectorAll('.rg-enter, .rg-md.is-streaming > *')]
      .map(node => parseFloat(getComputedStyle(node).animationDuration) || 0));
    expect(stream.every(value => value <= 0.002), 'animaciones en el texto: ' + stream.join(','));
    await page.screenshot({ path: out('desktop-23-reduced-motion-streaming.png') });
    await release();
    await lastTurn(page).locator('.rg-actions').waitFor({ timeout: 30000 });
    await page.context().close();
    return `${agent.durations.length + stream.length} animaciones a ≤1 ms; ping del indicador: ${agent.ping}`;
  });

  await check('Contraste AA del texto visible (chat, consentimiento, error, documento, agente, revisión)', async () => {
    const page = await open(browser);
    const issues = [];
    let count = 0;
    for (const id of [1, 3, 4, 6, 7, 9, 10]) {
      await page.goto(BASE + `/chat/${id}/`);
      await page.waitForTimeout(id >= 9 ? 1800 : 500);
      if (id === 9) {
        await page.locator('.rg-activity-head').first().click();
        await page.locator('.rg-agent-actions button', { hasText: 'Detalles' }).first().click().catch(() => {});
      }
      if (id === 3) await page.locator('[data-action=details]').last().click().catch(() => {});
      const found = await page.evaluate(CONTRAST);
      count += found.count;
      issues.push(...found.issues.map(issue => `/chat/${id}/ ${issue}`));
    }
    await page.context().close();
    expect(!issues.length, `${issues.length} de ${count}: ${issues.slice(0, 4).join(' | ')}`);
    return `${count} elementos con texto comprobados en 7 conversaciones`;
  });

  await check('Adjuntos en chat: txt validado, formato no admitido, arrastrar y soltar, respuesta con citas', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    const txt = { name: 'acta-comite.txt', mimeType: 'text/plain', buffer: Buffer.from(
      'Acta del comité de compras.\nSe aprueba el presupuesto de 2026 para equipos portátiles.\n' +
      'El plazo de entrega acordado es de diecisiete días laborables.\n') };
    await page.setInputFiles('#fileInput', { name: 'programa.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ') });
    const rejected = await page.locator('#composerHint').innerText();
    expect(/Formato no admitido/.test(rejected), 'no se rechaza un .exe: ' + rejected);
    expect(await page.locator('#filePreview').isHidden(), 'el .exe aparece como adjunto');
    await page.evaluate(() => {
      const transfer = new DataTransfer();
      transfer.items.add(new File(['concepto,importe\nhotel,120\n'], 'gastos.csv', { type: 'text/csv' }));
      const box = document.getElementById('composerBox');
      box.dispatchEvent(new DragEvent('dragenter', { dataTransfer: transfer, bubbles: true, cancelable: true }));
      box.dispatchEvent(new DragEvent('drop', { dataTransfer: transfer, bubbles: true, cancelable: true }));
    });
    await page.locator('#filePreview .rg-file', { hasText: 'gastos.csv' }).waitFor({ timeout: 3000 });
    await page.setInputFiles('#fileInput', txt);
    await page.locator('#filePreview .rg-file', { hasText: 'acta-comite.txt' }).waitFor({ timeout: 3000 });
    await ask(page, '¿Qué plazo de entrega se acordó?');
    await lastTurn(page).locator('.rg-attachment', { hasText: 'acta-comite.txt' }).waitFor({ timeout: 5000 });
    await lastTurn(page).locator('.rg-actions').waitFor({ timeout: 40000 });
    const answer = await lastTurn(page).locator('.rg-msg-ai').innerText();
    await page.screenshot({ path: out('desktop-24-attachment-answer.png') });
    await page.context().close();
    return `exe rechazado; csv por arrastre; respuesta: «${answer.split('\n')[0].slice(0, 70)}»`;
  });

  await check('Adjuntos en modo agente: solo CSV/XLSX', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    await page.click('label.rg-mode-option:nth-child(2)');
    const accept = await page.getAttribute('#fileInput', 'accept');
    expect(accept === '.csv,.xlsx', 'accept: ' + accept);
    await page.setInputFiles('#fileInput', { name: 'notas.txt', mimeType: 'text/plain', buffer: Buffer.from('x') });
    expect(/Formato no admitido/.test(await page.locator('#composerHint').innerText()), 'el .txt no se rechaza en modo agente');
    await page.setInputFiles('#fileInput', { name: 'ventas.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\n1,2\n') });
    await page.locator('#filePreview .rg-file', { hasText: 'ventas.csv' }).waitFor({ timeout: 3000 });
    expect(await page.locator('#driveButton').count() === 0, 'el selector de Drive aparece sin el conector');
    await page.context().close();
    return 'accept=.csv,.xlsx; .txt rechazado; .csv aceptado; sin botón de Drive sin REGULAY_AGENT_MCP_ENABLED';
  });

  if (DRIVE) {
    await check('Selector de Drive solo en modo agente con REGULAY_AGENT_MCP_ENABLED', async () => {
      const page = await open(browser, { base: DRIVE });
      await page.goto(DRIVE + '/chat/');
      expect(await page.locator('#driveButton').isHidden(), 'visible en modo chat');
      await page.click('label.rg-mode-option:nth-child(2)');
      await page.click('#driveButton');
      await page.locator('#drivePanel').waitFor({ state: 'visible' });
      expect(await page.evaluate(() => document.activeElement.id) === 'agentDocumentQuery', 'el foco no va al buscador');
      await page.fill('#agentDocumentQuery', 'ventas');
      await page.click('#agentDocumentSearch');
      await page.waitForTimeout(1200);
      const answer = await page.locator('#agentDocumentResults').innerText();
      await page.screenshot({ path: out('desktop-25-drive-picker.png') });
      await page.click('label.rg-mode-option:nth-child(1)');
      expect(await page.locator('#drivePanel').isHidden() && await page.locator('#driveButton').isHidden(), 'sigue visible al volver a Chat');
      await page.context().close();
      return `respuesta del laboratorio sin concesión de Drive: «${answer.trim()}»`;
    });
  }

  await check('Envío real en modo agente (laboratorio SQLite, sin worker)', async () => {
    const page = await open(browser);
    await page.goto(BASE + '/chat/');
    await page.click('label.rg-mode-option:nth-child(2)');
    await ask(page, 'Crea un informe de dos páginas en Word sobre la política de viajes');
    await page.waitForTimeout(5000);
    const state = await lastTurn(page).locator('.rg-msg-ai').innerText();
    await page.screenshot({ path: out('desktop-26-agent-send-sqlite.png') });
    expect(page.sends.length === 1, 'envíos: ' + page.sends.length);
    await page.context().close();
    return 'estado mostrado: «' + state.split('\n').filter(Boolean).slice(0, 2).join(' · ') + '»';
  });

  await check('Sin errores de consola ni excepciones de página', async () => {
    const own = consoleErrors.filter(line => !/favicon/.test(line));
    expect(!own.length, own.slice(0, 3).join(' | '));
  });

  await browser.close();
  fs.writeFileSync(out('verification.json'), JSON.stringify({ base: BASE, drive: DRIVE || null, results, consoleErrors }, null, 2));
  const failed = results.filter(result => !result.ok).length;
  console.log(`\n${results.length - failed}/${results.length} comprobaciones superadas`);
  process.exit(failed ? 1 : 0);
})().catch(error => { console.error(error); process.exit(2); });

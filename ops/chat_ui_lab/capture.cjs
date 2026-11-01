/* Lab-only screenshot capture with Playwright (loopback lab server, synthetic accounts).
 * Usage: node ops/chat_ui_lab/capture.cjs <shots.json> <output-dir>
 * shots.json: [{"name": "desktop-empty", "user": "lab-user", "path": "/chat/", "width": 1440,
 *   "height": 900, "full": false, "steps": [["click", "selector"], ["type", "selector", "text"],
 *   ["press", "Enter"], ["wait", 800], ["release"], ["scroll", "selector", 0]]}]
 * PLAYWRIGHT_MODULE may point at an installed playwright package. */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const BASE = process.env.LAB_URL || 'http://127.0.0.1:8800';
const PROVIDER = process.env.LAB_PROVIDER || 'http://127.0.0.1:8790';
const PASSWORD = 'lab-ui-synthetic-2026';

// One login per user and run: the app rate-limits repeated sign-ins.
const sessions = {};
async function session(browser, user) {
  if (sessions[user]) return sessions[user];
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(BASE + '/login/');
  await page.fill('input[name="username"]', user);
  await page.fill('input[name="password"]', PASSWORD);
  await Promise.all([page.waitForNavigation(), page.click('button[type="submit"]')]);
  if (page.url().includes('/login/')) throw new Error('Lab sign-in failed for ' + user);
  sessions[user] = await context.storageState();
  await context.close();
  return sessions[user];
}

(async () => {
  const [shotsFile, outDir] = process.argv.slice(2);
  const shots = JSON.parse(fs.readFileSync(shotsFile, 'utf8'));
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
  const contexts = {};
  for (const shot of shots) {
    const key = `${shot.user}:${shot.width}x${shot.height}:${shot.dark ? 'dark' : 'light'}:${shot.reducedMotion ? 'rm' : ''}`;
    if (!contexts[key]) {
      contexts[key] = await browser.newContext({ viewport: { width: shot.width, height: shot.height },
        deviceScaleFactor: shot.width < 600 ? 2 : 1, colorScheme: shot.dark ? 'dark' : 'light',
        reducedMotion: shot.reducedMotion ? 'reduce' : 'no-preference', locale: 'es-ES',
        storageState: await session(browser, shot.user) });
    }
    const page = await contexts[key].newPage();
    const consoleErrors = [];
    page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    await page.goto(BASE + shot.path, { waitUntil: 'networkidle' }).catch(() => {});
    await page.waitForTimeout(shot.settle ?? 900);
    const failures = [];
    for (const step of shot.steps || []) {
      const [kind, ...args] = step;
      try {
        if (kind === 'click') await page.click(args[0], { timeout: 5000 });
        else if (kind === 'type') await page.fill(args[0], args[1], { timeout: 5000 });
        else if (kind === 'press') await page.keyboard.press(args[0]);
        else if (kind === 'key') await page.keyboard.press(args[0]);
        else if (kind === 'wait') await page.waitForTimeout(args[0]);
        else if (kind === 'release') await fetch(PROVIDER + '/control/release', { method: 'POST' });
        else if (kind === 'scroll') await page.evaluate(([selector, top]) => {
          const element = document.querySelector(selector); if (element) element.scrollTop = top; }, args);
        else if (kind === 'eval') await page.evaluate(args[0]);
        else if (kind === 'focus') await page.focus(args[0]);
      } catch (error) {
        failures.push(`${kind} ${args[0] ?? ''}: ${String(error.message).split('\n')[0]}`);
      }
    }
    const file = path.join(outDir, shot.name + '.png');
    await page.screenshot({ path: file, fullPage: Boolean(shot.full) });
    console.log(file + (consoleErrors.length ? '  console errors: ' + consoleErrors.join(' | ') : '') +
      (failures.length ? '  step failures: ' + failures.join(' | ') : ''));
    await page.close();
  }
  await browser.close();
})().catch(error => { console.error(error); process.exit(1); });

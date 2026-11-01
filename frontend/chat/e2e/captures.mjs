// Evidence captures of the chat states on the lab: synthetic records, simulated
// provider transport, fixture agent events. Not provider latency or quality.
//   node e2e/captures.mjs <outDir>            screenshots at 1440, 768 and 360 px
//   VIDEO=1 node e2e/captures.mjs <outDir>    plus one recording where motion matters
// Run on a freshly prepared lab with the fixture driver running.
import { chromium } from "@playwright/test"
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"

const out = process.argv[2] ?? "captures"
const base = process.env.LAB_URL || "http://127.0.0.1:8890"
const labDir = join(tmpdir(), "regulai-chat-redesign", "lab")
const state = JSON.parse(readFileSync(join(labDir, "browser-state.json"), "utf8"))
const lab = JSON.parse(readFileSync(join(labDir, "lab.json"), "utf8"))
const sizes = (process.env.SIZES || "1440x900,768x1024,360x780").split(",").map((size) => size.split("x").map(Number))
const report = { fixture: true, base, sizes, shots: [], errors: [], foreign: [] }
const browser = await chromium.launch()

const prompt = (page) => page.getByRole("textbox", { name: "Mensaje" })
const lastTurn = (page) => page.locator("article[data-turn]").last()

function watch(page, width) {
  page.on("pageerror", (error) => report.errors.push({ width, error: error.message }))
  page.on("console", (message) => { if (message.type() === "error") report.errors.push({ width, error: message.text() }) })
  page.on("request", (request) => {
    const url = request.url()
    if (!url.startsWith(base) && !/^(data|blob|about):/.test(url)) report.foreign.push({ width, url })
  })
  page.on("response", (response) => {
    if (response.status() >= 400) report.errors.push({ width, status: response.status(), method: response.request().method(), url: response.url() })
  })
}

// On touch screens every visible control should offer about a fingertip (40 px). Links and
// citations inside running text are exempt (WCAG 2.5.8); citations get a larger hit area in CSS.
const TARGETS = () => {
  const selector = "button, a[href], input:not([type=hidden]), select, textarea, summary, [role=button], [role=menuitem], [role=menuitemradio], [role=option], [role=radio], [role=switch], [role=tab]"
  const small = []
  for (const node of document.querySelectorAll(selector)) {
    const rect = node.getBoundingClientRect()
    const style = getComputedStyle(node)
    if (!rect.width || !rect.height || style.visibility === "hidden" || Number(style.opacity) === 0) continue
    if (rect.bottom <= 0 || rect.top >= innerHeight || rect.right <= 0 || rect.left >= innerWidth) continue
    if (node.matches(".rg-md a, .rg-md .rg-cite") || node.closest("[aria-hidden=true], .sr-only, [inert]")) continue
    // A control inside a label is reached through the whole label.
    const label = node.closest("label")?.getBoundingClientRect()
    if (label && label.height >= 40 && label.width >= 40) continue
    if (rect.height < 40 || rect.width < 40) {
      small.push({ control: (node.getAttribute("aria-label") || node.textContent || node.getAttribute("role") || node.tagName).trim().slice(0, 48), width: Math.round(rect.width), height: Math.round(rect.height) })
    }
  }
  return small
}

async function shot(page, width, name) {
  await page.waitForTimeout(300)
  await page.screenshot({ path: join(out, String(width), `${name}.png`), animations: "disabled" })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
  const smallTargets = width < 1024 ? await page.evaluate(TARGETS) : undefined
  report.shots.push({ width, name, overflow, ...(smallTargets ? { smallTargets } : {}) })
}

async function send(page, text) {
  await prompt(page).click()
  await prompt(page).fill(text)
  await prompt(page).press("Enter")
}

/** Scroll up once the live answer is taller than the view (a new conversation starts short). */
async function readAbove(page) {
  const viewport = page.getByRole("region", { name: "Mensajes" })
  await viewport.evaluate((node) => new Promise((resolve) => {
    const check = () => (node.scrollHeight - node.clientHeight > 600 ? resolve() : setTimeout(check, 100))
    check()
  }))
  await viewport.hover()
  await page.mouse.wheel(0, -500)
}

async function fresh(page, mode) {
  await page.goto(`${base}/chat/`, { waitUntil: "networkidle" })
  const radio = page.getByRole("radio", { name: mode === "agent" ? "Agente" : "Chat", exact: true })
  if (await radio.count()) await radio.click()
}

async function states(page, width) {
  const desktop = width >= 1024
  await page.goto(`${base}/chat/`, { waitUntil: "networkidle" })
  await shot(page, width, "01-vacio")

  await page.goto(`${base}/chat/${lab.chat}/`, { waitUntil: "networkidle" })
  const turns = page.locator("article[data-turn]")
  for (const [index, name] of [[0, "02-historial-respuesta"], [1, "03-historial-bloqueado"], [2, "04-historial-consentimiento"], [3, "05-historial-fallo"]]) {
    await turns.nth(index).evaluate((node) => node.scrollIntoView({ block: "start" }))
    await shot(page, width, name)
  }
  if (!desktop) {
    await page.getByRole("button", { name: "Conversaciones y menú" }).click()
    await page.waitForTimeout(400)
    await shot(page, width, "06-cajon-conversaciones")
  }
  await page.getByRole("button", { name: /Cuenta de chat-ui/ }).click()
  await shot(page, width, "07-menu-cuenta")
  await page.keyboard.press("Escape")
  if (!desktop) await page.keyboard.press("Escape")
  await page.getByRole("button", { name: /Modelo:/ }).click()
  await shot(page, width, "08-menu-modelo")
  await page.keyboard.press("Escape")

  await fresh(page, "chat")
  await send(page, "Explica el caso largo con ejemplos")
  await lastTurn(page).locator(".rg-md[data-streaming]").waitFor()
  await page.waitForTimeout(1500)
  await shot(page, width, "09-respuesta-progresiva")
  await readAbove(page)
  await page.waitForTimeout(500)
  await shot(page, width, "10-leyendo-arriba")
  await page.getByRole("button", { name: "Ir al final" }).click()
  await lastTurn(page).getByRole("button", { name: "Copiar respuesta" }).waitFor({ timeout: 30_000 })
  await shot(page, width, "11-respuesta-larga")

  const input = page.locator('input[type="file"]')
  await input.setInputFiles({ name: "malware.exe", mimeType: "application/octet-stream", buffer: Buffer.from("MZ") })
  await shot(page, width, "12-adjunto-rechazado")
  await input.setInputFiles({ name: "notas-dietas.txt", mimeType: "text/plain", buffer: Buffer.from("Dietas: 45 euros por día.") })
  await shot(page, width, "13-adjunto-elegido")
  await send(page, "Resume el adjunto")
  await page.waitForFunction(() => {
    const chips = document.querySelectorAll("article[data-turn] [data-phase]")
    return /received|rejected/.test(chips[chips.length - 1]?.getAttribute("data-phase") ?? "")
  }, null, { timeout: 30_000 })
  // Documents need the semantic verifier, which the lab lacks: the policy blocks them after receipt.
  await page.getByRole("button", { name: "Enviar", exact: true }).waitFor({ timeout: 30_000 })
  await shot(page, width, "14-adjunto-recibido-bloqueado")

  await fresh(page, "agent")
  await prompt(page).click()
  await page.keyboard.type("/")
  await page.getByRole("listbox", { name: "Skills instaladas" }).waitFor()
  await shot(page, width, "15-selector-skills")
  await page.keyboard.press("Escape")
  await send(page, "Crea una landing de Madrid y entrega el HTML")
  const turn = lastTurn(page)
  await turn.getByRole("button", { name: /Actividad del agente/ }).waitFor()
  await page.waitForTimeout(1200)
  await shot(page, width, "16-agente-trabajando")
  await turn.locator("[data-skill]").waitFor({ timeout: 30_000 })
  await page.waitForTimeout(400)
  await shot(page, width, "17-skill-activada")
  // Open while the run works; the person's toggle wins over the automatic close at the end.
  await turn.getByRole("button", { name: /Actividad del agente/ }).click()
  await shot(page, width, "18-actividad-cerrada")
  await turn.locator("[data-status=verified]").first().waitFor({ timeout: 40_000 })
  await shot(page, width, "19-entregable-pendiente")
  const eye = turn.getByRole("button", { name: /Vista previa de madrid_landing\.html/ }).first()
  await eye.waitFor({ timeout: 40_000 })
  await page.waitForTimeout(600)
  await shot(page, width, "20-entregable")
  await eye.click()
  await page.getByRole("dialog", { name: "madrid_landing.html" }).waitFor()
  await page.waitForTimeout(700)
  await shot(page, width, "21-visor")
  await page.keyboard.press("Escape")
  await turn.getByRole("button", { name: /Actividad del agente/ }).click()
  await page.waitForTimeout(400)
  await shot(page, width, "22-actividad-final-abierta")
}

for (const [width, height] of sizes) {
  mkdirSync(join(out, String(width)), { recursive: true })
  const phone = width < 768
  const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1, storageState: state, hasTouch: width < 1024, isMobile: phone })
  await context.grantPermissions(["clipboard-read", "clipboard-write"])
  const page = await context.newPage()
  watch(page, width)
  await states(page, width)
  await context.close()
}

if (process.env.VIDEO) {
  const dir = join(out, "video")
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, storageState: state, recordVideo: { dir, size: { width: 1440, height: 900 } } })
  const page = await context.newPage()
  watch(page, "video")
  await fresh(page, "chat")
  await send(page, "Explica el caso largo con ejemplos")
  await lastTurn(page).locator(".rg-md[data-streaming]").waitFor()
  await page.waitForTimeout(1500)
  await readAbove(page)
  await page.waitForTimeout(2000)
  await page.getByRole("button", { name: "Ir al final" }).click()
  await lastTurn(page).getByRole("button", { name: "Copiar respuesta" }).waitFor({ timeout: 30_000 })
  await page.waitForTimeout(1200)
  await fresh(page, "agent")
  await send(page, "Crea una landing de Madrid y entrega el HTML")
  const turn = lastTurn(page)
  // Activity open while the run works, closing by itself once the file is delivered.
  const eye = turn.getByRole("button", { name: /Vista previa de madrid_landing\.html/ }).first()
  await eye.waitFor({ timeout: 40_000 })
  await page.waitForTimeout(1500)
  await eye.click()
  await page.waitForTimeout(2500)
  await page.keyboard.press("Escape")
  await page.waitForTimeout(800)
  await turn.getByRole("button", { name: /Actividad del agente/ }).click()
  await page.waitForTimeout(1500)
  const video = page.video()
  await context.close()
  renameSync(await video.path(), join(dir, "recorrido-1440.webm"))
}

await browser.close()
writeFileSync(join(out, "capturas.json"), JSON.stringify(report, null, 2))
const small = report.shots.flatMap((shot) => (shot.smallTargets ?? []).map((target) => `${shot.width}/${shot.name}: ${target.control} ${target.width}x${target.height}`))
console.log(JSON.stringify({ shots: report.shots.length, overflow: report.shots.filter((shot) => shot.overflow), errors: report.errors, foreign: report.foreign, smallTargets: [...new Set(small)] }, null, 1))

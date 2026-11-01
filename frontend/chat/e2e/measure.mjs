// Legacy chat vs island, same lab and machine: resources, load long tasks and
// the delay from a received stream event to the DOM change it causes.
// Fixture data (synthetic records, simulated provider at a fixed pace): these
// are client-side costs, never provider latency or quality.
//   node e2e/measure.mjs <out.json>
// Needs the lab fresh, the driver running, react on 8890 and legacy on 8891.
import { chromium } from "@playwright/test"
import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { gzipSync } from "node:zlib"

const out = process.argv[2] ?? "measure.json"
const RUNS = Number(process.env.RUNS || 5)
const CPU = Number(process.env.CPU || 4)
const PARTS = new Set((process.env.PARTS || "resources,load,stream").split(","))
const ONLY = process.env.ONLY ? process.env.ONLY.split(",") : null
const targets = { legacy: "http://127.0.0.1:8891", react: "http://127.0.0.1:8890" }
const labDir = join(tmpdir(), "regulai-chat-redesign", "lab")
const state = JSON.parse(readFileSync(join(labDir, "browser-state.json"), "utf8"))
const lab = JSON.parse(readFileSync(join(labDir, "lab.json"), "utf8"))
const browser = await chromium.launch()
const viewport = { width: 1440, height: 900 }

const median = (values) => {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}
const percentile = (values, p) => {
  if (!values.length) return null
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]
}
const round = (value) => (value === null ? null : Math.round(value * 10) / 10)

// Long tasks, paints and stream/DOM timestamps, installed before any page script.
const PROBE = () => {
  const probe = (window.__probe = { longtasks: [], events: [], finals: [], mutations: [] })
  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) probe.longtasks.push({ start: entry.startTime, duration: entry.duration })
  }).observe({ type: "longtask", buffered: true })
  // Stream events are stamped when they reach the page, before the app reads them.
  const fetch = window.fetch
  window.fetch = async (...args) => {
    const response = await fetch(...args)
    if (!response.body || !(response.headers.get("content-type") || "").includes("text/event-stream")) return response
    const decoder = new TextDecoder()
    let buffer = ""
    const stamp = new TransformStream({
      transform(chunk, controller) {
        const now = performance.now()
        buffer += decoder.decode(chunk, { stream: true }).replace(/\r\n?/g, "\n")
        let index
        while ((index = buffer.indexOf("\n\n")) >= 0) {
          const frame = buffer.slice(0, index)
          buffer = buffer.slice(index + 2)
          if (/^event: delta$/m.test(frame)) probe.events.push(now)
          if (/^event: final$/m.test(frame)) probe.finals.push(now)
        }
        controller.enqueue(chunk)
      },
    }, undefined, { highWaterMark: 1024 })
    return new Response(response.body.pipeThrough(stamp), { status: response.status, statusText: response.statusText, headers: response.headers })
  }
  const NativeEventSource = window.EventSource
  window.EventSource = class extends NativeEventSource {
    constructor(url, init) {
      super(url, init)
      // Registered before the app's own listener: stamped at dispatch.
      this.addEventListener("progress", (event) => {
        try { if (JSON.parse(event.data).kind === "text.delta") probe.events.push(performance.now()) } catch { /* not ours */ }
      })
      this.addEventListener("terminal", () => probe.finals.push(performance.now()))
    }
  }
  const inAnswer = (node) => (node?.nodeType === 1 ? node : node?.parentElement)?.closest?.(".rg-md")
  const observer = new MutationObserver((records) => {
    const now = performance.now()
    for (const record of records) {
      if (inAnswer(record.target) || [...record.addedNodes].some((node) => node.nodeType === 1 && (node.matches(".rg-md") || node.querySelector(".rg-md")))) {
        probe.mutations.push(now)
        return
      }
    }
  })
  document.addEventListener("DOMContentLoaded", () => observer.observe(document.body, { subtree: true, childList: true, characterData: true }))
}

async function open(name, { cpu = 1 } = {}) {
  const context = await browser.newContext({ viewport, storageState: state })
  await context.addInitScript(PROBE)
  const page = await context.newPage()
  if (cpu > 1) {
    const cdp = await context.newCDPSession(page)
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpu })
  }
  return { context, page, base: targets[name] }
}

// --- Resources ---------------------------------------------------------------
async function resources(name, path) {
  const { context, page, base } = await open(name)
  const rows = []
  page.on("response", async (response) => {
    try {
      const body = await response.body()
      rows.push({ type: response.request().resourceType(), url: response.url().replace(base, ""), bytes: body.length, gzip: gzipSync(body).length })
    } catch { /* redirects have no body */ }
  })
  await page.goto(`${base}/${path}`, { waitUntil: "networkidle" })
  await page.waitForTimeout(1500)
  await context.close()
  const byType = {}
  for (const row of rows) {
    const key = ["script", "stylesheet", "document", "font", "image"].includes(row.type) ? row.type : "other"
    byType[key] ??= { requests: 0, bytes: 0, gzip: 0 }
    byType[key].requests += 1
    byType[key].bytes += row.bytes
    byType[key].gzip += row.gzip
  }
  return { path, requests: rows.length, bytes: rows.reduce((sum, row) => sum + row.bytes, 0), gzip: rows.reduce((sum, row) => sum + row.gzip, 0), byType, files: rows }
}

// --- Load ----------------------------------------------------------------------
async function load(name, path) {
  const { context, page, base } = await open(name, { cpu: CPU })
  await page.goto(`${base}/${path}`, { waitUntil: "load" })
  await page.waitForTimeout(3000)
  const result = await page.evaluate(() => {
    const navigation = performance.getEntriesByType("navigation")[0]
    const fcp = performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? null
    const tasks = window.__probe.longtasks
    return {
      fcp, domContentLoaded: navigation.domContentLoadedEventEnd, load: navigation.loadEventEnd,
      longTasks: tasks.length, longTaskMs: tasks.reduce((sum, task) => sum + task.duration, 0),
      blockingMs: tasks.reduce((sum, task) => sum + Math.max(0, task.duration - 50), 0),
      longestMs: tasks.reduce((max, task) => Math.max(max, task.duration), 0),
    }
  })
  await context.close()
  return result
}

// --- Stream event -> DOM -------------------------------------------------------
const PROMPT = { legacy: "#prompt", react: "#regulai-prompt" }

async function stream(name, path, text, timeout) {
  const { context, page, base } = await open(name, { cpu: CPU })
  await page.goto(`${base}/${path}`, { waitUntil: "networkidle" })
  await page.waitForTimeout(800)
  const prompt = page.locator(PROMPT[name])
  await prompt.click()
  await prompt.fill(text)
  await page.evaluate(() => { window.__probe.events.length = 0; window.__probe.finals.length = 0; window.__probe.mutations.length = 0 })
  await prompt.press("Enter")
  await page.waitForFunction(() => window.__probe.finals.length > 0, null, { timeout })
  await page.waitForTimeout(1500)
  const { events, mutations } = await page.evaluate(() => window.__probe)
  await context.close()
  const delays = []
  for (const at of events) {
    const next = mutations.find((time) => time >= at)
    if (next !== undefined) delays.push(next - at)
  }
  return { events: events.length, domUpdates: mutations.length, matched: delays.length, delays }
}

const report = { fixture: true, machine: process.platform, cpuThrottling: CPU, runs: RUNS, viewport, lab: { chat: lab.chat, agent: lab.agent }, resources: {}, load: {}, stream: {} }
const pages = { nueva: "chat/", chat: `chat/${lab.chat}/`, agente: `chat/${lab.agent}/` }

const names = ONLY ?? Object.keys(targets)
for (const name of PARTS.has("resources") ? names : []) {
  report.resources[name] = {}
  for (const [label, path] of Object.entries(pages)) report.resources[name][label] = await resources(name, path)
}
for (const [label, path] of PARTS.has("load") ? Object.entries(pages) : []) {
  for (const name of names) {
    const samples = []
    for (let index = 0; index < RUNS; index += 1) samples.push(await load(name, path))
    const pick = (key) => round(median(samples.map((sample) => sample[key]).filter((value) => value !== null)))
    report.load[name] ??= {}
    report.load[name][label] = { fcp: pick("fcp"), domContentLoaded: pick("domContentLoaded"), load: pick("load"), longTasks: pick("longTasks"),
      longTaskMs: pick("longTaskMs"), blockingMs: pick("blockingMs"), longestMs: pick("longestMs"), samples }
  }
}
// Alternate implementations so both meet the same growing history.
const streams = [["chat", pages.chat, "Explica el caso largo con ejemplos", 60_000], ["agente", pages.agente, "Crea una landing de Madrid y entrega el HTML", 90_000]]
for (const [label, path, text, timeout] of PARTS.has("stream") ? streams : []) {
  const all = { legacy: [], react: [] }
  const counts = { legacy: [], react: [] }
  const runs = label === "agente" ? Math.max(2, Math.ceil(RUNS / 2)) : RUNS
  for (let index = 0; index < runs; index += 1) {
    for (const name of (index % 2 ? ["react", "legacy"] : ["legacy", "react"]).filter((value) => names.includes(value))) {
      const sample = await stream(name, path, text, timeout)
      all[name].push(...sample.delays)
      counts[name].push({ events: sample.events, domUpdates: sample.domUpdates, matched: sample.matched })
    }
  }
  for (const name of names) {
    report.stream[name] ??= {}
    report.stream[name][label] = { runs, events: counts[name], medianMs: round(median(all[name])), p95Ms: round(percentile(all[name], 95)), maxMs: round(Math.max(...all[name])) }
  }
}

await browser.close()
writeFileSync(out, JSON.stringify(report, null, 2))
const summary = {
  resources: Object.fromEntries(Object.entries(report.resources).map(([name, rows]) => [name, Object.fromEntries(Object.entries(rows).map(([label, row]) => [label, { requests: row.requests, kb: Math.round(row.bytes / 1024), gzipKb: Math.round(row.gzip / 1024) }]))])),
  load: Object.fromEntries(Object.entries(report.load).map(([name, rows]) => [name, Object.fromEntries(Object.entries(rows).map(([label, row]) => [label, { fcp: row.fcp, load: row.load, longTasks: row.longTasks, blockingMs: row.blockingMs, longestMs: row.longestMs }]))])),
  stream: report.stream,
}
console.log(JSON.stringify(summary, null, 1))

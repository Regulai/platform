import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { RunView } from "../state/model"
import type { AgentEvent, RunData, RunSnapshot } from "../types"
import { initialRunView, RunController, type RunHost } from "./runs"

/* Agent run adapter: events apply once by id, text by UTF-8 offset, a gap or
 * expired cursor asks for the authorized snapshot, revocation withdraws every
 * projection, and cleanup closes the stream (StrictMode, unmount, pagehide). */

class FakeEventSource {
  static open: FakeEventSource[] = []
  static CLOSED = 2
  url: string
  readyState = 1
  listeners = new Map<string, ((message: MessageEvent) => void)[]>()
  onerror: (() => void) | null = null
  constructor(url: string) {
    this.url = url
    FakeEventSource.open.push(this)
  }
  addEventListener(type: string, listener: (message: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener])
  }
  emit(type: string, data: unknown) {
    this.listeners.get(type)?.forEach((listener) => listener({ data: JSON.stringify(data) } as MessageEvent))
  }
  close() {
    this.readyState = 2
    FakeEventSource.open = FakeEventSource.open.filter((item) => item !== this)
  }
}

const run: RunData = {
  id: "run-1", request_id: "req", professional: true, resumable: false, resume_url: "/chat/agent/runs/run-1/resume/", status: "active",
  created_at: "2026-10-17T10:00:00Z", started_at: null, finished_at: null, events_url: "/chat/agent/runs/run-1/events/",
  status_url: "/chat/agent/runs/run-1/", cancel_url: "/chat/agent/runs/run-1/cancel/",
}
const event = (id: number, kind: string, data: Record<string, unknown> = {}): AgentEvent => ({ id, kind, data, created_at: "2026-10-17T10:00:01Z" })
const skill = (id: number, revision = "rev-1") => event(id, "skill.activated", { revision_id: revision, installation_id: "inst", alias: "design-taste-frontend", display_name: "Taste v2", reason: "instructions_read" })
const text = (id: number, offset: number, value: string, message = "inference:a") => ({ ...event(id, "text.delta", { message_id: message, inference_id: "a", offset }), data: { message_id: message, inference_id: "a", offset, text: value } })

function setup(snapshots: RunSnapshot[]) {
  let view = initialRunView(run)
  const announced: string[] = []
  const revoked: string[] = []
  const host: RunHost = {
    announce: (value) => announced.push(value),
    updateRun: (_id, update) => { view = update(view) },
    runChanged: () => undefined,
    revoked: (id) => revoked.push(id),
  }
  const queue = [...snapshots]
  const fetch = vi.fn(async () => {
    const next = queue.length > 1 ? queue.shift()! : queue[0]!
    if ((next as unknown as { status?: number }).status === 404) return new Response("{}", { status: 404 })
    return new Response(JSON.stringify(next), { headers: { Date: new Date().toUTCString() } })
  })
  vi.stubGlobal("fetch", fetch)
  return { host, fetch, announced, revoked, get view(): RunView { return view } }
}

const frame = () => new Promise((resolve) => requestAnimationFrame(() => resolve(undefined)))
const settle = async () => {
  for (let index = 0; index < 5; index++) await new Promise((resolve) => setTimeout(resolve, 0))
  await frame()
}

describe("RunController", () => {
  beforeEach(() => {
    FakeEventSource.open = []
    vi.stubGlobal("EventSource", FakeEventSource)
  })
  afterEach(() => vi.unstubAllGlobals())

  it("follows text by offset, dedupes replays and announces a skill once", async () => {
    const lab = setup([{ run, events: [event(1, "claimed")], text_segments: [], high_watermark: 1 }])
    const controller = new RunController(lab.host, run)
    controller.start()
    controller.start()
    await settle()
    expect(FakeEventSource.open).toHaveLength(1)
    const source = FakeEventSource.open[0]!
    expect(source.url).toBe("/chat/agent/runs/run-1/events/?cursor=1")
    source.emit("progress", skill(2))
    source.emit("progress", text(3, 0, "Hola "))
    source.emit("progress", text(4, 5, "mundo"))
    source.emit("progress", text(4, 5, "mundo"))
    source.emit("progress", skill(5))
    await settle()
    expect(lab.view.segments).toEqual([{ id: "inference:a", text: "Hola mundo", offset: 10, done: false, incomplete: false, tools: 0 }])
    expect(lab.view.skills.map((item) => [item.name, item.fresh])).toEqual([["Taste v2", true]])
    expect(lab.announced).toEqual(["Skill activada: Taste v2"])
    controller.dispose()
    expect(FakeEventSource.open).toHaveLength(0)
  })

  it("counts UTF-8 bytes, not string length, and recovers a gap from the snapshot", async () => {
    const lab = setup([
      { run, events: [], text_segments: [], high_watermark: 0 },
      { run, events: [], text_segments: [{ message_id: "inference:a", text: "Añadir más", offset: 0 }], high_watermark: 9 },
    ])
    const controller = new RunController(lab.host, run)
    controller.start()
    await settle()
    const source = FakeEventSource.open[0]!
    source.emit("progress", text(1, 0, "Añadir "))
    source.emit("progress", text(2, 8, "más"))
    await settle()
    expect(lab.view.segments[0]?.text).toBe("Añadir más")
    source.emit("progress", text(3, 999, "hueco"))
    await settle()
    expect(lab.fetch).toHaveBeenCalledTimes(2)
    expect(lab.view.segments[0]?.text).toBe("Añadir más")
    controller.dispose()
  })

  it("withdraws text, activity, files and notices on revocation and restores them quietly", async () => {
    const authorized: RunSnapshot = { run, events: [skill(1), event(2, "claimed")], text_segments: [{ message_id: "inference:a", text: "Texto", offset: 0 }], high_watermark: 2, artifacts: [] }
    const lab = setup([authorized, authorized])
    const controller = new RunController(lab.host, run)
    controller.start()
    await settle()
    expect(lab.view.skills[0]?.fresh).toBe(false)
    FakeEventSource.open[0]!.emit("revoked", {})
    await settle()
    expect(lab.view).toMatchObject({ unavailable: true, data: null, segments: [], skills: [], events: [] })
    expect(lab.revoked).toEqual(["run-1"])
    await controller.refresh()
    await settle()
    expect(lab.view.unavailable).toBe(false)
    expect(lab.view.segments[0]?.text).toBe("Texto")
    expect(lab.view.skills.map((item) => item.fresh)).toEqual([false])
    expect(lab.announced).toEqual([])
    controller.dispose()
  })

  it("closes on terminal and reads the final authorized state", async () => {
    const done = { ...run, status: "completed", finished_at: "2026-10-17T10:00:09Z" }
    const lab = setup([
      { run, events: [], text_segments: [], high_watermark: 0 },
      { run: done, events: [event(1, "completed")], text_segments: [{ message_id: "inference:a", text: "Fin", offset: 0 }], high_watermark: 1, result: { assistant_message: { content: "Fin" } } },
    ])
    const controller = new RunController(lab.host, run)
    controller.start()
    await settle()
    FakeEventSource.open[0]!.emit("terminal", done)
    await settle()
    expect(FakeEventSource.open).toHaveLength(0)
    expect(lab.view.run.status).toBe("completed")
    expect(lab.view.segments[0]).toMatchObject({ text: "Fin", done: true, incomplete: false })
    controller.dispose()
  })
})

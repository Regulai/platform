import { list } from "@/lib/format"
import type { AgentEvent, RunData, RunSnapshot, TextSegmentSnapshot } from "@/types"

import { isLiveRun, type RunView, type Segment, type SkillActivation } from "../state/model"
import { REFRESH } from "../state/run-model"
import { getJSON, isAbort, postJSON } from "./http"

/* One agent run: authorized snapshot, then SSE progress (EventSource with
 * Last-Event-ID), polling when SSE is unavailable. Events are applied once by
 * id; text uses UTF-8 byte offsets and recovers from gaps with a snapshot.
 * A disconnected browser never cancels or reruns execution. */

export type RunHost = {
  announce(text: string): void
  updateRun(id: string, update: (view: RunView) => RunView): void
  runChanged(id: string): void
  revoked(id: string): void
}

type WorkingSegment = Segment & { unread: boolean }

const encoder = new TextEncoder()
const bytes = (text: string) => encoder.encode(text).length

export function initialRunView(run: RunData): RunView {
  return { run: { ...run }, loaded: false, unavailable: false, events: [], segments: [], generating: null, skills: [], data: null, skew: null, note: null }
}

export class RunController {
  readonly id: string
  private host: RunHost
  private run: RunData
  private cursor = 0
  private version = 0
  private source: EventSource | null = null
  private pollTimer = 0
  private refreshTimer = 0
  private receiptTimer = 0
  private receiptPolls = 0
  private frame = 0
  private requests = new AbortController()
  private segments = new Map<string, WorkingSegment>()
  private skillKeys = new Set<string>()
  private snapshotPending = false
  private started = false
  private disposed = false
  private initial = false
  private events: AgentEvent[] = []
  private generating: Record<string, unknown> | null = null
  private skills: SkillActivation[] = []
  private data: RunSnapshot | null = null
  private loadedOnce = false
  detailsOpen = false

  constructor(host: RunHost, run: RunData) {
    this.host = host
    this.run = { ...run }
    this.id = run.id
  }

  get live() {
    return isLiveRun(this.run.status)
  }

  /** Idempotent: StrictMode, lazy history and remounts may call it repeatedly. */
  start() {
    if (this.started || this.disposed) return
    this.started = true
    this.requests = new AbortController()
    void this.snapshot().then((run) => {
      if (run && isLiveRun(run.status)) this.listen()
    }, (error) => {
      if (!isAbort(error)) this.revoke()
    })
  }

  /** Closes streams, timers and fetches; the run itself keeps going on the server. */
  stop() {
    this.started = false
    this.close()
    this.requests.abort()
    window.clearTimeout(this.refreshTimer)
    window.clearTimeout(this.receiptTimer)
    if (this.frame) cancelAnimationFrame(this.frame)
    this.frame = 0
  }

  dispose() {
    this.stop()
    this.disposed = true
  }

  private close() {
    this.source?.close()
    this.source = null
    window.clearTimeout(this.pollTimer)
    this.pollTimer = 0
  }

  private publish(patch: Partial<RunView>) {
    if (this.disposed) return
    this.host.updateRun(this.id, (view) => ({ ...view, ...patch, run: this.run }))
  }

  async snapshot(): Promise<RunData | null> {
    const expected = this.run.id
    const version = ++this.version
    let data: RunSnapshot
    let served = NaN
    try {
      const result = await getJSON<RunSnapshot>(this.run.status_url, this.requests.signal)
      served = Date.parse(result.response.headers.get("Date") || "")
      data = result.data
    } catch (error) {
      if (this.run.id !== expected || version !== this.version) return null
      throw error
    }
    if (this.disposed || this.run.id !== expected || version !== this.version || !data?.run) return null
    this.apply(data, Number.isFinite(served) ? served - Date.now() : null)
    return data.run
  }

  private apply(data: RunSnapshot, skew: number | null) {
    this.initial = !this.loadedOnce
    this.loadedOnce = true
    this.run = { ...this.run, ...data.run }
    list<TextSegmentSnapshot>(data.text_segments).forEach((segment) => this.textEvent({ ...segment, offset: 0 }, true))
    list<AgentEvent>(data.events).forEach((event) => {
      this.addEvent(event)
      // An authorized snapshot restores notices cleared by a revoke without
      // replaying activity or moving the cursor backwards.
      this.skillActivation(event)
    })
    if (Number.isSafeInteger(data.high_watermark)) this.cursor = Math.max(this.cursor, data.high_watermark!)
    if (!isLiveRun(this.run.status)) {
      this.segments.forEach((segment) => {
        segment.done = true
        if (this.run.status !== "completed") segment.incomplete = true
        segment.unread = false
      })
    }
    const message = data.result?.assistant_message?.content
    if (this.run.professional && !isLiveRun(this.run.status) && message) {
      // Professional runs answer in text too: the stored message completes its segment once.
      const answer = [...this.segments.values()].filter((segment) => !segment.tools).pop()
      if (answer) Object.assign(answer, { text: message, done: true, incomplete: false })
      else this.segments.set("final", { id: "final", text: message, offset: bytes(message), done: true, incomplete: false, tools: 0, unread: false })
    }
    this.publish({
      loaded: true, unavailable: false, data, skew: skew ?? null, note: null,
      events: [...this.events], generating: this.generating, skills: [...this.skills], segments: this.segmentList(),
    })
    this.data = data
    if (!isLiveRun(this.run.status)) this.close()
    this.host.runChanged(this.id)
    this.initial = false
    this.pollReceipt()
  }

  private segmentList(): Segment[] {
    return [...this.segments.values()].map(({ unread: _unread, ...segment }) => ({ ...segment }))
  }

  addEvent(event: AgentEvent): boolean {
    if (!event || typeof event.id !== "number" || event.id <= this.cursor) return false
    this.cursor = event.id
    if (event.kind === "text.delta" || event.kind === "text.snapshot") {
      this.textEvent(event.data as unknown as TextSegmentSnapshot & { snapshot_required?: boolean }, event.kind === "text.snapshot")
      return false
    }
    if (event.kind === "inference.started" || event.kind === "inference.delivery") this.generating = event.data
    if (event.kind === "inference.finished") {
      this.generating = null
      const segment = this.segments.get(String(event.data?.message_id))
      if (segment) {
        segment.done = true
        segment.incomplete = Boolean(event.data.incomplete)
        segment.tools = Number(event.data.tool_count) || 0
        this.queueText(segment)
      }
    }
    this.skillActivation(event)
    this.events.push(event)
    return true
  }

  private skillActivation(event: AgentEvent) {
    if (event?.kind !== "skill.activated" || typeof event.id !== "number") return
    const value = event.data as Record<string, string | undefined>
    const key = value.revision_id || value.installation_id || value.alias || value.name || String(event.id)
    if (this.skillKeys.has(key)) return
    this.skillKeys.add(key)
    const name = value.display_name || value.name || value.alias || "Skill"
    // Only an activation that happens while the page watches is announced and animated.
    const fresh = this.loadedOnce && !this.initial
    this.skills.push({ key, name, reason: value.reason ?? null, eventId: event.id, fresh })
    if (fresh) this.host.announce(`Skill activada: ${name}`)
  }

  private textEvent(data: TextSegmentSnapshot & { snapshot_required?: boolean }, snapshot = false) {
    if (snapshot && data?.snapshot_required) {
      this.recoverText()
      return
    }
    if (!data || typeof data.message_id !== "string" || typeof data.text !== "string" || !Number.isSafeInteger(data.offset) || data.offset < 0) return
    let segment = this.segments.get(data.message_id)
    if (!segment) {
      segment = { id: data.message_id, text: "", offset: 0, done: false, incomplete: false, tools: 0, unread: false }
      this.segments.set(data.message_id, segment)
    }
    const width = bytes(data.text)
    if (snapshot) {
      segment.text = data.text
      segment.offset = width
    } else if (data.offset < segment.offset && data.offset + width <= segment.offset) {
      return // Already applied (reconnection replay).
    } else if (data.offset !== segment.offset) {
      this.recoverText()
      return
    } else {
      segment.text += data.text
      segment.offset += width
    }
    this.queueText(segment)
  }

  private recoverText() {
    if (this.snapshotPending) return
    this.snapshotPending = true
    this.snapshot().catch((error) => { if (!isAbort(error)) this.revoke() }).finally(() => { this.snapshotPending = false })
  }

  /** Text batches paint once per frame; activity is not rebuilt for text. */
  private queueText(segment: WorkingSegment) {
    segment.unread = segment.unread || !this.initial
    if (this.frame) return
    this.frame = requestAnimationFrame(() => {
      this.frame = 0
      this.publish({ segments: this.segmentList(), generating: this.generating })
    })
  }

  private listen() {
    this.close()
    if (this.disposed || !this.started) return
    if (typeof EventSource !== "function") {
      this.poll()
      return
    }
    const source = new EventSource(`${this.run.events_url}?cursor=${this.cursor}`)
    this.source = source
    const current = () => this.source === source
    source.addEventListener("progress", (message) => {
      if (!current()) return
      let event: AgentEvent
      try {
        event = JSON.parse((message as MessageEvent<string>).data) as AgentEvent
      } catch {
        this.publish({ note: { text: "Se recibió un evento ilegible. Actualiza el estado para continuar.", tone: "error" } })
        return
      }
      if (this.addEvent(event)) this.publish({ events: [...this.events], generating: this.generating, skills: [...this.skills] })
      if (REFRESH.has(event.kind)) this.scheduleRefresh()
    })
    source.addEventListener("terminal", () => {
      if (!current()) return
      this.close()
      this.snapshot().catch((error) => { if (!isAbort(error)) this.revoke() })
    })
    source.addEventListener("revoked", () => { if (current()) this.revoke() })
    source.onerror = () => {
      if (!current()) return
      // EventSource reconnects by itself with Last-Event-ID; a closed source falls back to polling.
      if (source.readyState === EventSource.CLOSED) {
        this.close()
        this.poll()
      }
    }
  }

  private scheduleRefresh() {
    if (this.refreshTimer) return
    this.refreshTimer = window.setTimeout(() => {
      this.refreshTimer = 0
      this.snapshot().catch((error) => { if (!isAbort(error)) this.revoke() })
    }, 16)
  }

  private poll() {
    window.clearTimeout(this.pollTimer)
    this.pollTimer = window.setTimeout(async () => {
      try {
        const run = await this.snapshot()
        if (run && isLiveRun(run.status) && this.started) this.poll()
      } catch (error) {
        if (!isAbort(error)) this.revoke()
      }
    }, 2500)
  }

  /** A late financial settlement may still update the receipt after the run ends. */
  pollReceipt() {
    window.clearTimeout(this.receiptTimer)
    const total = (this.data?.receipt || this.data?.result?.receipt)?.total?.complete
    if (!this.detailsOpen || this.live || total !== false || this.receiptPolls >= 5) return
    this.receiptTimer = window.setTimeout(async () => {
      this.receiptPolls++
      try {
        await this.snapshot()
      } catch (error) {
        if (!isAbort(error)) this.revoke()
      }
    }, Math.min(30000, 2000 * 2 ** this.receiptPolls))
  }

  /** Access withdrawn: every authorized projection leaves the page (text, files, activity, receipts).
   * A later authorized snapshot replays from the start, so the cursor resets too. */
  revoke() {
    this.close()
    this.segments.clear()
    this.skills = []
    this.skillKeys.clear()
    this.events = []
    this.cursor = 0
    this.data = null
    this.generating = null
    // A later authorized snapshot restores what was shown, without re-announcing it.
    this.loadedOnce = false
    window.clearTimeout(this.receiptTimer)
    this.publish({
      unavailable: true, data: null, segments: [], skills: [], events: [], generating: null,
      note: { text: "El estado no está autorizado o no está disponible. Actualiza el estado para comprobar el acceso.", tone: "info" },
    })
    this.host.revoked(this.id)
    this.host.runChanged(this.id)
  }

  async refresh() {
    try {
      this.started = true
      const run = await this.snapshot()
      if (run && isLiveRun(run.status)) this.listen()
    } catch (error) {
      if (!isAbort(error)) this.revoke()
    }
  }

  async cancel() {
    if (!this.live || !this.run.cancel_url) return
    try {
      await postJSON(this.run.cancel_url, undefined, this.requests.signal)
      await this.snapshot()
    } catch (error) {
      if (!isAbort(error)) this.revoke()
    }
  }

  async resume(): Promise<boolean> {
    if (!this.run.resumable) return false
    try {
      const value = await postJSON<{ run?: RunData }>(this.run.resume_url, undefined, this.requests.signal)
      if (!value?.run) return false
      this.run = { ...this.run, ...value.run }
      this.events = []
      this.cursor = 0
      this.stop()
      this.start()
      return true
    } catch (error) {
      if (!isAbort(error)) this.publish({ note: { text: "No se puede reanudar: el punto guardado, los permisos o el presupuesto ya no son válidos.", tone: "error" } })
      return false
    }
  }

  note(text: string, tone: "info" | "error" = "info") {
    this.publish({ note: { text, tone } })
  }

  /** Mutations that change the run (review, export decision) re-read the authorized state. */
  async reload() {
    try {
      await this.snapshot()
    } catch (error) {
      if (!isAbort(error)) this.revoke()
    }
  }
}

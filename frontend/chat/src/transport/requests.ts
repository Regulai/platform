import { DELIVERY, FILE_REJECTIONS, stageText } from "@/lib/labels"
import type { ChatEvent, RequestResult, RunData } from "@/types"

import type { AttachmentPhase, Command, RequestState } from "../state/model"
import { outcomeFromResult } from "../state/model"
import { csrf, isAbort, sleep } from "./http"
import { readEventStream } from "./sse"

/* One web request: the same POST, rejoin and cancel endpoints the server-rendered
 * chat used. Events apply once, in order, by `seq`. Rejoining replays from the
 * last applied event and never starts work; retrying reuses the request id. */

export type RequestHost = {
  url(name: "send" | "send_conversation" | "request_stream" | "request_cancel", id?: string | number): string
  updateRequest(key: string, update: (state: RequestState) => RequestState): void
  setAttachment(key: string, phase: AttachmentPhase | null): void
  adoptConversation(id: number): void
  announce(text: string): void
  toast(text: string, error?: boolean): void
  agentAccepted(key: string, run: RunData, command: Command | null): void
  setSending(value: boolean): void
  setRequestBusy(key: string, active: boolean, stoppable: boolean): void
}

const LIVE = new Set(["processing", "received", "accepted"])

export class RequestController {
  readonly key: string
  readonly requestId: string
  command: Command | null
  private host: RequestHost
  private abort = new AbortController()
  private seq = 0
  private attempt = 0
  private text = ""
  private done = false
  private retracted = false
  private frame = 0
  private disposed = false
  private uploading = false
  private streamed = false
  private stopRequested = false
  private suspended = false
  private attaching = false
  /** The last rejoin heard from the server that it has no such request. */
  private missing = false
  /** The page was hidden while the body was still uploading. */
  private interrupted = false

  constructor(host: RequestHost, key: string, requestId: string, command: Command | null) {
    this.host = host
    this.key = key
    this.requestId = requestId
    this.command = command
  }

  private update(patch: Partial<RequestState> | ((state: RequestState) => Partial<RequestState>)) {
    if (this.disposed) return
    this.host.updateRequest(this.key, (state) => ({ ...state, ...(typeof patch === "function" ? patch(state) : patch) }))
  }

  /** Page hidden (bfcache) or StrictMode cleanup: stop reading, keep the request; resume() rejoins. */
  suspend() {
    if (this.done || this.disposed) return
    this.suspended = true
    this.interrupted = this.uploading
    this.abort.abort()
  }

  /** Rejoining holds the composer, as the send did; an upload cut by the page may never have arrived. */
  resume() {
    if (!this.suspended || this.disposed || this.done) return
    const upload = this.interrupted
    this.interrupted = false
    this.host.setRequestBusy(this.key, true, true)
    void this.attach({ reportMissing: !upload })
      .then(() => {
        if (upload && this.missing && !this.done && !this.disposed) {
          this.notSent("No se pudo obtener el resultado", "La página se ocultó antes de terminar la subida y el servidor no la recibió.", true)
        }
      })
      .finally(() => {
        if (!this.disposed) this.host.setRequestBusy(this.key, false, false)
      })
  }

  get active() {
    return this.attaching && !this.suspended
  }

  dispose() {
    this.disposed = true
    this.abort.abort()
    if (this.frame) cancelAnimationFrame(this.frame)
    this.frame = 0
  }

  /** Send (or confirm/cancel a pending consent) as this request's identity. */
  async submit(action: "" | "cancel" = "") {
    const command = this.command
    if (!command) return
    this.abort = new AbortController()
    const signal = this.abort.signal
    this.streamed = !action && command.mode !== "agent" && typeof ReadableStream === "function" && typeof TextDecoder === "function"
    this.done = false
    this.retracted = false
    this.stopRequested = false
    this.seq = 0
    this.text = ""
    this.update({
      phase: "sending", seq: 0, text: "", streaming: false, retracted: false, outcome: null, note: "", stopping: false,
      stage: action === "cancel" ? "Cancelando" : command.mode === "agent" ? "Enviando al agente" : "Enviando",
    })
    if (!action && command.file) this.host.setAttachment(this.key, "sending")
    this.host.setSending(true)
    this.host.setRequestBusy(this.key, true, this.streamed)
    const url = command.conversationId ? this.host.url("send_conversation", command.conversationId) : this.host.url("send")
    this.uploading = true
    try {
      const response = await fetch(url, {
        method: "POST", body: formData(command, action, this.streamed), credentials: "same-origin", signal,
        headers: { Accept: this.streamed ? "text/event-stream" : "application/json" },
      })
      this.uploading = false
      if (this.streamed && response.body && (response.headers.get("Content-Type") || "").includes("text/event-stream")) {
        // The body has reached the server once it answers with the stream.
        if (command.file && !action) this.host.setAttachment(this.key, "received")
        this.update({ phase: "live" })
        await readEventStream<ChatEvent>(response, (event) => this.apply(event), signal)
        if (!this.done && !this.disposed) await this.attach()
      } else {
        // Blocked and unavailable replies carry useful JSON even with 403/503; an HTML page
        // (rate limit, expired session or CSRF, proxy error) is not a result of this request.
        const data = await readResult(response)
        if (!data) throw new ReplyError(response)
        if (command.file && !action) this.host.setAttachment(this.key, "received")
        this.finish(data)
      }
    } catch (error) {
      this.uploading = false
      if (this.disposed || this.suspended) return
      if (isAbort(error) && this.stopRequested) {
        await this.afterAbortedUpload()
        return
      }
      const refused = error instanceof ReplyError ? refusal(error) : null
      if (refused) {
        this.notSent(refused.title, refused.text, true)
        return
      }
      // The request may have started before the connection failed: rejoin it. Only the server
      // saying it does not know the request lets the draft come back; otherwise a new send could
      // run it twice, so retrying keeps this identity.
      let missing = false
      if (this.streamed) {
        await this.attach({ reportMissing: false })
        missing = this.missing
      }
      if (!this.done && !this.disposed) {
        this.notSent(
          "No se pudo obtener el resultado",
          missing
            ? "La petición no llegó al servidor. Reintentar la envía con la misma identidad."
            : "No se pudo confirmar el envío. Reintentar consulta esta misma petición; no crea otra.",
          missing,
        )
      }
    } finally {
      if (!this.disposed) {
        this.host.setSending(false)
        this.host.setRequestBusy(this.key, false, false)
      }
    }
  }

  /** Stop: before the upload finishes the browser aborts it; afterwards the server is asked to stop. */
  async stop() {
    if (this.done) return
    this.stopRequested = true
    this.update({ stage: "Deteniendo", stopping: true })
    if (this.uploading) {
      this.abort.abort()
      return
    }
    try {
      const response = await fetch(this.host.url("request_cancel", this.requestId), {
        method: "POST", headers: { "X-CSRFToken": csrf() }, credentials: "same-origin",
      })
      if (!response.ok && response.status !== 404) throw new Error("cancel_failed")
    } catch {
      this.update({ stopping: false })
      this.host.toast("No se pudo detener. La respuesta sigue en curso.", true)
    }
  }

  /** After aborting an upload, check whether the server registered it before claiming it was not sent. */
  private async afterAbortedUpload() {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt) await sleep(500)
      try {
        const response = await fetch(`${this.host.url("request_stream", this.requestId)}?after=0`, {
          headers: { Accept: "text/event-stream" }, cache: "no-store", credentials: "same-origin",
        })
        if (response.status === 404) continue
        // Registered after all: ask it to stop and follow it to its final state.
        response.body?.cancel().catch(() => undefined)
        this.uploading = false
        await this.stop()
        await this.attach()
        return
      } catch {
        // Network down: keep checking a couple of times.
      }
    }
    this.done = true
    this.update({ phase: "done", stage: null, stopping: false, outcome: { kind: "cancelled", own: true, text: "Envío detenido antes de llegar al servidor." } })
    if (this.command?.file) this.host.setAttachment(this.key, "cancelled")
    this.host.setRequestBusy(this.key, false, false)
    this.host.announce("Envío detenido")
  }

  /** Rejoin: replays from the last applied event and never starts work. */
  async attach({ reportMissing = true }: { reportMissing?: boolean } = {}): Promise<boolean> {
    this.done = false
    this.suspended = false
    this.attaching = true
    try {
      return await this.rejoin(reportMissing)
    } finally {
      this.attaching = false
    }
  }

  private async rejoin(reportMissing: boolean): Promise<boolean> {
    this.abort = new AbortController()
    const signal = this.abort.signal
    this.missing = false
    this.update((state) => ({ phase: "reconnecting", stage: state.text ? state.stage : "Reconectando" }))
    for (let attempt = 0; attempt < 6 && !this.done && !this.disposed; attempt++) {
      try {
        if (attempt) await sleep(Math.min(8000, 500 * 2 ** (attempt - 1)), signal)
        const response = await fetch(`${this.host.url("request_stream", this.requestId)}?after=${this.seq}`, {
          headers: { Accept: "text/event-stream" }, cache: "no-store", credentials: "same-origin", signal,
        })
        if (response.status === 404) {
          this.missing = true
          break
        }
        if (!response.ok || !response.body) continue
        this.update({ phase: "live" })
        await readEventStream<ChatEvent>(response, (event) => this.apply(event), signal)
      } catch (error) {
        if (isAbort(error) || this.disposed) return false
      }
    }
    if (this.done || this.disposed || this.suspended) return this.done
    if (this.missing) {
      // Not registered for this account: never claim that it is still running.
      if (reportMissing) {
        this.done = true
        this.update({ phase: "done", stage: null, outcome: { kind: "error", title: "Petición no disponible", text: "No consta con tus permisos actuales.", retracted: false, actions: [] } })
      }
      return false
    }
    this.update({
      phase: "done", stage: null,
      outcome: { kind: "error", title: "Conexión interrumpida", text: "La petición sigue registrada; reconectar no la repite.", retracted: false, actions: ["check"] },
    })
    return false
  }

  apply(event: ChatEvent): boolean {
    if (!event || typeof event.seq !== "number" || event.seq <= this.seq || this.disposed) return false
    this.seq = event.seq
    switch (event.type) {
      case "accepted":
        if (event.conversation_id) this.host.adoptConversation(event.conversation_id)
        if (this.command?.file) this.host.setAttachment(this.key, "received")
        this.update({ seq: this.seq })
        break
      case "stage":
        this.update({ seq: this.seq, stage: stageText(event.stage, event.model, event.attempt) })
        if (event.stage === "generating" && (event.attempt ?? 1) > 1) this.host.announce("Reintentando con otro modelo")
        break
      case "delivery":
        this.update({ seq: this.seq, note: event.mode === "complete" ? DELIVERY[event.reason ?? ""] ?? "" : "" })
        break
      case "delta":
        if (event.attempt !== this.attempt) {
          this.attempt = event.attempt
          this.text = ""
        }
        this.text += event.text || ""
        this.paint()
        break
      case "retract": {
        const retry = event.reason === "retry"
        this.retracted = true
        this.text = ""
        if (this.frame) cancelAnimationFrame(this.frame)
        this.frame = 0
        this.update({
          seq: this.seq, text: "", streaming: false, retracted: true,
          stage: retry ? "Reintentando" : "Comprobando",
          note: retry ? "El texto anterior no superó las comprobaciones y se ha retirado." : "El texto mostrado se ha retirado.",
        })
        break
      }
      case "final":
        if (this.frame) cancelAnimationFrame(this.frame)
        this.frame = 0
        this.finish(event.result || {})
        break
      default:
        return false
    }
    return true
  }

  /** No result. Retrying reuses this identity; the draft comes back only when nothing was registered. */
  private notSent(title: string, text: string, restorable: boolean) {
    this.done = true
    this.update({ phase: "done", stage: null, streaming: false, stopping: false, outcome: { kind: "unsent", title, text, restorable } })
    if (this.command?.file) this.host.setAttachment(this.key, restorable ? "cancelled" : null)
    this.host.announce(title)
  }

  /** Growing text paints once per frame, never per token. */
  private paint() {
    if (this.frame) return
    this.frame = requestAnimationFrame(() => {
      this.frame = 0
      this.update({ seq: this.seq, text: this.text, streaming: true, stage: null, phase: "live" })
    })
  }

  finish(data: RequestResult) {
    data = data && typeof data === "object" ? data : {}
    const status = data.status || "validation_error"
    const command = this.command
    if (command) {
      command.status = status
      command.token = data.consent_token || command.token
    }
    if (data.conversation_id) this.host.adoptConversation(data.conversation_id)
    if (data.agent) {
      this.done = true
      this.update({ phase: "done", stage: null, streaming: false, outcome: null, receipt: null })
      this.host.agentAccepted(this.key, data.agent, command)
      return
    }
    const outcome = outcomeFromResult(data, command, this.retracted)
    const live = LIVE.has(status)
    this.done = !live
    if (command?.file && outcome?.kind === "error" && outcome.code && FILE_REJECTIONS.has(outcome.code)) {
      this.host.setAttachment(this.key, "rejected")
    }
    this.update({
      phase: live ? "reconnecting" : "done", stage: null, streaming: false, stopping: false, outcome,
      text: outcome?.kind === "answer" ? outcome.text : "",
      receipt: data.request_id ? { receipt: data.receipt || {}, status } : null,
    })
    this.host.setRequestBusy(this.key, false, false)
    if (!outcome) return
    const said: Record<string, string> = {
      answer: "Respuesta lista", blocked: "Bloqueado por la política", consent: "Requiere tu confirmación",
      cancelled: outcome.kind === "cancelled" && outcome.own ? "Respuesta detenida" : "Petición cancelada",
    }
    this.host.announce(said[outcome.kind] ?? (outcome.kind === "error" ? outcome.title : ""))
  }
}

/** A reply that is not a request result, e.g. the HTML page of a rate limit, login or proxy error. */
class ReplyError extends Error {
  readonly status: number
  readonly retryAfter: string | null
  readonly redirected: boolean
  constructor(response: Response) {
    super("reply_not_result")
    this.status = response.status
    this.retryAfter = response.headers.get("Retry-After")
    this.redirected = response.redirected
  }
}

/** Every result the send endpoints return is JSON with a status, accepted agent runs included. */
async function readResult(response: Response): Promise<RequestResult | null> {
  if (!(response.headers.get("Content-Type") || "").includes("json")) return null
  const data: unknown = await response.json().catch(() => null)
  return data && typeof data === "object" && typeof (data as RequestResult).status === "string" ? (data as RequestResult) : null
}

/** Refusals that happen before the request is handled, so nothing was registered or run. */
function refusal(error: ReplyError): { title: string; text: string } | null {
  if (error.status === 429) {
    const seconds = Number(error.retryAfter)
    const wait = error.retryAfter && Number.isFinite(seconds) && seconds > 0 ? `Espera ${Math.ceil(seconds)} s` : "Espera un momento"
    return { title: "Demasiados mensajes seguidos", text: `${wait} y reintenta. Este mensaje no se ha enviado.` }
  }
  if (error.status === 401 || error.status === 403 || error.redirected) {
    return { title: "La sesión ya no es válida", text: "Recarga la página para continuar. Este mensaje no se ha enviado." }
  }
  return null
}

function formData(command: Command, action: string, stream: boolean): FormData {
  const form = new FormData()
  form.append("prompt", command.prompt || "")
  form.append("request_id", command.requestId)
  form.append("auto_route", String(Boolean(command.autoRoute)))
  if (command.mode) form.append("mode", command.mode)
  if (command.inferenceProfile) form.append("inference_profile", command.inferenceProfile)
  if (command.skills) form.append("skills", JSON.stringify(command.skills))
  if (command.artifactId) form.append("artifact_id", command.artifactId)
  if (command.baseRevision) form.append("base_revision", command.baseRevision)
  if (command.documentReference) form.append("document_reference", command.documentReference)
  if (command.exportName) form.append("export_name", command.exportName)
  if (command.file) form.append("file", command.file)
  if (command.engineId) form.append("engine_id", command.engineId)
  if (command.modelId) form.append("model_id", command.modelId)
  if (command.token) form.append("consent_token", command.token)
  if (action) form.append("action", action)
  if (stream) form.append("stream", "1")
  form.append("csrfmiddlewaretoken", csrf())
  return form
}

import { requestUUID } from "@/lib/ids"
import type { Artifact, Bootstrap, Mode, RunData } from "@/types"

import { RequestController, type RequestHost } from "../transport/requests"
import { initialRunView, RunController, type RunHost } from "../transport/runs"
import { setCsrfToken } from "../transport/http"
import {
  emptyRequest, isLiveRun, requestFromBoot, turnFromBoot,
  type AttachmentPhase, type ChatState, type Command, type ComposerContext, type RequestState, type RunView, type TurnModel,
} from "./model"
import { groupSteps } from "./run-model"
import { createStore, type Store } from "./store"

/* The page's single owner of transport and state. React components read the
 * store and call these methods; nothing here touches the DOM. dispose() is
 * idempotent and closes every stream, fetch and timer (unmount, pagehide). */

export type SendInput = {
  prompt: string
  file: File | null
  mode: Mode
  inferenceProfile?: string
}

export type ModelSettings = { engineId: string | null; modelId: string | null; autoRoute: boolean }

export type SkillsBridge = {
  capture(): { selected: string[]; auto: boolean } | undefined
  accepted(): void
}

export class ChatSession implements RequestHost, RunHost {
  readonly boot: Bootstrap
  readonly store: Store<ChatState>
  private requestControllers = new Map<string, RequestController>()
  private runControllers = new Map<string, RunController>()
  private disposed = false
  private noticeId = 0
  private toastTimer = 0
  skills: SkillsBridge | null = null
  focusComposer: (() => void) | null = null
  composerDraft: (() => string) | null = null
  restoreComposer: ((draft: { prompt: string; file: File | null }) => void) | null = null
  modelSettings: () => ModelSettings = () => ({ engineId: null, modelId: null, autoRoute: false })
  onArtifactRevoked: ((runId: string) => void) | null = null

  constructor(boot: Bootstrap) {
    this.boot = boot
    setCsrfToken(boot.csrf_token)
    const turns: TurnModel[] = []
    const requests: Record<string, RequestState> = {}
    const runs: Record<string, RunView> = {}
    let latestRun: string | null = null
    boot.turns.forEach((turn, index) => {
      const model = turnFromBoot(turn, index)
      turns.push(model)
      if (turn.run_id && boot.runs[turn.run_id]) {
        runs[turn.run_id] = initialRunView(boot.runs[turn.run_id]!)
        latestRun = turn.run_id
      } else {
        requests[model.key] = requestFromBoot(turn)
      }
    })
    this.store = createStore<ChatState>({
      conversationId: boot.conversation?.id ?? null,
      title: boot.conversation?.title || "Nueva conversación",
      mode: boot.composer.mode,
      threads: boot.threads,
      turns,
      requests,
      attachments: {},
      runs,
      latestRun,
      busy: { owner: null, stoppable: false, hint: "" },
      sending: false,
      context: null,
      pendingExport: null,
      announcement: null,
      toast: null,
    })
  }

  /** Starts what the page needs now: the latest and live runs, and rejoins live requests. */
  start() {
    if (this.disposed) return
    const state = this.store.get()
    state.turns.forEach((turn) => {
      if (turn.runId) {
        const controller = this.runController(turn.runId)
        if (controller && (turn.runId === state.latestRun || isLiveRun(state.runs[turn.runId]?.run.status))) controller.start()
      } else if (turn.requestId && state.requests[turn.key]?.phase === "reconnecting") {
        this.rejoin(turn.key)
      }
    })
  }

  dispose() {
    if (this.disposed) return
    this.disposed = true
    this.requestControllers.forEach((controller) => controller.dispose())
    this.runControllers.forEach((controller) => controller.dispose())
    this.requestControllers.clear()
    this.runControllers.clear()
    window.clearTimeout(this.toastTimer)
  }

  get isDisposed() {
    return this.disposed
  }

  /* ------------------------------------------------------------ host API */

  url(name: "send" | "send_conversation" | "request_stream" | "request_cancel", id?: string | number): string {
    const pattern = this.boot.urls[name]
    return id === undefined ? pattern : pattern.replace("{id}", encodeURIComponent(String(id)))
  }

  updateRequest(key: string, update: (state: RequestState) => RequestState) {
    this.store.set((state) => {
      const current = state.requests[key] ?? emptyRequest()
      const next = update(current)
      return next === current ? state : { ...state, requests: { ...state.requests, [key]: next } }
    })
  }

  setAttachment(key: string, phase: AttachmentPhase | null) {
    this.store.set((state) => {
      const attachments = { ...state.attachments }
      if (phase) attachments[key] = phase
      else delete attachments[key]
      return { ...state, attachments }
    })
  }

  adoptConversation(id: number) {
    const state = this.store.get()
    if (!id || state.conversationId === id) return
    const href = this.boot.urls.conversation.replace("{id}", String(id))
    window.history.replaceState({}, "", href)
    const mode = state.mode
    this.store.set((current) => {
      const exists = current.threads.some((group) => group.items.some((item) => item.id === id))
      if (exists) return { ...current, conversationId: id }
      const threads = current.threads.map((group) => ({ ...group, items: [...group.items] }))
      const today = threads[0]?.label === "Hoy" ? threads[0] : null
      const item = { id, title: "Nueva conversación", mode }
      if (today) today.items.unshift(item)
      else threads.unshift({ label: "Hoy", items: [item] })
      return { ...current, conversationId: id, threads }
    })
  }

  announce(text: string) {
    if (!text) return
    this.store.set((state) => ({ ...state, announcement: { id: ++this.noticeId, text } }))
  }

  toast(text: string, error = false) {
    window.clearTimeout(this.toastTimer)
    this.store.set((state) => ({ ...state, toast: { id: ++this.noticeId, text, error } }))
    this.toastTimer = window.setTimeout(() => this.store.set((state) => ({ ...state, toast: null })), 3600)
  }

  setSending(value: boolean) {
    this.store.set((state) => (state.sending === value ? state : { ...state, sending: value }))
  }

  setRequestBusy(_key: string, active: boolean, stoppable: boolean) {
    if (active) this.store.set((state) => ({ ...state, busy: { owner: "request", stoppable, hint: "" } }))
    else this.recomputeBusy(true)
  }

  agentAccepted(key: string, run: RunData, command: Command | null) {
    this.skills?.accepted()
    this.store.set((state) => ({
      ...state,
      turns: state.turns.map((turn) => (turn.key === key ? { ...turn, runId: run.id } : turn)),
      runs: { ...state.runs, [run.id]: initialRunView(run) },
      latestRun: run.id,
      // A new run starts without the previous selection, Drive file or export.
      context: null,
      pendingExport: null,
    }))
    void command
    this.runController(run.id)?.start()
    this.recomputeBusy(true)
  }

  updateRun(id: string, update: (view: RunView) => RunView) {
    this.store.set((state) => {
      const current = state.runs[id]
      if (!current) return state
      const next = update(current)
      return next === current ? state : { ...state, runs: { ...state.runs, [id]: next } }
    })
  }

  runChanged(id: string) {
    if (this.store.get().latestRun === id) this.recomputeBusy(false)
  }

  revoked(id: string) {
    const state = this.store.get()
    if (state.latestRun === id && state.context?.kind === "revision") this.setContext(null)
    this.onArtifactRevoked?.(id)
  }

  /** The latest run drives the composer while it works; a web request takes priority while it streams. */
  private recomputeBusy(releaseRequest: boolean) {
    this.store.set((state) => {
      if (state.busy.owner === "request" && !releaseRequest) return state
      const view = state.latestRun ? state.runs[state.latestRun] : null
      const running = Boolean(view && isLiveRun(view.run.status) && !view.unavailable)
      let busy: ChatState["busy"] = { owner: null, stoppable: false, hint: "" }
      if (running && view) {
        const steps = groupSteps(view.events, view.run.status)
        const waiting = steps[steps.length - 1]?.kind
        busy = {
          owner: "agent", stoppable: Boolean(view.run.cancel_url),
          hint: waiting === "visual_pending" ? "Pendiente de tu revisión visual" : waiting === "approval_pending" ? "Pendiente de tu aprobación" : "El agente está trabajando",
        }
      }
      const same = state.busy.owner === busy.owner && state.busy.stoppable === busy.stoppable && state.busy.hint === busy.hint
      return same ? state : { ...state, busy }
    })
  }

  /* ------------------------------------------------------------ commands */

  canSend() {
    const state = this.store.get()
    return !state.busy.owner && !state.sending && !this.disposed
  }

  /** One request at a time; a second Enter while sending is ignored. */
  send(input: SendInput): boolean {
    if (!this.canSend()) return false
    const prompt = input.prompt.trim()
    if (!prompt && !input.file) return false
    const state = this.store.get()
    const requestId = requestUUID()
    const command: Command = {
      requestId, prompt, file: input.file, fileName: input.file?.name ?? null, fileSize: input.file?.size ?? null,
      conversationId: state.conversationId, ...this.modelSettings(),
    }
    if (input.mode === "agent") {
      Object.assign(command, { mode: "agent" as const, inferenceProfile: input.inferenceProfile || "legacy" }, this.captureAgent(input.file))
      const skills = this.skills?.capture()
      if (skills) command.skills = skills
    }
    this.store.set((current) => ({
      ...current,
      mode: input.mode,
      turns: [...current.turns, {
        key: requestId, requestId, runId: null, legacy: false, fresh: true,
        user: { content: prompt, file: input.file ? { name: input.file.name, size: input.file.size } : null },
        receiptUrl: null, evidenceUrl: null,
      }],
      requests: { ...current.requests, [requestId]: emptyRequest("sending") },
      context: null,
      pendingExport: null,
    }))
    const controller = new RequestController(this, requestId, requestId, command)
    this.requestControllers.set(requestId, controller)
    void controller.submit()
    return true
  }

  /** Agent context for the next message: export intent, Drive file or the revision being edited. */
  private captureAgent(file: File | null) {
    const state = this.store.get()
    if (state.pendingExport) return { ...state.pendingExport }
    const context = state.context
    if (context?.kind === "drive" && !file) return { documentReference: context.reference }
    const latest = state.latestRun ? state.runs[state.latestRun] : null
    const selected = this.boot.composer.professional
      ? (context?.kind === "revision" ? context.artifact : null)
      : latest?.data?.current_revision ?? null
    if (file || !selected) return {}
    return { artifactId: selected.logical_id, baseRevision: selected.id }
  }

  private commandFor(key: string): Command | null {
    return this.requestControllers.get(key)?.command ?? null
  }

  /** A new request with the same content (a new identity). */
  resend(key: string) {
    if (!this.canSend()) return
    const previous = this.commandFor(key) ?? this.historicalCommand(key)
    if (!previous) return
    if (previous.fileName && !previous.file) return
    const requestId = requestUUID()
    const command: Command = { ...previous, ...this.modelSettings(), requestId, token: null, status: undefined }
    this.store.set((state) => ({
      ...state,
      turns: [...state.turns, {
        key: requestId, requestId, runId: null, legacy: false, fresh: true,
        user: { content: command.prompt, file: command.file ? { name: command.file.name, size: command.file.size } : null },
        receiptUrl: null, evidenceUrl: null,
      }],
      requests: { ...state.requests, [requestId]: emptyRequest("sending") },
    }))
    const controller = new RequestController(this, requestId, requestId, command)
    this.requestControllers.set(requestId, controller)
    void controller.submit()
  }

  /** The same request again: the server deduplicates by request id. */
  retry(key: string) {
    const controller = this.requestControllers.get(key)
    if (!controller?.command || !this.canSend()) return
    void controller.submit()
  }

  /** Rebuilds the command of a history turn, as the legacy page did from its DOM. */
  private historicalCommand(key: string): Command | null {
    const state = this.store.get()
    const turn = state.turns.find((item) => item.key === key)
    if (!turn?.requestId) return null
    const boot = this.boot.turns.find((item) => item.request_id === turn.requestId)
    const command: Command = {
      requestId: turn.requestId, prompt: turn.user?.content ?? "", file: null,
      fileName: turn.user?.file?.name ?? null, fileSize: turn.user?.file?.size ?? null,
      conversationId: state.conversationId, ...this.modelSettings(),
    }
    if (state.mode === "agent") Object.assign(command, { mode: "agent" as const, inferenceProfile: "legacy" })
    const requested = boot?.notice?.kind === "consent" ? boot.notice.requested : null
    if (requested) {
      // The same request must be confirmed with the selection it was sent with.
      command.engineId = requested.engine_id === null || requested.engine_id === undefined ? null : String(requested.engine_id)
      command.modelId = requested.model_id === null || requested.model_id === undefined ? null : String(requested.model_id)
      command.autoRoute = !command.engineId && !command.modelId
    }
    if (boot?.notice?.token) command.token = boot.notice.token
    return command
  }

  confirmConsent(key: string) {
    const controller = this.ensureRequestController(key)
    if (!controller?.command?.token) return
    if (!this.canSend()) return
    void controller.submit("")
  }

  cancelConsent(key: string) {
    const controller = this.ensureRequestController(key)
    if (!controller?.command || !this.canSend()) return
    void controller.submit("cancel")
  }

  private ensureRequestController(key: string): RequestController | null {
    let controller = this.requestControllers.get(key)
    if (!controller) {
      const command = this.historicalCommand(key)
      if (!command) return null
      controller = new RequestController(this, key, command.requestId, command)
      this.requestControllers.set(key, controller)
    }
    const outcome = this.store.get().requests[key]?.outcome
    if (outcome?.kind === "consent" && outcome.token && controller.command) controller.command.token = outcome.token
    return controller
  }

  /** Rejoin a request after reload or a lost connection; never sends again. */
  rejoin(key: string) {
    const controller = this.ensureRequestController(key)
    if (!controller || controller.active) return
    this.store.set((state) => ({ ...state, busy: { owner: "request", stoppable: true, hint: "" } }))
    void controller.attach().finally(() => {
      if (!this.store.get().sending) this.recomputeBusy(true)
    })
  }

  check(key: string) {
    const controller = this.ensureRequestController(key)
    if (!controller) return
    void controller.attach()
  }

  /** Stop the work that keeps the composer busy. */
  stop() {
    const state = this.store.get()
    if (state.busy.owner === "request") {
      const live = [...this.requestControllers.values()].reverse().find((controller) => {
        const request = state.requests[controller.key]
        return request && request.phase !== "done"
      })
      void live?.stop()
    } else if (state.busy.owner === "agent" && state.latestRun) {
      void this.runController(state.latestRun)?.cancel()
    }
  }

  /** Puts a send the server never registered back into the composer (callers check that first). */
  takeDraft(key: string): { prompt: string; file: File | null } | null {
    const command = this.commandFor(key)
    if (!command) return null
    this.requestControllers.get(key)?.dispose()
    this.requestControllers.delete(key)
    this.store.set((state) => {
      const requests = { ...state.requests }
      const attachments = { ...state.attachments }
      delete requests[key]
      delete attachments[key]
      return { ...state, turns: state.turns.filter((turn) => turn.key !== key), requests, attachments }
    })
    return { prompt: command.prompt, file: command.file }
  }

  /* ------------------------------------------------------------ runs */

  runController(id: string): RunController | null {
    let controller = this.runControllers.get(id)
    if (!controller) {
      const view = this.store.get().runs[id]
      if (!view || this.disposed) return null
      controller = new RunController(this, view.run)
      this.runControllers.set(id, controller)
    }
    return controller
  }

  /** History runs start when they approach the viewport. */
  ensureRun(id: string) {
    this.runController(id)?.start()
  }

  setContext(context: ComposerContext | null) {
    this.store.set((state) => ({ ...state, context }))
  }

  editRevision(artifact: Artifact, title: string) {
    this.setContext({ kind: "revision", artifact, title })
  }

  /** Asks the agent to export a verified revision. The intent exists only with the send that carries it,
   * so a refused send (another request in flight) leaves nothing behind for a later message. */
  requestExport(artifact: Artifact, exportName: string): boolean {
    if (!artifact.logical_id || !this.canSend()) return false
    this.store.set((state) => ({ ...state, pendingExport: { artifactId: artifact.logical_id!, baseRevision: artifact.id, exportName } }))
    return this.send({ prompt: "Guarda la revisión verificada en la carpeta autorizada de Drive.", file: null, mode: "agent" })
  }

  setMode(mode: Mode) {
    this.store.set((state) => {
      if (state.mode === mode) return state
      // A Drive file is only an agent input: leaving agent mode drops it.
      const context = mode === "agent" ? state.context : state.context?.kind === "drive" ? null : state.context
      return { ...state, mode, context }
    })
  }

  /* ------------------------------------------------------------ page lifecycle */

  /** bfcache or StrictMode remount: streams were closed; reopen what is still live. */
  resume() {
    if (this.disposed) return
    this.start()
    this.requestControllers.forEach((controller) => controller.resume())
  }

  suspend() {
    this.runControllers.forEach((controller) => controller.stop())
    this.requestControllers.forEach((controller) => controller.suspend())
  }
}

import { list } from "@/lib/format"
import { DISCLOSURES, ERROR_TITLES, SETUP_CODES } from "@/lib/labels"
import type {
  AgentEvent, Artifact, BootTurn, EvidenceItem, Mode, Receipt, RequestResult, RunData, RunSnapshot, ThreadGroup,
} from "@/types"

export type AttachmentPhase = "sending" | "received" | "rejected" | "cancelled"

/** Everything one send needs to be retried, confirmed or rejoined as the same request. */
export type Command = {
  requestId: string
  prompt: string
  file: File | null
  fileName: string | null
  fileSize: number | null
  conversationId: number | null
  mode?: "agent"
  inferenceProfile?: string
  skills?: { selected: string[]; auto: boolean }
  artifactId?: string
  baseRevision?: string
  documentReference?: string
  exportName?: string
  engineId: string | null
  modelId: string | null
  autoRoute: boolean
  token?: string | null
  status?: string
}

export type FileLink = { name: string; size: number | null; url: string }

export type Outcome =
  | { kind: "answer"; text: string; unverified: boolean; evidence: EvidenceItem[]; file: FileLink | null; contextNote?: string }
  | { kind: "blocked"; rules: string[]; reason: string }
  | {
      kind: "consent"; rules: string[]; reason: string; disclosures: string[]; notices: string[]
      token: string | null; fileName: string | null; canConfirm: boolean
    }
  | { kind: "cancelled"; own: boolean; text: string }
  | { kind: "pending"; stale: boolean }
  | { kind: "error"; title: string; text: string; code?: string; retracted: boolean; actions: ErrorAction[] }
  /** No result. `restorable` only when the server registered nothing, so the draft can come back. */
  | { kind: "unsent"; title: string; text: string; restorable: boolean }
  | { kind: "system"; title: string; text: string }
  | { kind: "context"; title: string; text: string }

export type ErrorAction = "check" | "resend" | "retry"

export type RequestPhase = "sending" | "live" | "reconnecting" | "done"

export type RequestState = {
  phase: RequestPhase
  seq: number
  attempt: number
  text: string
  streaming: boolean
  retracted: boolean
  stage: string | null
  note: string
  outcome: Outcome | null
  receipt: { receipt: Receipt; status: string } | null
  stopping: boolean
}

export type TurnModel = {
  key: string
  requestId: string | null
  runId: string | null
  legacy: boolean
  user: { content: string; file: { name: string; size: number | null } | null } | null
  receiptUrl: string | null
  evidenceUrl: string | null
  /** Created by a send in this page (animated once); history never animates. */
  fresh: boolean
}

export type Step = {
  kind: string
  count: number
  text: string
  tools: string[]
  duration: number | null
  state: "done" | "failed" | "cancelled" | "waiting" | "active"
  skill?: { name: string; reason: string | null }
}

export type Segment = { id: string; text: string; offset: number; done: boolean; incomplete: boolean; tools: number }

export type SkillActivation = { key: string; name: string; reason: string | null; eventId: number; fresh: boolean }

export type RunView = {
  run: RunData
  loaded: boolean
  unavailable: boolean
  events: AgentEvent[]
  segments: Segment[]
  generating: Record<string, unknown> | null
  skills: SkillActivation[]
  data: RunSnapshot | null
  skew: number | null
  note: { text: string; tone: "info" | "error" } | null
}

export type ComposerContext =
  | { kind: "drive"; reference: string; label: string }
  | { kind: "revision"; artifact: Artifact; title: string }

export type Busy = { owner: "request" | "agent" | null; stoppable: boolean; hint: string }

export type ChatState = {
  conversationId: number | null
  title: string
  mode: Mode
  threads: ThreadGroup[]
  turns: TurnModel[]
  requests: Record<string, RequestState>
  attachments: Record<string, AttachmentPhase>
  runs: Record<string, RunView>
  latestRun: string | null
  busy: Busy
  sending: boolean
  context: ComposerContext | null
  pendingExport: { artifactId: string; baseRevision: string; exportName: string } | null
  announcement: { id: number; text: string } | null
  toast: { id: number; text: string; error: boolean } | null
}

export const LIVE_REQUEST = new Set(["processing", "received"])
export const LIVE_RUN = new Set(["queued", "active", "outcome_unknown"])
export const isLiveRun = (status: string | undefined) => LIVE_RUN.has(status ?? "")

export function emptyRequest(phase: RequestPhase = "sending"): RequestState {
  return { phase, seq: 0, attempt: 0, text: "", streaming: false, retracted: false, stage: null, note: "", outcome: null, receipt: null, stopping: false }
}

const names = (rules: { name?: string }[] | undefined) => list<{ name?: string }>(rules).map((rule) => rule?.name).filter((name): name is string => Boolean(name))

const UNVERIFIED_PREFIX = "No verificado\n\n"
const DOWNLOAD = /^\/chat\/download\/\d+\/$/

export function disclosureText(item: { code: string; count?: number | null; locators?: string[] }): string {
  const locators = list<string>(item.locators).join(", ")
  return `${DISCLOSURES[item.code] ?? item.code} (${item.count ?? "No disponible"})${locators ? `: ${locators}` : ""}`
}

/** One request's outcome from a stream's final event or a JSON reply (legacy renderOutcome). */
export function outcomeFromResult(data: RequestResult, command: Command | null, retracted: boolean): Outcome | null {
  const status = data.status || "validation_error"
  if (status === "completed" && data.assistant_message) {
    const agentResult = command?.mode === "agent" || Boolean((data.receipt as Receipt | undefined)?.jev && data.agent)
    const verified = data.receipt?.verification?.status === "passed"
    let text = data.assistant_message.content || ""
    const unverified = !verified && !agentResult
    if (unverified && text.startsWith(UNVERIFIED_PREFIX)) text = text.slice(UNVERIFIED_PREFIX.length)
    const message = data.assistant_message
    const file = message.file_name && message.file_url && DOWNLOAD.test(message.file_url)
      ? { name: message.file_name, size: typeof message.file_size === "number" ? message.file_size : null, url: message.file_url }
      : null
    const raw = Array.isArray(data.evidence) ? data.evidence : list<EvidenceItem>(data.evidence?.items)
    const evidence = verified && !agentResult
      ? raw.filter((item) => item && typeof item === "object" && typeof item.locator === "string")
        .map((item) => ({ claim_index: item.claim_index ?? null, locator: item.locator, excerpt: item.excerpt || (item as { text?: string }).text || "" }))
      : []
    return { kind: "answer", text, unverified, evidence, file }
  }
  if (status === "blocked") {
    const rules = names(data.blocked_rules)
    return { kind: "blocked", rules, reason: rules.length ? "" : data.error || "" }
  }
  if (status === "pending_consent") {
    const reason = data.consent_reason || (data.receipt?.consent_reason as string | undefined) || ""
    const token = data.consent_token || command?.token || null
    return {
      kind: "consent", rules: names(data.consent_rules), reason,
      disclosures: list<{ code: string }>(data.receipt?.coverage?.disclosures).filter((item) => item && typeof item.code === "string").map(disclosureText),
      notices: list<string>(data.receipt?.notices),
      token, fileName: command?.fileName ?? null,
      canConfirm: Boolean(command && token && (!command.fileName || command.file)),
    }
  }
  if (status === "cancelled") {
    const own = data.error_type === "cancelled_by_user"
    return { kind: "cancelled", own, text: own ? data.error || "Respuesta detenida." : "Petición cancelada. No se ha enviado." }
  }
  if (LIVE_REQUEST.has(status) || status === "accepted") return { kind: "pending", stale: false }
  const code = data.error_type
  const title = code && SETUP_CODES.has(code) ? "Configuración incompleta" : (code && ERROR_TITLES[code]) || "No se pudo completar"
  const actions: ErrorAction[] = []
  if (status === "outcome_unknown") actions.push("check")
  if ((status === "failed" || status === "outcome_unknown") && command && (command.prompt || command.file)) actions.push("resend")
  return { kind: "error", title, text: data.error || "La petición no se pudo completar.", code, retracted, actions }
}

/** History rendered by the server, as one outcome (chat_page.notice / answer). */
export function outcomeFromBoot(turn: BootTurn): Outcome | null {
  const notice = turn.notice
  if (notice) {
    switch (notice.kind) {
      case "blocked": return { kind: "blocked", rules: notice.rules, reason: notice.rules.length ? "" : notice.detail || "" }
      case "consent": return {
        kind: "consent", rules: notice.rules, reason: notice.reason || "", disclosures: [], notices: [],
        token: notice.token ?? null, fileName: notice.file_name ?? null, canConfirm: Boolean(notice.token),
      }
      case "cancelled": return { kind: "cancelled", own: notice.title === "Respuesta detenida", text: notice.text || "" }
      case "live": return { kind: "pending", stale: Boolean(notice.stale) }
      case "system": return { kind: "system", title: notice.title || "Aviso del sistema", text: notice.text || "" }
      case "context":
        if (!turn.answer) return { kind: "context", title: notice.title || "", text: notice.text || "" }
        break
      case "error": {
        const actions: ErrorAction[] = notice.code === "outcome_unknown" ? ["check"] : notice.retry ? ["resend"] : []
        return { kind: "error", title: notice.title || "No se pudo completar", text: notice.text || "", code: notice.code, retracted: false, actions }
      }
    }
  }
  if (turn.answer) {
    return {
      kind: "answer", text: turn.answer.text, unverified: turn.answer.unverified && turn.answer.recorded,
      evidence: turn.answer.evidence, file: turn.assistant_file ? { ...turn.assistant_file } : null,
      ...(notice?.kind === "context" && notice.text ? { contextNote: notice.text } : {}),
    }
  }
  return null
}

export function turnFromBoot(turn: BootTurn, index: number): TurnModel {
  return {
    key: turn.request_id || `history-${index}`,
    requestId: turn.request_id,
    runId: turn.run_id,
    legacy: turn.legacy,
    user: turn.user ? { content: turn.user.content, file: turn.user.file_name ? { name: turn.user.file_name, size: turn.user.file_size } : null } : null,
    receiptUrl: turn.receipt_url,
    evidenceUrl: turn.evidence_url,
    fresh: false,
  }
}

export function requestFromBoot(turn: BootTurn): RequestState {
  const state = emptyRequest("done")
  const outcome = outcomeFromBoot(turn)
  return {
    ...state,
    phase: turn.live ? "reconnecting" : "done",
    outcome: turn.live ? null : outcome,
    stage: turn.live ? (turn.notice?.stale ? "Sin respuesta reciente" : "Generando") : null,
    text: "",
  }
}

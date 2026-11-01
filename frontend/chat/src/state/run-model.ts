import { duration, list, plural, time } from "@/lib/format"
import { runLabel, STEP, TIMING_SCOPES, TOOLS } from "@/lib/labels"
import type { AgentEvent } from "@/types"

import { isLiveRun, type RunView, type Step } from "./model"

/* Pure projections of a run: what the activity line and its detail show.
 * Nothing is inferred: no plan, percentage or time unless the server recorded it. */

export const WAITING = new Set(["visual_pending", "approval_pending"])
const FAILED = new Set(["draft", "failed"])
const UNCERTAIN = new Set(["interrupted", "export_uncertain"])

/** Kinds after which the authorized snapshot (artifacts, receipt, sources) can change. */
export const REFRESH = new Set([
  "claimed", "input", "calculate", "compose", "render", "verify", "recalculate", "rename",
  "visual_pending", "verified", "draft", "approval_pending", "export_completed", "export_uncertain", "inference_completed",
  "visual_reviewed", "searching", "reading", "executing", "installing", "verifying",
  "sandbox_waiting", "sandbox_preparing", "sandbox_acquired", "sandbox_prepared", "provider_waiting", "provider_started", "provider_completed",
  "tool.finished", "artifact.available", "run.finished",
])

export function recordedDuration(event: AgentEvent): number | null {
  const value = event.data?.duration_ms
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value
  const interval = event.data?.interval as { started_at?: string; completed_at?: string } | undefined
  const start = time(interval?.started_at), end = time(interval?.completed_at)
  return start !== null && end !== null && end >= start ? end - start : null
}

type Group = { kind: string; count: number; text: string; tools: Set<string>; duration: number | null; skill?: { name: string; reason: string | null } }

/** Consecutive events of one kind form a step; recorded intervals are timings, not steps. */
const HIDDEN = new Set(["interval"])

export function groupSteps(events: AgentEvent[], status: string): Step[] {
  const groups: Group[] = []
  for (const event of events) {
    if (HIDDEN.has(event.kind)) continue
    const last = groups[groups.length - 1]
    const text = typeof event.data?.text === "string" ? event.data.text : ""
    const tool = typeof event.data?.tool === "string" ? event.data.tool : ""
    const elapsed = recordedDuration(event)
    if (event.kind === "skill.activated") {
      const data = event.data as Record<string, string | undefined>
      groups.push({ kind: event.kind, count: 1, text: "", tools: new Set(), duration: null,
        skill: { name: data.display_name || data.name || data.alias || "Skill", reason: data.reason ?? null } })
      continue
    }
    if (last && last.kind === event.kind) {
      last.count++
      if (text) last.text = text
      if (tool) last.tools.add(tool)
      last.duration = last.duration === null || elapsed === null ? null : last.duration + elapsed
      continue
    }
    groups.push({ kind: event.kind, count: 1, text, tools: new Set(tool ? [tool] : []), duration: elapsed })
  }
  return groups.map((group, index) => {
    const lastStep = index === groups.length - 1
    let state: Step["state"] = "done"
    if (FAILED.has(group.kind)) state = "failed"
    else if (group.kind === "cancelled") state = "cancelled"
    else if ((WAITING.has(group.kind) || UNCERTAIN.has(group.kind)) && lastStep) state = "waiting"
    else if (lastStep && isLiveRun(status)) state = "active"
    return {
      kind: group.kind, count: group.count, text: group.text, tools: [...group.tools].map((name) => TOOLS[name] ?? name),
      duration: group.duration, state: group.skill && state === "active" ? "done" : state, skill: group.skill,
    }
  })
}

export type Tone = "live" | "ok" | "warn" | "bad" | "muted"
export type Headline = { text: string; tone: Tone; icon: "check" | "alert" | "clock" | "x" | "eye" | "shield" | "info" | null }

export function headline(view: RunView, steps: Step[]): Headline {
  const status = view.run.status
  const last = steps[steps.length - 1]
  if (view.unavailable) return { text: "Estado no disponible", tone: "bad", icon: "alert" }
  const delivery = view.data?.delivery
  if (delivery?.status === "partial") return { text: "Entrega parcial", tone: "warn", icon: "alert" }
  if (delivery?.status === "failed") return { text: "No se pudo entregar el archivo", tone: "bad", icon: "alert" }
  if (status === "completed" && delivery?.status === "complete") return { text: "Archivo disponible", tone: "ok", icon: "check" }
  if (status === "completed" && delivery?.status === "not_required") return { text: "Respuesta completada", tone: "ok", icon: "check" }
  if (isLiveRun(status) && delivery?.status === "pending" && list(view.data?.artifacts).length)
    return { text: "Archivo generado, pendiente de entrega", tone: "live", icon: null }
  if (status === "completed") return { text: "Listo", tone: "ok", icon: "check" }
  if (status === "failed") return { text: "No completado", tone: "bad", icon: "alert" }
  if (status === "cancelled") return { text: "Cancelado", tone: "muted", icon: "x" }
  if (status === "interrupted") return { text: "Interrumpido", tone: "warn", icon: "alert" }
  if (status === "outcome_unknown") return { text: "Resultado por confirmar", tone: "warn", icon: "clock" }
  if (!isLiveRun(status)) return { text: runLabel(status), tone: "muted", icon: "info" }
  if (view.generating) return {
    text: view.generating.mode === "complete" ? "Generando · se mostrará tras comprobarlo" : "Generando",
    tone: "live", icon: null,
  }
  if (last && WAITING.has(last.kind)) return { text: STEP[last.kind] ?? last.kind, tone: "warn", icon: last.kind === "visual_pending" ? "eye" : "shield" }
  if (!view.loaded) return { text: "Consultando el estado", tone: "live", icon: null }
  return { text: last ? STEP[last.kind] ?? runLabel(last.kind) : "Preparando", tone: "live", icon: null }
}

export function brief(request: Record<string, unknown> | null | undefined): string {
  if (!request || typeof request !== "object") return ""
  const formats = list<string>(request.formats)
  if (!formats.length) return request.delivery_required ? "Entregar un archivo" : ""
  const operation = ({ create: "Crear", transform: "Transformar", edit: "Editar", download: "Descargar" } as Record<string, string>)[String(request.operation)] ?? "Crear"
  const parts = [`${operation} ${formats.map((value) => String(value).toUpperCase()).join(" y ")}`]
  if (Number.isInteger(request.pages)) parts.push(`${request.pages} ${formats.includes("pptx") ? "diapositivas" : "páginas"}`)
  if (request.language) parts.push(request.language === "en" ? "en inglés" : "en español")
  if (request.research_required) parts.push("con fuentes actuales")
  if (request.allow_mock) parts.push("datos ficticios solicitados")
  return parts.join(" · ")
}

/** The work ended at the last recorded step when an interruption is noticed late. */
export function finishedAt(view: RunView): number | null {
  if (view.run.status === "interrupted") {
    const last = [...view.events].reverse().find((event) => event.kind !== "interrupted")
    const stamp = time(last?.created_at)
    if (stamp !== null) return stamp
  }
  return time(view.run.finished_at) ?? time(view.events[view.events.length - 1]?.created_at)
}

/** Elapsed time from server timestamps (server clock while running), never a client guess. */
export function elapsed(view: RunView, now: number): string {
  const start = time(view.run.created_at) ?? time(view.events[0]?.created_at)
  const end = isLiveRun(view.run.status) ? (view.skew === null ? null : now + view.skew) : finishedAt(view)
  return start !== null && end !== null ? duration(end - start) : ""
}

export function metaLine(view: RunView, steps: Step[], now: number): string {
  const parts: string[] = []
  if (steps.length) parts.push(plural(steps.length, "paso", "pasos"))
  const sources = list<{ opened?: boolean }>(view.data?.sources).filter((source) => source.opened).length
  if (sources) parts.push(plural(sources, "fuente", "fuentes"))
  const spent = elapsed(view, now)
  if (spent) parts.push(spent)
  return parts.join(" · ")
}

/** Durations recorded per scope; intervals may overlap, so they are never summed into a total. */
export function timings(events: AgentEvent[]): { scope: string; label: string; value: string }[] {
  const totals = new Map<string, number>()
  for (const event of events) {
    if (event.kind !== "interval") continue
    const value = recordedDuration(event)
    const scope = typeof event.data?.category === "string" ? event.data.category : ""
    if (value !== null && scope) totals.set(scope, (totals.get(scope) ?? 0) + value)
  }
  return [...totals].map(([scope, value]) => ({ scope, label: TIMING_SCOPES[scope] ?? scope, value: duration(value) })).filter((row) => row.value)
}

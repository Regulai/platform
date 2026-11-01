import { describe, expect, it } from "vitest"

import type { BootTurn } from "../types"
import { outcomeFromBoot, outcomeFromResult, type Command } from "./model"

const command = (extra: Partial<Command> = {}): Command => ({
  requestId: "r1", prompt: "Hola", file: null, fileName: null, fileSize: null, conversationId: 1,
  engineId: null, modelId: null, autoRoute: false, ...extra,
})

describe("request outcome (legacy renderOutcome contract)", () => {
  it("labels an unverified answer once and keeps only server download links", () => {
    const outcome = outcomeFromResult({
      status: "completed", request_id: "r1", receipt: { verification: { status: "failed" } },
      assistant_message: { content: "No verificado\n\nTexto", file_name: "a.py", file_url: "/chat/download/7/", file_size: 3 },
    }, command(), false)
    expect(outcome).toMatchObject({ kind: "answer", text: "Texto", unverified: true, file: { url: "/chat/download/7/", size: 3 } })
    for (const url of ["javascript:alert(1)", "https://outside.invalid/chat/download/7/", "/chat/download/7/?x=1"]) {
      const other = outcomeFromResult({ status: "completed", assistant_message: { content: "x", file_name: "x.py", file_url: url } }, command(), false)
      expect(other?.kind === "answer" && other.file).toBeNull()
    }
  })

  it("shows citations only for a verified, non-agent answer", () => {
    const evidence = { items: [{ claim_index: 1, locator: "p. 2", excerpt: "Cita" }, { locator: 3 } as never] }
    const verified = outcomeFromResult({ status: "completed", receipt: { verification: { status: "passed" } }, evidence, assistant_message: { content: "x" } }, command(), false)
    expect(verified?.kind === "answer" && verified.evidence).toEqual([{ claim_index: 1, locator: "p. 2", excerpt: "Cita" }])
    const agent = outcomeFromResult({ status: "completed", receipt: { verification: { status: "passed" } }, evidence, assistant_message: { content: "x" } }, command({ mode: "agent" }), false)
    expect(agent?.kind === "answer" && agent.evidence).toEqual([])
  })

  it("never presents an unknown outcome as success and offers check and resend", () => {
    const outcome = outcomeFromResult({ status: "outcome_unknown", error_type: "outcome_unknown", error: "No se pudo confirmar." }, command(), true)
    expect(outcome).toEqual({ kind: "error", title: "Resultado desconocido", text: "No se pudo confirmar.", code: "outcome_unknown", retracted: true, actions: ["check", "resend"] })
    expect(outcomeFromResult({ status: "failed", error_type: "no_api_key" }, null, false)).toMatchObject({ title: "Configuración incompleta", actions: [] })
    expect(outcomeFromResult({ status: "processing" }, command(), false)).toEqual({ kind: "pending", stale: false })
  })

  it("asks for the same file again before a consent can be confirmed", () => {
    const data = { status: "pending_consent", consent_token: "t", consent_rules: [{ name: "Datos" }], consent_reason: "consent_expired" }
    expect(outcomeFromResult(data, command(), false)).toMatchObject({ kind: "consent", canConfirm: true, rules: ["Datos"], token: "t" })
    expect(outcomeFromResult(data, command({ fileName: "a.pdf" }), false)).toMatchObject({ canConfirm: false, fileName: "a.pdf" })
    const file = new File(["x"], "a.pdf")
    expect(outcomeFromResult(data, command({ fileName: "a.pdf", file }), false)).toMatchObject({ canConfirm: true })
  })

  it("separates a stop by the person from a cancelled request", () => {
    expect(outcomeFromResult({ status: "cancelled", error_type: "cancelled_by_user", error: "Respuesta detenida." }, null, false))
      .toEqual({ kind: "cancelled", own: true, text: "Respuesta detenida." })
    expect(outcomeFromResult({ status: "cancelled" }, null, false)).toEqual({ kind: "cancelled", own: false, text: "Petición cancelada. No se ha enviado." })
  })
})

describe("history projection", () => {
  const base: BootTurn = {
    request_id: "r", status: "completed", run_id: null, legacy: false, live: false, user: null, notice: null,
    answer: null, assistant_file: null, receipt_url: null, evidence_url: null,
  }
  it("maps server notices to the same outcomes, and the consent token only when present", () => {
    expect(outcomeFromBoot({ ...base, notice: { kind: "blocked", rules: ["R"], detail: "x" } })).toEqual({ kind: "blocked", rules: ["R"], reason: "" })
    expect(outcomeFromBoot({ ...base, notice: { kind: "blocked", rules: [], detail: "La política no autoriza…" } }))
      .toEqual({ kind: "blocked", rules: [], reason: "La política no autoriza…" })
    expect(outcomeFromBoot({ ...base, notice: { kind: "consent", rules: [], token: null, file_name: "a.pdf" } })).toMatchObject({ canConfirm: false, fileName: "a.pdf" })
    expect(outcomeFromBoot({ ...base, notice: { kind: "error", rules: [], code: "outcome_unknown", title: "Resultado desconocido" } })).toMatchObject({ actions: ["check"] })
    expect(outcomeFromBoot({ ...base, notice: { kind: "live", rules: [], stale: true } })).toEqual({ kind: "pending", stale: true })
  })

  it("keeps the context notice next to its answer", () => {
    const outcome = outcomeFromBoot({ ...base, notice: { kind: "context", rules: [], title: "Contexto anterior limitado", text: "Algunos mensajes…" },
      answer: { text: "Respuesta", unverified: false, recorded: true, evidence: [] } })
    expect(outcome).toMatchObject({ kind: "answer", text: "Respuesta", contextNote: "Algunos mensajes…" })
  })
})

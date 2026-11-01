import { ChevronRightIcon, DownloadIcon, FileTextIcon, PencilLineIcon, QuoteIcon, RotateCwIcon, TriangleAlertIcon } from "lucide-react"
import { lazy, memo, Suspense, useCallback, useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { fileSize } from "@/lib/format"
import { consentReason } from "@/lib/labels"
import { cn } from "@/lib/utils"

import { useChat, useSession } from "../app/session-context"
import { RunPart } from "../agent/RunPart"
import { ChatMarkdown } from "../markdown/ChatMarkdown"
import { plain } from "../markdown/renderer"
import type { Outcome, RequestState, TurnModel } from "../state/model"
import { getJSON } from "../transport/http"
import type { EvidenceItem, Receipt } from "../types"
import { Notice } from "./Notice"
import { CopyButton, SentAttachment, StatusLine, UserMessage } from "./parts"

// The decision record renders only when someone opens "Detalles".
const RequestReceipt = lazy(() => import("./Receipt").then((module) => ({ default: module.RequestReceipt })))

export const Turn = memo(function Turn({ turn }: { turn: TurnModel }) {
  const phase = useChat((state) => state.attachments[turn.key] ?? null)
  const agentConversation = useChat((state) => state.mode === "agent")
  const note = turn.user?.file && !phase
    ? agentConversation ? "Entrada privada conservada para las revisiones" : "El original no se conserva: vuelve a adjuntarlo para preguntar de nuevo"
    : undefined
  return (
    <article className="flex flex-col gap-4" data-turn="" data-request-id={turn.requestId ?? undefined} data-run={turn.runId ?? undefined}>
      {turn.user && (
        <UserMessage content={turn.user.content} fresh={turn.fresh}>
          {turn.user.file && <SentAttachment name={turn.user.file.name} size={turn.user.file.size} phase={phase} note={note} />}
        </UserMessage>
      )}
      <div className="flex min-w-0 flex-col gap-3">
        {turn.runId ? <RunPart runId={turn.runId} turn={turn} /> : <RequestPart turn={turn} />}
        {turn.legacy && turn.user && (
          <p className="text-xs text-subtle-foreground">Excluido del contexto: mensaje anterior sin registro de decisión validado.</p>
        )}
      </div>
    </article>
  )
})

function RequestPart({ turn }: { turn: TurnModel }) {
  const request = useChat((state) => state.requests[turn.key])
  if (!request) return null
  const outcome = request.outcome
  const live = request.phase !== "done"
  const answer = outcome?.kind === "answer" ? outcome : null
  const source = answer ? answer.text : request.text
  const showLine = live && !request.text
  return (
    <>
      {showLine && <StatusLine text={request.stage || "Procesando"} note={request.note || undefined} />}
      {!live && request.retracted && !answer && outcome?.kind !== "error" && (
        <p className="text-[0.8125rem] text-subtle-foreground">El texto parcial se retiró y no se ha guardado.</p>
      )}
      {answer?.unverified && (
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full bg-warning-soft px-2.5 py-1 text-xs font-medium text-warning" role="status"
          title="La respuesta no superó la verificación configurada y se entrega en modo informativo">
          <TriangleAlertIcon className="size-3.5" aria-hidden />
          No verificado
        </span>
      )}
      {source && <Answer turn={turn} source={source} streaming={!answer && request.streaming} live={turn.fresh} evidence={answer?.evidence ?? []} />}
      {answer?.contextNote && <p className="text-[0.8125rem] text-subtle-foreground">{answer.contextNote}</p>}
      {answer?.file && (
        <a
          href={answer.file.url}
          download={answer.file.name}
          className="flex w-fit max-w-full items-center gap-2.5 rounded-xl bg-surface px-3 py-2 text-sm ring-1 ring-border transition-colors hover:bg-surface-2 focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:min-h-11"
        >
          <FileTextIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="min-w-0 truncate font-medium">{answer.file.name}</span>
          {answer.file.size !== null && <span className="shrink-0 text-xs text-subtle-foreground tabular-nums">{fileSize(answer.file.size)}</span>}
          <DownloadIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        </a>
      )}
      {outcome && outcome.kind !== "answer" && <OutcomeNotice turn={turn} outcome={outcome} request={request} />}
      {turn.requestId && !live && <Actions turn={turn} request={request} source={answer ? answer.text : ""} />}
    </>
  )
}

function Answer({ turn, source, streaming, live, evidence }: { turn: TurnModel; source: string; streaming: boolean; live: boolean; evidence: EvidenceItem[] }) {
  const [open, setOpen] = useState(false)
  const list = useRef<HTMLOListElement>(null)
  const cite = useCallback((index: string) => {
    setOpen(true)
    window.requestAnimationFrame(() => {
      const row = list.current?.querySelector<HTMLElement>(`[data-claim="${CSS.escape(index)}"]`)
      if (!row) return
      row.scrollIntoView({ block: "nearest", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" })
      row.dataset.flash = ""
      window.setTimeout(() => delete row.dataset.flash, 1400)
    })
  }, [])
  return (
    <>
      <ChatMarkdown source={source} streaming={streaming} animate={live} onCite={evidence.length ? cite : undefined} />
      {evidence.length > 0 && (
        <Collapsible open={open} onOpenChange={setOpen}>
          <CollapsibleTrigger className="group/cites flex w-fit items-center gap-1.5 rounded-md py-1 text-[0.8125rem] font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
            <QuoteIcon className="size-3.5" aria-hidden />
            Citas del documento · {evidence.length}
            <ChevronRightIcon className="size-3.5 transition-transform group-aria-expanded/cites:rotate-90" aria-hidden />
          </CollapsibleTrigger>
          <CollapsibleContent className="h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-200 data-ending-style:h-0 data-starting-style:h-0">
            <ol ref={list} className="mt-2 flex flex-col gap-2">
              {evidence.map((item, index) => (
                <li key={index} data-claim={String(item.claim_index ?? "")}
                  className="flex gap-3 rounded-lg px-2 py-1.5 transition-colors data-flash:bg-brand-soft">
                  <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-surface-2 text-[0.6875rem] font-semibold text-muted-foreground tabular-nums">
                    {item.claim_index ?? "·"}
                  </span>
                  <div className="min-w-0 text-[0.8125rem]">
                    <p className="text-subtle-foreground">{item.locator}</p>
                    <blockquote className="mt-0.5 text-foreground/85">{item.excerpt}</blockquote>
                  </div>
                </li>
              ))}
            </ol>
            <p className="mt-2 text-xs text-subtle-foreground">
              Vuelve a adjuntar el original para comprobarlas de nuevo.
              {turn.evidenceUrl && <> <a className="underline underline-offset-2" href={turn.evidenceUrl}>Evidencia (JSON)</a></>}
            </p>
          </CollapsibleContent>
        </Collapsible>
      )}
    </>
  )
}

function OutcomeNotice({ turn, outcome, request }: { turn: TurnModel; outcome: Outcome; request: RequestState }) {
  const session = useSession()
  const busy = useChat((state) => Boolean(state.busy.owner) || state.sending)
  const live = turn.fresh
  switch (outcome.kind) {
    case "blocked":
      return (
        <Notice tone="blocked" title="Bloqueado por la política" live={live}>
          <p>
            {outcome.rules.length ? `Coincide con ${outcome.rules.join(", ")}. ` : outcome.reason ? `${outcome.reason} ` : ""}
            No se ha enviado a ningún proveedor.
          </p>
        </Notice>
      )
    case "consent":
      return (
        <Notice
          tone="consent"
          title="Requiere tu confirmación"
          live={live}
          actions={
            <>
              {outcome.canConfirm && outcome.token && (
                <Button size="sm" disabled={busy} onClick={() => session.confirmConsent(turn.key)}>Confirmar envío</Button>
              )}
              <Button size="sm" variant="outline" disabled={busy} onClick={() => session.cancelConsent(turn.key)}>Cancelar</Button>
            </>
          }
        >
          <p>
            {outcome.rules.length ? `Coincide con ${outcome.rules.join(", ")}. ` : ""}
            {outcome.reason ? consentReason(outcome.reason) : "Revisa el aviso antes de enviar este mismo contenido."}
          </p>
          {outcome.disclosures.length > 0 && (
            <ul className="list-disc pl-4 text-[0.8125rem]">{outcome.disclosures.map((item, index) => <li key={index}>{item}</li>)}</ul>
          )}
          {outcome.notices.map((item, index) => <p key={index} className="text-[0.8125rem] text-muted-foreground">{item}</p>)}
          {!outcome.canConfirm && outcome.fileName && (
            <p className="text-[0.8125rem] text-muted-foreground">Para confirmar, vuelve a enviar la petición con «{outcome.fileName}» adjunto.</p>
          )}
        </Notice>
      )
    case "cancelled":
      return (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p className="text-[0.8125rem] text-subtle-foreground">{outcome.own ? outcome.text || "Respuesta detenida." : outcome.text}</p>
          {turn.fresh && !request.receipt && <RestoreDraft turnKey={turn.key} />}
        </div>
      )
    case "pending":
      return (
        <div className="flex flex-wrap items-center gap-3">
          <StatusLine text={outcome.stale ? "Sin respuesta reciente" : "Sin resultado todavía"} live={false} />
          <Button size="sm" variant="outline" onClick={() => session.check(turn.key)}><RotateCwIcon aria-hidden />Comprobar estado</Button>
        </div>
      )
    case "system":
    case "context":
      return <Notice tone="info" title={outcome.title} live={live}><p>{outcome.text}</p></Notice>
    case "unsent":
      return (
        <Notice
          tone="error"
          title={outcome.title}
          live={live}
          actions={<>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => session.retry(turn.key)}><RotateCwIcon aria-hidden />Reintentar</Button>
            {outcome.restorable && <RestoreDraft turnKey={turn.key} />}
          </>}
        >
          <p>{outcome.text}</p>
        </Notice>
      )
    case "error":
      return (
        <Notice
          tone="error"
          title={outcome.title}
          live={live}
          actions={outcome.actions.length ? (
            <>
              {outcome.actions.includes("check") && (
                <Button size="sm" variant="outline" onClick={() => session.check(turn.key)}><RotateCwIcon aria-hidden />Comprobar estado</Button>
              )}
              {outcome.actions.includes("resend") && (
                <Button size="sm" variant="outline" disabled={busy} onClick={() => session.resend(turn.key)}><RotateCwIcon aria-hidden />Volver a enviar</Button>
              )}
            </>
          ) : undefined}
        >
          <p>{outcome.text}</p>
          {(outcome.retracted || request.retracted) && <p className="text-[0.8125rem] text-muted-foreground">El texto parcial se retiró y no se ha guardado.</p>}
        </Notice>
      )
    default:
      return null
  }
}

/** A send the server never registered goes back to the composer; nothing is resent. */
function RestoreDraft({ turnKey }: { turnKey: string }) {
  const session = useSession()
  return (
    <Button size="sm" variant="ghost" className="text-muted-foreground" onClick={() => {
      const draft = session.takeDraft(turnKey)
      if (draft) session.restoreComposer?.(draft)
    }}>
      <PencilLineIcon aria-hidden />Recuperar mensaje
    </Button>
  )
}

function Actions({ turn, request, source }: { turn: TurnModel; request: RequestState; source: string }) {
  const session = useSession()
  const [open, setOpen] = useState(false)
  const [loaded, setLoaded] = useState<{ receipt: Receipt; status: string } | null>(request.receipt)
  const [failed, setFailed] = useState(false)
  const url = turn.receiptUrl || session.boot.urls.request_receipt.replace("{id}", turn.requestId ?? "")
  useEffect(() => {
    if (!open || loaded) return
    const controller = new AbortController()
    getJSON<{ receipt?: Receipt; status: string }>(url, controller.signal)
      .then(({ data }) => setLoaded({ receipt: data.receipt || {}, status: data.status }))
      .catch((error) => { if ((error as { name?: string }).name !== "AbortError") setFailed(true) })
    return () => controller.abort()
  }, [open, loaded, url])
  useEffect(() => {
    if (request.receipt) setLoaded(request.receipt)
  }, [request.receipt])
  const copy = useCallback(() => plain(source), [source])
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="flex flex-col">
      <div className="-ml-2 flex items-center gap-0.5">
        {source && <CopyButton text={copy} />}
        <CollapsibleTrigger className="group/details flex h-8 items-center gap-1 rounded-md px-2 text-[0.8125rem] text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:h-11">
          Detalles
          <ChevronRightIcon className="size-3.5 transition-transform group-aria-expanded/details:rotate-90" aria-hidden />
        </CollapsibleTrigger>
      </div>
      <CollapsibleContent className="h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-200 data-ending-style:h-0 data-starting-style:h-0">
        <div className={cn("mt-2 rounded-xl bg-surface px-4 py-3")}>
          <div className="mb-3 flex items-center justify-between gap-3 text-xs">
            <span className="font-medium text-muted-foreground">Registro de la decisión</span>
            <a className="text-brand-strong underline-offset-2 hover:underline" href={url} download>Exportar JSON</a>
          </div>
          {loaded ? (
            <Suspense fallback={<p className="text-[0.8125rem] text-muted-foreground">Cargando…</p>}>
              <RequestReceipt receipt={loaded.receipt} status={loaded.status} />
            </Suspense>
          ) : failed ? <p className="text-[0.8125rem] text-muted-foreground">No se ha podido cargar el registro con tus permisos actuales.</p>
            : <p className="text-[0.8125rem] text-muted-foreground">Cargando…</p>}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

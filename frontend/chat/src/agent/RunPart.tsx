import {
  BookOpenIcon, ChevronRightIcon, CircleAlertIcon, CircleCheckIcon, CircleXIcon, ClockIcon, ExternalLinkIcon, EyeIcon,
  InfoIcon, LoaderCircleIcon, PlayIcon, RotateCwIcon, ShieldCheckIcon, SquareIcon, WrenchIcon,
} from "lucide-react"
import { AnimatePresence, m } from "motion/react"
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import {
  Trace, TraceCollapsible, TraceCollapsibleContent, TraceCollapsibleTrigger, TraceDescription, TraceIcon, TraceLine, TraceTitle,
} from "@/components/ui/trace"
import { duration, list, plural, timestamp } from "@/lib/format"
import { useNow } from "@/lib/hooks"
import { runLabel, SKILL_REASON, STEP, TOOLS } from "@/lib/labels"
import { cn } from "@/lib/utils"

import { useChat, useSession } from "../app/session-context"
import { ChatMarkdown } from "../markdown/ChatMarkdown"
import { plain } from "../markdown/renderer"
import { isLiveRun, type RunView, type Step, type TurnModel } from "../state/model"
import { brief, groupSteps, headline, metaLine, timings, WAITING, type Headline } from "../state/run-model"
import { getJSON } from "../transport/http"
import type { Artifact } from "../types"
import { CopyButton } from "../turn/parts"
import { Deliverable } from "./Deliverable"

// Loaded when they are needed: run details on opening, export proposals when one exists.
const Oversight = lazy(() => import("./Oversight"))
const ExportProposal = lazy(() => import("./ExportProposal").then((module) => ({ default: module.ExportProposal })))

/* One agent request: a Trace line with the current step and its detail, a small
 * notice when a skill was really activated, the authorized text, deliverables and
 * the decisions it is waiting for. Only recorded facts are shown. */

export function RunPart({ runId, turn }: { runId: string; turn: TurnModel }) {
  const session = useSession()
  const view = useChat((state) => state.runs[runId])
  const host = useRef<HTMLDivElement>(null)

  // History runs start as they approach the viewport; the latest and live ones started already.
  useEffect(() => {
    const node = host.current
    if (!node) return
    if (typeof IntersectionObserver !== "function") {
      session.ensureRun(runId)
      return
    }
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        observer.disconnect()
        session.ensureRun(runId)
      }
    }, { rootMargin: "600px 0px" })
    observer.observe(node)
    return () => observer.disconnect()
  }, [session, runId])

  if (!view) return null
  return (
    <div ref={host} className="flex min-w-0 flex-col gap-3" data-run-state={view.unavailable ? "unavailable" : view.run.status}>
      <RunBody view={view} turn={turn} />
    </div>
  )
}

const TONE_ICON: Record<NonNullable<Headline["icon"]>, typeof InfoIcon> = {
  check: CircleCheckIcon, alert: CircleAlertIcon, clock: ClockIcon, x: CircleXIcon, eye: EyeIcon, shield: ShieldCheckIcon, info: InfoIcon,
}
const TONE_CLASS: Record<Headline["tone"], string> = {
  live: "text-brand", ok: "text-success", warn: "text-warning", bad: "text-danger", muted: "text-subtle-foreground",
}

function RunBody({ view, turn }: { view: RunView; turn: TurnModel }) {
  const session = useSession()
  const steps = useMemo(() => groupSteps(view.events, view.run.status), [view.events, view.run.status])
  const live = isLiveRun(view.run.status) && !view.unavailable
  const now = useNow(live)
  const head = headline(view, steps)
  const meta = metaLine(view, steps, now)
  const last = steps[steps.length - 1]
  const waiting = Boolean(last && WAITING.has(last.kind))
  const [userOpen, setUserOpen] = useState<boolean | null>(null)
  const open = userOpen ?? (live && !waiting)
  const HeadIcon = head.icon ? TONE_ICON[head.icon] : null
  const data = view.data
  const answers = view.segments.filter((segment) => !segment.tools)
  const bootAnswer = view.run.professional && !answers.length && !view.unavailable
    ? session.boot.turns.find((item) => item.run_id === view.run.id)?.answer?.text ?? ""
    : ""
  const failure = view.run.status === "failed" && typeof data?.result?.error === "string" ? data.result.error.trim() : ""
  const visible: Artifact[] = list<Artifact>(data?.artifacts).length ? list<Artifact>(data?.artifacts) : data?.current_revision ? [data.current_revision] : []
  const controller = session.runController(view.run.id)
  const lastAnswer = answers[answers.length - 1]
  const copySource = lastAnswer?.done ? lastAnswer.text : bootAnswer

  return (
    <>
      <Trace className="gap-1.5">
        <TraceCollapsible open={open} onOpenChange={setUserOpen}>
          <TraceCollapsibleTrigger className="min-h-7 pointer-coarse:min-h-11" aria-label={`Actividad del agente: ${head.text}`}>
            <TraceLine status={head.tone === "live" ? "running" : head.tone === "bad" ? "error" : undefined} className="text-[0.8125rem]">
              <TraceIcon className={TONE_CLASS[head.tone]}>
                {HeadIcon ? <HeadIcon /> : <LoaderCircleIcon className="animate-spin" />}
              </TraceIcon>
              <TraceTitle className="font-medium text-foreground/85" aria-live="polite">{head.text}</TraceTitle>
              {meta && <TraceDescription className="text-subtle-foreground">{meta}</TraceDescription>}
            </TraceLine>
          </TraceCollapsibleTrigger>
          <TraceCollapsibleContent keepMounted={false}>
            <ActivityDetail view={view} steps={steps} />
          </TraceCollapsibleContent>
        </TraceCollapsible>
      </Trace>

      <SkillNotices view={view} />

      {list<string>(view.run.limitations).length > 0 && (
        <ul className="flex flex-col gap-1 text-[0.8125rem] text-muted-foreground">
          {list<string>(view.run.limitations).map((item, index) => (
            <li key={index} className="flex gap-2"><InfoIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />{item}</li>
          ))}
        </ul>
      )}

      {failure && (
        <div role="status" className="flex items-start gap-3 rounded-xl bg-danger-soft px-4 py-3 text-sm">
          <CircleAlertIcon className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
          <p className="text-foreground">{failure}</p>
        </div>
      )}
      {view.note && (
        <div role="status" className={cn("flex items-start gap-3 rounded-xl px-4 py-3 text-sm", view.note.tone === "error" ? "bg-danger-soft" : "bg-surface-2")}>
          <InfoIcon className={cn("mt-0.5 size-4 shrink-0", view.note.tone === "error" ? "text-danger" : "text-muted-foreground")} aria-hidden />
          <p>{view.note.text}</p>
        </div>
      )}

      {answers.map((segment) => (
        <div key={segment.id} className="flex flex-col gap-1.5">
          {segment.incomplete && <p className="text-xs text-warning">Respuesta incompleta · texto autorizado recibido</p>}
          <ChatMarkdown source={segment.text} streaming={!segment.done} animate={turn.fresh || !segment.done} />
        </div>
      ))}
      {bootAnswer && <ChatMarkdown source={bootAnswer} />}

      {visible.length > 0 && (
        <div className="flex flex-col gap-2">
          <AnimatePresence initial={false}>
            {visible.map((artifact) => (
              <Deliverable
                key={artifact.id}
                artifact={artifact}
                data={data}
                runId={view.run.id}
                revisions={list<Artifact>(data?.artifacts)}
                professional={view.run.professional}
                live={live}
                canExport={Boolean(data?.export_enabled) && !live}
              />
            ))}
          </AnimatePresence>
        </div>
      )}

      {data?.export && (
        <Suspense fallback={null}>
          <ExportProposal proposal={data.export} run={view.run} />
        </Suspense>
      )}

      <RunActions view={view} live={live} copySource={copySource} onRefresh={() => controller?.refresh()} />
    </>
  )
}

const STEP_ICON: Record<Step["state"], { icon: typeof InfoIcon; className: string; spin?: boolean }> = {
  done: { icon: CircleCheckIcon, className: "text-subtle-foreground" },
  failed: { icon: CircleXIcon, className: "text-danger" },
  cancelled: { icon: CircleXIcon, className: "text-subtle-foreground" },
  waiting: { icon: ClockIcon, className: "text-warning" },
  active: { icon: LoaderCircleIcon, className: "text-brand", spin: true },
}

function ActivityDetail({ view, steps }: { view: RunView; steps: Step[] }) {
  // A run that is no longer authorized keeps nothing of its projection, the request summary included.
  const request = view.unavailable ? "" : brief(view.run.request)
  const times = timings(view.events)
  const data = view.data
  const notes = view.segments.filter((segment) => segment.tools)
  const sources = list<NonNullable<typeof data>["sources"] extends (infer T)[] | undefined ? T : never>(data?.sources)
  const operations = list<{ name: string; status: string; details_url?: string }>(data?.operations)
  const failureText = view.run.status === "failed" && typeof data?.result?.error === "string" ? data.result.error.trim() : ""
  return (
    <div className="flex flex-col gap-3 text-[0.8125rem]">
      {request && <p className="text-muted-foreground">Petición interpretada: {request}</p>}
      {steps.length > 0 && (
        <ol className="flex flex-col gap-1.5" aria-label="Pasos registrados">
          {steps.map((step, index) => {
            const { icon: Icon, className, spin } = step.skill ? { icon: BookOpenIcon, className: "text-brand", spin: false } : STEP_ICON[step.state]
            const lastStep = index === steps.length - 1
            const sentence = lastStep && step.text && step.text.trim() !== failureText ? step.text : ""
            const extra = [step.tools.join(", "), sentence].filter(Boolean).join(" — ")
            const label = step.skill
              ? `Skill activada · ${step.skill.name}${step.skill.reason && SKILL_REASON[step.skill.reason] ? ` (${SKILL_REASON[step.skill.reason]})` : ""}`
              : STEP[step.kind] ?? runLabel(step.kind)
            return (
              <li key={index} className="flex gap-2" data-state={step.state} data-kind={step.kind} title={step.text || undefined}>
                <Icon className={cn("mt-0.5 size-3.5 shrink-0", className, spin && "animate-spin")} aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span className={cn("min-w-0 text-foreground/85", step.state === "failed" && "text-danger")}>{label}</span>
                    {step.count > 1 && <span className="text-subtle-foreground tabular-nums">×{step.count}</span>}
                    {duration(step.duration) && <span className="ml-auto shrink-0 text-subtle-foreground tabular-nums">{duration(step.duration)}</span>}
                  </div>
                  {extra && <p className="mt-0.5 text-muted-foreground">{extra}</p>}
                </div>
              </li>
            )
          })}
        </ol>
      )}
      {notes.map((segment) => (
        <div key={segment.id} className="flex flex-col gap-1 rounded-lg bg-surface-2/60 px-3 py-2">
          <p className="text-xs font-medium text-muted-foreground">Nota pública del modelo</p>
          <ChatMarkdown source={segment.text} streaming={!segment.done} className="rg-md-compact" />
        </div>
      ))}
      {sources.length > 0 && <Sources sources={sources} />}
      {operations.length > 0 && <Operations operations={operations} />}
      {times.length > 0 && (
        <p className="text-subtle-foreground tabular-nums" title="Duraciones registradas por ámbito. Los intervalos pueden solaparse; no se suman como tiempo total.">
          {times.map((row) => `${row.label}: ${row.value}`).join(" · ")}
        </p>
      )}
      {!steps.length && !request && <p className="text-muted-foreground">{view.loaded ? "Sin pasos registrados todavía." : "Consultando el estado…"}</p>}
    </div>
  )
}

function Sources({ sources }: { sources: { title?: string; url?: string; final_url?: string; opened?: boolean; reading?: string; excerpt?: string; snippet?: string; retrieved_at?: string; publication_date?: string }[] }) {
  const opened = sources.filter((source) => source.opened).length
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-xs font-medium text-muted-foreground">Fuentes · {plural(opened, "consultada", "consultadas")}</p>
      <ol className="flex flex-col gap-2">
        {sources.map((source, index) => {
          const url = source.final_url || source.url
          const safe = typeof url === "string" && /^https?:\/\/[^\s]+$/i.test(url)
          return (
            <li key={index} className="min-w-0">
              {safe ? (
                <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex max-w-full items-center gap-1 font-medium text-brand-strong underline-offset-2 hover:underline">
                  <span className="truncate">{source.title || url}</span>
                  <ExternalLinkIcon className="size-3 shrink-0" aria-hidden />
                </a>
              ) : <span className="font-medium">{source.title || url}</span>}
              <p className="text-xs text-subtle-foreground">
                {source.opened ? (source.reading === "complete" ? "Lectura completa" : "Lectura parcial") : "Resultado del buscador · no abierto"}
                {source.opened && ` · Consulta: ${timestamp(source.retrieved_at)} · Publicación: ${source.publication_date || "fecha desconocida"}`}
              </p>
              {(source.excerpt || source.snippet) && <p className="mt-0.5 line-clamp-3 text-muted-foreground">{source.excerpt || source.snippet}</p>}
            </li>
          )
        })}
      </ol>
    </div>
  )
}

const OPERATION = /^\/chat\/agent\/runs\/[0-9a-f-]+\/operations\/\d+\/$/

function Operations({ operations }: { operations: { name: string; status: string; details_url?: string }[] }) {
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-xs font-medium text-muted-foreground">Herramientas · {operations.length}</p>
      <ul className="flex flex-col gap-1">
        {operations.map((operation, index) => <OperationRow key={index} operation={operation} />)}
      </ul>
    </div>
  )
}

function OperationRow({ operation }: { operation: { name: string; status: string; details_url?: string } }) {
  const [detail, setDetail] = useState<{ state: "idle" | "loading" | "ready" | "error"; text?: string }>({ state: "idle" })
  const load = async () => {
    if (!operation.details_url || !OPERATION.test(operation.details_url)) return
    setDetail({ state: "loading" })
    try {
      const { data } = await getJSON<unknown>(operation.details_url)
      setDetail({ state: "ready", text: JSON.stringify(data, null, 2) })
    } catch {
      setDetail({ state: "error" })
    }
  }
  return (
    <li className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <WrenchIcon className="size-3.5 shrink-0 text-subtle-foreground" aria-hidden />
        <span className="text-foreground/85">{TOOLS[operation.name] ?? runLabel(operation.name)} · {runLabel(operation.status)}</span>
        {operation.details_url && OPERATION.test(operation.details_url) && detail.state !== "ready" && (
          <button type="button" className="ml-auto rounded text-xs text-brand-strong underline-offset-2 hover:underline disabled:opacity-60" disabled={detail.state === "loading"} onClick={load}>
            Ver resultado y duración
          </button>
        )}
      </div>
      {detail.state === "ready" && <pre className="max-h-48 overflow-auto rounded-md bg-surface-2 p-2 text-xs">{detail.text}</pre>}
      {detail.state === "error" && <p className="text-xs text-muted-foreground">El detalle ya no está disponible con tus permisos actuales.</p>}
    </li>
  )
}

/** A skill the server confirmed for this turn: a small, quiet notice that never takes focus. */
function SkillNotices({ view }: { view: RunView }) {
  if (!view.skills.length) return null
  return (
    <div className="flex flex-wrap gap-1.5" aria-label="Skills activadas">
      <AnimatePresence initial={false}>
        {view.skills.map((skill) => (
          <m.span
            key={skill.key}
            initial={skill.fresh ? { opacity: 0, y: 4, scale: 0.98 } : false}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            className="inline-flex max-w-full items-center gap-1.5 rounded-full bg-brand-soft px-2.5 py-1 text-xs font-medium text-brand-strong"
            data-skill={skill.key}
          >
            <BookOpenIcon className="size-3.5 shrink-0" aria-hidden />
            <span className="truncate">{skill.name}</span>
            {skill.reason && SKILL_REASON[skill.reason] && <span className="font-normal text-brand-strong">· {SKILL_REASON[skill.reason]}</span>}
          </m.span>
        ))}
      </AnimatePresence>
    </div>
  )
}

function RunActions({ view, live, copySource, onRefresh }: { view: RunView; live: boolean; copySource: string; onRefresh: () => void }) {
  const session = useSession()
  const controller = session.runController(view.run.id)
  const [open, setOpen] = useState(false)
  const [resuming, setResuming] = useState(false)
  useEffect(() => {
    if (!controller) return
    controller.detailsOpen = open
    if (open) controller.pollReceipt()
  }, [controller, open])
  const copy = useMemo(() => () => plain(copySource), [copySource])
  const hasDetails = Boolean(view.data) && !view.unavailable
  const resumable = Boolean(view.run.resumable) && !view.unavailable
  if (!live && !resumable && !view.unavailable && !hasDetails && !copySource) return null
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="flex flex-col">
      <div className="-ml-2 flex flex-wrap items-center gap-0.5">
        {copySource && !live && <CopyButton text={copy} />}
        {live && (
          <Button variant="ghost" size="sm" className="h-8 text-[0.8125rem] text-muted-foreground pointer-coarse:h-11" onClick={() => controller?.cancel()}>
            <SquareIcon className="size-3 fill-current" aria-hidden />Detener
          </Button>
        )}
        {resumable && (
          <Button variant="ghost" size="sm" disabled={resuming} className="h-8 text-[0.8125rem] text-muted-foreground pointer-coarse:h-11"
            onClick={async () => { setResuming(true); await controller?.resume(); setResuming(false) }}>
            <PlayIcon aria-hidden />Reanudar
          </Button>
        )}
        {view.unavailable && (
          <Button variant="ghost" size="sm" className="h-8 text-[0.8125rem] text-muted-foreground pointer-coarse:h-11" onClick={onRefresh}>
            <RotateCwIcon aria-hidden />Actualizar estado
          </Button>
        )}
        {hasDetails && (
          <CollapsibleTrigger className="group/details flex h-8 items-center gap-1 rounded-md px-2 text-[0.8125rem] text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:h-11">
            Detalles
            <ChevronRightIcon className="size-3.5 transition-transform group-aria-expanded/details:rotate-90" aria-hidden />
          </CollapsibleTrigger>
        )}
      </div>
      {hasDetails && (
        <CollapsibleContent className="h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-200 data-ending-style:h-0 data-starting-style:h-0">
          <Suspense fallback={<p className="mt-2 text-[0.8125rem] text-muted-foreground">Cargando…</p>}>
            <Oversight view={view} />
          </Suspense>
        </CollapsibleContent>
      )}
    </Collapsible>
  )
}

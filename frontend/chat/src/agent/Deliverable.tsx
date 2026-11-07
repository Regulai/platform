import {
  CheckIcon, ChevronRightIcon, CloudUploadIcon, DownloadIcon, EyeIcon, FileArchiveIcon, FileCodeIcon, FileIcon,
  FileImageIcon, FileSpreadsheetIcon, FileTextIcon, PencilIcon, PresentationIcon, TriangleAlertIcon,
} from "lucide-react"
import { m } from "motion/react"
import { useCallback, useMemo, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { fileSize, list, present } from "@/lib/format"
import { cn } from "@/lib/utils"

import { useChat, useSession } from "../app/session-context"
import { postJSON } from "../transport/http"
import type { Artifact, RunSnapshot } from "../types"
import { useArtifactViewer } from "../viewer/ArtifactViewer"
import { canPreview as canOpenViewer, PAGE } from "../viewer/contracts"

const DOWNLOAD = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/download\/(?:\?format=(?:docx|pdf))?$/
const ACTION = "h-8 gap-1.5 px-2.5 text-[0.8125rem] text-muted-foreground hover:text-foreground pointer-coarse:h-11"
const REVIEW = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/review\/$/

const KIND: Record<string, string> = {
  xlsx: "Hoja de cálculo", csv: "CSV", docx: "Documento Word", pdf: "PDF", pptx: "Presentación", html: "Página HTML",
  htm: "Página HTML", svg: "Imagen SVG", md: "Markdown", txt: "Texto", json: "JSON", py: "Python", js: "JavaScript",
  css: "CSS", zip: "Archivo ZIP", png: "Imagen PNG", jpg: "Imagen JPEG", jpeg: "Imagen JPEG",
}
const ICON: Record<string, typeof FileIcon> = {
  xlsx: FileSpreadsheetIcon, csv: FileSpreadsheetIcon, docx: FileTextIcon, pdf: FileTextIcon, pptx: PresentationIcon,
  html: FileCodeIcon, htm: FileCodeIcon, css: FileCodeIcon, js: FileCodeIcon, py: FileCodeIcon, json: FileCodeIcon,
  md: FileTextIcon, txt: FileTextIcon, svg: FileImageIcon, png: FileImageIcon, jpg: FileImageIcon, jpeg: FileImageIcon,
  zip: FileArchiveIcon,
}
const CHECKS: [string, string][] = [
  ["integrity", "Integridad del archivo"], ["instructions", "Formato e instrucciones"], ["layout", "Maquetación y paginación"],
  ["sources", "Fuentes y respaldo factual"], ["security", "Seguridad y políticas"],
]
const CHECK_STATUS: Record<string, string> = { passed: "Superada", failed: "Fallida", reviewed: "Revisada por el modelo", partial: "Parcial", not_performed: "No realizada" }
const COVERAGE: Record<string, string> = { complete: "Cobertura completa del texto inspeccionable", partial: "Cobertura parcial", legacy: "Cobertura del lector histórico" }

export function deliverableModel(artifact: Artifact, data: RunSnapshot | null) {
  const preview = (artifact.preview ?? {}) as NonNullable<Artifact["preview"]>
  const format = String(artifact.format || "").toLowerCase()
  const delivery = data?.delivery
  const receiptAllows = !delivery || (["complete", "partial"].includes(String(delivery.status)) && list<{ artifact_id?: string; id?: string; sha256?: string }>(delivery.artifacts)
    .some((reference) => (reference.artifact_id || reference.id) === artifact.id && reference.sha256 === artifact.sha256))
  const verified = artifact.status === "verified" && receiptAllows
  // The server serves a file only once delivered (file_continuity.delivered): listed in a complete
  // or partial receipt, or, without a receipt, after the run completed. Until then the card shows
  // the file without actions the server would refuse.
  const delivered = verified && (delivery ? true : data?.run?.status === "completed")
  const pageUrls = list<string>(preview.pages)
  const pages = pageUrls.filter((url) => PAGE.test(url))
  const document = ["docx", "pdf", "pptx"].includes(format)
  const count = format === "xlsx"
    ? (present(preview.sheet_count) ? `${preview.sheet_count} ${preview.sheet_count === 1 ? "hoja" : "hojas"}` : "")
    : document ? `${preview.page_count ?? pageUrls.length} ${format === "pptx" ? "diapositivas" : "páginas"}` : ""
  const viewer = canOpenViewer(artifact)
  const pagesPreview = document ? pages.length > 0 && pages.length === pageUrls.length : format === "xlsx" && (Array.isArray(preview.sheets) || list(preview.rows).length > 0)
  const seen = new Set<string>()
  const downloads: { format: string; url: string }[] = []
  for (const download of [{ format: artifact.format, url: artifact.download_url }, ...list<{ format?: string; url?: string }>(artifact.downloads)]) {
    const value = String(download.format || artifact.format || "").toLowerCase()
    if (typeof download.url !== "string" || !DOWNLOAD.test(download.url) || seen.has(value)) continue
    seen.add(value)
    downloads.push({ format: value, url: download.url })
  }
  const size = typeof artifact.size_bytes === "number" && Number.isSafeInteger(artifact.size_bytes) && artifact.size_bytes >= 0 ? artifact.size_bytes : null
  const title = artifact.filename || preview.title || "Entregable"
  const meta = [KIND[format] ?? (format.toUpperCase() || "Archivo"), count, size !== null ? fileSize(size) : "", `Revisión ${artifact.revision}`].filter(Boolean).join(" · ")
  return { preview, format, verified, delivered, pages, pageUrls, document, viewer, pagesPreview, downloads, size, title, meta, mock: artifact.data_mode === "mock" || preview.data_mode === "mock" }
}

/** A deliverable: name, type and the actions the server allows; review and technical detail on demand. */
export function Deliverable({ artifact, data, runId, revisions, professional, live, canExport }: {
  artifact: Artifact
  data: RunSnapshot | null
  runId: string
  revisions: Artifact[]
  professional: boolean
  live: boolean
  canExport: boolean
}) {
  const session = useSession()
  const viewer = useArtifactViewer()
  const model = useMemo(() => deliverableModel(artifact, data), [artifact, data])
  const Icon = ICON[model.format] ?? FileIcon
  const reviewable = !model.verified && model.document && typeof artifact.review_url === "string" && REVIEW.test(artifact.review_url)
  const [loaded, setLoaded] = useState<Set<number>>(() => new Set())
  const [reviewing, setReviewing] = useState(false)
  // The dialog keeps the request it opened with, so the guard lives here: one confirmation in flight.
  const confirming = useRef(false)
  const allLoaded = reviewable && model.pages.length > 0 && model.pages.length === model.pageUrls.length && loaded.size === model.pageUrls.length

  const pageLoaded = useCallback((index: number) => setLoaded((current) => (current.has(index) ? current : new Set(current).add(index))), [])
  const confirmReview = useCallback(async () => {
    if (!artifact.review_url || !REVIEW.test(artifact.review_url) || confirming.current) return
    confirming.current = true
    setReviewing(true)
    try {
      await postJSON(artifact.review_url, { sha256: artifact.sha256, page_sha256: artifact.page_sha256, checks: artifact.review_checks })
      session.announce("Revisión visual registrada")
      viewer.closeForRun(runId)
      await session.runController(runId)?.reload()
    } catch {
      session.runController(runId)?.note("No se pudo registrar la revisión visual. Recarga el estado para comprobar los permisos y la ejecución.", "error")
    } finally {
      confirming.current = false
      setReviewing(false)
    }
  }, [artifact, runId, session, viewer])

  const open = (trigger: HTMLElement | null, focusIndex = 0) => {
    if (model.viewer) {
      viewer.open(artifact, trigger, revisions, runId)
      return
    }
    viewer.openPages({
      runId, artifact, title: model.title, meta: model.meta, focusIndex, trigger, verified: model.delivered, downloads: model.downloads,
      review: reviewable ? { ready: Boolean(allLoaded) && !reviewing, confirm: confirmReview, pageLoaded } : undefined,
    })
  }

  const canPreview = model.delivered && (model.viewer || model.pagesPreview)
  const editable = professional && model.delivered && !live
  const thumb = model.delivered && model.document && model.pagesPreview ? model.pages[0] : null
  const coverage = artifact.coverage || artifact.verification_checks?.coverage
  const checks = artifact.verification_checks ?? {}
  const failed = CHECKS.filter(([key]) => (checks[key] as { status?: string } | undefined)?.status === "failed").length

  return (
    <m.article
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className="@container flex flex-col gap-3 rounded-xl bg-surface p-3 ring-1 ring-border"
      data-status={artifact.status || ""}
    >
      {/* Name first; the actions sit beside it when the card is wide and in a row of their own
          below it when it is narrow. Each action says what it does without hover. */}
      <div className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1 @lg:grid-cols-[auto_minmax(0,1fr)_auto]">
        {thumb ? (
          <button type="button" className="relative h-14 w-11 shrink-0 overflow-hidden rounded-md bg-white ring-1 ring-border transition-shadow hover:ring-input focus-visible:outline-2 focus-visible:outline-ring"
            aria-label={`Vista previa de ${model.title}`} onClick={(event) => open(event.currentTarget)}>
            <img src={thumb} alt="" loading="lazy" className="size-full object-cover object-top" />
          </button>
        ) : (
          <span className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-background text-muted-foreground ring-1 ring-border" data-format={model.format}>
            <Icon className="size-5" aria-hidden />
          </span>
        )}
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold" title={model.title}>{model.title}</h3>
          <p className="truncate text-xs text-subtle-foreground tabular-nums">{model.meta}</p>
        </div>
        {(canPreview || (model.delivered && model.downloads.length > 0) || editable) && (
          <div className="col-span-2 -ml-2.5 flex flex-wrap items-center gap-0.5 @lg:col-span-1 @lg:ml-0">
            {canPreview && (
              <Button variant="ghost" size="sm" className={ACTION} aria-label={`Vista previa de ${model.title}`} onClick={(event) => open(event.currentTarget)}>
                <EyeIcon aria-hidden />Vista previa
              </Button>
            )}
            {model.delivered && model.downloads.map((download) => (
              <Button key={download.format} variant="ghost" size="sm" className={ACTION}
                render={<a href={download.url} download={artifact.filename || ""} />}
                aria-label={`Descargar ${download.format.toUpperCase()}`}>
                <DownloadIcon aria-hidden />{download.format.toUpperCase()}
              </Button>
            ))}
            {editable && (
              <Button variant="ghost" size="sm" className={ACTION} aria-label={`Editar ${model.title}`}
                onClick={() => { session.editRevision(artifact, model.title); session.focusComposer?.() }}>
                <PencilIcon aria-hidden />Editar
              </Button>
            )}
          </div>
        )}
      </div>

      {model.mock && (
        <p className="flex items-center gap-1.5 text-xs font-medium text-warning">
          <TriangleAlertIcon className="size-3.5" aria-hidden />
          Datos ficticios solicitados expresamente
        </p>
      )}

      {reviewable && (
        <div className="flex flex-col gap-2.5 rounded-lg bg-warning-soft p-3" role="group" aria-label="Revisión visual pendiente">
          <p className="text-[0.8125rem] font-semibold text-foreground">
            Revisa {model.pageUrls.length === 1 ? (model.format === "pptx" ? "la diapositiva" : "la página") : `las ${model.pageUrls.length} ${model.format === "pptx" ? "diapositivas" : "páginas"}`} antes de publicar
          </p>
          <div className="flex gap-2 overflow-x-auto pb-1">
            {model.pages.map((url, index) => (
              <button key={url} type="button" onClick={(event) => open(event.currentTarget, index)}
                className="relative h-20 w-15 shrink-0 overflow-hidden rounded-md bg-white ring-1 ring-border focus-visible:outline-2 focus-visible:outline-ring"
                aria-label={`${model.format === "pptx" ? "Diapositiva" : "Página"} ${index + 1} de ${model.pageUrls.length}: abrir a tamaño completo`}>
                <img src={url} alt="" className="size-full object-cover object-top" onLoad={() => pageLoaded(index)} />
                <span className="absolute right-1 bottom-1 rounded bg-foreground/70 px-1 text-[0.625rem] text-background tabular-nums">{index + 1}</span>
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={!allLoaded || reviewing} onClick={confirmReview}>
              <CheckIcon aria-hidden />
              Confirmar revisión visual
            </Button>
            <Button size="sm" variant="outline" onClick={(event) => open(event.currentTarget)}>Ver a tamaño completo</Button>
          </div>
          <p className="text-xs text-muted-foreground">Tu confirmación registra únicamente la revisión visual.</p>
        </div>
      )}
      {!model.delivered && !reviewable && <p className="text-xs text-subtle-foreground">Archivo pendiente de entrega verificada.</p>}

      <Collapsible>
        <CollapsibleTrigger className="group/more -my-1.5 flex min-h-7 w-fit items-center gap-1 rounded-md pr-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring pointer-coarse:my-0 pointer-coarse:min-h-11">
          <ChevronRightIcon className="size-3.5 transition-transform group-aria-expanded/more:rotate-90" aria-hidden />
          Revisión y comprobaciones
          {failed > 0 && <span className="ml-1 rounded-full bg-danger-soft px-1.5 text-[0.6875rem] font-semibold text-danger tabular-nums">{failed} fallida{failed > 1 ? "s" : ""}</span>}
        </CollapsibleTrigger>
        <CollapsibleContent className="h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-200 data-ending-style:h-0 data-starting-style:h-0">
          <div className="mt-2.5 flex flex-col gap-3 text-xs">
            <p className="text-muted-foreground">{COVERAGE[String(coverage?.status)] ?? "Cobertura no disponible"}</p>
            <ul className="flex flex-col gap-1.5">
              {CHECKS.map(([key, name]) => {
                const check = (checks[key] ?? {}) as { status?: string; detail?: string }
                const status = ["passed", "failed", "reviewed", "partial"].includes(String(check.status)) ? String(check.status) : "not_performed"
                return (
                  <li key={key} className="grid grid-cols-[1fr_auto] gap-x-3" data-status={status}>
                    <span className="font-medium text-foreground">{name}</span>
                    <span className={cn("tabular-nums", status === "failed" ? "text-danger" : status === "passed" ? "text-success" : "text-muted-foreground")}>{CHECK_STATUS[status]}</span>
                    <span className="col-span-2 text-subtle-foreground">{check.detail || "No hay una comprobación registrada para esta categoría."}</span>
                  </li>
                )
              })}
            </ul>
            {artifact.sha256 && <p className="break-all text-subtle-foreground">SHA-256 · {artifact.sha256}</p>}
            {model.delivered && canExport && <ExportForm artifact={artifact} />}
          </div>
        </CollapsibleContent>
      </Collapsible>
    </m.article>
  )
}

function ExportForm({ artifact }: { artifact: Artifact }) {
  const session = useSession()
  const busy = useChat((state) => Boolean(state.busy.owner) || state.sending)
  const [name, setName] = useState(`informe-r${artifact.revision}.${artifact.format || "xlsx"}`)
  return (
    <form
      className="flex flex-wrap items-end gap-2 rounded-lg bg-background p-2.5 ring-1 ring-border"
      onSubmit={(event) => {
        event.preventDefault()
        session.requestExport(artifact, name)
      }}
    >
      <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs text-muted-foreground">
        Guardar una copia en Google Drive como
        <input value={name} maxLength={120} onChange={(event) => setName(event.target.value)}
          className="h-8 rounded-md bg-background px-2 text-sm text-foreground ring-1 ring-input focus-visible:outline-2 focus-visible:outline-ring" />
      </label>
      <Button type="submit" size="sm" variant="outline" disabled={busy}><CloudUploadIcon aria-hidden />Preparar exportación</Button>
    </form>
  )
}

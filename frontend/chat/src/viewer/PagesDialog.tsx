import { CheckIcon, DownloadIcon, ExternalLinkIcon } from "lucide-react"
import { useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { list, present } from "@/lib/format"

import { PAGE, type PagesRequest } from "./contracts"

/* Rendered pages (PDF/Office) or a workbook sample from the verified record,
 * loaded the first time it opens. Images come from the authenticated page
 * endpoint; nothing external loads. */

export function PagesDialog({ request, onClose }: { request: PagesRequest | null; onClose: () => void }) {
  const focusRef = useRef<HTMLElement | null>(null)
  // Pages seen here count for the review too: confirming requires every page loaded.
  const [loaded, setLoaded] = useState<Set<number>>(() => new Set())
  const [confirming, setConfirming] = useState(false)
  useEffect(() => {
    setLoaded(new Set())
    if (request?.focusIndex) window.setTimeout(() => focusRef.current?.scrollIntoView({ block: "start" }), 60)
  }, [request])
  const preview = (request?.artifact.preview ?? {}) as Record<string, unknown>
  const isSheet = request?.artifact.format === "xlsx"
  const urls = list<string>(preview.pages)
  const valid = urls.filter((url) => PAGE.test(url))
  const pageName = request?.artifact.format === "pptx" ? "Diapositiva" : "Página"
  return (
    <Dialog open={Boolean(request)} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent
        finalFocus={() => request?.trigger ?? true}
        className="flex max-h-[min(92dvh,60rem)] w-full max-w-[min(56rem,94vw)] flex-col gap-0 p-0"
      >
        {request && (
          <>
            <div className="shrink-0 px-5 pt-5 pb-3 pr-12">
              <DialogTitle className="truncate text-[0.9375rem] font-semibold">{request.title}</DialogTitle>
              <DialogDescription className="mt-0.5 text-xs text-subtle-foreground tabular-nums">{request.meta}</DialogDescription>
            </div>
            <div className="min-h-0 flex-1 overflow-auto px-5 pb-4">
              {isSheet ? <Sheets preview={preview} /> : (
                <div className="flex flex-col gap-5">
                  {valid.map((url, index) => (
                    <figure key={url} ref={index === request.focusIndex ? (node) => { focusRef.current = node } : undefined} className="flex flex-col gap-2">
                      <figcaption className="flex items-center justify-between text-xs text-muted-foreground">
                        <span className="tabular-nums">{pageName} {index + 1} de {urls.length}</span>
                        <a href={url} target="_blank" rel="noopener" className="inline-flex items-center gap-1 underline-offset-2 hover:underline">
                          Abrir en una pestaña <ExternalLinkIcon className="size-3" aria-hidden />
                        </a>
                      </figcaption>
                      <img
                        src={url}
                        alt={`${pageName} ${index + 1}: ${String(preview.title || "documento")}.`}
                        className="w-full rounded-lg bg-white ring-1 ring-border"
                        onLoad={() => {
                          request.review?.pageLoaded(index)
                          setLoaded((current) => new Set(current).add(index))
                        }}
                      />
                    </figure>
                  ))}
                </div>
              )}
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2 px-5 py-3">
              {request.review && !request.verified && (
                <>
                  <p className="mr-auto text-xs text-muted-foreground">Tu confirmación registra únicamente la revisión visual; la exportación se autoriza aparte.</p>
                  <Button
                    disabled={confirming || !(request.review.ready || (valid.length === urls.length && loaded.size === urls.length && urls.length > 0))}
                    onClick={async () => {
                      setConfirming(true)
                      try {
                        await request.review?.confirm()
                      } finally {
                        setConfirming(false)
                      }
                    }}
                  >
                    <CheckIcon aria-hidden />
                    Confirmar revisión visual
                  </Button>
                </>
              )}
              {request.verified && request.downloads.map((download, index) => (
                <Button key={download.format} variant={index ? "outline" : "default"} render={<a href={download.url} download="" />}>
                  <DownloadIcon aria-hidden />
                  Descargar {download.format.toUpperCase()}
                </Button>
              ))}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function Sheets({ preview }: { preview: Record<string, unknown> }) {
  if (Array.isArray(preview.sheets)) {
    return (
      <div className="flex flex-col gap-5">
        {(preview.sheets as { name?: string; rows?: number; columns?: number; preview?: unknown[][] }[]).map((sheet, index) => (
          <section key={index} className="flex flex-col gap-2">
            <h3 className="text-[0.8125rem] font-semibold">{sheet.name} · {sheet.rows} filas · {sheet.columns} columnas</h3>
            <div className="overflow-auto rounded-lg ring-1 ring-border">
              <table className="w-full text-[0.8125rem]">
                <tbody>
                  {list<unknown[]>(sheet.preview).map((row, rowIndex) => (
                    <tr key={rowIndex} className="border-b border-border last:border-0">
                      {list<unknown>(row).map((value, cellIndex) => <td key={cellIndex} className="px-2.5 py-1.5 whitespace-nowrap">{String(value ?? "")}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
      </div>
    )
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-auto rounded-lg ring-1 ring-border">
        <table className="w-full text-[0.8125rem]">
          <caption className="sr-only">Muestra del archivo generado</caption>
          <thead>
            <tr className="border-b border-border bg-surface">
              {list<unknown>(preview.headers).map((value, index) => <th key={index} scope="col" className="px-2.5 py-1.5 text-left font-semibold whitespace-nowrap">{String(value ?? "")}</th>)}
            </tr>
          </thead>
          <tbody>
            {list<unknown[]>(preview.rows).map((row, rowIndex) => (
              <tr key={rowIndex} className="border-b border-border last:border-0">
                {list<unknown>(row).map((value, cellIndex) => <td key={cellIndex} className="px-2.5 py-1.5 whitespace-nowrap">{String(value ?? "")}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {present(preview.total_euros) && <p className="text-[0.8125rem] text-muted-foreground">Total del archivo: {String(preview.total_euros)} €</p>}
      {present(preview.rows_total) && <p className="text-[0.8125rem] text-muted-foreground">{String(preview.rows_total)} filas en el archivo.</p>}
    </div>
  )
}

import { CircleAlertIcon, DownloadIcon, XIcon } from "lucide-react"
import { useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

import { getJSON, HttpError, isAbort } from "../transport/http"
import type { Artifact } from "../types"
import { canPreview, DOWNLOAD, type Opened } from "./contracts"

/* The static projection of a professional artifact, loaded the first time a
 * viewer opens. Its HTML comes sanitized by the server and only enters an
 * iframe with an empty sandbox (no scripts, no same-origin, no forms, no
 * navigation); code is text. Every opening re-checks access and that id, hash
 * and revision still match the card that opened it. */

type Preview = {
  artifact_id: string; sha256: string; revision: number; format: string; size_bytes: number; filename?: string
  notice?: string; code?: string; html?: string; download_url?: string; message?: string
}

type PanelProps = {
  opened: Opened
  onClose: () => void
  onSelect: (artifact: Artifact) => void
  width: number
  onWidth: (value: number) => void
}

/** Wide screens: a side panel next to the conversation, which stays usable. */
export function ViewerAside({ opened, onClose, onSelect, width, onWidth }: PanelProps) {
  return (
    <aside
      role="dialog"
      aria-labelledby="artifact-viewer-title"
      className="relative flex shrink-0 flex-col bg-surface"
      style={{ width }}
      onKeyDown={(event) => { if (event.key === "Escape") { event.preventDefault(); onClose() } }}
    >
      <ViewerBody opened={opened} onClose={onClose} onSelect={onSelect} width={width} onWidth={onWidth} wide />
    </aside>
  )
}

/** Narrow screens: a modal dialog; stays mounted after the first opening so it can close softly. */
export function ViewerDialog({ opened, onClose, onSelect, width, onWidth }: Omit<PanelProps, "opened"> & { opened: Opened | null }) {
  return (
    <Dialog open={Boolean(opened)} onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent showCloseButton={false} className="flex h-dvh max-h-dvh w-full max-w-full flex-col gap-0 rounded-none p-0 sm:h-[min(92dvh,56rem)] sm:max-w-[min(48rem,94vw)] sm:rounded-2xl">
        {opened && <ViewerBody opened={opened} onClose={onClose} onSelect={onSelect} width={width} onWidth={onWidth} wide={false} />}
      </DialogContent>
    </Dialog>
  )
}

function ViewerBody({ opened, onClose, onSelect, width, onWidth, wide }: PanelProps & { wide: boolean }) {
  const { artifact, revisions } = opened
  const [state, setState] = useState<{ status: "loading" | "ready" | "error"; data?: Preview; message?: string }>({ status: "loading" })
  const close = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    close.current?.focus()
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    setState({ status: "loading" })
    if (!canPreview(artifact)) {
      setState({ status: "error", message: "La vista previa no está disponible para este archivo." })
      return
    }
    getJSON<Preview>(artifact.preview_url!, controller.signal)
      .then(({ data }) => {
        if (data.artifact_id !== artifact.id || data.sha256 !== artifact.sha256 || data.revision !== artifact.revision) {
          setState({ status: "error", message: "La revisión ha cambiado. Actualiza el estado del chat." })
          return
        }
        setState({ status: "ready", data })
      })
      .catch((error) => {
        if (isAbort(error)) return
        const message = error instanceof HttpError ? (error.data as { message?: string } | null)?.message : undefined
        setState({ status: "error", message: message || "No se pudo abrir esta revisión. Consulta el estado del chat." })
      })
    return () => controller.abort()
  }, [artifact])

  const data = state.data
  const available = revisions.filter((value) => value.logical_id === artifact.logical_id && canPreview(value))
  const meta = data
    ? `${data.format.toUpperCase()} · ${data.size_bytes.toLocaleString("es-ES")} bytes · Revisión ${data.revision}`
    : `${String(artifact.format ?? "").toUpperCase()} · Revisión ${artifact.revision}`
  return (
    <>
      <header className="flex shrink-0 items-start gap-3 px-4 pt-4 pb-3">
        <div className="min-w-0 flex-1">
          {wide
            ? <h2 id="artifact-viewer-title" className="truncate text-[0.9375rem] font-semibold">{artifact.filename || "Archivo"}</h2>
            : <DialogTitle className="truncate text-[0.9375rem] font-semibold">{artifact.filename || "Archivo"}</DialogTitle>}
          <p className="mt-0.5 text-xs text-subtle-foreground tabular-nums">{meta}</p>
        </div>
        <Button ref={close} variant="ghost" size="icon" className="size-9 shrink-0 text-muted-foreground" aria-label="Volver al chat" onClick={onClose}>
          <XIcon />
        </Button>
      </header>
      {/* One persistent live region: its content changes, so the result is announced. */}
      <div role="status" className="shrink-0 px-4 text-[0.8125rem]">
        {state.status === "error" ? (
          <p className="flex items-start gap-2.5 rounded-lg bg-surface-2 px-3 py-2.5 text-foreground">
            <CircleAlertIcon className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
            {state.message}
          </p>
        ) : (
          <p className="text-muted-foreground">{state.status === "loading" ? "Comprobando acceso a esta revisión…" : data?.notice || ""}</p>
        )}
      </div>
      {state.status === "ready" && data && (
        <Tabs defaultValue={typeof data.html === "string" ? "preview" : "code"} className="flex min-h-0 flex-1 flex-col gap-0 px-4 pt-3">
          <TabsList className="w-fit pointer-coarse:h-12!">
            {typeof data.html === "string" && <TabsTrigger value="preview">Vista previa</TabsTrigger>}
            <TabsTrigger value="code">Código</TabsTrigger>
          </TabsList>
          {typeof data.html === "string" && (
            <TabsContent value="preview" className="mt-3 min-h-0 flex-1 overflow-hidden rounded-xl bg-background ring-1 ring-border" tabIndex={0}>
              <iframe
                title={`Vista estática de ${data.filename || artifact.filename || "archivo"}`}
                sandbox=""
                referrerPolicy="no-referrer"
                srcDoc={data.html}
                className="size-full bg-white"
              />
            </TabsContent>
          )}
          <TabsContent value="code" className="mt-3 min-h-0 flex-1 overflow-auto rounded-xl bg-background ring-1 ring-border" tabIndex={0}>
            <pre className="p-3 text-xs leading-relaxed whitespace-pre-wrap break-words"><code>{data.code || ""}</code></pre>
          </TabsContent>
        </Tabs>
      )}
      <footer className="mt-auto flex shrink-0 flex-wrap items-center gap-3 px-4 py-3">
        {data?.download_url && DOWNLOAD.test(data.download_url) && (
          <Button render={<a href={data.download_url} download={data.filename || ""} />}>
            <DownloadIcon aria-hidden />
            Descargar original
          </Button>
        )}
        {available.length > 1 && (
          <label className="flex items-center gap-2 text-[0.8125rem] text-muted-foreground">
            Revisión
            <select
              className="h-8 rounded-md bg-background px-2 text-foreground ring-1 ring-input"
              value={artifact.id}
              onChange={(event) => {
                const next = available.find((value) => value.id === event.target.value)
                if (next) onSelect(next)
              }}
            >
              {available.map((value) => <option key={value.id} value={value.id}>v{value.revision}</option>)}
            </select>
          </label>
        )}
        {wide && (
          <label className="ml-auto flex items-center gap-2 text-[0.8125rem] text-muted-foreground">
            Ancho
            <input type="range" min={480} max={640} step={8} value={width} onChange={(event) => onWidth(Number(event.target.value))} className="accent-brand" aria-label="Ancho del visor" />
          </label>
        )}
      </footer>
    </>
  )
}

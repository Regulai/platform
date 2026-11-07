import { createContext, lazy, Suspense, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react"

import { useMediaQuery } from "@/lib/hooks"

import type { Artifact } from "../types"
import type { Opened, PagesRequest } from "./contracts"

export { canPreview } from "./contracts"

/* Who may open a viewer and where focus returns. The viewers themselves (side
 * panel, dialog, rendered pages) load the first time one opens. */

const ViewerAside = lazy(() => import("./ViewerPanel").then((module) => ({ default: module.ViewerAside })))
const ViewerDialog = lazy(() => import("./ViewerPanel").then((module) => ({ default: module.ViewerDialog })))
const PagesDialog = lazy(() => import("./PagesDialog").then((module) => ({ default: module.PagesDialog })))

type ViewerApi = {
  open(artifact: Artifact, trigger: HTMLElement | null, revisions: Artifact[], runId: string): void
  openPages(request: PagesRequest): void
  close(): void
  closeForRun(runId: string): void
}

const ViewerContext = createContext<ViewerApi | null>(null)

export function useArtifactViewer(): ViewerApi {
  const value = useContext(ViewerContext)
  if (!value) throw new Error("ArtifactViewerProvider missing")
  return value
}

export function ArtifactViewerProvider({ children }: { children: ReactNode }) {
  const wide = useMediaQuery("(min-width: 1100px)")
  const [opened, setOpened] = useState<Opened | null>(null)
  const [pages, setPages] = useState<PagesRequest | null>(null)
  // Dialogs stay mounted after their first opening so closing keeps its transition.
  const [used, setUsed] = useState({ viewer: false, pages: false })
  const [width, setWidth] = useState(560)
  const restore = useRef<HTMLElement | null>(null)

  const close = useCallback(() => {
    setOpened(null)
    // Focus returns to what opened the viewer.
    const target = restore.current
    restore.current = null
    window.requestAnimationFrame(() => target?.isConnected && target.focus())
  }, [])
  const api = useMemo<ViewerApi>(() => ({
    open(artifact, trigger, revisions, runId) {
      restore.current = trigger ?? (document.activeElement as HTMLElement | null)
      setUsed((current) => (current.viewer ? current : { ...current, viewer: true }))
      setOpened({ artifact, revisions, trigger, runId })
    },
    openPages(request) {
      setUsed((current) => (current.pages ? current : { ...current, pages: true }))
      setPages(request)
    },
    close,
    closeForRun(runId) {
      setOpened((current) => (current?.runId === runId ? null : current))
      setPages((current) => (current?.runId === runId ? null : current))
    },
  }), [close])

  const select = (artifact: Artifact) => setOpened((current) => (current ? { ...current, artifact } : current))
  return (
    <ViewerContext.Provider value={api}>
      <div className="flex h-dvh w-full overflow-hidden">
        <div className="flex min-w-0 flex-1">{children}</div>
        {opened && wide && (
          <Suspense fallback={null}>
            <ViewerAside opened={opened} onClose={close} onSelect={select} width={width} onWidth={setWidth} />
          </Suspense>
        )}
      </div>
      {!wide && used.viewer && (
        <Suspense fallback={null}>
          <ViewerDialog opened={opened} onClose={close} onSelect={select} width={width} onWidth={setWidth} />
        </Suspense>
      )}
      {used.pages && (
        <Suspense fallback={null}>
          <PagesDialog request={pages} onClose={() => setPages(null)} />
        </Suspense>
      )}
    </ViewerContext.Provider>
  )
}

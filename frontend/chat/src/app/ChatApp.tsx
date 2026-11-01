import { MenuIcon, PanelLeftOpenIcon, SparklesIcon, SquarePenIcon, TriangleAlertIcon } from "lucide-react"
import { AnimatePresence, LazyMotion, MotionConfig, m } from "motion/react"
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useMediaQuery, useStoredFlag } from "@/lib/hooks"
import { cn } from "@/lib/utils"

import { Composer } from "../composer/Composer"
import type { ChatSession } from "../state/session"
import { ArtifactViewerProvider } from "../viewer/ArtifactViewer"
import { Conversation } from "./Conversation"
import { EmptyHero } from "./EmptyHero"
import { SessionContext, useChat, useSession } from "./session-context"
import { Sidebar } from "./Sidebar"

const QUIET = [0.2, 0.7, 0.2, 1] as const
// Movement is added once its chunk arrives; until then every state renders in place.
const motionFeatures = () => import("./motion-features").then((module) => module.default)
const Drawer = lazy(() => import("./Drawer"))

export function ChatApp({ session }: { session: ChatSession }) {
  // StrictMode mounts twice in development: start/suspend are both idempotent.
  useEffect(() => {
    session.resume()
    return () => session.suspend()
  }, [session])
  return (
    <SessionContext.Provider value={session}>
      <LazyMotion features={motionFeatures} strict>
        <MotionConfig reducedMotion="user" transition={{ duration: 0.18, ease: QUIET }}>
          <TooltipProvider delay={500} closeDelay={0}>
            <ArtifactViewerProvider>
              <Shell />
            </ArtifactViewerProvider>
            <LiveRegion />
            <Toast />
          </TooltipProvider>
        </MotionConfig>
      </LazyMotion>
    </SessionContext.Provider>
  )
}

const encode = (visible: boolean) => (visible ? "shown" : "hidden")
const decode = (raw: string) => raw !== "hidden"

function Shell() {
  const session = useSession()
  const desktop = useMediaQuery("(min-width: 1024px)")
  const [sidebar, setSidebar] = useStoredFlag("regulai.chat.threads", true, encode, decode)
  const [drawer, setDrawer] = useState(false)
  const [drawerUsed, setDrawerUsed] = useState(false)
  const empty = useChat((state) => state.turns.length === 0)
  const menuButton = useRef<HTMLButtonElement>(null)
  const showSidebar = desktop && sidebar

  useEffect(() => {
    if (desktop) setDrawer(false)
  }, [desktop])

  const closeDrawer = useCallback(() => setDrawer(false), [])

  return (
    <div className="flex h-full w-full min-w-0 overflow-hidden bg-background text-foreground">
      <a
        href="#regulai-prompt"
        onClick={(event) => { event.preventDefault(); session.focusComposer?.() }}
        className="sr-only z-50 rounded-md bg-foreground px-3 py-2 text-sm text-background focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Ir a escribir un mensaje
      </a>
      {showSidebar && (
        <aside className="flex w-68 shrink-0 flex-col bg-surface" aria-label="Conversaciones y cuenta">
          <Sidebar onHide={() => setSidebar(false)} />
        </aside>
      )}
      {!desktop && drawerUsed && (
        <Suspense fallback={null}>
          <Drawer open={drawer} onOpenChange={setDrawer} finalFocus={menuButton}>
            <Sidebar onNavigate={closeDrawer} />
          </Drawer>
        </Suspense>
      )}
      <main className="relative flex min-w-0 flex-1 flex-col" data-artifact-room="">
        {session.boot.demo && (
          <p role="status" className="flex shrink-0 items-center gap-2 bg-warning-soft px-4 py-2 text-[0.8125rem] text-warning">
            <TriangleAlertIcon className="size-4 shrink-0" aria-hidden />
            <span><strong className="font-semibold">Demo offline — fallo simulado.</strong> Datos, modelos y jueces sintéticos; sin llamadas a proveedores reales ni métricas de calidad real.</span>
          </p>
        )}
        <Header
          desktop={desktop}
          sidebarVisible={showSidebar}
          onShowSidebar={() => setSidebar(true)}
          onOpenDrawer={() => { setDrawerUsed(true); setDrawer(true) }}
          menuButton={menuButton}
        />
        <div className="relative flex min-h-0 flex-1 flex-col">
          {empty ? <EmptyHero /> : <Conversation />}
          <ComposerDock empty={empty} />
        </div>
      </main>
    </div>
  )
}

function Header({ desktop, sidebarVisible, onShowSidebar, onOpenDrawer, menuButton }: {
  desktop: boolean
  sidebarVisible: boolean
  onShowSidebar: () => void
  onOpenDrawer: () => void
  menuButton: React.RefObject<HTMLButtonElement | null>
}) {
  const boot = useSession().boot
  const title = useChat((state) => state.title)
  const agent = useChat((state) => state.conversationId !== null && state.mode === "agent")
  return (
    <header className="flex h-14 shrink-0 items-center gap-1 px-3 lg:px-4">
      {!desktop && (
        <Button ref={menuButton} variant="ghost" size="icon" className="size-10 text-muted-foreground" aria-label="Conversaciones y menú" onClick={onOpenDrawer}>
          <MenuIcon />
        </Button>
      )}
      {desktop && !sidebarVisible && (
        <>
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon" className="text-muted-foreground" aria-label="Mostrar conversaciones" onClick={onShowSidebar} />}>
              <PanelLeftOpenIcon />
            </TooltipTrigger>
            <TooltipContent>Mostrar conversaciones</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon" className="text-muted-foreground" aria-label="Nueva conversación" render={<a href={boot.urls.chat} />} />}>
              <SquarePenIcon />
            </TooltipTrigger>
            <TooltipContent>Nueva conversación</TooltipContent>
          </Tooltip>
        </>
      )}
      <div className="flex min-w-0 flex-1 items-center gap-2 px-1.5">
        <h1 className="truncate text-[0.9375rem] font-semibold tracking-tight">{title}</h1>
        {agent && (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-surface-2 px-2 py-0.5 text-xs font-medium text-muted-foreground">
            <SparklesIcon className="size-3" aria-hidden />
            Agente
          </span>
        )}
      </div>
      {!desktop && (
        <Button variant="ghost" size="icon" className="size-10 text-muted-foreground" aria-label="Nueva conversación" render={<a href={boot.urls.chat} />}>
          <SquarePenIcon />
        </Button>
      )}
    </header>
  )
}

/** The composer stays mounted: leaving the empty state only moves it (layout animation). */
function ComposerDock({ empty }: { empty: boolean }) {
  return (
    <div className={cn("relative z-10 w-full shrink-0 px-3 sm:px-4", empty ? "pb-[min(30vh,16rem)]" : "pb-3 sm:pb-4")}>
      <m.div layout="position" className="mx-auto w-full max-w-(--read)">
        <Composer />
      </m.div>
    </div>
  )
}

/** One polite region for state changes; streamed text is never read token by token. */
function LiveRegion() {
  const announcement = useChat((state) => state.announcement)
  const [text, setText] = useState("")
  useEffect(() => {
    if (!announcement) return
    setText("")
    const timer = window.setTimeout(() => setText(announcement.text), 40)
    return () => window.clearTimeout(timer)
  }, [announcement])
  return <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{text}</div>
}

/** Under the header: a passing message never covers the composer or the newest answer. */
function Toast() {
  const toast = useChat((state) => state.toast)
  return (
    <div className="pointer-events-none fixed inset-x-0 top-16 z-50 flex justify-center px-4">
      <AnimatePresence>
        {toast && (
          <m.div
            key={toast.id}
            role={toast.error ? "alert" : "status"}
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, transition: { duration: 0.12 } }}
            className={cn("pointer-events-auto max-w-md rounded-lg px-3.5 py-2 text-sm shadow-lg", toast.error ? "bg-danger text-white" : "bg-foreground text-background")}
          >
            {toast.text}
          </m.div>
        )}
      </AnimatePresence>
    </div>
  )
}

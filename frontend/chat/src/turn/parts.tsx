import {
  CheckIcon, CircleAlertIcon, CircleCheckIcon, CircleXIcon, CopyIcon, FileArchiveIcon, FileCodeIcon, FileIcon,
  FileImageIcon, FileSpreadsheetIcon, FileTextIcon, LoaderCircleIcon, PresentationIcon,
} from "lucide-react"
import { m } from "motion/react"
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { copyText } from "@/lib/clipboard"
import { extension, fileSize } from "@/lib/format"
import { cn } from "@/lib/utils"

import { useSession } from "../app/session-context"
import type { AttachmentPhase } from "../state/model"

const FILE_ICONS: Record<string, typeof FileIcon> = {
  ".xlsx": FileSpreadsheetIcon, ".csv": FileSpreadsheetIcon, ".pptx": PresentationIcon, ".pdf": FileTextIcon,
  ".docx": FileTextIcon, ".txt": FileTextIcon, ".md": FileTextIcon, ".json": FileCodeIcon, ".py": FileCodeIcon,
  ".js": FileCodeIcon, ".html": FileCodeIcon, ".htm": FileCodeIcon, ".css": FileCodeIcon, ".svg": FileImageIcon,
  ".sh": FileCodeIcon, ".png": FileImageIcon, ".jpg": FileImageIcon, ".jpeg": FileImageIcon, ".zip": FileArchiveIcon,
}

export const fileIcon = (name: string) => FILE_ICONS[extension(name)] ?? FileIcon

const PHASE: Record<AttachmentPhase, { label: string; tone: string }> = {
  sending: { label: "Enviando", tone: "text-muted-foreground" },
  received: { label: "Recibido", tone: "text-muted-foreground" },
  rejected: { label: "Rechazado", tone: "text-danger" },
  cancelled: { label: "No enviado", tone: "text-muted-foreground" },
}

/** An attachment as sent: indeterminate activity while uploading, never an invented percentage. */
export function SentAttachment({ name, size, phase, note }: { name: string; size: number | null; phase: AttachmentPhase | null; note?: string }) {
  const Icon = fileIcon(name)
  const state = phase ? PHASE[phase] : null
  const chip = (
    <div
      className={cn(
        "flex max-w-full min-w-0 items-center gap-2.5 rounded-xl bg-surface px-2.5 py-2 text-left ring-1 ring-border",
        phase === "rejected" && "ring-danger/30",
      )}
      data-phase={phase ?? "history"}
    >
      <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted-foreground", phase === "rejected" && "bg-danger-soft text-danger")}>
        {phase === "sending" ? <LoaderCircleIcon className="size-4 animate-spin" aria-hidden /> : <Icon className="size-4" aria-hidden />}
      </span>
      <span className="min-w-0 leading-tight">
        <span className="block truncate text-[0.8125rem] font-medium text-foreground">{name}</span>
        <span className="flex items-center gap-1 text-xs text-subtle-foreground tabular-nums">
          {size !== null && size !== undefined && <span>{fileSize(size)}</span>}
          {state && (
            <span className={cn("inline-flex items-center gap-1", state.tone)} role="status">
              {size !== null && size !== undefined && <span aria-hidden>·</span>}
              {phase === "received" && <CircleCheckIcon className="size-3" aria-hidden />}
              {phase === "rejected" && <CircleAlertIcon className="size-3" aria-hidden />}
              {phase === "cancelled" && <CircleXIcon className="size-3" aria-hidden />}
              {state.label}
            </span>
          )}
        </span>
      </span>
    </div>
  )
  if (!note) return chip
  return (
    <Tooltip>
      <TooltipTrigger render={<div tabIndex={0} className="max-w-full rounded-xl outline-none focus-visible:ring-3 focus-visible:ring-ring/40" />}>{chip}</TooltipTrigger>
      <TooltipContent className="max-w-64">{note}</TooltipContent>
    </Tooltip>
  )
}

/** The person's message; only a message sent from this page enters with movement. */
export function UserMessage({ content, fresh, children }: { content: string; fresh: boolean; children?: ReactNode }) {
  return (
    <m.div
      className="flex flex-col items-end gap-2"
      initial={fresh ? { opacity: 0, y: 10 } : false}
      animate={{ opacity: 1, y: 0 }}
    >
      {content && (
        <div className="max-w-[88%] rounded-2xl bg-surface-2 px-4 py-2.5 text-[0.9375rem] leading-relaxed break-words whitespace-pre-wrap text-foreground sm:max-w-[34rem]">
          {content}
        </div>
      )}
      {children}
    </m.div>
  )
}

/** Copy confirms only when the browser confirms; a failure says so. */
export function CopyButton({ text, label = "Copiar respuesta" }: { text: () => string; label?: string }) {
  const session = useSession()
  const [done, setDone] = useState(false)
  const timer = useRef(0)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const copy = useCallback(async () => {
    const ok = await copyText(text())
    if (!ok) {
      session.toast("No se pudo copiar. Selecciona el texto y cópialo manualmente.", true)
      return
    }
    setDone(true)
    session.announce("Copiado")
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setDone(false), 1600)
  }, [session, text])
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          // It opens a row pulled left by -ml-2: on touch the wider target keeps its glyph on the text edge.
          <Button variant="ghost" size="icon" className="size-8 text-muted-foreground pointer-coarse:size-11 pointer-coarse:justify-start pointer-coarse:pl-2" aria-label={done ? "Copiado" : label} onClick={copy} />
        }
      >
        <span className="relative size-4">
          <CopyIcon className={cn("absolute inset-0 size-4 transition-[opacity,scale] duration-150", done && "scale-75 opacity-0")} aria-hidden />
          <CheckIcon className={cn("absolute inset-0 size-4 text-success transition-[opacity,scale] duration-150", !done && "scale-75 opacity-0")} aria-hidden />
        </span>
      </TooltipTrigger>
      <TooltipContent>{done ? "Copiado" : "Copiar"}</TooltipContent>
    </Tooltip>
  )
}

/** A current step: a quiet line with an icon that says what the server reported. */
export function StatusLine({ text, note, live = true }: { text: string; note?: string; live?: boolean }) {
  return (
    <div className="flex min-h-6 items-center gap-2 text-[0.8125rem] text-muted-foreground" data-slot="status-line">
      {live ? <LoaderCircleIcon className="size-3.5 shrink-0 animate-spin text-brand" aria-hidden /> : <span className="size-1.5 shrink-0 rounded-full bg-subtle-foreground" aria-hidden />}
      <span className="min-w-0">
        <span className="text-foreground/80">{text}</span>
        {note && <span className="text-subtle-foreground"> · {note}</span>}
      </span>
    </div>
  )
}

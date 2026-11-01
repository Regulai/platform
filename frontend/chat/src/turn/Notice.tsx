import { CircleAlertIcon, InfoIcon, ShieldAlertIcon, ShieldCheckIcon, type LucideIcon } from "lucide-react"
import { m } from "motion/react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

type Tone = "blocked" | "consent" | "error" | "info"

const TONES: Record<Tone, { icon: LucideIcon; box: string; mark: string }> = {
  blocked: { icon: ShieldAlertIcon, box: "bg-surface-2", mark: "text-foreground" },
  consent: { icon: ShieldCheckIcon, box: "bg-warning-soft", mark: "text-warning" },
  error: { icon: CircleAlertIcon, box: "bg-danger-soft", mark: "text-danger" },
  info: { icon: InfoIcon, box: "bg-surface-2", mark: "text-muted-foreground" },
}

/** Cause, effect and the next action, in one short block (P1 §7.5). */
export function Notice({ tone, title, children, actions, live = true }: {
  tone: Tone
  title: string
  children?: ReactNode
  actions?: ReactNode
  live?: boolean
}) {
  const { icon: Icon, box, mark } = TONES[tone]
  return (
    <m.div
      initial={live ? { opacity: 0, y: 4 } : false}
      animate={{ opacity: 1, y: 0 }}
      className={cn("flex items-start gap-3 rounded-xl px-4 py-3 text-sm", box)}
      data-tone={tone}
    >
      <Icon className={cn("mt-0.5 size-4 shrink-0", mark)} aria-hidden />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <p className="font-semibold text-foreground">{title}</p>
        {children && <div className="flex flex-col gap-1 text-foreground/85">{children}</div>}
        {actions && <div className="mt-1 flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </m.div>
  )
}

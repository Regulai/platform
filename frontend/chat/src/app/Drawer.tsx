import type { ReactNode, RefObject } from "react"

import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet"

/** Conversations and account on small screens; loaded the first time it opens. */
export default function Drawer({ open, onOpenChange, finalFocus, children }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  finalFocus: RefObject<HTMLButtonElement | null>
  children: ReactNode
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="w-[min(20rem,88vw)] gap-0 bg-surface p-0" showCloseButton={false} finalFocus={finalFocus}>
        <SheetTitle className="sr-only">Conversaciones y cuenta</SheetTitle>
        {children}
      </SheetContent>
    </Sheet>
  )
}

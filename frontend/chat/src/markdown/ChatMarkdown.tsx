import { memo, useCallback, useLayoutEffect, useRef } from "react"

import { cn } from "@/lib/utils"
import { copyText } from "@/lib/clipboard"

import { clear, render } from "./renderer"

/* The single content policy for model and document text in the chat.
 * The renderer owns this element's children (a clear DOM boundary: React never
 * renders inside it); it only creates text nodes and allowlisted elements.
 * Streaming re-renders reuse finished blocks, so history and selections in
 * closed blocks are untouched while the last block grows. */

type Props = {
  source: string
  streaming?: boolean
  /** Fade in blocks that appear while this message is live; history never animates. */
  animate?: boolean
  onCite?: (index: string) => void
  onCopied?: (ok: boolean) => void
  className?: string
}

export const ChatMarkdown = memo(function ChatMarkdown({ source, streaming = false, animate = false, onCite, onCopied, className }: Props) {
  const ref = useRef<HTMLDivElement>(null)

  useLayoutEffect(() => {
    const root = ref.current
    if (!root) return
    if (!source) clear(root)
    else render(root, source, { streaming, animate })
  }, [source, streaming, animate])

  const click = useCallback(async (event: React.MouseEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement
    const copy = target.closest<HTMLButtonElement>(".rg-code-copy")
    if (copy) {
      const ok = await copyText(copy.dataset.copy ?? "")
      onCopied?.(ok)
      if (!ok) return
      copy.textContent = "Copiado"
      copy.dataset.done = ""
      window.setTimeout(() => {
        copy.textContent = "Copiar"
        delete copy.dataset.done
      }, 1600)
      return
    }
    const cite = target.closest<HTMLElement>(".rg-cite")
    if (cite?.dataset.cite) onCite?.(cite.dataset.cite)
  }, [onCite, onCopied])

  return (
    <div
      ref={ref}
      className={cn("rg-md", className)}
      data-streaming={streaming ? "" : undefined}
      aria-busy={streaming || undefined}
      onClick={click}
    />
  )
})

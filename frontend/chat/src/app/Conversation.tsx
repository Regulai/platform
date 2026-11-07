import { ArrowDownIcon } from "lucide-react"

import {
  MessageScroller, MessageScrollerButton, MessageScrollerContent, MessageScrollerItem, MessageScrollerProvider,
  MessageScrollerViewport,
} from "@/components/ui/message-scroller"

import { Turn } from "../turn/Turn"
import { useChat } from "./session-context"

/* The thread. A new question settles near the top and the answer grows into the
 * room below; following the live edge only while the reader stays there. Reading
 * above keeps the position and offers a quiet way back. */
export function Conversation() {
  const turns = useChat((state) => state.turns)
  const streaming = useChat((state) => Object.values(state.requests).some((request) => request.streaming))
  return (
    <MessageScrollerProvider autoScroll defaultScrollPosition="last-anchor" scrollPreviousItemPeek={56}>
      <MessageScroller className="min-h-0 flex-1">
        {/* Text leaving under the header fades instead of being cut mid-line. */}
        <MessageScrollerViewport aria-label="Mensajes" className="[mask-image:linear-gradient(to_bottom,transparent,#000_1rem)]">
          <MessageScrollerContent
            aria-live="off"
            aria-busy={streaming || undefined}
            className="mx-auto w-full max-w-(--read) gap-9 px-4 pt-4 pb-10"
          >
            {turns.map((turn) => (
              <MessageScrollerItem key={turn.key} messageId={turn.key} scrollAnchor>
                <Turn turn={turn} />
              </MessageScrollerItem>
            ))}
          </MessageScrollerContent>
        </MessageScrollerViewport>
        <MessageScrollerButton
          variant="outline"
          size="sm"
          className="bottom-3 h-8 gap-1.5 rounded-full bg-background px-3 text-[0.8125rem] font-medium text-muted-foreground shadow-sm data-[active=false]:duration-150"
        >
          <ArrowDownIcon className="size-3.5" aria-hidden />
          Ir al final
        </MessageScrollerButton>
      </MessageScroller>
    </MessageScrollerProvider>
  )
}

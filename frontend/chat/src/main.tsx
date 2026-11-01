import "./styles/app.css"

import { startTransition, StrictMode } from "react"
import { createRoot, type Root } from "react-dom/client"

import { ChatApp } from "./app/ChatApp"
import { readBootstrap } from "./bootstrap"
import { ChatSession } from "./state/session"

/* The only bootstrap of the chat page: one root, one owner of its DOM.
 * Mounting twice is a no-op; pagehide closes streams, pageshow from the
 * back/forward cache reopens what is still live. */

declare global {
  interface Window {
    __regulaiChat?: { root: Root; session: ChatSession }
  }
}

function mount() {
  if (window.__regulaiChat) return
  const host = document.getElementById("regulai-chat-root")
  if (!host) return
  const session = new ChatSession(readBootstrap(document))
  const root = createRoot(host)
  window.__regulaiChat = { root, session }
  // A transition lets the first render yield to the browser instead of one long task.
  startTransition(() => {
    root.render(
      <StrictMode>
        <ChatApp session={session} />
      </StrictMode>,
    )
  })
  window.addEventListener("pagehide", () => session.suspend())
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) session.resume()
  })
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount, { once: true })
else mount()

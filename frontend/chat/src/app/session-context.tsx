import { createContext, useContext } from "react"

import type { ChatState } from "../state/model"
import type { ChatSession } from "../state/session"
import { useSelector } from "../state/store"

export const SessionContext = createContext<ChatSession | null>(null)

export function useSession(): ChatSession {
  const session = useContext(SessionContext)
  if (!session) throw new Error("ChatSession missing")
  return session
}

/** Read a slice of the chat state; the selector must return stable references. */
export function useChat<S>(selector: (state: ChatState) => S, equal?: (a: S, b: S) => boolean): S {
  const session = useSession()
  return useSelector(session.store, selector, equal)
}

import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { getJSON, postJSON } from "../transport/http"
import type { ChatSession } from "../state/session"
import type { Mode } from "../types"

/* Manual skill selection for the next agent message, with the same contracts as
 * static/js/skills.js: lazy catalogue (no GET when the chat opens empty), up to
 * three, Auto persisted per chat (sessionStorage for a new one), pending choice
 * and draft carried across the library. Automatic activation is the server's:
 * nothing here suggests or claims that a skill was used. */

export type SkillRow = {
  id: string
  alias?: string
  name?: string
  display_name?: string
  summary?: string
  description?: string
  enabled?: boolean
  availability?: { available?: boolean; requirement_labels?: string[]; requirements?: string[] }
}

const MAX = 3
const AGENT_NOTE = "Las skills se usan en modo Agente. Se ha abierto un chat nuevo; el borrador del chat anterior se conserva."

export const displayName = (row: SkillRow) => row.display_name || row.alias || row.name || "Skill"
export const summary = (row: SkillRow) => row.summary || row.description || ""
const requirements = (row: SkillRow) => (row.availability?.requirement_labels || row.availability?.requirements || []).join(", ")

function storageGet(key: string): string | null {
  try { return window.sessionStorage.getItem(key) } catch { return null }
}
function storageSet(key: string, value: string) {
  try { window.sessionStorage.setItem(key, value) } catch { /* Optional. */ }
}
function storageRemove(key: string) {
  try { window.sessionStorage.removeItem(key) } catch { /* Optional. */ }
}

export type SkillsApi = ReturnType<typeof useSkills>

export function useSkills(session: ChatSession, mode: Mode, setMode: (mode: Mode) => void, setDraft: (text: string) => void) {
  const boot = session.boot
  const enabled = boot.composer.skills.catalog
  const conversation = boot.conversation ? String(boot.conversation.id) : "new"
  const selectionKey = `regulai.skills.selection.${conversation}`
  const autoKey = `regulai.skills.auto.${conversation}`
  const [runtime, setRuntime] = useState(boot.composer.skills.runtime)
  const [rows, setRows] = useState<SkillRow[]>([])
  const [loaded, setLoaded] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [selected, setSelected] = useState<string[]>(() => {
    try {
      const value = JSON.parse(storageGet(selectionKey) || "[]")
      return Array.isArray(value) ? [...new Set(value.filter((id): id is string => typeof id === "string"))].slice(0, MAX) : []
    } catch {
      return []
    }
  })
  const [auto, setAutoState] = useState<boolean>(() => {
    if (conversation === "new") {
      const saved = storageGet(autoKey)
      if (saved === "true" || saved === "false") return saved === "true"
    }
    return boot.conversation ? boot.conversation.auto_skills : true
  })
  const inflight = useRef<Promise<void> | null>(null)
  const latest = useRef({ selected, auto, runtime })
  latest.current = { selected, auto, runtime }

  useEffect(() => { storageSet(selectionKey, JSON.stringify(selected)) }, [selectionKey, selected])

  const ready = useCallback((row: SkillRow) => runtime && Boolean(row.enabled) && Boolean(row.availability?.available), [runtime])

  const prepareAgent = useCallback(() => {
    if (conversation === "new") setMode("agent")
  }, [conversation, setMode])

  const load = useCallback(() => {
    if (!enabled) return Promise.resolve()
    if (inflight.current) return inflight.current
    setLoading(true)
    setError("")
    inflight.current = (async () => {
      try {
        const { data } = await getJSON<{ installations?: SkillRow[]; runtime_enabled?: boolean }>(`${boot.urls.skills_library}?format=json`)
        if (!Array.isArray(data.installations) || data.installations.some((row) => !row || typeof row.id !== "string")) {
          throw new Error("No se ha podido leer la lista de skills. Vuelve a cargarla.")
        }
        const list = data.installations
        const live = data.runtime_enabled === true
        setRows(list)
        setLoaded(true)
        setRuntime(live)
        if (live) {
          const isReady = (row: SkillRow) => Boolean(row.enabled) && Boolean(row.availability?.available)
          let next = latest.current.selected.filter((id) => list.some((row) => row.id === id && isReady(row)))
          if (next.length !== latest.current.selected.length) setNotice("Se han quitado de este mensaje las skills que ya no están disponibles. Revisa tu selección.")
          const pending = storageGet("regulai.skills.pending")
          if (pending) {
            const row = list.find((item) => item.id === pending)
            if (!row || !isReady(row)) {
              setNotice("Esta skill ya no está disponible. Revisa su instalación en la biblioteca.")
              storageRemove("regulai.skills.pending")
              storageRemove("regulai.skills.pending_note")
            } else if (conversation !== "new" && mode !== "agent") {
              // Skills belong to agent mode: open a new agent chat and keep this draft.
              storageSet(`regulai.skills.draft.${conversation}`, session.composerDraft?.() ?? "")
              storageSet("regulai.skills.pending_note", AGENT_NOTE)
              window.location.assign(boot.urls.chat)
              return
            } else if (next.includes(pending) || next.length < MAX) {
              if (!next.includes(pending)) next = [...next, pending]
              prepareAgent()
              storageRemove("regulai.skills.pending")
              const note = storageGet("regulai.skills.pending_note")
              if (note) {
                setNotice(note)
                storageRemove("regulai.skills.pending_note")
              }
            } else {
              prepareAgent()
              setNotice(`Ya has elegido tres skills. Quita una y vuelve a elegir ${displayName(row)}.`)
            }
          }
          setSelected(next)
        }
      } catch (problem) {
        setError(problem instanceof Error && problem.message.startsWith("No se") ? problem.message : "No se ha podido cargar la lista de skills. Vuelve a intentarlo.")
      } finally {
        setLoading(false)
        inflight.current = null
      }
    })()
    return inflight.current
  }, [enabled, conversation, mode, prepareAgent, boot.urls.chat, boot.urls.skills_library, session])

  // The catalogue loads only for a manual action or a saved intent, never on an empty chat.
  useEffect(() => {
    if (!enabled) return
    const draft = storageGet(`regulai.skills.draft.${conversation}`)
    if (draft) {
      setDraft(draft)
      storageRemove(`regulai.skills.draft.${conversation}`)
    }
    if (latest.current.selected.length || storageGet("regulai.skills.pending")) void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  /** Returns a message when the choice is refused (limit of three). */
  const toggle = useCallback((row: SkillRow): string | null => {
    if (!ready(row)) return null
    const current = latest.current.selected
    if (!current.includes(row.id) && current.length >= MAX) return "Puedes seleccionar hasta tres skills. Quita una para elegir otra."
    const next = current.includes(row.id) ? current.filter((id) => id !== row.id) : [...current, row.id]
    latest.current = { ...latest.current, selected: next }
    setSelected(next)
    setNotice("")
    return null
  }, [ready])

  const remove = useCallback((id: string) => setSelected((current) => current.filter((value) => value !== id)), [])

  const setAuto = useCallback(async (value: boolean) => {
    if (!latest.current.runtime) return
    setAutoState(value)
    if (conversation === "new") {
      storageSet(autoKey, String(value))
      return
    }
    try {
      await postJSON(boot.urls.skill_preference.replace("{id}", conversation), { auto: value })
    } catch (problem) {
      setAutoState(!value)
      setNotice(problem instanceof Error ? "No se pudo guardar la preferencia. Vuelve a intentarlo." : String(problem))
    }
  }, [autoKey, boot.urls.skill_preference, conversation])

  /** Before leaving for the library: remember where to return, the draft and the choice. */
  const leaving = useCallback(() => {
    storageSet("regulai.skills.return", window.location.pathname)
    storageSet("regulai.skills.return_mode", mode)
    storageSet(`regulai.skills.draft.${conversation}`, session.composerDraft?.() ?? "")
    if (conversation === "new") storageSet(autoKey, String(latest.current.auto))
    storageSet(selectionKey, JSON.stringify(latest.current.selected))
  }, [autoKey, conversation, mode, selectionKey, session])

  // The command carries the selection only when the runtime is on, so a plain
  // send keeps the conversation's stored Auto preference untouched.
  useEffect(() => {
    if (!enabled) return
    session.skills = {
      capture: () => (latest.current.runtime ? { selected: [...latest.current.selected], auto: latest.current.auto } : undefined),
      accepted: () => {
        if (!latest.current.runtime) return
        setSelected([])
        storageRemove(autoKey)
        setNotice("")
      },
    }
    return () => { session.skills = null }
  }, [enabled, session, autoKey])

  const chips = useMemo(() => selected.map((id) => {
    const row = rows.find((item) => item.id === id)
    return { id, name: row ? displayName(row) : "Skill seleccionada" }
  }), [rows, selected])

  return { enabled, runtime, rows, loaded, loading, error, notice, setNotice, selected, chips, auto, ready, load, toggle, remove, setAuto, leaving, requirements }
}

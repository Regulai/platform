import { useCallback, useEffect, useState, useSyncExternalStore } from "react"

export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback((notify: () => void) => {
    const list = window.matchMedia(query)
    list.addEventListener("change", notify)
    return () => list.removeEventListener("change", notify)
  }, [query])
  return useSyncExternalStore(subscribe, () => window.matchMedia(query).matches, () => false)
}

/** A ticking clock only while `active`; used for running durations from the server clock. */
export function useNow(active: boolean, interval = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), interval)
    return () => window.clearInterval(timer)
  }, [active, interval])
  return now
}

/** Optional preference in localStorage; failures (private mode) fall back to memory. */
export function useStoredFlag(key: string, fallback: boolean, encode: (value: boolean) => string, decode: (raw: string) => boolean) {
  const [value, setValue] = useState<boolean>(() => {
    try {
      const raw = window.localStorage.getItem(key)
      return raw === null ? fallback : decode(raw)
    } catch {
      return fallback
    }
  })
  const update = useCallback((next: boolean) => {
    setValue(next)
    try {
      window.localStorage.setItem(key, encode(next))
    } catch {
      // Optional.
    }
  }, [key, encode])
  return [value, update] as const
}

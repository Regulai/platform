import { useCallback, useRef, useSyncExternalStore } from "react"

/* A minimal external store: transport writes, React reads through selectors.
 * Updates are immutable, so a selector that returns a sub-object only
 * re-renders its component when that object changed. */

export type Store<T> = {
  get(): T
  set(next: T | ((previous: T) => T)): void
  subscribe(listener: () => void): () => void
}

export function createStore<T>(initial: T): Store<T> {
  let state = initial
  const listeners = new Set<() => void>()
  return {
    get: () => state,
    set(next) {
      const value = typeof next === "function" ? (next as (previous: T) => T)(state) : next
      if (Object.is(value, state)) return
      state = value
      listeners.forEach((listener) => listener())
    },
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
  }
}

export function useSelector<T, S>(store: Store<T>, selector: (state: T) => S, equal: (a: S, b: S) => boolean = Object.is): S {
  const cache = useRef<{ state: T; value: S } | null>(null)
  const snapshot = useCallback(() => {
    const state = store.get()
    const cached = cache.current
    if (cached && Object.is(cached.state, state)) return cached.value
    const value = selector(state)
    if (cached && equal(cached.value, value)) {
      cache.current = { state, value: cached.value }
      return cached.value
    }
    cache.current = { state, value }
    return value
  }, [store, selector, equal])
  return useSyncExternalStore(store.subscribe, snapshot, snapshot)
}

export const shallowArray = <T,>(a: T[], b: T[]) => a.length === b.length && a.every((value, index) => Object.is(value, b[index]))

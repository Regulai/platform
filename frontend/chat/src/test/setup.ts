import { cleanup } from "@testing-library/react"
import { afterEach } from "vitest"

/* jsdom lacks layout APIs the island and Base UI use; inert stand-ins keep the
 * behaviour under test (state, transport, focus, events) observable. */

if (!window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: query.includes("min-width: 1024px") || query.includes("pointer: fine"),
    media: query, onchange: null,
    addEventListener: () => undefined, removeEventListener: () => undefined,
    addListener: () => undefined, removeListener: () => undefined, dispatchEvent: () => false,
  }) as MediaQueryList
}

class InertObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
globalThis.ResizeObserver ??= InertObserver as unknown as typeof ResizeObserver
globalThis.IntersectionObserver ??= InertObserver as unknown as typeof IntersectionObserver
Element.prototype.scrollIntoView ??= function scrollIntoView() {}
Element.prototype.scrollTo ??= function scrollTo() {} as Element["scrollTo"]
HTMLElement.prototype.hasPointerCapture ??= () => false

afterEach(() => {
  cleanup()
  window.sessionStorage.clear()
  window.localStorage.clear()
})

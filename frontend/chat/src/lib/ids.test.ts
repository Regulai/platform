import { afterEach, describe, expect, it, vi } from "vitest"

import { requestUUID } from "./ids"

describe("request identity", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("is a v4 UUID even where crypto.randomUUID is unavailable (plain-HTTP origins)", () => {
    const original = globalThis.crypto
    vi.stubGlobal("crypto", { getRandomValues: original.getRandomValues.bind(original) })
    const value = requestUUID()
    expect(value).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(requestUUID()).not.toBe(value)
  })
})

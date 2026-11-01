import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { emptyRequest, type AttachmentPhase, type Command, type RequestState } from "../state/model"
import { RequestController, type RequestHost } from "./requests"

/* The web request adapter against scripted server replies: same identity on
 * retry, events applied once by seq, rejoin never re-sends, stop asks the
 * server (or aborts an upload that did not arrive). */

const sse = (events: object[], close = true) => {
  const encoder = new TextEncoder()
  return new Response(new ReadableStream<Uint8Array>({
    start(controller) {
      events.forEach((event) => controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`)))
      if (close) controller.close()
    },
  }), { headers: { "Content-Type": "text/event-stream; charset=utf-8" } })
}

function host() {
  const state: { request: RequestState; attachment: AttachmentPhase | null; adopted: number[]; announced: string[]; toasts: string[]; busy: boolean[] } = {
    request: emptyRequest(), attachment: null, adopted: [], announced: [], toasts: [], busy: [],
  }
  const value: RequestHost = {
    url: (name, id) => ({ send: "/chat/send/", send_conversation: `/chat/${id}/send/`, request_stream: `/chat/requests/${id}/stream/`, request_cancel: `/chat/requests/${id}/cancel/` })[name],
    updateRequest: (_key, update) => { state.request = update(state.request) },
    setAttachment: (_key, phase) => { state.attachment = phase },
    adoptConversation: (id) => state.adopted.push(id),
    announce: (text) => state.announced.push(text),
    toast: (text) => state.toasts.push(text),
    agentAccepted: () => undefined,
    setSending: () => undefined,
    setRequestBusy: (_key, active) => state.busy.push(active),
  }
  return { state, value }
}

const command = (extra: Partial<Command> = {}): Command => ({
  requestId: "11111111-1111-4111-8111-111111111111", prompt: "Hola", file: null, fileName: null, fileSize: null,
  conversationId: null, engineId: null, modelId: null, autoRoute: false, ...extra,
})

const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

describe("RequestController", () => {
  let calls: { url: string; init?: RequestInit }[]
  beforeEach(() => {
    calls = []
  })
  afterEach(() => vi.unstubAllGlobals())

  it("streams a send, applies events once and settles on the final result", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return sse([
        { type: "accepted", seq: 1, conversation_id: 7 },
        { type: "stage", seq: 2, stage: "generating", model: "m" },
        { type: "delta", seq: 3, attempt: 1, text: "Hola" },
        { type: "delta", seq: 3, attempt: 1, text: "Hola" },
        { type: "delta", seq: 4, attempt: 1, text: " mundo" },
        { type: "final", seq: 5, result: { status: "completed", request_id: "r", receipt: { verification: { status: "passed" } }, assistant_message: { content: "Hola mundo" } } },
      ])
    }))
    const { state, value } = host()
    const file = new File(["datos"], "a.txt")
    const controller = new RequestController(value, "k", command().requestId, command({ file, fileName: "a.txt" }))
    await controller.submit()
    const body = calls[0]!.init!.body as FormData
    expect(calls[0]!.url).toBe("/chat/send/")
    expect(body.get("request_id")).toBe(command().requestId)
    expect(body.get("stream")).toBe("1")
    expect(state.adopted).toEqual([7])
    expect(state.attachment).toBe("received")
    expect(state.request.outcome).toMatchObject({ kind: "answer", text: "Hola mundo" })
    expect(state.request.phase).toBe("done")
    expect(state.announced).toContain("Respuesta lista")
  })

  it("rejoins after a dropped stream from the last applied event and ignores replays", async () => {
    let call = 0
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      call++
      if (call === 1) return sse([{ type: "delta", seq: 1, attempt: 1, text: "Uno" }, { type: "delta", seq: 2, attempt: 1, text: " dos" }])
      return sse([
        { type: "delta", seq: 2, attempt: 1, text: " dos" },
        { type: "delta", seq: 3, attempt: 1, text: " tres" },
        { type: "final", seq: 4, result: { status: "completed", assistant_message: { content: "Uno dos tres" }, receipt: { verification: { status: "passed" } } } },
      ])
    }))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    await controller.submit()
    expect(calls).toHaveLength(2)
    expect(calls[1]!.url).toBe(`/chat/requests/${command().requestId}/stream/?after=2`)
    expect(calls[1]!.init?.method).toBeUndefined()
    expect(state.request.outcome).toMatchObject({ kind: "answer", text: "Uno dos tres" })
  })

  it("withdraws retracted text from the view and reports it with the failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => sse([
      { type: "delta", seq: 1, attempt: 1, text: "Borrador" },
      { type: "retract", seq: 2, reason: "verification" },
      { type: "final", seq: 3, result: { status: "failed", error_type: "verification_failed", error: "No superó la verificación." } },
    ])))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    await controller.submit()
    expect(state.request.text).toBe("")
    expect(state.request.retracted).toBe(true)
    expect(state.request.outcome).toMatchObject({ kind: "error", title: "Respuesta no entregada", retracted: true })
  })

  it("reports a send that never reached the server and keeps its identity for retry", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (init?.method === "POST") throw new TypeError("network down")
      return new Response(null, { status: 404 })
    }))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    await controller.submit()
    // The server said it does not know the request: the draft may come back.
    expect(state.request.outcome).toMatchObject({ kind: "unsent", restorable: true })
    await controller.submit()
    const ids = calls.filter((item) => item.init?.method === "POST").map((item) => (item.init!.body as FormData).get("request_id"))
    expect(ids).toEqual([command().requestId, command().requestId])
  })

  it("offers only a retry with the same identity when nothing confirms whether the send arrived", async () => {
    vi.useFakeTimers()
    try {
      vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url, init })
        throw new TypeError("network down")
      }))
      const { state, value } = host()
      const file = new File(["x"], "a.txt")
      const controller = new RequestController(value, "k", command().requestId, command({ file, fileName: "a.txt" }))
      const sending = controller.submit()
      await vi.runAllTimersAsync()
      await sending
      expect(calls.filter((item) => item.url.includes("/stream/"))).toHaveLength(6)
      // It may be running on the server: a new send with another id could run it twice.
      expect(state.request.outcome).toMatchObject({ kind: "unsent", restorable: false, title: "No se pudo obtener el resultado" })
      expect(state.attachment).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it("treats an HTML rate-limit page as a refusal: nothing ran and the draft may come back", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return new Response("<!doctype html><title>Demasiadas peticiones</title>", { status: 429, headers: { "Content-Type": "text/html; charset=utf-8", "Retry-After": "12" } })
    }))
    const { state, value } = host()
    const file = new File(["x"], "a.txt")
    const controller = new RequestController(value, "k", command().requestId, command({ file, fileName: "a.txt" }))
    await controller.submit()
    expect(calls).toHaveLength(1)
    expect(state.request.outcome).toEqual({
      kind: "unsent", restorable: true, title: "Demasiados mensajes seguidos",
      text: "Espera 12 s y reintenta. Este mensaje no se ha enviado.",
    })
    expect(state.attachment).toBe("cancelled")
    expect(state.busy.at(-1)).toBe(false)
  })

  it("treats the agent's JSON rate limit, which has no status, as the same refusal", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "Too many messages. Please wait a moment.", rate_limit: { limit: 30 } }, { status: 429 })))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command({ mode: "agent" }))
    await controller.submit()
    expect(state.request.outcome).toMatchObject({ kind: "unsent", restorable: true, title: "Demasiados mensajes seguidos" })
  })

  it("asks to reload when the session or its CSRF token is no longer valid", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<!doctype html><h1>Forbidden</h1>", { status: 403, headers: { "Content-Type": "text/html" } })))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    await controller.submit()
    expect(state.request.outcome).toMatchObject({ kind: "unsent", restorable: true, title: "La sesión ya no es válida" })
  })

  it("rejoins after a proxy error page, because the request may have run", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (init?.method === "POST") return new Response("<html>Bad gateway</html>", { status: 502, headers: { "Content-Type": "text/html" } })
      return sse([{ type: "final", seq: 3, result: { status: "completed", assistant_message: { content: "Hecho" }, receipt: { verification: { status: "passed" } } } }])
    }))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    await controller.submit()
    expect(calls.filter((item) => item.init?.method === "POST")).toHaveLength(1)
    expect(state.request.outcome).toMatchObject({ kind: "answer", text: "Hecho" })
  })

  it("holds the composer while a page restored from bfcache rejoins its stream", async () => {
    let call = 0
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      call++
      if (call === 1) {
        // The first stream stays open until the page hides it.
        return Promise.resolve(new Response(new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('data: {"type":"accepted","seq":1}\n\n'))
            init?.signal?.addEventListener("abort", () => controller.error(new DOMException("Aborted", "AbortError")))
          },
        }), { headers: { "Content-Type": "text/event-stream" } }))
      }
      return Promise.resolve(sse([{ type: "final", seq: 2, result: { status: "completed", assistant_message: { content: "Listo" }, receipt: { verification: { status: "passed" } } } }]))
    }))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    const sending = controller.submit()
    await flush()
    controller.suspend()
    await sending
    expect(state.busy.at(-1)).toBe(false)
    controller.resume()
    expect(state.busy.at(-1)).toBe(true)
    await vi.waitFor(() => expect(state.request.outcome).toMatchObject({ kind: "answer", text: "Listo" }))
    expect(calls[1]!.url).toBe(`/chat/requests/${command().requestId}/stream/?after=1`)
    expect(state.busy.at(-1)).toBe(false)
  })

  it("brings back, as not sent, an upload the page cut before the server received it", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (init?.method === "POST") {
        return new Promise<Response>((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError"))))
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    }))
    const { state, value } = host()
    const file = new File(["x"], "a.txt")
    const controller = new RequestController(value, "k", command().requestId, command({ file, fileName: "a.txt" }))
    const sending = controller.submit()
    await flush()
    controller.suspend()
    await sending
    controller.resume()
    await vi.waitFor(() => expect(state.request.outcome).toMatchObject({ kind: "unsent", restorable: true }))
    expect(state.request.outcome).not.toMatchObject({ title: "Petición no disponible" })
    expect(state.attachment).toBe("cancelled")
  })

  it("aborts an upload that has not arrived and says so only after the server confirms it does not know it", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (init?.method === "POST") {
        return new Promise<Response>((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError"))))
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    }))
    const { state, value } = host()
    const file = new File(["x"], "a.txt")
    const controller = new RequestController(value, "k", command().requestId, command({ file, fileName: "a.txt" }))
    const sending = controller.submit()
    await flush()
    expect(state.attachment).toBe("sending")
    await controller.stop()
    await sending
    expect(calls.filter((item) => item.url.includes("/stream/"))).toHaveLength(3)
    expect(calls.some((item) => item.url.includes("/cancel/"))).toBe(false)
    expect(state.request.outcome).toEqual({ kind: "cancelled", own: true, text: "Envío detenido antes de llegar al servidor." })
    expect(state.attachment).toBe("cancelled")
  })

  it("asks the server to stop once the request is running", async () => {
    let release!: () => void
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (url.endsWith("/cancel/")) return Promise.resolve(new Response("{}", { status: 202 }))
      const encoder = new TextEncoder()
      return Promise.resolve(new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('data: {"type":"accepted","seq":1}\n\n'))
          release = () => {
            controller.enqueue(encoder.encode('data: {"type":"final","seq":2,"result":{"status":"cancelled","error_type":"cancelled_by_user","error":"Respuesta detenida."}}\n\n'))
            controller.close()
          }
        },
      }), { headers: { "Content-Type": "text/event-stream" } }))
    }))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, command())
    const sending = controller.submit()
    await flush()
    await flush()
    await controller.stop()
    release()
    await sending
    expect(calls.some((item) => item.url === `/chat/requests/${command().requestId}/cancel/` && item.init?.method === "POST")).toBe(true)
    expect(state.request.outcome).toEqual({ kind: "cancelled", own: true, text: "Respuesta detenida." })
  })

  it("never rejoins as running a request the account cannot see", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 404 })))
    const { state, value } = host()
    const controller = new RequestController(value, "k", command().requestId, null)
    await controller.attach()
    expect(state.request.outcome).toMatchObject({ kind: "error", title: "Petición no disponible" })
  })
})

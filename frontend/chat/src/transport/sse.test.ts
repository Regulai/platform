import { describe, expect, it } from "vitest"

import { parseFrame, readEventStream } from "./sse"

function response(chunks: string[]): Response {
  const encoder = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      chunks.forEach((chunk) => controller.enqueue(encoder.encode(chunk)))
      controller.close()
    },
  })
  return new Response(body, { headers: { "Content-Type": "text/event-stream" } })
}

describe("SSE frames (like EventSource)", () => {
  it("takes the type from `event:` when the JSON has none and ignores comments", () => {
    expect(parseFrame(": keepalive")).toBeNull()
    expect(parseFrame('id: 3\nevent: stage\ndata: {"seq": 3, "stage": "generating"}')).toEqual({ seq: 3, stage: "generating", type: "stage" })
    expect(parseFrame('event: x\ndata: {"type": "final", "seq": 9}')).toEqual({ type: "final", seq: 9 })
    expect(parseFrame("data: not json")).toBeNull()
  })

  it("joins multi-line data and reassembles frames split across chunks and CRLF", async () => {
    const seen: unknown[] = []
    await readEventStream(response(['event: delta\r\ndata: {"seq": 1, ', '"text": "Ho"}\r\n\r\n: ping\n\n', 'data: {"type": "delta", "seq": 2,\ndata: "text": "la"}\n\n']),
      (event) => seen.push(event))
    expect(seen).toEqual([{ seq: 1, text: "Ho", type: "delta" }, { type: "delta", seq: 2, text: "la" }])
  })

  it("stops reading when aborted", async () => {
    const controller = new AbortController()
    const seen: unknown[] = []
    const stream = new ReadableStream<Uint8Array>({
      start(sink) { sink.enqueue(new TextEncoder().encode('data: {"type":"stage","seq":1}\n\n')) },
    })
    const reading = readEventStream(new Response(stream), (event) => {
      seen.push(event)
      controller.abort()
    }, controller.signal)
    await expect(reading).resolves.toBeUndefined()
    expect(seen).toHaveLength(1)
  })
})

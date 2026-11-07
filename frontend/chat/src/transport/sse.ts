/* Server-sent events over fetch, for the POST that starts a web request and its
 * rejoin GET. Frames are parsed like EventSource: `event:` names the type when
 * the JSON has none; comments and keepalives are ignored. */

export function parseFrame<T extends { type?: string }>(frame: string): T | null {
  const data: string[] = []
  let type = "message"
  for (const line of frame.split("\n")) {
    if (!line || line.startsWith(":")) continue
    const colon = line.indexOf(":")
    const field = colon < 0 ? line : line.slice(0, colon)
    let value = colon < 0 ? "" : line.slice(colon + 1)
    if (value.startsWith(" ")) value = value.slice(1)
    if (field === "event") type = value
    else if (field === "data") data.push(value)
  }
  if (!data.length) return null
  try {
    const event = JSON.parse(data.join("\n")) as T
    if (event && typeof event === "object" && !event.type) (event as { type?: string }).type = type
    return event
  } catch {
    return null
  }
}

/** Reads until the server closes or `signal` aborts; each complete frame is delivered once. */
export async function readEventStream<T extends { type?: string }>(
  response: Response,
  onEvent: (event: T) => void,
  signal?: AbortSignal,
): Promise<void> {
  if (!response.body) return
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ""
  const cancel = () => void reader.cancel().catch(() => undefined)
  signal?.addEventListener("abort", cancel, { once: true })
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n?/g, "\n")
      let index
      while ((index = buffer.indexOf("\n\n")) >= 0) {
        const event = parseFrame<T>(buffer.slice(0, index))
        buffer = buffer.slice(index + 2)
        if (event) onEvent(event)
      }
    }
  } finally {
    signal?.removeEventListener("abort", cancel)
  }
}

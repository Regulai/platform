/* Same-origin fetch helpers. CSRF comes from the page bootstrap; every call
 * can be aborted so unmounting never leaves a request writing into state. */

let csrfToken = ""

export function setCsrfToken(value: string) {
  csrfToken = value
}

export function csrf(): string {
  return csrfToken
}

export class HttpError extends Error {
  status: number
  data: unknown
  constructor(status: number, data: unknown) {
    super(`http_${status}`)
    this.status = status
    this.data = data
  }
}

export async function getJSON<T>(url: string, signal?: AbortSignal): Promise<{ data: T; response: Response }> {
  const response = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin", signal })
  if (!response.ok) throw new HttpError(response.status, await response.json().catch(() => null))
  return { data: (await response.json()) as T, response }
}

/** JSON body with the CSRF header; the agent and skills endpoints expect this shape. */
export async function postJSON<T>(url: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { "X-CSRFToken": csrf(), Accept: "application/json" }
  const init: RequestInit = { method: "POST", headers, credentials: "same-origin", signal }
  if (body !== undefined) {
    headers["Content-Type"] = "application/json"
    init.body = JSON.stringify(body)
  }
  const response = await fetch(url, init)
  const data = await response.json().catch(() => null)
  if (!response.ok) throw new HttpError(response.status, data)
  return data as T
}

/** Form body (engine/model selection), as the legacy page posted it. */
export async function postForm<T>(url: string, fields: Record<string, string>, signal?: AbortSignal): Promise<T> {
  const form = new FormData()
  Object.entries(fields).forEach(([key, value]) => form.append(key, value))
  form.append("csrfmiddlewaretoken", csrf())
  const response = await fetch(url, { method: "POST", body: form, credentials: "same-origin", signal })
  const data = await response.json().catch(() => null)
  if (!response.ok) throw new HttpError(response.status, data)
  return data as T
}

export const isAbort = (error: unknown): boolean =>
  error instanceof DOMException ? error.name === "AbortError" : (error as { name?: string })?.name === "AbortError"

export const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("Aborted", "AbortError"))
    const timer = window.setTimeout(() => {
      signal?.removeEventListener("abort", stop)
      resolve()
    }, ms)
    const stop = () => {
      window.clearTimeout(timer)
      reject(new DOMException("Aborted", "AbortError"))
    }
    signal?.addEventListener("abort", stop, { once: true })
  })

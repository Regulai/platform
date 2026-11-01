export const present = (value: unknown): boolean => value !== null && value !== undefined && value !== ""

export const list = <T,>(value: T[] | null | undefined | unknown): T[] => (Array.isArray(value) ? (value as T[]) : [])

/** Decimal comma, as the server-rendered chat showed sizes. */
export function fileSize(bytes: number | null | undefined): string {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return ""
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1).replace(".", ",")} KB`
  return `${(bytes / 1024 / 1024).toFixed(1).replace(".", ",")} MB`
}

/** Only measured durations are shown; under a second is not worth a label. */
export function duration(ms: number | null | undefined): string {
  if (typeof ms !== "number" || !Number.isFinite(ms) || ms < 1000) return ""
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return seconds % 60 ? `${minutes} min ${seconds % 60} s` : `${minutes} min`
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`
}

export const time = (value: string | null | undefined): number | null =>
  value && Number.isFinite(Date.parse(value)) ? Date.parse(value) : null

export function timestamp(value: string | null | undefined): string {
  const parsed = time(value)
  return parsed === null ? "No disponible" : new Date(parsed).toLocaleString("es-ES")
}

export function amount(value: unknown, currency?: string | null): string {
  return present(value) && Number.isFinite(Number(value)) ? `${String(value)} ${currency || ""}`.trim() : "No disponible"
}

export function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`
}

export function extension(name: string): string {
  const index = name.lastIndexOf(".")
  return index < 0 ? "" : name.slice(index).toLowerCase()
}

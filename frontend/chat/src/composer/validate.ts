import { extension, fileSize } from "@/lib/format"
import type { Bootstrap, Mode } from "@/types"

/** Client checks mirror the server's limits and never replace them. */
export function fileProblem(file: File, mode: Mode, composer: Bootstrap["composer"]): string | null {
  const accept = composer.accept[mode]
  if (accept.length && !accept.includes(extension(file.name))) return `Formato no admitido aquí. Admitidos: ${accept.join(", ")}`
  if (file.size === 0) return "El archivo está vacío."
  const max = mode === "agent" ? composer.max_bytes.agent : composer.max_bytes.chat
  if (max && file.size > max) return `El archivo supera el máximo de ${fileSize(max)}.`
  return null
}

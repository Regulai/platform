/** True only when the browser confirms the copy; callers show "Copiado" only then. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Permission denied or insecure context: try the synchronous fallback once.
  }
  const area = document.createElement("textarea")
  area.value = text
  area.setAttribute("readonly", "")
  area.style.position = "fixed"
  area.style.opacity = "0"
  document.body.appendChild(area)
  area.select()
  let copied = false
  try {
    copied = document.execCommand("copy")
  } catch {
    copied = false
  }
  area.remove()
  return copied
}

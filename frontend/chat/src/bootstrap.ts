import type { Bootstrap } from "./types"

/** The public bootstrap rendered by Django with json_script; never page HTML. */
export function readBootstrap(doc: Document): Bootstrap {
  const node = doc.getElementById("regulai-chat-bootstrap")
  if (!node?.textContent) throw new Error("chat_bootstrap_missing")
  const data = JSON.parse(node.textContent) as Bootstrap
  if (data?.version !== 1 || typeof data.csrf_token !== "string" || !data.urls || !Array.isArray(data.turns)) {
    throw new Error("chat_bootstrap_invalid")
  }
  return data
}

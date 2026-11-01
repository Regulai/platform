import { act, fireEvent, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { StrictMode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { ChatSession } from "../state/session"
import { bootstrap } from "../test/boot"
import type { Artifact, BootTurn, RunData } from "../types"
import { ChatApp } from "./ChatApp"

/* The composer and session as a person uses them (jsdom; transport scripted). */

type Call = { url: string; init?: RequestInit }

function pendingStream(): Response {
  // The request stays open: the composer must stay busy and refuse a second send.
  return new Response(new ReadableStream<Uint8Array>({ start() {} }), { headers: { "Content-Type": "text/event-stream" } })
}

function mount(overrides: Parameters<typeof bootstrap>[0] = {}, strict = false) {
  const session = new ChatSession(bootstrap(overrides))
  const app = <ChatApp session={session} />
  const utils = render(strict ? <StrictMode>{app}</StrictMode> : app)
  return { session, ...utils, prompt: () => screen.getByRole("textbox", { name: "Mensaje" }) as HTMLTextAreaElement }
}

describe("composer", () => {
  let calls: Call[]
  beforeEach(() => {
    calls = []
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      if (String(url).startsWith("/skills/")) return new Response(JSON.stringify({ runtime_enabled: true, installations: [
        { id: "taste", display_name: "Taste v2", summary: "Diseño", enabled: true, availability: { available: true } },
      ] }))
      return pendingStream()
    }))
  })
  afterEach(() => vi.unstubAllGlobals())

  const posts = () => calls.filter((call) => call.init?.method === "POST" && call.url.includes("/send/"))

  it("sends once with Enter, keeps Shift+Enter as a new line and ignores Enter while composing", async () => {
    const user = userEvent.setup()
    const { prompt } = mount()
    await user.type(prompt(), "Hola{Shift>}{Enter}{/Shift}mundo")
    expect(prompt().value).toBe("Hola\nmundo")
    fireEvent.keyDown(prompt(), { key: "Enter", isComposing: true })
    fireEvent.keyDown(prompt(), { key: "Enter", keyCode: 229 })
    expect(posts()).toHaveLength(0)
    await user.keyboard("{Enter}")
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect((posts()[0]!.init!.body as FormData).get("prompt")).toBe("Hola\nmundo")
    expect(prompt().value).toBe("")
    await user.type(prompt(), "Otra{Enter}")
    await user.keyboard("{Enter}")
    expect(posts()).toHaveLength(1)
    expect(prompt().value).toBe("Otra")
    expect(screen.getByRole("button", { name: "Detener respuesta" })).toBeTruthy()
  })

  it("checks one file against the server's types and size before upload", async () => {
    const user = userEvent.setup({ applyAccept: false })
    const { container } = mount()
    const input = container.ownerDocument.querySelector<HTMLInputElement>('input[type="file"]')!
    await user.upload(input, new File(["x"], "virus.exe"))
    expect(screen.getByText(/Formato no admitido aquí/)).toBeTruthy()
    await user.upload(input, new File([new Uint8Array(2048)], "grande.txt"))
    expect(screen.getByText(/supera el máximo de 1,0 KB/)).toBeTruthy()
    await user.upload(input, new File(["hola"], "nota.txt"))
    expect(screen.getByText("nota.txt")).toBeTruthy()
    await user.click(screen.getByRole("button", { name: "Quitar nota.txt" }))
    await waitFor(() => expect(screen.queryByText("nota.txt")).toBeNull())
  })

  it("accepts a dropped file only on the composer and blocks navigation elsewhere", async () => {
    const { container } = mount()
    const file = new File(["datos"], "datos.csv")
    const transfer = { files: [file], types: ["Files"], dropEffect: "" }
    const outside = new Event("drop", { bubbles: true, cancelable: true })
    Object.assign(outside, { dataTransfer: transfer })
    act(() => { document.body.dispatchEvent(outside) })
    expect(outside.defaultPrevented).toBe(true)
    expect(screen.queryByText("datos.csv")).toBeNull()
    const surface = container.ownerDocument.querySelector("[data-slot=input-group]")!.parentElement!
    fireEvent.drop(surface, { dataTransfer: transfer })
    expect(screen.getByText("datos.csv")).toBeTruthy()
  })

  it("does not request the skills catalogue when an empty chat opens; a leading / does", async () => {
    const user = userEvent.setup()
    const { prompt } = mount()
    await user.click(screen.getByRole("radio", { name: /Agente/ }))
    expect(calls.some((call) => call.url.startsWith("/skills/"))).toBe(false)
    await user.type(prompt(), "a/")
    expect(calls.some((call) => call.url.startsWith("/skills/"))).toBe(false)
    await user.clear(prompt())
    fireEvent.change(prompt(), { target: { value: "/", selectionStart: 1, selectionEnd: 1 }, nativeEvent: { isComposing: true } })
    await user.clear(prompt())
    await user.type(prompt(), "/")
    // The picker itself (options, Escape, focus return) is checked in a real browser (e2e/journeys.spec.ts).
    await waitFor(() => expect(calls.filter((call) => call.url === "/skills/?format=json")).toHaveLength(1))
  })

  it("keeps Auto off and the draft that came back from the library", async () => {
    window.sessionStorage.setItem("regulai.skills.auto.new", "false")
    window.sessionStorage.setItem("regulai.skills.draft.new", "Borrador conservado")
    const user = userEvent.setup()
    const { prompt } = mount({ composer: { mode: "agent" } })
    expect(prompt().value).toBe("Borrador conservado")
    await user.click(prompt())
    await user.keyboard("{Enter}")
    await waitFor(() => expect(posts()).toHaveLength(1))
    const body = posts()[0]!.init!.body as FormData
    expect(body.get("mode")).toBe("agent")
    expect(JSON.parse(String(body.get("skills")))).toEqual({ selected: [], auto: false })
    expect(window.sessionStorage.getItem("regulai.skills.draft.new")).toBeNull()
  })

  it("mounts once under StrictMode and closes everything on dispose", async () => {
    const { session, unmount } = mount({}, true)
    const user = userEvent.setup()
    await user.type(screen.getByRole("textbox", { name: "Mensaje" }), "Hola{Enter}")
    await waitFor(() => expect(posts()).toHaveLength(1))
    unmount()
    session.dispose()
    session.dispose()
    expect(session.isDisposed).toBe(true)
  })
})

describe("agent runs", () => {
  afterEach(() => vi.unstubAllGlobals())

  const run: RunData = {
    id: "run-1", request_id: "req-1", professional: false, resumable: true, resume_url: "/chat/agent/runs/run-1/resume/",
    status: "interrupted", request: { formats: ["html"], language: "es" }, created_at: null, started_at: null, finished_at: null,
    events_url: "/chat/agent/runs/run-1/events/", status_url: "/chat/agent/runs/run-1/", cancel_url: "",
  }
  const turn: BootTurn = {
    request_id: "req-1", status: "accepted", run_id: "run-1", legacy: false, live: false,
    user: { content: "Crea un HTML", file_name: null, file_size: null }, notice: null, answer: null,
    assistant_file: null, receipt_url: null, evidence_url: null,
  }

  it("drops Resume once the run is no longer authorized and only offers to refresh its state", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "agent_not_found" }, { status: 404 })))
    mount({
      conversation: { id: 9, title: "Agente", mode: "agent", auto_skills: true }, composer: { mode: "agent", modes: ["agent"] },
      turns: [turn], runs: { [run.id]: run },
    })
    await screen.findByRole("button", { name: /Actualizar estado/ })
    expect(screen.queryByRole("button", { name: /Reanudar/ })).toBeNull()
  })

  it("keeps no export intent when the send is refused and carries it only with an accepted send", () => {
    const calls: Call[] = []
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init })
      return pendingStream()
    }))
    const boot = () => bootstrap({ conversation: { id: 9, title: "Agente", mode: "agent", auto_skills: true }, composer: { mode: "agent", modes: ["agent"] } })
    const artifact = { id: "rev-2", logical_id: "art-1", revision: 2, format: "xlsx" } as Artifact

    // Another request is in flight: the export is refused and leaves nothing for the next message.
    const busy = new ChatSession(boot())
    expect(busy.send({ prompt: "Primero", file: null, mode: "agent" })).toBe(true)
    expect(busy.requestExport(artifact, "informe.xlsx")).toBe(false)
    expect(busy.store.get().pendingExport).toBeNull()
    busy.dispose()

    const idle = new ChatSession(boot())
    calls.length = 0
    expect(idle.requestExport(artifact, "informe.xlsx")).toBe(true)
    const body = calls.find((call) => call.init?.method === "POST")!.init!.body as FormData
    expect([body.get("artifact_id"), body.get("base_revision"), body.get("export_name")]).toEqual(["art-1", "rev-2", "informe.xlsx"])
    expect(idle.store.get().pendingExport).toBeNull()
    idle.dispose()
  })
})

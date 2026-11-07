import { act, fireEvent, render } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ChatMarkdown } from "./ChatMarkdown"
import { plain } from "./renderer"

/* The content policy of the chat (one place): text only, allowlisted links, no
 * images or raw HTML, masking markers and citations as labelled elements, stable
 * blocks while streaming, and nothing left in the DOM after a retraction. This is
 * also the equivalence gate any other renderer must pass before replacing it. */

const view = (source: string, props: Partial<Parameters<typeof ChatMarkdown>[0]> = {}) =>
  render(<ChatMarkdown source={source} {...props} />).container.querySelector(".rg-md") as HTMLElement

describe("ChatMarkdown content policy", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("never parses markup: HTML is shown as text and nothing executes or loads", () => {
    const root = view("<img src=x onerror=alert(1)> **bien** <script>alert(2)</script>\n\n![logo](https://tracker.invalid/p.png)")
    expect(root.querySelectorAll("img, script, iframe, object, embed, video, audio, source")).toHaveLength(0)
    expect(root.textContent).toContain("<img src=x onerror=alert(1)> bien <script>alert(2)</script>")
    expect(root.querySelector("strong")?.textContent).toBe("bien")
    expect(root.textContent).toContain("!logo")
  })

  it("links only http(s) and mailto, opened safely, never nested", () => {
    const root = view("[web](https://example.org/a_(b)) [mail](mailto:a@b.es) [js](javascript:alert(1)) [data](data:text/html,x) [rel](/admin/) <https://auto.example> https://bare.example/x.")
    const links = [...root.querySelectorAll("a")]
    expect(links.map((link) => link.getAttribute("href"))).toEqual(["https://example.org/a_(b)", "mailto:a@b.es", "https://auto.example", "https://bare.example/x"])
    links.forEach((link) => {
      expect(link.target).toBe("_blank")
      expect(link.rel).toBe("noopener noreferrer nofollow")
    })
    expect(root.textContent).toContain("js")
    expect(root.textContent).not.toContain("javascript:")
    expect(view("[a [b](https://x.example)](https://y.example)").querySelectorAll("a a")).toHaveLength(0)
  })

  it("shows masking markers as protected labels, except inside code", () => {
    const root = view("Escribe a [[REGULAI_EMAIL]] o a `[[REGULAI_PHONE]]`; [[REGULAI_UNKNOWN]] queda igual.")
    const chip = root.querySelector(".rg-redacted")!
    expect(chip.textContent).toBe("correo protegido")
    expect(chip.getAttribute("title")).toBe("Dato enmascarado antes de salir de la organización")
    expect(root.querySelector("code")?.textContent).toBe("[[REGULAI_PHONE]]")
    expect(root.textContent).toContain("[[REGULAI_UNKNOWN]]")
  })

  it("copies readable labels instead of raw markers", () => {
    expect(plain("Llama a [[REGULAI_PHONE]] y [[REGULAI_PERSON]]")).toBe("Llama a [teléfono protegido] y [nombre protegido]")
  })

  it("turns [n] into a citation that opens its evidence, and keeps document outline below the page", () => {
    const onCite = vi.fn()
    const root = view("# Informe\n\nDato verificado [2]. Enlace [3](https://x.example).", { onCite })
    expect(root.querySelector("h1")).toBeNull()
    expect(root.querySelector("h2")?.textContent).toBe("Informe")
    const cite = root.querySelector<HTMLElement>(".rg-cite")!
    expect(cite.dataset.cite).toBe("2")
    expect(root.querySelectorAll(".rg-cite")).toHaveLength(1)
    fireEvent.click(cite)
    expect(onCite).toHaveBeenCalledWith("2")
  })

  it("renders tables as labelled scroll regions with alignment, and task lists with names", () => {
    const root = view("| A | B |\n|:--|--:|\n| 1 | 2 |\n\n- [x] Hecho\n- [ ] Pendiente")
    const region = root.querySelector(".rg-table")!
    expect(region.getAttribute("role")).toBe("region")
    expect(region.getAttribute("aria-label")).toBe("Tabla")
    expect(region.getAttribute("tabindex")).toBe("0")
    expect(root.querySelectorAll("td")[1]?.getAttribute("style")).toContain("right")
    expect([...root.querySelectorAll(".rg-task")].map((box) => box.getAttribute("aria-label"))).toEqual(["Hecho", "Pendiente"])
  })

  it("keeps incomplete fragments readable while streaming", () => {
    const { container, rerender } = render(<ChatMarkdown source={"Texto **negri"} streaming />)
    const root = container.querySelector(".rg-md")!
    expect(root.querySelector("strong")?.textContent).toBe("negri")
    rerender(<ChatMarkdown source={"Usa `cod"} streaming />)
    expect(root.querySelector("code")?.textContent).toBe("cod")
    rerender(<ChatMarkdown source={"Ver [el enlace](https://exa"} streaming />)
    expect(root.querySelector("a")).toBeNull()
    expect(root.textContent).toBe("Ver el enlace")
    rerender(<ChatMarkdown source={"Tabla:\n| Concepto | Límite |"} streaming />)
    expect(root.textContent).toBe("Tabla:")
    rerender(<ChatMarkdown source={"```js\nconst a = 1"} streaming />)
    expect(root.querySelector(".rg-code.is-open code")?.textContent).toBe("const a = 1")
  })

  it("reuses finished blocks while the last one grows, and the final render keeps them", () => {
    const { container, rerender } = render(<ChatMarkdown source={"Primero.\n\nSeg"} streaming animate />)
    const root = container.querySelector(".rg-md")!
    const first = root.firstElementChild
    rerender(<ChatMarkdown source={"Primero.\n\nSegundo.\n\n- uno"} streaming animate />)
    expect(root.firstElementChild).toBe(first)
    rerender(<ChatMarkdown source={"Primero.\n\nSegundo.\n\n- uno\n- dos"} animate />)
    expect(root.firstElementChild).toBe(first)
    expect(root.querySelectorAll("li")).toHaveLength(2)
  })

  it("removes withdrawn text from the page entirely", () => {
    const { container, rerender } = render(<ChatMarkdown source={"Texto que se retirará"} streaming />)
    rerender(<ChatMarkdown source="" />)
    expect(container.querySelector(".rg-md")?.childNodes).toHaveLength(0)
  })

  it("confirms a code copy only when the clipboard does", async () => {
    const onCopied = vi.fn()
    const writeText = vi.fn().mockRejectedValueOnce(new Error("denied")).mockResolvedValueOnce(undefined)
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } })
    document.execCommand = vi.fn(() => false)
    const root = view("```py\nprint(1)\n```", { onCopied })
    const button = root.querySelector<HTMLButtonElement>(".rg-code-copy")!
    await act(async () => { fireEvent.click(button) })
    expect(onCopied).toHaveBeenLastCalledWith(false)
    expect(button.textContent).toBe("Copiar")
    await act(async () => { fireEvent.click(button) })
    expect(writeText).toHaveBeenLastCalledWith("print(1)")
    expect(onCopied).toHaveBeenLastCalledWith(true)
    expect(button.textContent).toBe("Copiado")
  })
})

import { readFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"

import { expect, type Page, type Request } from "@playwright/test"

export type Lab = { chat: number; agent: number; installations: Record<string, string>; fixture: true }

export const lab = (): Lab => JSON.parse(readFileSync(join(tmpdir(), "regulai-chat-redesign", "lab", "lab.json"), "utf8")) as Lab

export const prompt = (page: Page) => page.getByRole("textbox", { name: "Mensaje" })

/** Every request the page makes; rendering content must never reach another origin. */
export function watchNetwork(page: Page, base: string) {
  const requests: Request[] = []
  page.on("request", (request) => requests.push(request))
  return {
    requests,
    foreign: () => requests.map((request) => request.url()).filter((url) => !url.startsWith(base) && !url.startsWith("data:") && !url.startsWith("blob:") && url !== "about:srcdoc"),
    posts: (fragment: string) => requests.filter((request) => request.method() === "POST" && request.url().includes(fragment)),
  }
}

export function watchErrors(page: Page) {
  const errors: string[] = []
  page.on("pageerror", (error) => errors.push(error.message))
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()) })
  return errors
}

export async function send(page: Page, text: string) {
  await prompt(page).click()
  await prompt(page).fill(text)
  await prompt(page).press("Enter")
  await expect(prompt(page)).toHaveValue("")
}

/** The newest turn of the conversation. */
export const lastTurn = (page: Page) => page.locator("article[data-turn]").last()

// Quick look at real pages (lab fixture): node e2e/shoot.mjs chat/1/ <width>x<height> <out.png> [waitMs]
import { chromium } from "@playwright/test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"

const [rawPath = "chat/", size = "1440x900", out = "shot.png", wait = "800"] = process.argv.slice(2)
const [width, height] = size.split("x").map(Number)
const base = process.env.LAB_URL || "http://127.0.0.1:8890"
const state = JSON.parse(readFileSync(join(tmpdir(), "regulai-chat-redesign", "lab", "browser-state.json"), "utf8"))
const browser = await chromium.launch()
const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1, storageState: state, reducedMotion: process.env.REDUCED ? "reduce" : "no-preference" })
const page = await context.newPage()
const errors = []
page.on("pageerror", (error) => errors.push(error.message))
page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()) })
// Paths are given without the leading slash (Git Bash rewrites "/chat" as a file path).
await page.goto(base + "/" + rawPath.replace(/^\/+/, ""), { waitUntil: "networkidle" })
await page.waitForTimeout(Number(wait))
await page.screenshot({ path: out, fullPage: false })
console.log(JSON.stringify({ out, errors, overflow: await page.evaluate(() => document.documentElement.scrollWidth > innerWidth) }))
await browser.close()

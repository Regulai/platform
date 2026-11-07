import { join } from "node:path"
import { tmpdir } from "node:os"

import { defineConfig } from "@playwright/test"

/* Real-browser checks of the built island served by Django (no Vite dev server).
 * Start the lab first: python ops/chat_ui/lab.py prepare --fresh; session; serve; drive. */
const lab = join(tmpdir(), "regulai-chat-redesign", "lab")

export default defineConfig({
  testDir: "e2e",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  outputDir: process.env.E2E_OUT || join(tmpdir(), "regulai-chat-redesign", "e2e-results"),
  use: {
    baseURL: process.env.LAB_URL || "http://127.0.0.1:8890",
    storageState: join(lab, "browser-state.json"),
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    locale: "es-ES",
    timezoneId: "Europe/Madrid",
    video: process.env.E2E_VIDEO ? { mode: "on", size: { width: 1440, height: 900 } } : "off",
    trace: "off",
  },
})

import type { Artifact } from "../types"

/* What the viewers accept from the server, shared by the cards (always loaded)
 * and the viewers themselves (loaded the first time one opens). */

export const PREVIEW = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/preview\/$/
export const DOWNLOAD = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/download\/$/
export const PAGE = /^\/chat\/agent\/artifacts\/[0-9a-f-]+\/pages\/\d+\/$/

export const canPreview = (artifact: Artifact) => typeof artifact.preview_url === "string" && PREVIEW.test(artifact.preview_url)

export type Opened = { artifact: Artifact; revisions: Artifact[]; trigger: HTMLElement | null; runId: string }

export type PagesRequest = {
  runId: string
  artifact: Artifact
  title: string
  meta: string
  focusIndex: number
  trigger: HTMLElement | null
  verified: boolean
  downloads: { format: string; url: string }[]
  review?: { ready: boolean; confirm: () => void | Promise<void>; pageLoaded: (index: number) => void }
}

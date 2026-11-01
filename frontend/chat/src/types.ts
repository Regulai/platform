/* Server contracts as the island receives them. Field names stay snake_case:
 * they are the Django payloads (bootstrap, SSE events, run snapshots). */

export type Mode = "chat" | "agent"

export type NavItem = { key: string; label: string; href: string; active: boolean }
export type NavGroup = { label: string; items: NavItem[] }

export type AlertSummary = {
  count: number
  href: string
  recent: { id: number; title: string; description: string; severity: string; href: string }[]
}

export type ThreadGroup = { label: string; items: { id: number; title: string; mode: Mode }[] }

export type NoticeKind = "blocked" | "consent" | "error" | "cancelled" | "system" | "live" | "context"

export type Notice = {
  kind: NoticeKind
  title?: string
  text?: string
  rules: string[]
  reason?: string
  /** Blocked without a matching rule: the policy's own reason (bootstrap only). */
  detail?: string
  code?: string
  stale?: boolean
  retry?: boolean
  token?: string | null
  file_name?: string | null
  requested?: { engine_id: number | string | null; model_id: number | string | null } | null
}

export type EvidenceItem = { claim_index: number | string | null; locator: string; excerpt: string }

export type BootTurn = {
  request_id: string | null
  status: string | null
  run_id: string | null
  legacy: boolean
  live: boolean
  user: { content: string; file_name: string | null; file_size: number | null } | null
  notice: Notice | null
  answer: { text: string; unverified: boolean; recorded: boolean; evidence: EvidenceItem[] } | null
  assistant_file: { name: string; size: number | null; url: string } | null
  receipt_url: string | null
  evidence_url: string | null
}

export type RunStatus =
  | "queued" | "active" | "outcome_unknown" | "completed" | "failed" | "interrupted" | "cancelled" | "expired" | string

export type RunData = {
  id: string
  request_id: string
  skills?: { selected?: string[] | null; auto?: boolean | null; selected_aliases?: string[] }
  professional: boolean
  resumable: boolean
  resume_url: string
  status: RunStatus
  request?: Record<string, unknown> | null
  created_at: string | null
  started_at: string | null
  finished_at: string | null
  events_url: string
  status_url: string
  cancel_url: string
  limitations?: string[]
}

export type Bootstrap = {
  version: 1
  csrf_token: string
  urls: {
    home: string; chat: string; conversation: string; delete: string; send: string; send_conversation: string
    request_stream: string; request_cancel: string; request_receipt: string
    select_engine: string; select_model: string; skills_library: string; skill_preference: string
    documents_search: string; ai_connections: string; profile: string; logout: string; logo: string
  }
  user: { name: string; initial: string; company: string | null; avatar_url: string | null }
  navigation: NavGroup[]
  alerts: AlertSummary | null
  demo: boolean
  setup: { missing: boolean; can_manage: boolean }
  conversation: { id: number; title: string; mode: Mode; auto_skills: boolean } | null
  threads: ThreadGroup[]
  composer: {
    modes: Mode[]
    mode: Mode
    professional: boolean
    agent_available: boolean
    accept: Record<Mode, string[]>
    max_bytes: { chat: number; agent: number | null }
    placeholders: Record<Mode, string>
    suggestions: { label: string; text: string }[]
    inference_profiles: { value: string; label: string }[]
    drive: boolean
    skills: { catalog: boolean; runtime: boolean }
  }
  models: {
    engines: { id: number; name: string; detail: string }[]
    models: { id: number; name: string; detail: string }[]
    engine_id: number | null
    model_id: number | null
    automatic: boolean
    difficulty: boolean
    provider_limits: boolean
  }
  turns: BootTurn[]
  runs: Record<string, RunData>
}

/* Web chat request events (chat_streaming.ChatEvents). */
export type ChatEvent =
  | { type: "accepted"; seq: number; conversation_id?: number }
  | { type: "stage"; seq: number; stage: string; model?: string; attempt?: number }
  | { type: "delivery"; seq: number; mode: string; reason?: string | null }
  | { type: "delta"; seq: number; text: string; attempt: number }
  | { type: "retract"; seq: number; reason?: string; attempt?: number }
  | { type: "final"; seq: number; result: RequestResult; http_status?: number }

export type RequestResult = {
  status?: string
  success?: boolean
  request_id?: string
  conversation_id?: number
  error?: string
  error_type?: string
  consent_token?: string
  consent_reason?: string
  consent_rules?: { name?: string }[]
  blocked_rules?: { name?: string }[]
  assistant_message?: { content?: string; file_name?: string; file_url?: string; file_size?: number }
  receipt?: Receipt
  evidence?: { items?: EvidenceItem[] } | EvidenceItem[]
  agent?: RunData
  mode?: string
}

export type Receipt = Record<string, unknown> & {
  policy?: { status?: string; reason_codes?: string[]; rules?: { name?: string; id?: string | number }[] }
  notices?: string[]
  consent_reason?: string
  coverage?: Coverage
  history?: Record<string, number | null>
  limits?: Record<string, number | boolean | null>
  route?: Record<string, unknown> & { reason_codes?: string[] }
  delivery?: { mode?: string; reason?: string; withdrawn?: { attempt: number; reason: string }[] }
  verification?: { status?: string; reason_codes?: string[] }
  calls?: ReceiptCall[]
  total?: { cost?: number | string | null; known_cost?: number | string | null; currency?: string; cost_status?: string; status?: string; complete?: boolean; duration_ms?: number | null }
  jev?: Record<string, unknown>
}

export type ReceiptCall = Record<string, unknown> & {
  purpose?: string; status?: string; provider?: string; provider_name?: string; model?: string; model_effective?: string; model_requested?: string
  cost?: number | string | null; currency?: string; duration_ms?: number | null; cost_kind?: string; sequence?: number
  signals?: Record<string, { noul?: number }>; threshold?: number
}

export type Coverage = {
  status?: string; units_read?: number | null; units_total?: number | null; warnings?: string[]
  disclosures?: { code: string; count?: number | null; locators?: string[] }[]
}

/* Agent run events (event_store.serialized_event) and snapshots (views._full_snapshot). */
export type AgentEvent = {
  v?: number
  id: number
  seq?: number
  kind: string
  data: Record<string, unknown> & { text?: string; tool?: string; duration_ms?: number }
  created_at: string
}

export type TextSegmentSnapshot = { message_id: string; inference_id?: string; text: string; offset: number; expired?: boolean }

export type Artifact = Record<string, unknown> & {
  id: string
  logical_id?: string
  revision: number
  sha256?: string
  page_sha256?: string
  format?: string
  status?: string
  filename?: string
  size_bytes?: number
  preview?: Record<string, unknown> & { title?: string; pages?: string[]; page_count?: number; sheet_count?: number; sheets?: unknown[]; rows?: unknown[]; headers?: unknown[]; data_mode?: string }
  preview_url?: string
  download_url?: string
  downloads?: { format?: string; url?: string }[]
  review_url?: string
  review_checks?: unknown
  verification_checks?: Record<string, { status?: string; detail?: string }> & { coverage?: { status?: string } }
  coverage?: { status?: string }
  data_mode?: string
}

export type ExportProposal = {
  status: string; account?: string; folder?: string; name?: string; revision?: number; bytes?: number; sha256?: string
  expires_at?: string; preview_url?: string; decision_url?: string; binding?: string
}

export type RunSnapshot = {
  run: RunData
  result?: { error?: string; assistant_message?: { content?: string }; receipt?: Receipt } & Record<string, unknown>
  receipt?: Receipt
  export?: ExportProposal | null
  high_watermark?: number
  text_segments?: TextSegmentSnapshot[]
  sources?: { title?: string; url?: string; final_url?: string; opened?: boolean; reading?: string; excerpt?: string; snippet?: string; retrieved_at?: string; publication_date?: string }[]
  operations?: { name: string; status: string; details_url?: string }[]
  infrastructure?: Record<string, unknown> | null
  export_enabled?: boolean
  current_revision?: Artifact | null
  events?: AgentEvent[]
  delivery?: { status?: string; artifacts?: { artifact_id?: string; id?: string; sha256?: string }[] } | null
  artifacts?: Artifact[]
}

import type { Bootstrap } from "../types"

/** A synthetic bootstrap shaped like chat_bootstrap.chat_bootstrap(); fixture only. */
export function bootstrap(overrides: Omit<Partial<Bootstrap>, "composer"> & { composer?: Partial<Bootstrap["composer"]> } = {}): Bootstrap {
  const base: Bootstrap = {
    version: 1,
    csrf_token: "synthetic-csrf",
    urls: {
      home: "/", chat: "/chat/", conversation: "/chat/{id}/", delete: "/chat/{id}/delete/", send: "/chat/send/",
      send_conversation: "/chat/{id}/send/", request_stream: "/chat/requests/{id}/stream/",
      request_cancel: "/chat/requests/{id}/cancel/", request_receipt: "/chat/requests/{id}/receipt/",
      select_engine: "/chat/select-engine/", select_model: "/chat/select-model/", skills_library: "/skills/",
      skill_preference: "/skills/conversations/{id}/preference/", documents_search: "/chat/agent/documents/search/",
      ai_connections: "/settings/ai/", profile: "/profile/", logout: "/logout/", logo: "/static/images/logos/logo.png",
    },
    user: { name: "persona", initial: "P", company: "Empresa sintética", avatar_url: null },
    navigation: [{ label: "General", items: [{ key: "home", label: "Inicio", href: "/", active: false }, { key: "chat", label: "Chat", href: "/chat/", active: true }] }],
    alerts: null,
    demo: false,
    setup: { missing: false, can_manage: false },
    conversation: null,
    threads: [],
    composer: {
      modes: ["chat", "agent"], mode: "chat", professional: true, agent_available: true,
      accept: { chat: [".txt", ".pdf", ".csv"], agent: [".txt", ".pdf", ".csv", ".png"] },
      max_bytes: { chat: 1024, agent: 2048 },
      placeholders: { chat: "Escribe un mensaje…", agent: "Describe qué quieres investigar, calcular o crear…" },
      suggestions: [], inference_profiles: [], drive: false, skills: { catalog: true, runtime: true },
    },
    models: { engines: [{ id: 1, name: "Proveedor", detail: "" }], models: [{ id: 2, name: "Modelo", detail: "m" }], engine_id: 1, model_id: 2, automatic: false, difficulty: false, provider_limits: false },
    turns: [],
    runs: {},
  }
  return { ...base, ...overrides, composer: { ...base.composer, ...(overrides.composer ?? {}) } }
}

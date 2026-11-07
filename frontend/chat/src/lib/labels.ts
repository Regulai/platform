/* Server codes → short Spanish labels. Same vocabulary as the server-rendered
 * chat (chat_page.py, chat.js, agent-chat.js); unknown codes are shown as-is. */

export const REQUEST_STATUS: Record<string, string> = {
  completed: "Completada", blocked: "Bloqueada", pending_consent: "Pendiente de confirmación",
  processing: "En curso", received: "Recibida", accepted: "Aceptada", failed: "No completada",
  validation_error: "No completada", outcome_unknown: "Resultado desconocido", cancelled: "Cancelada",
}

export const POLICY: Record<string, string> = {
  allow: "Permitida", allowed: "Permitida", block: "Bloqueada", blocked: "Bloqueada",
  consent: "Requiere confirmación", consent_required: "Requiere confirmación", confirmed: "Confirmada por el usuario",
}

export const PURPOSE: Record<string, string> = {
  generation: "Generación", verification: "Verificación", classification: "Clasificación",
  difficulty: "Dificultad", masking: "Enmascarado", obfuscation: "Enmascarado", research: "Consulta de fuentes",
}

export const CALL_STATUS: Record<string, string> = {
  completed: "completada", failed: "fallida", started: "iniciada, sin resultado",
  stopped: "detenida", cancelled: "cancelada", outcome_unknown: "resultado desconocido",
}

export const VERIFICATION: Record<string, string> = {
  passed: "Superada", failed: "No superada", not_verified: "No realizada (servicio no disponible)",
}

export const ROUTE: Record<string, string> = { auto: "Automática", manual: "Elegida por el usuario", fallback: "Escalada a otro modelo" }

export const DELIVERY: Record<string, string> = {
  document_citations: "Se mostrará completa, con las citas comprobadas.",
  response_verification: "Se mostrará completa tras la verificación.",
  remote_masking: "Se mostrará completa tras enmascararla.",
  policy_needs_complete_text: "Las reglas de salida necesitan el texto completo.",
  structured_answer: "Respuesta estructurada: se mostrará completa.",
  provider_streaming_unverified: "Este proveedor no tiene entrega progresiva verificada.",
  streaming_disabled: "La entrega progresiva está desactivada.",
}

export const DISCLOSURES: Record<string, string> = {
  images_unread: "Imágenes no analizadas ni enviadas", images_omitted: "Imágenes no analizadas ni enviadas",
  attachments_unread: "Adjuntos no analizados ni enviados", charts_unread: "Gráficos no analizados ni enviados",
  comments_unread: "Comentarios no analizados ni enviados", equations_unread: "Ecuaciones no analizadas ni enviadas",
  symbols_unread: "Símbolos no analizados ni enviados", form_fields_unread: "Campos de formulario no analizados ni enviados",
  annotations_unread: "Anotaciones no analizadas ni enviadas", external_content_unread: "Contenido externo no analizado ni enviado",
  page_without_text: "Página sin texto extraíble; su contenido visual no se ha analizado ni enviado",
  tracked_changes_present: "Se ha usado la vista con los cambios aceptados",
  encoding_assumed: "Se ha interpretado la codificación como Windows-1252", blank_page: "Página en blanco",
  formula_expression_security_only: "La fórmula se comprueba para seguridad; se envía su valor en caché",
  formula_coverage_unknown: "El valor actual de la fórmula no se ha podido comprobar",
  numbering_unsupported: "No se ha podido representar esta numeración",
}

export const LIMITS: Record<string, string> = {
  jev_state_bytes: "Entrada máxima del evaluador (bytes)", response_bytes: "Límite de respuesta (bytes)",
  max_output_tokens: "Límite de salida (tokens)", call_timeout_seconds: "Tiempo máximo por llamada (s)",
  deadline_seconds: "Plazo de la petición (s)", history_max_bytes: "Límite del historial (bytes)",
  history_max_turns: "Límite del historial (turnos)", judge_input_bytes_bound: "Entrada máxima del juez (bytes)",
}

export const SIGNALS: Record<string, string> = {
  failure_omission: "Señal de Jev · requisitos omitidos",
  failure_contradiction: "Señal de Jev · contradicción o afirmación sin respaldo",
}

export const ERROR_TITLES: Record<string, string> = {
  verification_failed: "Respuesta no entregada", provider_failed: "Error del proveedor",
  outcome_unknown: "Resultado desconocido", security_check_failed: "Comprobación de seguridad no superada",
  deadline_exceeded: "Tiempo agotado", budget_exhausted: "Presupuesto insuficiente", unknown_price: "Coste no acotado",
  context_overflow: "Contenido demasiado largo", evaluation_input_too_large: "Contenido demasiado largo",
  input_unreadable: "Documento no legible", authorization_changed: "Permisos cambiados",
  consent_invalid: "Confirmación caducada", internal_error: "Error interno", cancelled_by_user: "Respuesta detenida",
}

export const SETUP_CODES = new Set([
  "masking_required", "policy_configuration_invalid", "jev_unavailable", "no_api_key", "model_not_allowed",
  "no_authorized_candidates", "empty_policy_not_authorized", "destination_not_allowed", "quality_unavailable",
  "capability_unavailable",
])

/** Codes that mean the server refused the attached file itself. */
export const FILE_REJECTIONS = new Set([
  "input_unreadable", "agent_input_size_limit", "agent_input_invalid", "agent_professional_input_invalid",
  "file_type_not_allowed", "file_too_large", "invalid_file",
])

export function consentReason(reason: string | undefined | null, pending = true): string {
  if (!reason) return ""
  const past: Record<string, string> = {
    consent_expired: "Una confirmación anterior caducó.",
    consent_context_changed: "La política o el contexto cambiaron durante la petición.",
    coverage_incomplete: "Parte del documento no se analizó ni se envió.",
  }
  const now: Record<string, string> = {
    consent_expired: "La confirmación caducó. Revísala y confirma de nuevo.",
    consent_context_changed: "La política o el contexto cambiaron. Revísalo y confirma de nuevo.",
    coverage_incomplete: "Parte del documento no se ha podido analizar y no se enviará.",
  }
  return (pending ? now : past)[reason] ?? reason
}

export function stageText(stage: string, model?: string, attempt?: number): string {
  const retry = (attempt ?? 1) > 1
  switch (stage) {
    case "protecting": return "Protegiendo datos sensibles"
    case "classifying": return "Clasificando la petición"
    case "generating": return (retry ? "Reintentando" : "Generando") + (model ? ` · ${model}` : "")
    case "verifying": return "Verificando la respuesta"
    case "waiting": return "Esperando el resultado"
    default: return "Procesando"
  }
}

/* Agent runs (agent-chat.js). */
export const RUN_LABELS: Record<string, string> = {
  queued: "En cola", active: "En curso", outcome_unknown: "Resultado por confirmar",
  completed: "Finalizado", failed: "No completado", interrupted: "Interrumpido", cancelled: "Cancelado",
  expired: "Caducado", pending: "Pendiente", passed: "Superada", not_performed: "No realizada",
  consulted: "Consultado", not_consulted: "No consultado", disabled: "Deshabilitado", no_response: "Sin respuesta",
  allow: "Permitido", allowed: "Permitido", block: "Bloqueado", blocked: "Bloqueado", unavailable: "No disponible",
  continue: "Continuar", not_required: "No requerido", required: "Requerido", automatic: "Automática",
  agent_profile: "Perfil del agente", classification: "Clasificación", generation: "Generación",
  research: "Consulta de fuentes", primary_source_read: "Consulta de fuente primaria", no_api_charge: "Sin cargo de API",
  verification: "Comprobación", not_used: "Sin fallback de Regulay", used: "Utilizado", unknown: "No disponible",
  reviewed: "Revisada por el modelo", web_search: "Búsqueda web", web_read: "Lectura web",
  web_browser_resource: "Recurso del navegador", package_download: "Descarga de dependencia",
  configured_upper_bound_estimate: "Estimación máxima configurada", started: "Iniciada", partial: "Parcial",
}

export const runLabel = (value: unknown): string =>
  (typeof value === "string" && RUN_LABELS[value]) || (value === null || value === undefined || value === "" ? "No disponible" : String(value))

export const STEP: Record<string, string> = {
  queued: "En cola", claimed: "Ejecución iniciada", recovered: "Recuperación solicitada",
  sandbox_waiting: "Esperando un entorno disponible", sandbox_preparing: "Preparando el entorno",
  sandbox_acquired: "Entorno reservado", sandbox_prepared: "Entorno preparado", provider_waiting: "Esperando capacidad del proveedor",
  provider_started: "Generando la respuesta", provider_completed: "Generación terminada",
  generation: "Generando la respuesta", capacity_waiting: "Esperando capacidad disponible",
  input: "Leyendo el archivo", calculate: "Calculando con Python", recalculate: "Recalculando fórmulas",
  rename: "Renombrando la revisión", compose: "Redactando el documento", render: "Renderizando páginas",
  verify: "Comprobando el archivo final", searching: "Buscando fuentes", reading: "Leyendo fuentes",
  executing: "Trabajando con archivos y código", installing: "Preparando dependencias", verifying: "Comprobando el resultado",
  visual_pending: "Revisión visual pendiente", visual_reviewed: "Revisión visual registrada",
  draft: "Comprobación no superada", verified: "Comprobaciones técnicas superadas",
  approval_pending: "Exportación pendiente de aprobación", export_intent: "Exportando a Google Drive",
  export_completed: "Exportación confirmada", export_uncertain: "Exportación por confirmar",
  export_recovery: "Recuperación de la exportación", completed: "Finalizado", cancelled: "Cancelado",
  interrupted: "Interrumpido", failed: "No completado",
  "inference.started": "Generando", "inference.finished": "Generación terminada",
  "inference.delivery": "Comprobando antes de mostrar", "tool.started": "Ejecutando herramienta",
  "tool.finished": "Herramienta terminada", "skill.activated": "Skill activada",
  "artifact.available": "Archivo disponible", "run.finished": "Ejecución terminada", interval: "Tiempo registrado",
}

export const TOOLS: Record<string, string> = {
  web_search: "búsqueda web", web_open: "abrir página", web_find: "buscar en la página",
  web_download: "descarga", web_browse: "navegador", ls: "listar archivos", read_file: "leer archivo",
  write_file: "escribir archivo", edit_file: "editar archivo", glob: "buscar archivos", grep: "buscar texto",
  execute: "ejecutar código", install_packages: "instalar dependencias", publish_artifact: "publicar entregable",
  inspect_image: "revisar imagen", read_output: "leer salida",
}

/** skill_context.py reasons: explicit selection, instructions read for the task, or restored context. */
export const SKILL_REASON: Record<string, string> = {
  user_selected: "elegida por ti",
  instructions_read: "según la tarea",
  context_restored: "recuperada del contexto",
}

export const TIMING_SCOPES: Record<string, string> = {
  queue: "Cola", provider: "Modelo", tool: "Herramientas", protection: "Controles",
  preparation: "Preparación", checkpoint: "Checkpoint", network: "Red",
}

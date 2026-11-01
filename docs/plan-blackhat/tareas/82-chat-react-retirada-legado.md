# 82 — Chat React: validación con personas y retirada del frontend anterior

Status: pendiente (no iniciada). El chat anterior sigue disponible como reversión
local con `REGULAI_CHAT_FRONTEND=legacy`.
Blocked by: un ensayo con personas reales ([81](81-chat-react-verificacion.md) completada).

Especificación: [prompt de renovación](../../../output/chat-ui-research-20261017/prompt.md),
criterio final y «validación con usuarios reales».

Aceptación: ensayo de tareas con personas que no conocen la implementación
(comprensión de estados, esfuerzo y errores), sin sustituirlo por la opinión del
autor. Sólo después, retirar las plantillas `chat/chat.html` y `chat/_turn.html`, los
IIFE que sólo carga el chat (`chat.js`, `agent-chat.js`, `chat-markdown.js`,
`artifact-viewer.js`), `artifacts.css` y sus pruebas, conservando las de contratos
HTTP/estado/dinero. `skills.js` y `chat.css` se quedan: los cargan también las
páginas de la biblioteca de skills.

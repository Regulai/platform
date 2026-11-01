# 80 — Chat React: recorridos y sistema visual

Status: completada.
Blocked by: ninguno ([79](79-chat-react-base.md) completada).

Especificación: [prompt de renovación](../../../output/chat-ui-research-20261017/prompt.md),
apartados de dirección visual 1–8; [inventario de estados](../chat-react-estados.md).

Decisión ChatMarkdown (17-10-2026): se encapsula el renderer actual (port a
TypeScript de `chat-markdown.js`, mismo algoritmo) con un límite DOM propio.
Streamdown 2.7.0, configurado sin HTML crudo (sin rehype-raw), sin imágenes,
con saneado y enlaces http/https/mailto, superó 6 de 7 comprobaciones del
contrato; falla al retener una posible cabecera de tabla incompleta (mostraría
`| a | b |` en crudo) y añade 475 KB minificados / 142 KB gzip al JS inicial
(medido con el mismo build y React en ambos) sin aportar funciones exigidas.
No se adopta; evidencia y candidato en `output/chat-react-20261017/streamdown/`.

Aceptación: recorrido vertical compositor→envío→streaming→actividad/skill→archivo
y después menús, historial, visor y recuperación, con adaptador al protocolo
actual (transporte, estado y presentación separados). Un único ChatMarkdown con
la política de contenido (Streamdown sólo si supera equivalencia). Sin useChat ni
otro runtime; sin multiarchivo, edición, regeneración ni voz nuevos.

Verificación observada: recorrido vertical completo y después menús, historial,
visor y recuperación sobre el protocolo actual, con transporte (`transport/`),
estado (`state/`) y presentación separados; un único bootstrap y dueño del DOM,
con limpieza idempotente en StrictMode, desmontaje y `pagehide`. Compositor de una
sola superficie (Enter, Mayús+Enter e IME; `/`; adjuntar con comprobación local;
enviar/detener). Streaming sólo con los fragmentos del transporte, deduplicados
por `seq` y sin reanimar el historial; sigue el final salvo si la persona sube a
leer («Ir al final»). Actividad tipo Trace, aviso de skill deduplicado y sin robar
foco, entregables compactos con acciones sólo cuando el servidor serviría el
archivo, y visor lateral desde 1100 px (modal por debajo) con `iframe` sin
permisos. Visor, selectores, detalles y Motion se cargan al primer uso. Áreas
táctiles de 40–44 px con puntero grueso; la auditoría automática de las capturas
no encuentra ningún control por debajo de 40 px. Pruebas, medidas y límites en
[81](81-chat-react-verificacion.md).

# 78 — Investigación de componentes y microinteracciones del chat

Status: completada (investigación; implementación no iniciada).
Blocked by: ninguno.

Continúa [77](77-p1-skills-chat-usabilidad.md) y el
[plan P1](../plan-p1-skills-streaming-20261016.md).
Petición: investigar librerías y preparar un prompt para renovar la experiencia
del chat, con menos texto explicativo y más interacción sutil.

Aceptación: contrastar bibliotecas con fuentes primarias y con los contratos
actuales; concretar compositor, streaming, archivos, skills y actividad;
entregar un prompt ejecutable con criterios de aceptación y límites claros.

[Investigación y decisión propuesta](../investigacion-chat-ui-20261017.md).
[Prompt de implementación](../../../output/chat-ui-research-20261017/prompt.md).

Verificación observada: reconocimiento independiente de plantilla, scripts,
recursos locales y contratos; contraste independiente de assistant-ui,
Prompt Kit y shadcn/ui; documentación y licencias oficiales consultadas el
17-10-2026. Revisión de capturas existentes de la tarea 77 a 360 y 1440 px;
no constituyen una nueva validación del navegador ni del diseño propuesto.

El usuario autorizó expresamente migrar el frontend si mejora el resultado:
«Que si hay que migrar a otra cosa de frontend se hace eh». Con esa decisión,
se recomienda React/TypeScript/Vite limitado al chat, componentes actuales de
AI Elements/shadcn, Motion y Lucide. Django conserva backend y contratos.
El prompt documenta la excepción autorizada a la decisión histórica sobre
React e incluye build reproducible y sustitución de los montajes anteriores.
Sin instalaciones,
modificaciones de producto, llamadas de pago, migraciones ni despliegues.

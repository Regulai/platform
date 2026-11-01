# 74 — P1 E7: chat y visor

Status: implementada y verificada visualmente; cierre integrado E8.
Blocked by: ninguno para el alcance local autorizado.

Especificación y aceptación: [plan P1, E7](../plan-p1-skills-streaming-20261016.md#e7-chat-incremental-tiempos-reales-y-visor-de-artefactos).

Verificación observada: 47 pruebas de visor/render incremental/frontend anteriores y 41 focalizadas E6/E7/chat pasan; detalle de comandos y artefactos, autorización, descarga exacta, revocación, offsets UTF-8, snapshot y DOM estable. [Evidencia](../../../output/p1-20261016/e6-e7-verification.md).

La revisión visual independiente detectó y corrigió el cambio de modo del visor al cruzar 1100 px: conserva contenido/foco y pasa a modal en tamaños menores. Biblioteca, chat y visor inspeccionados a 360/768/1440 px, claro/oscuro; pestañas Vista previa/Código con flechas/Escape y retorno de foco. Iframe hostil sin scripts/cookies/red/acceso al padre; código literal y descarga original. CSS zoom 200 % y movimiento reducido emulado sin desbordamiento. No se declara ensayo manual con lector de pantalla.

[Capturas, medidas y alcance](../../../output/p1-20261016/e8/visual-review.md). Texto autorizado publicado→render p95 260,35 ms/20 muestras; 200 nodos históricos y bloques cerrados conservan identidad. El tiempo de apertura del visor medido con Playwright se informa por separado; no sustituye esa medida.

Cierre con rueda real: lectura arriba sin movimiento durante 20 publicaciones; contador por mensaje, sin duplicar por token ni contar hidratación inicial, y salto al final con limpieza. Admisión real del formulario→estado durable visible p95 226 ms/20. Tarjetas commit→SSE→GET autorizado→render p95 316,59 ms/20, frente a 824 ms iniciales y 477 ms intermedios conservados. El ajuste elimina consultas redundantes conservando autorización completa bajo lock. [Tarjetas y scroll](../../../output/p1-20261016/e8/artifact-browser-latency-snapshot.json).

Regresión final: 16/16 transporte/render, 1/1 hidratación, 4/4 scroll y 12/12 + 1/1 permisos/preview/snapshot revocado. [Informe de cierre](../../../output/p1-20261016/e8/publication-review.md).

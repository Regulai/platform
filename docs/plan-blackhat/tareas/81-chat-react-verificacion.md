# 81 — Chat React: verificación, medidas y revisión independiente

Status: completada, con los límites de abajo; la validación con personas sigue en [82](82-chat-react-retirada-legado.md).
Blocked by: ninguno ([80](80-chat-react-recorridos.md) completada).

Especificación: [prompt de renovación](../../../output/chat-ui-research-20261017/prompt.md),
apartado «Implementación y comprobación».

Aceptación: tipos/build y artefacto instalable con manifest y CSS verificados sin
dev server; pruebas de las tres entradas HTTP, transporte del proveedor simulado y
estado/dinero; casos de UI donde cambia el comportamiento; navegador real a 360,
768 y 1440 px con capturas y grabación etiquetadas como fixtures; teclado/IME,
foco, áreas táctiles, movimiento reducido y lectura accesible; tamaño, tareas
largas y evento→DOM antes/después con el mismo corpus; revisión independiente de
contratos y acabado visual.

Verificación observada (17-10-2026, código `8d0f526`; laboratorio con datos
sintéticos y proveedor simulado, nunca un proveedor real):

- Typecheck y 47 pruebas unitarias: SSE, adaptadores de petición y ejecución,
  política de contenido, compositor, rutas de fallo del envío, bfcache, revocación
  y exportación. 10/10 recorridos en Chromium contra el build servido por Django:
  streaming y lectura hacia arriba, copiar, detener, recarga sin reenvío, adjunto
  comprobado y rechazado, selector de skills, actividad con aviso de skill y visor
  aislado, consentimiento con su token, teclado y movimiento reducido.
- Suite Django completa (88 módulos, PostgreSQL desechable): ningún fallo atribuible
  a la isla. Cinco módulos fallan igual en la base `2bfb930` (`test_agent_inference`,
  `test_agent_professional`, `test_agent_runtime_p0`, `test_agent_transparency` y el
  icono `book-bookmark-line-duotone` de `test_frontend_resources`), y
  `test_agent_preflight_inputs` da a veces un 409 `idempotency_conflict`, también en
  la base (1 de 8 ejecuciones aquí, 1 de 12 allí).
- Entrega comprobada en una copia limpia (`git archive 2bfb930` + parche): coincide
  byte a byte con el árbol de la rama; `npm ci` desde el lockfile, typecheck, pruebas
  y un build idéntico al commiteado; 151 pruebas Django del chat (sólo falla el icono
  preexistente) y 4 del instalador. `git apply --check` pasa contra el checkout
  principal tal como está.
- Navegador a 360, 768 y 1440 px: 65 capturas de 22 estados y una grabación a 1440 px,
  sin desbordes, errores de consola o red, peticiones a otros orígenes ni controles
  táctiles de menos de 40 px ([capturas](../../../output/chat-react-20261017/capturas-fixture/README.md)).
- Medidas con el mismo corpus y máquina, CPU ×4 y 5 pasadas
  ([datos](../../../output/chat-react-20261017/medidas/medidas-8d0f526.json)). Recursos:
  19 peticiones y 236–238 KB gzip en el chat anterior frente a 10 y 264–266 KB en la
  isla (JS +98 KB, CSS −65 KB). Primera carga: FCP 340–404 ms frente a 496–624 ms y
  bloqueo total 0–50 ms frente a 165–215 ms. Del evento recibido al DOM: chat
  9,5/17,1 ms (mediana/p95) frente a 9,1/17,1 ms; agente 9,7/23,5 ms frente a
  11,7/25,2 ms, porque la isla pinta una vez por fotograma.
- Revisión independiente con verificación escéptica: 6 defectos de contrato
  confirmados y corregidos (dos eran regresiones frente al chat anterior) y 7
  hallazgos visuales confirmados y corregidos; 3 refutados y 2 inciertos quedan como
  decisiones ([revisión](../../../output/chat-react-20261017/revision-independiente.md)).

Límites: la primera carga es más lenta porque la isla pinta tras ejecutar su JS y no
hay HTML inicial del servidor; mitigación posible, no hecha: un esqueleto estático
en `chat/app.html`. Ninguna persona ha usado aún la interfaz: sólo el agente que la
construyó y los revisores automáticos. Falta el ensayo con personas ([82](82-chat-react-retirada-legado.md)).
No se revisaron el tema oscuro ni el teclado virtual de un teléfono real. Las
cifras son de esta máquina y del laboratorio; no describen la latencia, la calidad
ni el coste de un proveedor.

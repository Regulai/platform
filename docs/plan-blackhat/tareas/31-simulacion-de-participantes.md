# 31 — Simular los dos participantes del piloto

**Status:** done — simulación solicitada completada; sin participación humana real.
**Blocked by:** ninguno para la simulación; esta tarea no produce validación humana real.
**Propietarios:** `pilot_persona_alpha` y `pilot_persona_beta`, nuevos subagentes Astra Max; integración del orquestador.
**Especificación:** [piloto preparado](../piloto-controlado.md), [guiones y formulario](../documentos-y-ensayos-piloto.md), [tarea26](26-piloto-controlado.md).

El usuario respondió «simúlalos» cuando se preguntó por los dos participantes. P01 (empleado de Alpha) y P02 (administrador de Beta) tienen recorridos y formularios como perfiles artificiales. Se respetaron cuatro agentes concurrentes contando root; cada perfil tuvo su propia carpeta y no modificó producto ni compartió ediciones.

## Aceptación

- [x] Dos recorridos completos sobre H1/H2 y formulario de observaciones simulado por perfil.
- [x] Distinguir evidencia técnica ya existente, comprobaciones nuevas realmente ejecutadas e inferencias hipotéticas de cada perfil.
- [x] Cubrir privacidad, consentimiento/cancelación/renovación, cobertura y omisiones, citas/ficha, teclado/móvil, recarga/export, aislamiento y coste/estado incierto.
- [x] Clasificar dudas e incidencias con fundamento; no inventar tiempos ni acciones de navegador.
- [x] Conservar archivos, comandos, hashes y síntesis de decisión continuar/corregir/detener en el alcance simulado.
- [x] Mantener el banco humano y sus etiquetas sin validaciones inventadas; cero participantes humanos, contactos y llamadas reales en esta tarea.

[Resultados e inventario de 50 archivos](../../../evals/reports/pilot-personas-20261003-01/README.md). P01 añadió cancelación de un Word con teclado y descarga real de ficha: cero llamadas y ninguna respuesta. P02 añadió 22 tests correctos y aislamiento de un administrador Beta sin privilegios globales; conserva fallido un suplemento de tres subcasos cuya fixture carecía de Jev. Las hipótesis P2 sobre idioma, omisiones, intento rechazado y longitud de ficha no son observaciones humanas. La decisión es continuar únicamente la demostración local sintética y mantener detenido el ensayo pagado hasta conciliar su resultado incierto.

La simulación puede orientar una revisión de usabilidad, pero no prueba que una persona comprenda el producto, ni valida las referencias de calidad de la fase4. La evidencia viva ya ejecutada permanece independiente y detenida; esta tarea no autoriza reintentos.

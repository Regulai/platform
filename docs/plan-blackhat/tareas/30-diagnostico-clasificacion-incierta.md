# 30 — Diagnosticar la clasificación incierta del ensayo real

**Status:** corrector local completado, verificado y revisado; causa externa anterior pendiente, sin nuevas llamadas.
**Blocked by:** para recuperar la causa externa anterior falta evidencia del proveedor; no se puede reconstruir el dato descartado.
**Propietario:** C (análisis aislado) y orquestador (integración).
**Especificación:** [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md), [ensayo autorizado 29](29-ensayo-autorizado-vercel.md).

La ejecución viva del commit `698e8f0` se detuvo tras ocho de las 24 combinaciones previstas, en `document-success/strong`, con `classification` en `outcome_unknown`. El ledger mantiene coste `null` y reserva de 0,003 USD. Se conservan 17 llamadas externas y 12 transformaciones locales. No se repite la llamada ni se continúa gastando durante este diagnóstico.

## Aceptación

- [x] Contrastar el diario, las llamadas y la suma de costes sin contar dos veces las filas de resumen por split.
- [x] Identificar únicamente lo que permite la evidencia; no atribuir un HTTP/timeout/contrato concreto sin datos.
- [x] Reproducir sin red cualquier pérdida de código diagnóstico antes de corregirla.
- [x] Conservar únicamente códigos seguros, con regresión; no cuerpos remotos, claves ni contenido sensible en logs.
- [x] Conservar ledger, reservas, umbrales y resultados originales; revisión independiente de cualquier cambio de producto.
- [x] Preparar una siguiente acción verificable, sin reintentar automáticamente resultados inciertos.

Reproducción roja: timeout, HTTP503 y JSON inválido perdían su código seguro y compartían el texto inexacto de ausencia de envío. Commit `972edb88c82a5220a43ffcc89316a9f9033e82f7`: campo aditivo `provider_error_code` con lista cerrada en ficha/log/ledger; los códigos desconocidos se sustituyen por uno genérico y el mensaje remite a la ficha. Cinco métodos nuevos y 73 tests focales correctos, incluidas tres HTTP, rechazo de cuerpos/secretos y reserva intacta. [Evidencia](../../../evals/reports/pilot-real-diagnosis-20261003-01/README.md).

Las [revisiones independientes](../../../evals/reports/pilot-independent-diagnostics-20261003-01/README.md) no encontraron nuevos bloqueantes: Seguridad comparó 18 escenarios y Spec once observaciones entre los commits fijos, sin cambios funcionales o contables. Las [cinco puertas finales](../../../evals/reports/pilot-integrated-gates-20261003-05/README.md) pasan con 387 tests y fuentes estables.

La causa concreta del fallo vivo sigue indeterminada. Siguiente acción: contrastar el evento Gateway de 2026-10-03 15:43:21 UTC, conservar la reserva de 0,003 USD y revisar los rechazos antes de proponer otra ejecución. Se reprodujeron además falsos positivos de máscara sobre palabras comunes; se declaran sin modificar detector, casos ni umbrales y sin atribuirles causalidad demostrada sobre Jev.

# 24: Preparar referencias humanas independientes y calibración

Seguimiento final: [72 recorridos con detectorv2](../../../evals/reports/pilot-local-final-20261003-01/README.md), cero fallos de controles y cero revisiones humanas. Referencias, etiquetas y umbrales permanecen sin cambios.

**Status:** pending human validation — banco y agregación local implementados
**Blocked by:** dos personas, validación de representatividad/referencias y adjudicación; comparación viva además depende de 23
**Specification:** [05](../05-clasificacion-documental.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md).

El usuario pidió simular los participantes: [tarea 31](31-simulacion-de-participantes.md) completada. Sus formularios artificiales no se incorporan como revisiones humanas ni etiquetas del conjunto reservado.

- [x] Banco sintético propuesto de 24 casos con 12 de desarrollo y 12 reservados; referencias en archivos separados.
- [x] Rúbrica fija, hashes, guía para revisión independiente y plantilla vacía con trazabilidad al resultado.
- [x] Informe por caso y agregado: entrega/cobertura, acierto/abstención humanos, sensibilidad, citas, segundo intento, dinero por procedencia y p50/p95 con n.
- [x] Coste por respuesta correcta condicionado a revisión completa y costes completos; ninguna inferencia automática de calidad/ahorro desde el juez prefijado.
- [x] Preparación offline sin claves ni coste de API; revisión de transportes/métricas mediante pruebas locales.
- [x] Nuevos ensayos usan detector de máscara real local y generación/jueces prefijados; casos, referencias, rúbrica y umbrales sin ajuste para favorecer aciertos.
- [x] Ensayo final 72 recorridos/72 controles, 120 transformaciones locales y 180 llamadas simuladas; cero revisiones humanas/coste real de API. Son controles de ejecución, no validación de calidad.
- [ ] Dos personas validan representatividad y referencias; resolver desacuerdos y registrar nombres/fecha/razón.
- [ ] Congelar referencias antes de comparar; no usar reservados para ajustar umbrales ni luego llamarlos independientes.
- [ ] Completar revisiones humanas reales de resultados, medir errores corregidos/introducidos y comparar configuraciones sin selección favorable.
- [ ] Repetir con proveedores vivos autorizados si se desea afirmar precisión, calibración o ahorro reales.

[Banco y rúbrica](../../../evals/pilot-human/README.md), [procedimiento](../ejecucion-real-y-calibracion-piloto.md), [evidencia local del detector](../../../evals/reports/pilot-evaluation-local-20261003-01/README.md) e [histórico](../../../evals/reports/pilot-evaluation-20261003-01/README.md). Las referencias actuales son borradores del autor, no etiquetas humanas completadas. Las sesiones iniciales propuestas son locales, con coste de API 0 USD; no se ha contactado con revisores ni inventado su aprobación. El detector también requiere revisión de omisiones/falsos positivos y no acredita privacidad completa.

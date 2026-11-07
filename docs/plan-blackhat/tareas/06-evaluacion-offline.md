# 06: Banco de regresión reproducible sin red

**Status:** done
**Blocked by:** 03 y 04 (controles automatizados disponibles)
**Specification:** [plan 11](../11-evaluacion-reproducible.md).

- [x] 50 casos y etiquetas, desarrollo/reservados, tres configuraciones comparables.
- [x] Manifiesto/hashes, resultados por caso, costes desconocidos y resúmenes; conservar informes anteriores.
- [x] Ausencia de salidas reales/prohibidas y estados/citas esperados.

`evaluate_ai --settings=regulai.test_settings --output <directorio-nuevo>` ejecutado mediante RTK: [informe final 04](../../../evals/reports/offline-2026-10-02-04/report.md), 150 ejecuciones, cero controles fallidos y cero llamadas reales, tras cambios finales Jev/simulador/smoke y con hashes SHA-256 de los bytes exactos de los archivos probados. Los seis hashes coinciden con los archivos actuales. Comando completo en [guía](../arranque-y-demo.md); informes previos conservados.

Calidad y costes de fixtures no demuestran calidad ni ahorro reales. `--real` permanece desactivado; smoke real y pendiente de calibración en tarea 08. Tests demo/evaluación/API/runtime: 21 correctas.

# Cambios del banco por D3

Justificación registrada antes de integrar P. D3 fue aprobada por el humano: la ambigüedad y la evidencia insuficiente producen un aviso por defecto; `unknown` aporta masa a `confidential`. El umbral sigue en 0,8. No se cambian entradas, distribuciones, señales, particiones, precios ni calidades para aprobar el banco.

Solo cambian estos tres casos de desarrollo de `evals/cases.jsonl`:

| Caso | Expectativa anterior | Expectativa de D3 y motivo |
| --- | --- | --- |
| `ambiguous-es` | `clarification_required` | `completed` con aviso de ambigüedad: «¿Cuánto me corresponde?» puede continuar e indicar al generador que pida aclaración. El control exige el aviso, además del estado. |
| `document-missing-answer` | `clarification_required` | `completed` con aviso de evidencia insuficiente: falta la fecha solicitada en la fuente. D3 permite continuar con ese aviso; no permite inventar una fecha ni afirmar verificación documental. El control exige el aviso. |
| `unknown-sensitivity` | `blocked`, cero generaciones | `completed`, sensibilidad `confidential`, una generación: la política sintética del caso autoriza `confidential`, por lo que la masa unknown ya no causa un bloqueo automático. El control exige la sensibilidad resultante. |

El evaluador incorpora comprobaciones genéricas de avisos y sensibilidad esperados; no se limita a cambiar etiquetas de éxito. El manifiesto debe registrar las rúbricas de clasificación y tarea realmente usadas (v2). No se ajusta ningún caso de la partición reservada. Los resultados siguen siendo simulados: no acreditan calibración, exactitud factual ni ahorro real.

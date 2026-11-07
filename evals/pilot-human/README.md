# Banco humano propuesto — revisión pendiente

24 casos sintéticos: 12 de desarrollo y 12 reservados. Su representatividad empresarial y todas sus referencias necesitan revisión de dos personas; no se atribuye revisión a nadie.

`cases.jsonl` contiene las entradas. `development-labels.pending.jsonl` y `reserved-labels.pending.jsonl` contienen referencias propuestas sin aprobación humana. El runner comprueba hashes, pero no utiliza etiquetas para generar ni puntuar. La [rúbrica](rubric.md) define acierto, abstención, requisitos, sensibilidad, citas y segundo intento. `sensitivity_false_negative` y `sensitivity_false_positive` permiten registrar ambos tipos de error con denominador revisado.

Primero acordar referencias y rúbrica en desarrollo. Congelar etiquetas y configuración antes de abrir reservados. Si se ajusta algo después de verlos, esos casos dejan de ser reservados y se necesita otro conjunto. Los umbrales 0,8 y calidades del manifiesto siguen siendo provisionales, no calibrados.

La preparación offline cuesta 0 USD de APIs. El enmascarador es el detector local real, spaCy en CPU más patrones; respuestas y jueces son fixtures prefijados. Los ensayos no prueban precisión de proveedores ni eliminación completa de PII/secretos. Los posibles errores del detector deben registrarse sin modificar estos casos, referencias ni umbrales para conseguir aciertos. Permiten revisar controles y preparar sesiones humanas sin gasto de API; todas las métricas de calidad permanecen pendientes. CPU y operación no se han valorado. Una comparación viva requiere además resolver la tarea 23 y registrar una aprobación nueva.

Los resultados crean `human-review.pending.json` con campos null. Completar una copia solo tras revisión humana real. Conservar el hash de cada fila, identidad, fecha con zona horaria y razón. `scripts/pilot_human_report.py` agrega a una carpeta nueva y rechaza revisiones duplicadas, sin autor o de resultados cambiados. No llama a modelos ni ajusta umbrales. El coste por respuesta correcta permanece null si falta revisión o cualquier coste es desconocido.

[Procedimiento y propuesta](../../docs/plan-blackhat/ejecucion-real-y-calibracion-piloto.md), [tarea 24](../../docs/plan-blackhat/tareas/24-calibracion-humana.md), [evidencia del detector local](../reports/pilot-evaluation-local-20261003-01/README.md) e [histórico de máscara simulada](../reports/pilot-evaluation-20261003-01/README.md).

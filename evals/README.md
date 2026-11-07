# Evaluación reproducible sin red

Los 50 casos son sintéticos. Los siete IDs originales y el documento de evidencia tardía se conservan. El reparto está fijado antes de la ejecución: 12 tareas, 10 documentos, 10 casos de sensibilidad, 8 adversariales y 10 estados; 30 casos de desarrollo y 20 reservados. Las etiquetas exactas y su razón están en `cases.jsonl`.

Ejecutar desde la raíz del repositorio, eligiendo un directorio de salida nuevo:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py evaluate_ai --settings=regulai.test_settings --output evals/reports/my-offline-run
```

El comando admite únicamente SQLite en memoria. Crea sus propias empresas, usuarios y catálogo sintéticos; no actualiza datos existentes. Un directorio de salida existente se rechaza. `--real` permanece desactivado hasta disponer del presupuesto persistente para todas las llamadas reales. `--split development` o `--split reserved` selecciona un reparto sin cambiar sus etiquetas.

Las tres configuraciones comparten política, permisos, clasificación, rúbrica, umbrales y presupuesto. Economy y strong usan un único candidato fijo; router puede elegir capacidad y corregir una vez con mayor calidad configurada. La referencia económica puede abstenerse si no supera el mínimo de capacidad para una tarea fuerte: esa falta de cobertura se muestra y no cuenta como respuesta correcta.

Los proveedores son respuestas prefijadas en el límite de generación y el HTTP real de Jev. Se ejecuta `send_chat_message`, incluidos extractores, reglas YARA, confirmaciones, historial, límites, cálculo de costes y citas. El socket está bloqueado para impedir cualquier conexión no simulada. Una respuesta y un juez prefijados solo prueban que el control de flujo reacciona; no miden precisión de Jev, calidad factual ni ahorro real.

Cada ejecución guarda `manifest.json`, `results.jsonl`, `summary.json`, `summary.csv` y `report.md`. El manifiesto captura tarifas, modelos, umbrales, versiones de rúbricas, commit, hashes de código y documentos y orden alternado según una semilla fija. Se conserva cada ejecución anterior. Los hashes de resultados excluyen latencias y IDs de ejecución; las latencias proceden de un reloj monotónico y su variación no cambia el resultado determinista.

Las etiquetas humanas `clarification_required`, `blocked` y `not_verified` describen el efecto visible. El JSONL conserva también el estado de ejecución y su código de error: pedir aclaración puede ser `validation_error`; la ausencia de rutas permitidas se considera bloqueo; una respuesta o un juez rechazados se consideran no verificados. Un ID externo, una ruta, HTML usado como ID o una cifra inventada dentro de una cita no cuentan como fuente. Solo los espacios se normalizan al comparar literales. Una cita real con una afirmación falsa requiere juicio y no aprueba por literalidad.

Se cuentan todas las llamadas iniciadas, también las fallidas y descartadas, y el coste conocido con `Decimal`. Un timeout o un uso ausente deja partidas desconocidas: el total completo y el coste por respuesta correcta quedan vacíos, nunca cero. El informe muestra entregas, abstenciones, aciertos exactos, errores corregidos, salidas prohibidas y citas mostradas inválidas. Las métricas de calidad y ahorro reales quedan sin medir. Los percentiles muestran su tamaño muestral y no representan un SLA.

Las expectativas reservadas se fijaron para este banco de regresión y se ejecutan automáticamente, pero son visibles para quien mantiene el código. Antes de anunciar resultados con proveedores reales, mantener un conjunto humano reservado independiente y sin adaptar sus umbrales después de mirarlo.

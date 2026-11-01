# Spec Q — operación y CI

Comparación inmutable `4400f0b...9549e74`. Checkout intacto, sin fixes.

**Implementación incorrecta / requisito parcial — [P2] La evaluación puede fallar y dejar CI verde.** Encargo: «`.github/workflows/ci.yml`: […] `evaluate_ai` offline en un directorio temporal» y «Puertas en verde […] `evaluate_ai` offline». El paso nuevo en `.github/workflows/ci.yml:17` confía exclusivamente en el código de salida de `evaluate_ai`; no verifica sus controles. El contrato existente del comando (`regulai/front/management/commands/evaluate_ai.py:432–433`) cuenta y muestra los fallos, pero devuelve éxito. Una regresión que produzca `control_pass=false` puede superar esta puerta; el `trap` además elimina los informes temporales.

Reproducción en la interfaz pública: `rtk proxy C:\Users\javi\Documents\Codex\regulai-platform\.venv\Scripts\python.exe -X utf8 C:\Users\javi\Documents\Codex\regulai-wt\Q-review-probe.py`. El probe copia el banco fuera del repo, mantiene todos los casos/etiquetas y aumenta únicamente el mínimo de calidad de la configuración sintética para provocar abstenciones. Invoca `evaluate_ai --settings=regulai.test_settings --split development`: **90 ejecuciones, 52 controles fallidos, código 0, cero ejecuciones reservadas**. Evidencia: `Q-review-probe.log` y `Q-review-bank/failing-runtime-policy/summary.json`. El defecto del comando preexiste; el hallazgo corresponde a la nueva puerta CI que lo usa sin comprobar el resultado.

**Fuera de alcance:** no identificado en Q.

Comprobaciones: seis tests de operación correctos, `check` sin incidencias; configuración y JSON del workflow inspeccionados. No encontré otra violación reproducida de privacidad en logging/auditoría; las pruebas cubren excepción, parámetros URL y fallo al persistir auditoría. Gunicorn declara `gthread`, cuatro hilos y 240 segundos frente al máximo de 180. El evaluador identifica el commit mediante Git sin RTK como dependencia runtime.

Actions, PostgreSQL y ejecución de Gunicorn Linux siguen pendientes explícitos; no se ejecutaron ni se presentan como bugs.

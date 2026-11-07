# Ensayo real y calibración humana del piloto

Estado a 3 de octubre de 2026: **el usuario autorizó hasta 1 USD para los ocho casos iniciales y después indicó usar Jev a través de Vercel**. El registro se vincula al manifiesto exacto del commit `698e8f0`; la ventana termina a las 23:59:59 UTC de ese día, dentro de las 24 horas aprobadas. [Evidencia de la ejecución autorizada](../../evals/reports/pilot-real-vercel-20261003-01/) conserva la comprobación previa y los resultados observados. El banco humano no está autorizado. La autorización del 2 de octubre no se reutiliza.

Los informes offline anteriores conservan sus propios snapshots y resultados: detector local real, generación/jueces simulados y bases en memoria. No acreditan calidad, calibración ni ahorro reales. El ensayo vivo tampoco sustituye una revisión humana.

**Resultado observado:** 8 de 24 combinaciones ejecutadas, correspondientes a cinco IDs, con 17 llamadas externas y 12 transformaciones locales. Se detuvo ante una clasificación incierta, después de dos respuestas entregadas, tres bloqueos y dos rechazos documentales. Costes comunicados: 0,000312522 USD; estimados: 0,00074496 USD; reserva incierta: 0,003 USD; exposición conservadora: 0,013858062 USD. No se repitió la llamada ni se liberó la reserva. El [corrector posterior](tareas/30-diagnostico-clasificacion-incierta.md), commit `972edb8`, conserva diagnósticos seguros para fallos futuros; no recupera la causa histórica. El manifiesto vivo sigue congelado en el código realmente ejecutado: no ignorar su `source_changed` para reanudar.

Los [dos perfiles simulados](../../evals/reports/pilot-personas-20261003-01/README.md) se completaron por petición posterior del usuario. Sus formularios no rellenan referencias humanas ni permiten anunciar calidad comparativa.

## Qué queda preparado

`smoke_ai` y `evaluate_ai` llaman al mismo `send_chat_message`, con máscara obligatoria, política, consentimiento, clasificación, generación, verificación y como máximo un segundo intento. Los dos comandos comparten `EvaluationBudget` y, en modo real, el archivo fijo `.claude/pilot-real-budget.sqlite3` y su lock. No hay selector de otro ledger para eludir el límite. El límite conjunto aprobado para el ensayo inicial es **1,00 USD**, incluidos fallos y reservas inciertas. No autoriza ejecutar el banco humano; cualquier uso posterior requiere aprobación explícita, revisar el saldo y conservar las reservas existentes.

El estado normal es offline. El modo real exige `--real`, `--max-usd 1.00`, autorización explícita con identidad/referencia humana, lista de hashes exactos de manifiestos y una ventana de hasta 24 horas. Antes de reservar y otra vez tras la reserva, antes de iniciar transporte o cómputo, se comprueban autorización, fuentes, dataset, rúbrica, runtime, identidad/hash del detector, destinos y fecha de revisión de tarifas. Una edición intermedia detiene las llamadas siguientes. Si se revoca durante la espera por la reserva, la operación no iniciada queda registrada a coste cero; esta es la protección SEC-1. El fichero de aprobación es un registro operativo de la aprobación del usuario, no un mecanismo criptográfico de firma ni permiso para que el agente se autorice a sí mismo.

La ejecución acepta únicamente SQLite en memoria. Crea empresas/usuarios/credenciales temporales y medios en un directorio temporal; no cambia empresas ni bases existentes. El puente autorizado lee un único par de credenciales DeepSeek/Gateway perteneciente a la misma empresa mediante una conexión separada SQLite `mode=ro`. Las inyecta en `REGULAI_EVAL_GENERATOR_KEY` y `REGULAI_EVAL_JEV_KEY` del proceso hijo, nunca en manifiestos, argumentos, informes o conversaciones. Compara el hash de la base original antes y después y registra solo el resultado de conservación.

## Ensayo inicial exacto: ocho casos sintéticos

[Entradas completas](../../evals/pilot-real/cases.jsonl), [manifiesto Vercel aprobado](../../evals/pilot-real/manifest-vercel.json) y [registro de autorización](../../evals/reports/pilot-real-vercel-20261003-01/authorization.json). SHA256 del manifiesto: `ff5a3056a6d13d7bc8a9c8baae559b002e201cc235be1a3aaa3cc4cd9e6e5b9d`. Los archivos `manifest.json` y `authorization.pending.json` conservan la propuesta directa anterior; no son el alcance aprobado activo.

| ID | Comprobación | Alcance de la expectativa |
| --- | --- | --- |
| arithmetic | 2 + 2, respuesta 4 | Resultado exacto; la revisión humana continúa separada. |
| blocked | Marcador ficticio de credencial | Bloqueo local antes de cualquier salida. |
| consent-pending | Marcador ficticio de consentimiento | Cero llamadas mientras está pendiente. |
| consent-accepted | Mismo marcador, confirmación firmada | Confirma solo la petición sintética declarada; no amplía destinos. |
| document-success | Contrato ficticio con plazo de 17 días | Respuesta documental, cita y cobertura. |
| evidence-absent | Penalización ausente de la fuente | Aviso y respuesta limitada; pertinencia revisada por una persona. |
| verification-failed | Cita editada por el fixture offline | Demuestra rechazo en simulación; en vivo no se fuerza un fallo. |
| second-attempt | Fixture económico dice 30 días frente a 17 | Router puede corregir una vez en simulación; un proveedor vivo puede acertar a la primera. |

Cada caso se ensaya en economy, strong y router: 24 recorridos con idénticos datos y restricciones. Se fija semilla `20261003`, orden mezclado reproducible, límite de 512 tokens de salida, 16.000 bytes de datos de entrada por caso, plazo de 90 segundos y presupuesto de 0,15 USD por petición. Economy/strong permiten una generación; router permite dos. Las calidades configuradas 0,6/0,95 y los umbrales 0,8 son valores provisionales, **no resultados de calibración**.

## Destinos y modelos del ensayo autorizado

| Función | Destino exacto | Modelo / versión | Tarifa de referencia USD por millón |
| --- | --- | --- | --- |
| Generación económica | `https://api.deepseek.com` | API `deepseek-flash`; versión publicada DeepSeek-V4.1-Flash | Entrada sin caché pico 0,30; salida pico 1,20. |
| Generación fuerte | mismo destino | API `deepseek-v4-pro`; versión publicada DeepSeek-V4-Pro-0813 | Entrada sin caché pico 1,32; salida pico 3,96. |
| Clasificación y juez | `https://ai-gateway.vercel.sh/typesafe/v1/systemone` | Alias `typesafe-ai/jev`, limitado al proveedor `typesafe-ai` | Entrada 0,042; salida 0. |
| Enmascarado | Proceso local en CPU, sin endpoint HTTP | `regulai-local-v2`, spaCy 3.8.16, `xx_ent_wiki_sm` 3.8.0 y patrones | Coste de API 0 USD; cómputo/operación sin valorar. |

Referencias oficiales consultadas el 3 de octubre: [DeepSeek, modelos y tarifas](https://api-docs.deepseek.com/quick_start/pricing/), [catálogo exacto del Gateway](https://ai-gateway.vercel.sh/v1/models), [API compatible TypeSafe](https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe) y [restricción de proveedores](https://vercel.com/docs/ai-gateway/models-and-providers/provider-options). Se usa `providerOptions.gateway.only=[typesafe-ai]`, sin fallback de modelo. La tarifa del catálogo es 0,000000042 USD por token de entrada; la página comercial la redondea. Sus declaraciones no constituyen garantía de retención cero.

Se utiliza la tarifa pico sin caché de DeepSeek como estimación conservadora. La generación conserva las temperaturas del servicio compartido: 0,6 para entrada general y 0,1 cuando hay documento; ambos valores y `thinking: disabled` están fijados y contrastados con el cuerpo HTTP del SDK. El transporte directo TypeSafe continúa disponible como una combinación exacta alternativa, pero este ensayo no lo autoriza ni lo utiliza.

DeepSeek publica versiones, pero sus identificadores de API son alias móviles. El Gateway también expone un alias Jev sin versión inmutable subyacente. Se conservan esa limitación y el modelo comunicado; un identificador efectivo inesperado o ausente detiene la evaluación. Si el proveedor mantiene el alias mientras cambia los pesos, ese cambio no se detecta solo con la respuesta. Las tarifas se revisaron el mismo día; no se presenta como una comparación plenamente reproducible de pesos.

## Detector local y límites de su validación

La propuesta usa `ObfuscationConfig.backend=local`, `detect=both`, idioma vacío (español/inglés admitidos), URL vacía y cota API explícita `0`. El detector procesa lotes completos, reconoce entidades con spaCy y aplica patrones de PII/secretos. No llama a DeepSeek para enmascarar, no arranca un servicio HTTP ni descarga modelos durante las peticiones. Si falta el modelo, cambia su identidad o falla la transformación, el servicio se detiene; no hay fallback externo.

El manifiesto fija el hash SHA-256 del wheel `6f3c4b853852ea9e9d2dc76cc950dddb10a7e4c42d813308caefe6c5e8be2f0a` y el hash observado de los datos instalados `4f5b7a5c5baf29c9e940befeb1f02a3021acc22806e3c1cbcef48e2078a2477a`, además de versiones y hash del módulo. `detector_metadata()` revisa archivos/versiones sin red ni carga de NLP. Los [metadatos oficiales del modelo](https://raw.githubusercontent.com/explosion/spacy-models/master/meta/xx_ent_wiki_sm-3.8.0.json) documentan versión, licencia MIT y procedencia WikiNER; [spaCy](https://spacy.io/usage/models) documenta la instalación de paquetes versionados. Las fuentes se revisaron el 3 de octubre de 2026.

La eliminación es heurística: puede omitir información sensible o marcar texto inocuo, y puede cambiar citas/respuestas. Las pruebas sintéticas de transporte demuestran el tratamiento de esos ejemplos, **no anonimización completa ni precisión empresarial**. Casos, rúbricas, etiquetas y umbrales permanecen congelados; cualquier fallo del banco causado por el detector se conserva y se informa.

La aplicación del detector al banco histórico de 50 casos produjo seis discrepancias literales, conservadas en `legacy-local-01`: los nombres de `multi-constraint-es` se ocultan y «Único» en `duplicate-request` se marca como persona. El segundo es un falso positivo contextual. No se han ajustado el detector ni las etiquetas para esos ejemplos. Ese banco conserva su fixture HTTP de identidad como regresión del contrato original; los nuevos bancos de ocho y 24 casos y la demo usan el detector real. El fixture HTTP no acredita eliminación de PII.

El original se procesa localmente. DeepSeek y Jev son los únicos destinos externos de la propuesta y reciben el resultado del enmascarado. Los marcadores bloqueados por YARA no salen a ningún destino. Restricted permanece bloqueado. El backend HTTP se conserva para configuraciones anteriores y pruebas de compatibilidad, pero no forma parte de estos manifiestos ni de su solicitud de aprobación. No se concede permiso para publicar, desplegar, comprar créditos o contactar a un proveedor.

## Contabilidad, parada y recuperación

Cada transformación de máscara y llamada de clasificación, generación o juez obtiene una reserva SQLite **antes** del transporte/cómputo, después de persistir su intención en la ficha. La máscara local deja una entrada `transport=local`, coste API 0 y procedencia `configured_zero`; sus transformaciones no cuentan como llamadas externas. Se registran también fallos, descartes y los dos intentos. Las transacciones del ledger se cierran antes de la red. El lock común evita solapar los dos comandos; una reserva también se serializa atómicamente.

Se distinguen costes calculados por tarifa, costes comunicados por el proveedor y reservas inciertas. Una estimación barata no libera su reserva conservadora. Un timeout o un error externo sin factura no equivale a cero. Solo un importe comunicado válido, cero API demostrado para cómputo local, o una llamada demostrablemente no iniciada permiten liquidar según esos datos. Un fallo local puede dejar resultado de cómputo incierto y a la vez coste de API conocido igual a cero. Si el importe externo observado supera la cota, se conserva y se bloquean las llamadas posteriores. Las cotas por llamada son 0,05 USD de generación y 0,003 USD de clasificación/verificación; el saldo conjunto nunca se amplía para terminar un banco.

El techo es un control local de admisión sustentado en las cotas revisadas; no garantiza que un proveedor nunca facture por encima de ellas. No se hacen recargas ni compras. Si ocurre una discrepancia, un fallo de contrato/transporte, deriva de modelo, revocación, presupuesto insuficiente o control fallido, se para el banco y se conservan resultados parciales. No se repite automáticamente un resultado incierto.

La carpeta nueva contiene plan, casos y rúbrica congelados, resultados JSONL, recibos, respuestas sintéticas de cada generación —sin razonamiento privado—, CSV/JSON/Markdown agregados, snapshot del ledger y plantilla de revisión vacía. Cada caso terminado se escribe y sincroniza en un diario incremental; el ledger conserva incluso una llamada que muera antes del informe. Un proceso interrumpido puede dejar lock: comprobar que terminó, conservar archivos, revisar reservas y retirar manualmente el lock únicamente tras esa revisión. Nunca borrar/recrear el ledger para conseguir presupuesto nuevo. Una aprobación modificada no renueva ni reemplaza implícitamente la autorización ya ligada al ledger.

## Calibración humana inicial local: dos personas y 0 USD de APIs

[Banco propuesto](../../evals/pilot-human/cases.jsonl): 24 casos, 12 desarrollo y 12 reservados, español/inglés, cálculo, contratos, extracción, resumen, evidencia ausente, contradicciones, sensibilidad, consentimiento e inyección. Es una propuesta sintética de cobertura, **no representatividad validada de un uso empresarial**. Una persona conocedora del dominio y otra revisora independiente deben validar representatividad y referencias; nombres, fechas y revisiones están vacíos.

Las [referencias de desarrollo](../../evals/pilot-human/development-labels.pending.jsonl) y las [reservadas](../../evals/pilot-human/reserved-labels.pending.jsonl) son borradores separados. El runner comprueba hashes, pero no usa sus etiquetas en prompts, respuestas o puntuaciones. Se fijan las etiquetas humanas antes de comparar modelos vivos. Los casos reservados se abren tras congelar respuestas; si sirven para ajustar umbrales, dejan de ser reservados y se necesita otro conjunto. No bajar umbrales para forzar un recorrido exitoso.

Dos sesiones locales propuestas: primero acordar la [rúbrica](../../evals/pilot-human/rubric.md) y adjudicar desacuerdos solo en desarrollo; después revisar el recorrido y la comprensión de bloqueo, consentimiento, cobertura, citas y coste usando resultados offline claramente rotulados. Esas sesiones preparan etiquetas y comprensión; no miden precisión de modelos vivos. La calibración real vendrá después con autorización y dependencias resueltas.

Cada revisión exige identidad, fecha con zona horaria, razón y hash de la fila original. El agregador rechaza duplicados, filas desconocidas o hashes cambiados. Acierto, abstención correcta, cobertura, sensibilidad/falsos positivos y negativos, citas y cambios del segundo intento se muestran con denominadores explícitos. Coste por respuesta correcta queda `null` hasta revisión completa y ausencia de costes desconocidos; se separan cocientes estimados y comunicados. p50/p95 incluyen n y no son SLA. No se ha rellenado ninguna revisión ni anunciado calidad/ahorro.

## Comandos locales

Elegir siempre directorios nuevos:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py smoke_ai --settings=regulai.test_settings --output evals/reports/pilot-smoke-nuevo
rtk proxy .venv/Scripts/python.exe regulai/manage.py evaluate_ai --settings=regulai.test_settings --manifest evals/pilot-human/manifest.json --output evals/reports/pilot-human-nuevo
rtk proxy .venv/Scripts/python.exe regulai/manage.py smoke_ai --settings=regulai.test_settings --preflight --authorization evals/pilot-real/authorization.pending.json --output evals/reports/no-se-crea
```

Tras revisar cualquier cambio de código/datos/tarifas, preparar un manifiesto **nuevo**, comparar el diff y obtener una aprobación nueva ligada a sus hashes; este script no aprueba ni contacta con proveedores:

```powershell
rtk proxy .venv/Scripts/python.exe scripts/prepare_pilot_manifest.py --manifest evals/pilot-real/manifest.json --output evals/pilot-real/manifest-revisado.json
```

El ensayo concreto usa el puente versionado `evals/reports/pilot-real-vercel-20261003-01/run_authorized.py`, primero con `--preflight` y después una vez con `--real`. Rechaza sobrescribir resultados o cambiar manifiesto/aprobación tras el preflight. La disponibilidad de credenciales no demuestra éxito de integración: el resultado vivo queda en su informe. El registro aprobado cubre solamente el hash Vercel citado; no habilita el banco humano ni una repetición automática. No ejecutar el modo real como parte del arranque ordinario.

Cuando personas reales completen una copia de la plantilla de resultados:

```powershell
rtk proxy .venv/Scripts/python.exe scripts/pilot_human_report.py --results RUTA/results.jsonl --reviews RUTA/revisiones-humanas.json --output RUTA/revision-nueva
```

## Estado de aceptación

Lote offline conservado: [24+72 recorridos con detector v2](../../evals/reports/pilot-local-final-20261003-01/README.md), con fuentes/runtime del candidato `d63731a`. Manifiestos SHA256 `12aecafee1351be7584791db4f4e0d22d9f522abb7552bdce7af804e2525c1ed` (inicial) y `82e94e25bbf0ea512e82c925884e57ca85a8cd6b693be86907ecd9c31f349665` (humano). Se conservan como snapshots y no se reescriben al añadir la ruta Vercel. Para otro entorno o para el banco humano futuro se prepara/revisa otro manifiesto; no ignorar `source_changed`.

El seguimiento vigente del ensayo autorizado está en la [tarea 29](tareas/29-ensayo-autorizado-vercel.md) y su [carpeta de evidencias](../../evals/reports/pilot-real-vercel-20261003-01/). Las dos comprobaciones previas se distinguen: la directa quedó bloqueada por falta de credencial, sin ledger ni llamadas; la de Vercel es satisfactoria y conserva el hash de la base del usuario.

Las [tareas 23](tareas/23-recorrido-real.md) y [24](tareas/24-calibracion-humana.md) distinguen preparación comprobada de validación viva/humana pendiente. Los resultados del detector están en [evidencia local nueva](../../evals/reports/pilot-evaluation-local-20261003-01/README.md); el [ensayo anterior](../../evals/reports/pilot-evaluation-20261003-01/README.md) conserva su máscara simulada. Las cifras y la autorización histórica permanecen en la tarea 08 y no se contabilizan como ejecución de este piloto.

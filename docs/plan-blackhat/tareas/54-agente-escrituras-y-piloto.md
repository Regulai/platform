# 54. Escritura externa aprobada y cierre del piloto

Estado: implementada y verificada localmente el 13 de octubre de 2026; preparación de piloto completada, activación real y evaluación generativa pendientes.
Blocked by: [53](53-agente-mcp-lectura.md).
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), recuperación/aprobación del [plan](../../plan-capacidades-agenticas-regulay-2026-10-07.md) y [corpus documental](../../investigacion-prompts-skills-documentales-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 54. Lee AGENTS.md, la guía de ejecución y la
evidencia de 48–53. No confundas un test simulado con la activación de un piloto.

Añade una sola escritura al conector documental de la 53: guardar/exportar una
revisión verificada en una carpeta autorizada. No añadas correo, publicación
pública, borrados remotos ni varios tipos de acción para demostrar lo mismo.

Usa la interrupción/checkpoint oficial de Deep Agents para presentar una propuesta
concreta antes del efecto: cuenta, carpeta, nombre, revisión, contenido/hash y
si crea o sustituye un archivo. La aprobación durable pertenece a Regulay y se
vincula a esos argumentos, usuario, empresa, ejecución, permisos y caducidad.
Revalida al ejecutar. Cambiar el destino o los bytes invalida la aprobación.
Las lecturas y cálculos locales continúan sin aprobación adicional.

Registra intención antes del efecto y resultado después. Usa una clave idempotente
del destino o reconciliación. Si un timeout deja incierto si se escribió, no
repitas a ciegas. Reanudar dos veces una aprobación no puede duplicar el archivo.
Un checkpoint conserva estado, no permisos. No construyas un motor de workflows.

Completa los casos operativos sobre el backend real: caída/reinicio del ejecutor,
pérdida de concesión, cancelación, reconexión SSE, pool agotado, retención/borrado
y dos usuarios/empresas. Comprueba que un sandbox liberado no reaparece con datos
previos, que la revocación corta los pasos siguientes y que desactivar el modo
impide ejecuciones nuevas sin borrar el historial ni descargas aún autorizadas.

Ejecuta el corpus local de 16 tareas y registra fallos, reparaciones, tiempos,
integridad y previews de los cuatro formatos. Prepara la evaluación generativa
con entradas/configuración repetibles. Si no existe autorización específica para
modelos de pago, no la ejecutes y deja esa validación pendiente: fixtures y modelos
simulados no prueban que la calidad iguale a Claude.

Prueba la escritura remota mediante transporte simulado; no escribas en una
cuenta real ni publiques resultados sin autorización. Ejecuta las regresiones
finales de las tres entradas, autorización de red, migraciones y dinero. No
vuelvas a introducir topes de generación retirados por la tarea 44 para aprobar
un test de presupuesto.

Deja un procedimiento breve de arranque, parada, recuperación y reversión con las
configuraciones necesarias. Resume evidencia, limitaciones y condiciones aún
pendientes. Mantén desactivado lo no validado. No hagas push ni despliegues.
```

## Aceptación

- Una escritura concreta se revisa y aprueba antes del efecto; argumentos/versiones cambiados invalidan la aprobación.
- Reinicios, reintentos y doble reanudación no duplican efectos; resultados inciertos se reconcilian.
- Aislamiento, pool, cancelación, retención y revocación probados en el backend real.
- Evidencia por formato y métricas propias, distinguiendo validación de runtime y calidad del modelo.
- Reversión y operación documentadas; ninguna cuenta real activada con una prueba pendiente o autorización supuesta.

## Verificación observada

Se inició después de verificar y guardar la 53 en el commit local `5aa8ed7`.
Se añade exclusivamente **crear un archivo nuevo de una revisión verificada en
la carpeta concedida de Drive**. No hay sustitución, borrado remoto ni otros
conectores. El cliente MCP, gobierno, ResultGate, artefactos privados y diseño
de DOCX/PDF/PPTX de 51–52 se reutilizan.

La propuesta procede del interrupt oficial de Deep Agents. `SqliteSaver` guarda
el thread por ejecución en el ejecutor privado, persistiendo el call ID entre
caída y reanudación. Regulay conserva `AgentExport`: propuesta cifrada,
vinculación de argumentos/usuario/empresa/ejecución/autorización/concesión,
caducidad de diez minutos, decisión, intención, ID remoto cifrado y resultado.
El modelo recibe referencias opacas, nombre protegido y SHA; no cuenta, carpeta,
documento original, token ni bytes finales. La aprobación se revalida antes del
efecto y antes de completar el recibo. Cambios de contenido o destino la invalidan.

La intención se reclama atómicamente en PostgreSQL antes de crear. Drive reserva
un ID y la única creación usa ese ID; las reanudaciones consultan y verifican
carpeta, appProperty SHA y SHA de bytes descargados. Un timeout después del
efecto se reconcilia sin otro POST. Ausencia/ambigüedad no autoriza reintentar.
No se mantiene una transacción DB durante llamadas externas. Una revocación
durante el efecto conserva el resultado real y retira la entrega posterior.

Migración `0040_agent_approved_export`: conserva conexiones anteriores con
`write_enabled=False`. Flags `REGULAY_AGENT_MCP_WRITES_ENABLED=False`, MCP y
agente deshabilitados por defecto. La configuración administrada pasa a revisión
2; lectura antigua compatible, catálogo completo fijado y escritura concedida
por separado. Las etiquetas de cuenta/carpeta requieren provisión administrativa
contrastada; el transporte valida identidad, carpeta y capacidad por operación.

### Comandos, versiones y resultados

[Evidencia](../../../evals/reports/task54-export-20261013/) y
[procedimiento de arranque/parada/recuperación/rollback](../../../ops/agent_chat/EXPORT_RUNBOOK.md).
Todos los comandos del host empiezan por `rtk`; PostgreSQL aislado real, Drive
simulado y ninguna llamada de pago o escritura externa real.

- `rtk proxy .venv/Scripts/python.exe ops/agent_chat/record.py --output-dir evals/reports/task54-export-20261013 agent-final rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_exports front.test_agent_mcp front.test_agent_chat front.test_agent_inference front.test_agent_state front.test_agent_documents front.test_agent_presentations --settings=regulai.agent_chat_test_settings --noinput`: **73 OK**, 91,250 s totales. Tres entradas HTTP, argumentos/bytes/versiones/caducidad, cancelación, revocación, dos empresas, mode-off con descargas, retención, migración 0039↔0040 y solapamiento real de dos transacciones con un único POST.
- `... governance-final ... test front.test_pipeline front.test_pipeline_privacy front.test_required_masking front.test_ai_connections front.test_difficulty_routing front.test_local_masking_integration front.test_state front.test_smoke front.test_evaluation_budget front.test_calibration_budget front.test_backend_hardening front.test_connectors front.test_frontend_chat front.test_frontend_resources --settings=regulai.test_settings --noinput`: **196 OK**, 62,313 s. Frontera real del SDK OpenAI hacia transporte simulado, privacidad/estado/dinero y límites del proveedor. No se añaden topes de generación.
- Tras corregir la etiqueta del recibo final, `... export-receipt-final ... test front.test_agent_exports ...`: **13 OK**, 26,985 s; el recibo de exportación confirmado queda vinculado a la verificación y SHA de la revisión. No se alteran documentos para reparar el corpus.
- `rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_chat/verify_export_sdk.py --output evals/reports/task54-export-20261013/sdk`: interrupt/HITL y checkpoint oficiales, cierre/reapertura SQLite, call ID conservado, una ejecución de herramienta y `delete_thread`: **OK**. Este ensayo simula modelo/sandbox y no se cuenta como prueba E2B. Deep Agents **0.6.12**, LangGraph **1.2.14**, checkpoint-sqlite **3.0.3**, langchain-e2b **0.0.6**, E2B **2.53.1**, MCP **1.26.0**. Extensión fijada con hashes: aiosqlite **0.22.1**, sqlite-vec **0.1.9**; lock base de 48 conservado, build y `pip check` correctos.
- `bundle.py`, `remote.py start_mcp_lab.sh`, `start_export_worker.sh`, `run_export_live.sh`: **HTTP → gobierno → Deep Agents oficial → E2B real → Drive simulado OK**. `SIGKILL` mientras espera aprobación, lease real caducada y segunda claim del mismo trabajo, cero efectos antes de aprobar, aprobación duplicada y **un archivo** con SHA idéntico. SSE desconectado/reconectado conserva cursor. Timeout tras creación → interrupción → nueva tentativa → GET de reconciliación, sin otra creación. Cancelación, revocación, dos usuarios/empresas, mode-off e historial/descarga autorizados, borrado local y eliminación de checkpoints oficiales. [Resultado](../../../evals/reports/task54-export-20261013/final-live/task54-live/report.json).
- `remote.py run_ops54.sh`: **14 comprobaciones operativas OK**: envío duplicado, SSE, CSV/XLSX con pandas/Calc reales, total 375 céntimos y cero/negativos, edición localizada y base obsoleta 409, cancelación/perfil revocado, aislamiento y muerte del worker durante inferencia sin replay. Pool real: agotamiento devuelve ningún slot; liberar destruye sandbox `i837m0n2pchz9gitqu94u`, reemplazo limpio `itw1o6tt6ro9f3dmf0pkt`, marcador anterior ausente. Preparación 0,755/0,764 s. [Log](../../../evals/reports/task54-export-20261013/operational.log).
- `remote.py refresh_executor.sh`: **sockets reales OK** con controles positivos IPv4/IPv6 antes/después; ejecutor y E2B sin receptor ajeno, DB ni metadatos. UID 1000, capacidades cero, input de solo lectura. Continúa **NoNewPrivs=0 dentro de Firecracker**, límite histórico de 48; no se declara solucionado. [Evidencia](../../../evals/reports/task54-export-20261013/executor-network-build.log).
- `makemigrations --check --dry-run`: sin cambios; `node --check regulai/static/js/agent-chat.js`: correcto; `git diff --check -- regulai ops docs`: limpio en código y documentación. Los logs crudos conservan sus finales de línea/espacios originales.
- `verify_evidence54.py`: **257 hashes de archivos del corpus coinciden con los blobs staged de Git**, incluyendo CSV/JSON; atributos `-text` preservan los bytes en futuros checkouts.
- Inspección UI escritorio y móvil 472×800: destino/nombre/revisión/bytes/SHA/efecto/caducidad/aprobar/rechazar visibles; sin desbordamiento horizontal (457=457). Confirmación tras aprobación real de UI contra fixture: un nuevo upload simulado, estado y recibo verificados. Dos prompts por recorrido, sin marcadores privados, imágenes inline, IDs externos ni cuenta/carpeta. [Prueba](../../../evals/reports/task54-export-20261013/ui-live/task54-ui-final/ui-proof.json), [privacidad](../../../evals/reports/task54-export-20261013/ui-live/task54-ui-final/report.json), [captura](../../../evals/reports/task54-export-20261013/ui-confirmed-final-desktop.jpg).

### Corpus local de 16 tareas

`remote.py run_corpus54.sh` y `run_corpus54_second.sh` ejecutan programas
documentales reales en la imagen Linux fijada, sin red, y un verificador en un
proceso separado. **No son 16 recorridos generativos ni 16 ejecuciones E2B**.
[Manifest final](../../../evals/reports/task54-export-20261013/final-live/task54-corpus2/report.json)
retiene comandos, fallos, tiempos por fase/caso, hashes, campos y archivos.

| Formato | Correctos | No soportados | Fallos observados |
|---|---|---|---|
| DOCX | Plantilla, tabla de 65 filas en cinco páginas, título localizado | Entrada DOCX con comentarios (`input_format_unsupported`); control de cambios queda fuera del contrato de entrada | 0 |
| XLSX | 0 | Identificadores/fechas y columnas arbitrarias, fórmula entre hojas/nulos, rellenado de fórmula | Gráfico/impresión: fórmulas y total correctos, pero el gráfico solicitado no se conserva |
| PPTX | Plantilla/masters corporativos, presentación nueva, edición localizada | Texto largo combinado con tablas/gráficos: límite documental existente `presentation_text_unsupported` | 0 |
| PDF | PDF español de dos páginas, tabla y fuentes incrustadas | AcroForm, OCR de PDF escaneado, redacción de contenido existente (`input_format_unsupported`) | 0 |

Total **7 correctos, 8 no soportados, 1 fallo**, cero reparaciones de producto,
cero llamadas de modelo y coste 0. Los 21 previews de los ocho casos con salida
fueron inspeccionados a resolución original mediante galerías: texto español,
tablas, márgenes y gráficos editables de PPTX legibles; estilos de DOCX conservados.
El gráfico ausente de XLSX permanece como fallo. [Revisión visual vinculada a los hashes](../../../evals/reports/task54-export-20261013/visual-review.json).
Los helpers acotados no acreditan edición documental general ni calidad de Claude.

Se conservan intentos fallidos: fixture inicial con URL de conversación incorrecta,
nombre de módulo de pruebas inexistente, primer controlador no incluido en imagen,
warnings de caché de fuentes de solo lectura y selección diagnóstica de ledger
sin excluir fechas nulas y carrera entre `docker stop` y retirada automática del contenedor
al limpiar. Se corrigieron los harnesses y se repitieron los casos
afectados. Ninguno se cuenta como éxito; el fallo de gráfico y los ocho rechazos
de producto siguen presentes en el resultado final.

### Condiciones pendientes

[Plan generativo reproducible](../../../evals/reports/task54-export-20261013/final-live/task54-corpus2/generative-plan.json):
16 entradas con hashes, tres repeticiones, rúbrica, hashes de programas/prompts,
temperatura 0 y límites del proveedor. Proveedor/modelo concreto, precios y
autorización de gasto siguen pendientes; no se ha ejecutado ni atribuido calidad
generativa a simulaciones.

Cuenta OAuth de usuario/empresa y carpeta real, etiquetas contrastadas y prueba
de consentimiento/alcance siguen pendientes. No se activan cuentas, piloto ni
capacidades documentales no verificadas. No hay push, despliegue, publicación,
escritura externa real o llamada pagada. La parada conserva evidencias y
volúmenes de E2B; los tres PDFs ajenos permanecen sin cambios. `cleanup_export_lab.sh`
terminó correctamente: contenedores, túneles, PostgreSQL aislado y red de laboratorio
detenidos/retirados; VM apagada normalmente, volumen e imágenes conservados.

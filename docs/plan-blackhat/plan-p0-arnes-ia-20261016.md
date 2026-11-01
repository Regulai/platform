# Plan técnico: ocho P0 del arnés de IA

**Estado:** propuesta ejecutable; no implementada. **Fecha:** 16 de octubre de 2026. **Base inspeccionada:** `a16d03984c0a97f400e21093f81eda04a5222c2b`. Este documento es la única entrega de esta tarea; no abre tickets ni autoriza despliegues o llamadas de pago.

**Resultado exigido:** «Madrid → crea HTML → descárgalo → cambia el color» conserva contexto y bytes autorizados, incluso al recargar o reiniciar el worker; una simulación no impide atender otra conversación dentro de la capacidad admitida. Una ejecución solo anuncia una entrega de archivo si existe una revisión accesible. Cada salida externa conserva las comprobaciones, el registro previo y la contabilidad actuales.

Se mantienen Django, PostgreSQL, Deep Agents/LangGraph instalados, el ejecutor aislado y la pasarela de regulAI. No se incorporan React, Redis, Celery, memoria vectorial, microservicios ni otro framework de agentes. Rigen el [vocabulario y decisiones compartidas](README.md), la [documentación de dominio](../agents/domain.md) y la [organización de tareas](../agents/issue-tracker.md). Las futuras tareas locales podrán enlazar este plan sin duplicarlo.

## 1. Diagnóstico actualizado

### Alcance y evidencia

Se han leído el [informe anterior](../../output/harness-audit-20261016/INFORME.md), los [registros de los chats 5 y 6](../../output/harness-audit-20261016/live-evidence.json), la [evidencia del worker](../../output/harness-audit-20261016/worker-evidence.json), las [sondas](../../output/harness-audit-20261016/offline-probes.json) y sus scripts, además del código que enlaza las tres entradas HTTP con el proveedor. La inspección no altera las conversaciones ni vuelve a ejecutar sus peticiones.

El HEAD posterior al informe cambia la aceptación opcional de un origen de túnel, no el arnés. Se han recalculado los SHA-256 de los once archivos recogidos en `live-evidence.json`: **los once coinciden** con el checkout actual. Se ha repetido `rtk proxy python output/harness-audit-20261016/probe_contracts_offline.py`: reproduce los contratos vacíos para HTML/CSV/ZIP y la ausencia de control de pensamiento/límite de salida en la sonda; cero llamadas de red. Es una sonda sobre el cliente sustituido, no una captura HTTP histórica.

| Hallazgo | Comprobación actual | Clasificación e implicación |
| --- | --- | --- |
| El agente no marca historial reutilizable | `professional.complete()` crea `Message`/`Response`, pero no `history_eligible` ni `history_digest`; `chat_service.authorized_history()` los exige | Hecho en código. Arreglar solo la selección de mensajes no basta |
| El siguiente turno empieza sin los anteriores | `professional_worker.run_professional()` inicia `[HumanMessage(granted['message'])]`; `service.infer()` combina instrucciones y `request.messages`. `_context()` comprueba historial para política, pero no lo inyecta | Hecho en código. Comprobar autorización no equivale a enviar contexto |
| HTML anterior conservado pero inaccesible al siguiente turno | El checkpoint histórico del turno de creación contiene `output/madrid_landing.html`, 13.269 bytes; el siguiente no contiene archivos. `checkpoints.load()` pertenece a una ejecución y su watermark | Hecho histórico más causa vigente. No se ha recuperado ni publicado ese archivo en esta tarea |
| HTML no publicable y petición mal interpretada | `professional_artifacts.MIMES` no contiene HTML/CSS/SVG/ZIP; `request_contract.interpret(..., general=True)` solo identifica los formatos documentales previstos. `FILE_REQUEST` tampoco cubre HTML/landing | Hecho en código y sonda. Hoy `formats=[]` permite terminar sin el archivo solicitado |
| Una tarea bloqueó otra conversación | `worker.run()` reclama después de obtener sandbox y llama `run_job()` síncronamente. `CleanPool` tiene una plaza y no prepara otra mientras está prestada | Hecho en código; la descarga histórica esperó 211,83 s. La saturación de CPU o el límite del proveedor no se han aislado como causas adicionales |
| `reasoning=False` no desactiva explícitamente pensamiento | `OpenAIConnector.chat()` usa el booleano para temperatura y nombre del límite de salida; no genera `thinking.type=disabled`. `service.infer()` admite límite `None` con `provider_managed` | Hecho reproducido offline. Que DeepSeek aplicase su valor predeterminado en aquella llamada es una inferencia, no una captura de su cuerpo HTTP |
| El rótulo del sandbox incluye generación | Los eventos de reserva y la siguiente actividad abarcan la primera llamada al modelo; la UI calcula intervalos entre eventos agrupados | Hecho histórico y mecanismo vigente. No atribuir ese intervalo entero al arranque de la microVM |
| Ya existen revisiones y registro idempotente | `AgentArtifact`: ID, logical_id, revision, base, SHA, contenido cifrado. `AgentInference`/`AgentOperation`: claves únicas; `jobs.claim()`: `skip_locked`, claim_id y lease; restricción `agent_one_writer` | Hecho. Extender estos mecanismos, sin crear una segunda persistencia o cola |
| La descarga depende indebidamente del éxito de toda la ejecución | `views.download()`, `jobs.latest()` y `_snapshot()` filtran por ejecución completada | Hecho. Un resultado parcial verificado necesitará una autorización de entrega independiente |
| La compactación tiene un reintento oculto relevante | La librería instalada usa `model.with_retry()` para resumir; `RegulayModel._generate()` genera un call_id nuevo en cada invocación | Hecho en código. Riesgo de repetir una compactación tras un resultado incierto; no hay evidencia de un doble cobro ocurrido en los chats estudiados |

Referencias locales principales: [chat_service.py](../../regulai/front/chat_service.py), [professional.py](../../regulai/front/agents/professional.py), [professional_worker.py](../../regulai/front/agents/professional_worker.py), [service.py](../../regulai/front/agents/service.py), [adapter.py](../../regulai/front/agents/adapter.py), [checkpoints.py](../../regulai/front/agents/checkpoints.py), [jobs.py](../../regulai/front/agents/jobs.py), [records.py](../../regulai/front/agents/records.py), [views.py](../../regulai/front/agents/views.py).

### Lo medido y lo pendiente

| Ejecución histórica | Total | Cola | Proveedor | Herramientas |
| --- | ---: | ---: | ---: | ---: |
| Chat 5: pregunta de Madrid | 3,97 s | 0,31 s | 1 llamada | Reserva sandbox sin necesitarlo |
| Chat 5: HTML | 39,02 s | 0,90 s | 4 llamadas | Termina sin artefacto |
| Chat 6: simulación | 230,64 s | 7,88 s | 180,99 s en 13 llamadas | 27,45 s; cálculo principal 19,10 s |
| Chat 5: descarga | 219,69 s | 211,83 s | 2 llamadas | No recupera archivo/contexto |

En el chat 6 quedan 14,32 s sin desglose suficiente entre preparación, protección, checkpoints y persistencia. Los 0,226 s de 45 enmascarados no representan toda la pasarela. La primera llamada duró 86,803 s y declaró 14.493 tokens de salida; no existe separación suficiente para atribuirlos a pensamiento. Entre reserva y primera llamada transcurrieron aproximadamente 1,96 s: la etiqueta de unos 89 s de sandbox incluye aquella generación.

Estos son casos individuales, **no p95 ni un A/B**. Quedan por medir capacidad disponible, memoria de host/microVM, coste completo, calidad con pensamiento desactivado y latencias frío/caliente después de implementar. La caché `ProtectedHistory` ya integrada evita reproteger mensajes de una misma ejecución; no conserva turnos ni vuelve a justificar el ahorro histórico de la tarea 59.

## 2. Implementaciones reales seleccionadas

### Pi: procedencia y adaptación limitada

[pi.dev](https://pi.dev/) enlaza el repositorio oficial actual [earendil-works/pi](https://github.com/earendil-works/pi); el antiguo `badlogic/pi-mono` redirige allí. Se clonó con profundidad 1, sin instalar dependencias ni ejecutar el proyecto. Commit leído: **`698a2d23b86a5045dd54554354a5e0cb7e466795`**, fechado el 16/10/2026 a las 17:12:24 +02:00. Copia de consulta fuera del proyecto: `C:\Users\javi\AppData\Local\Temp\regulai-pi-p0-0e186abbcc414a0d99dfc4fe84e29d29`.

Todas las referencias de esta tabla fijan ese commit, no `main`.

| Patrón, archivo y función | Problema que resuelve allí | Adaptación suficiente en regulAI y parte descartada |
| --- | --- | --- |
| [session-manager.ts: buildSessionProjection/buildSessionContext, L542–583](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/session-manager.ts#L542), [sdk.ts: createAgentSession, L411–418](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/sdk.ts#L411) | Reconstruye una proyección y realmente la introduce en el agente | E1: seleccionar pares autorizados de Django e inyectarlos en la frontera del servidor. No copiar JSONL, ramas, nuevo store ni `pi-durable` |
| [agent-session.ts: message_end, L1147–1168](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/agent-session.ts#L1147), [agent-loop.ts: createToolResultMessage, L930–948](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L930) | Conserva mensajes y resultados con toolCallId sin volver a ejecutar herramientas al leerlos | E4/E6: mantener el registro actual de operaciones y resultados; historial entre turnos de usuario con respuestas finales y referencias. No importar razonamiento privado, extensiones ni un log universal |
| [agent-session.ts: _startRun, L1831–1881](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/agent-session.ts#L1831), [agent-loop.ts: runLoop, L163–320](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L163) | Una sesión contiene varias ejecuciones y cada ejecución varios ciclos de modelo/herramientas | Conservar Conversation → Prompt/AgentExecution → AgentInference/AgentOperation. El `turn` interno de Pi se denomina aquí ciclo de inferencia. No copiar steering, colas de follow-up ni su runtime durable |
| [compaction.ts: shouldCompact/findCutPoint/prepareCompaction, L267, L430 y L859](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/compaction/compaction.ts#L267), [agent-session.ts: _checkCompaction, L2962](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/agent-session.ts#L2962) | Reserva espacio y corta contexto en límites coherentes; conservar hechos no exige repetir trabajo completado | E1: ventana de pares completos; E6: compactación de la ejecución existente, gobernada y contabilizada. No copiar sus umbrales, resúmenes de ramas ni llamadas directas al proveedor; no añadir resumen entre turnos para resolver Madrid |
| [agent-loop.ts: runLoop/prepareToolCall, L219 y L708](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L219) | Prepara cada inferencia, valida herramientas y termina ante error/aborto o decisión explícita | E3/E6/E7: comprobaciones en las fronteras existentes, sandbox en la primera operación que lo necesita y entrega verificada por servidor. No incorporar una API genérica de hooks |
| [openai-completions.ts: buildParams, L804–850 y L930–939](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/ai/src/api/openai-completions.ts#L804) | Separa selección de pensamiento de su traducción HTTP; DeepSeek recibe thinking enabled/disabled explícito | E5: opciones efectivas tipadas y prueba del JSON HTTP. No catálogo remoto completo, OAuth, router nuevo ni preferencias globales modificadas |

Su [índice de operaciones de archivos](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/compaction/utils.ts#L12) conserva rutas leídas/escritas, **no revisiones descargables**. E4 necesita bytes, hashes y permisos propios. El [README de Pi](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/README.md#L88) explicita que no incorpora restricciones propias de procesos, archivos, red o credenciales: ningún patrón anterior sustituye la frontera de seguridad de regulAI.

No se consultó OpenCode: no quedó una cuestión concreta de estos P0 que justificara una tercera implementación.

### Runtime realmente instalado

Se consultaron metadatos y código del contenedor existente `regulai-v2-worker` mediante lecturas acotadas: **Deep Agents 0.6.12, LangGraph 1.2.14, LangChain 1.4.3 y langchain-e2b 0.0.6**. No se instaló ni ejecutó un proyecto externo. Las distribuciones no contienen `direct_url.json`; no es correcto atribuirles un commit Git no acreditado. La versión instalada y las referencias de código siguientes son la base de diseño.

`deepagents.create_deep_agent()` ya permite backend, middleware, checkpointer, store, memory y skills. El adaptador actual desactiva subagentes, memoria y skills, y usa `RegulayModel` para que toda inferencia vuelva a Django. Se conserva esa configuración. LangGraph permite persistencia de grafo, pero introducir un `PostgresSaver` además de nuestros checkpoints duplicaría autoridad y registros sin resolver la elegibilidad del historial.

La implementación instalada de summarization usa un evento `_summarization_event` y adapta el contexto del modelo sin reemplazar el historial canónico. `SafeBoundary` guarda hoy solo mensajes y archivo: no conserva ese evento. E6 debe preservar su referencia autorizada al recuperar una ejecución y hacer idempotente el resumidor; no se debe depender de que el grafo «recuerde» automáticamente. El offload de esta implementación puede llamar al backend antes de resumir: E7 debe cubrirlo para que una conversación textual no abra una microVM de forma indirecta.

| Código instalado inspeccionado | Comportamiento y adaptación elegida |
| --- | --- |
| Deep Agents `graph.py:create_deep_agent`, L772–839 | Instala filesystem, compactación y reparación de pares; conservar montaje actual y pasarela, sin usar un segundo checkpointer/store |
| Deep Agents `middleware/filesystem.py:wrap_model_call`, L1890–1896; factories L942–952 | Resuelve backend antes de inferir; una factory que cree VM seguiría siendo anticipada y además está deprecada. E7 usa la instancia WorkspaceSandbox sin recursos hasta autorización |
| Deep Agents `middleware/summarization.py:compute_summarization_defaults`, L261–297; `_apply_event_to_messages`, L820–855; `wrap_model_call`, L1413–1508 | Umbral relativo al perfil, resumen más cola y offload opcional. E1 pasa capacidad residual real; E6 guarda referencia del resumen y E7 permite offload ausente. No copiar el fallback de 170.000 tokens |
| LangChain `agents/middleware/summarization.py`, L356–359 y `_create_summary`, L856–860 | `with_retry()` puede volver a invocar el adaptador. E6 fija identidad de compactación, sin inferencias nuevas para un resultado ya guardado |
| LangGraph `pregel/main.py`, L3069–3078, y `_loop.py` | El límite de recursión cuenta superpasos. E6 mantiene el fusible pero exige contadores de inferencias/herramientas en Django |
| langchain-e2b `sandbox.py:E2BSandbox.__init__` | Asigna atributos, no crea la VM. E7 adapta el backend existente; no necesita otro ejecutor |

Identificadores SHA-256 del código instalado, en `/usr/local/lib/python3.12/site-packages/`:

```text
deepagents/graph.py                          22d4f88d8ae2e3fb78c0bef5f51b4575ba153b475e5e582f8e1886ecf683f570
deepagents/middleware/summarization.py       784ed89a855c9e8263ef548e111c50a0b6889d474f7ef2c4625f100dc31ed8de
deepagents/middleware/filesystem.py          5d7c1ab63317030c504b7fa4c0b9b6c00ea059c546b2dd8344e658df559fa7e1
deepagents/backends/protocol.py              1cda874a12b5588909659773a891ccc551764ca06abe30709b803f83c6827ea7
langchain/agents/middleware/summarization.py 51898a62d0c88c15dfaf399484d966478fc46fcc6b65e6969caa5c20a522d603
langgraph/pregel/main.py                     4240b2969810edca2fd98dde201a7daa941390e4821ea550a4018ab945c5b470
langgraph/pregel/_loop.py                    84dc91f8faaa963ea1f62ba3cd4201bbd3dd336c7817ab019f95ef54da120c65
langchain_e2b/sandbox.py                     a140a2d5f1e53917e69ea9037e0b80edbbcca7ee95b9e84bf929e0d8dfdc7752
```

La versión y estos hashes sustituyen un commit desconocido únicamente para las distribuciones instaladas; Pi sí se inspeccionó en un commit Git acreditado. No se propone actualizar ninguna de ellas para ejecutar este plan.

## 3. Diseño mínimo y contratos comunes

### Tres ámbitos con propietarios claros

| Ámbito | Fuente de verdad | Identidad y reglas |
| --- | --- | --- |
| Conversación | Conversation, Message, Prompt, Response en Django | Propietario y empresa actuales, política vigente; pares user/assistant autorizados, nunca promovidos a system |
| Turno solicitado | Prompt.request_id + AgentExecution | Un registro por petición; una ejecución escritora por conversación; reconexión lee estado, no vuelve a enviar |
| Trabajo interno | AgentInference, AgentOperation, AgentToolResult y checkpoint de la misma ejecución | call_id, digest, attempt y watermark; resultado conocido se reutiliza, resultado incierto no se vuelve a producir automáticamente |
| Archivo | AgentArtifact y manifiesto cifrado en AgentInput | ID de revisión, logical_id, base, SHA-256, tamaño, nombre, procedencia y conversación; permisos se vuelven a comprobar |

La aplicación decide contexto, herramientas permitidas, límites y referencias de entrega. El worker nunca elige otra conversación, otro proveedor, ni concede permisos. La configuración de una ejecución se fija en `job` y se vincula a `authorization_digest`; una revocación detiene nuevas salidas y retiene respuestas no autorizadas. Los mensajes, resúmenes y resultados de herramientas siguen siendo contenido no confiable.

### Historial y límite de contexto

`authorized_history()` sigue siendo la selección canónica. E1 devuelve también IDs/digests y omisiones para la ruta del agente, preservando la interfaz del chat normal. `service.infer()` añade esa selección **una sola vez** delante de los mensajes de la ejecución para generación/visión. El bootstrap no duplica ese prefijo en el estado del grafo. Para `purpose=compaction` no se añade: el resumen es solo de la ejecución; añadirlo también allí duplicaría historia al volver a generar.

La ventana selecciona pares completos recientes dentro de `AIConfig.history.max_turns/max_bytes`, añade únicamente referencias de archivo autorizadas y reserva espacio para sistema, esquema de herramientas, ejecución y salida. Si no cabe un turno, no se corta a mitad ni se sustituuye por instrucciones inventadas: se reduce la ventana y se registra la omisión; si la pregunta depende de lo omitido, se pide el fragmento o referencia concreta. No se añade un resumidor de conversaciones en estos P0.

La capacidad comunicada al grafo debe descontar el prefijo añadido por Django y proceder del modelo configurado, sin el `200000/8000` fijo actual. Django vuelve a calcular el límite sobre el payload completo protegido antes de enviar. El tamaño es una cota conservadora, no una afirmación de conteo exacto del tokenizer del proveedor.

### Archivo guardado, archivo verificable y entrega

Se añade un único registro tabular `artifact_formats.py` con extensión canónica/alias, MIME, familia de inspección, capacidad de render y reglas de cobertura. Una entrada reutiliza lectores de familia (`text`, `image`, `office`, `pdf`, `zip`); no una clase por extensión. Extensión desconocida no implica permiso para transmitir bytes opacos. La extensión, contenido y lector deben ser compatibles y la cobertura suficiente para la política vigente.

Los estados se mantienen separados:

- **Ejecución:** queued/active/completed/failed/cancelled/interrupted/outcome_unknown, sin nueva máquina de estados paralela.
- **Archivo:** draft o verified, con cobertura y procedencia. Guardarlo no lo hace descargable ni entregado.
- **Entrega:** `Prompt.decision.delivery` versionado con `required`, `status` (`not_required`, `pending`, `complete`, `partial`, `failed`), requisitos, referencias y problemas. `completed` con archivo solicitado exige `delivery.status=complete`.

Una referencia de entrega contiene `{artifact_id, logical_id, revision, filename, size_bytes, sha256, format, download_url}`; la URL la construye Django con su ruta nombrada. La respuesta del modelo puede citar un ID emitido por el servidor, pero no autoriza una URL. El servidor construye la lista de descargas y rechaza referencias falsas, ajenas, caducadas o `/workspace/...` usadas como única entrega.

La descarga revalida propietario, empresa, acceso al perfil, estado de retención, integridad y política/cobertura del archivo. Una revocación posterior puede retirar acceso; «entrega completada» acredita el momento de finalización, no acceso perpetuo. En E6, los archivos parciales ya verificados podrán descargarse con recibo explícito aunque la ejecución termine fallida/cancelada; drafts y archivos retenidos por seguridad nunca.

### Persistencia mínima

| Ubicación | Adición propuesta | Compatibilidad |
| --- | --- | --- |
| Prompt.decision | Elegibilidad/digest/version/scope del historial; selección y omisiones; contrato y recibo de entrega; perfil de trabajo y opciones efectivas | JSON versionado, sin backfill de autorizaciones; conservar recibos anteriores |
| AgentArtifact | `filename` (255, vacío por defecto) y `size_bytes` (nullable para anteriores); resto en verification versionado | Migración aditiva; fallback de nombre actual para archivos antiguos; tamaño se obtiene de bytes tras validar hash |
| AgentInput | `kind='manifest'` con referencias de archivos, paths relativos y dependencias; checkpoint v2 cifrado | Reutiliza tabla y cifrado. No meter nombres privados, contenido ni resúmenes en trazas generales |
| AgentExecution.job | IDs/digests de selección, manifest, contrato, opciones y presupuestos; datos mínimos de capacidad/sandbox | Sin credenciales ni contenido privado; mantener lectores v1 para runs ya creados |
| AgentModelProfile.limits | Perfiles de trabajo y opciones de inferencia validados; topes existentes como techo | Campos opcionales; configuración antigua no se reescribe. Activación explícita y visible del perfil nuevo |

No crear ConversationMemory, Workspace, FileRevision ni un sistema genérico de configuración. La revisión de archivo ya existe. Las ampliaciones del protocolo interno son versionadas; el servidor admite v1 durante transición y solo anuncia capacidades v2 a workers compatibles. Las filas nuevas quedan intactas al revertir código; no se hace downgrade destructivo de datos.

## 4. Entregas ejecutables, en orden

| Entrega | P0 cubierto | Dependencias | Mejora observable |
| --- | --- | --- | --- |
| E1 | P0.1 | Ninguna | Recuerda el mensaje anterior y las correcciones autorizadas |
| E2 | P0.3 | Ninguna; ejecutar tras E1 | Descarga HTML/CSS/SVG/ZIP con bytes y nombre reales |
| E3 | P0.4 | E2 | Una petición de archivo no acaba con una falsa entrega |
| E4 | P0.2 | E1–E3 | «Dámelo» y «cambia el color» conservan y revisan el archivo |
| E5 | P0.7 | Ninguna técnica; antes de E6 | El cuerpo HTTP refleja las opciones de pensamiento y salida |
| E6 | P0.8 | E3–E5 | Trabajo acotado, recuperación sin repetir y parcial honesto |
| E7 | P0.5 | E4, E6 | Responde texto sin reservar sandbox |
| E8 | P0.6 | E6, E7 | Atiende dos conversaciones dentro de capacidad comprobada |

Cada entrega incluye pruebas regresivas que fallen primero por el comportamiento ausente, no tests que reproduzcan literalmente la implementación. No es necesario esperar al A/B de pago para cerrar la implementación offline de una entrega.

### E1 — Historial autorizado que llega realmente al modelo

**Problema y resultado.** Tras «Hablo de Madrid» → «Me refería a Madrid, España» → «¿Qué te dije antes?», la petición HTTP al proveedor lleva los pares anteriores con roles correctos y la corrección más reciente. Funciona tras recargar y reiniciar el worker. Evidencia: `chat_service.py:189`, `professional.py:152`, `professional_worker.py:195`, `service.py:595`; patrón Pi de reconstrucción e inyección efectiva.

**Archivos/contratos:** `front/chat_service.py:authorized_history`; `agents/professional.py:complete/bootstrap`; `agents/service.py:_context/infer`; `front/routing.py:route` como comprobador existente de capacidad; `agents/professional_worker.py:run_professional`; `agents/adapter.py:build_agent`; `front/chat_page.py:notice`; nuevo `front/test_agent_continuity.py`, más `test_agent_inference.py` y `test_state.py`.

**Pasos:**

1. Añadir fixture de dos turnos completados por las tres entradas HTTP, con proveedor `httpx.MockTransport`. Capturar el JSON real saliente del SDK; demostrar que falta el primer par. Añadir corrección, reinicio de worker y reintento del mismo request_id.
2. En la transacción de `professional.complete`, después de validar inferencia final, entrega, integridad y autorización vigente, persistir `history_version=2`, `history_scope='text_only'`, `history_eligible=True`, `history_digest=digest([user_message.content, assistant.content])`. Calcular sobre los mensajes realmente guardados. Elegible significa reutilizable bajo controles; no calidad semántica garantizada. Si falla cualquier comprobación o contabilidad, no se vuelve elegible.
3. Extender la selección compartida para devolver pares con identidad/procedencia a la ruta del agente. Excluir registros sin vínculo, roles incorrectos, contenido cambiado, bloqueado, fallido, pendiente, de otra empresa o sin acceso actual. La exclusión actual por `file_sha256` solo se levanta para un turno profesional v2 con scope textual: reutiliza el texto, nunca los bytes del adjunto de forma implícita. El chat antiguo mantiene su comportamiento.
4. En enqueue fijar IDs y digests de la ventana en `job.history` y contabilizar omisiones en decision. `_context` reconstruye esos registros y revalida la política actual. El replay de una ejecución no cambia silenciosamente la selección. Un registro editado, borrado o revocado invalida la autorización de esa ejecución.
5. En `infer`, convertir la selección del servidor en WireMessage user/assistant y añadirla una vez antes del estado de la ejecución para generación/visión, antes de protección, clasificación, cálculo de capacidad y `start_call`. Para compaction no añadir el prefijo. No aceptar mensajes históricos aportados por el worker como prueba de autorización. El bootstrap solo informa IDs/digest, omisiones y espacio disponible; no vuelve a insertar el prefijo.
6. Reemplazar el perfil fijo del grafo por capacidades derivadas de EngineModel y reserva del prefijo. Para legacy con provider_managed, reservar como cota de salida `EngineModel.max_tokens`; para modo acotado, min de ese valor y el máximo configurado. Capacidad desconocida produce `unknown_capacity`, sin inventar 200.000. `route` hoy omite capacidad si provider_managed: hacer una comprobación pura acotada con `provider_managed=False`, `budget=None` y esa reserva antes de despachar, sin modificar configuración ni facturación global. E5 usará directamente esa ruta acotada al seleccionar perfil explícito. Contar instrucciones y herramientas; si excede, reducir pares completos antes de fijar selección o detener con `context_overflow`. Mantener `ProtectedHistory` limitado a la ejecución/autorización vigente.
7. Mostrar una nota breve cuando existan mensajes antiguos/omitidos no utilizables. No responder que «no hubo mensajes» cuando el servidor sabe que están fuera del contexto autorizado.

**Datos antiguos y migración:** sin migración de esquema. Ningún backfill marca turnos anteriores como seguros. Se conservan visibles bajo sus permisos actuales, excluidos del modelo si faltan marcas; para reutilizarlos el usuario reenvía el texto o adjunto en un turno nuevo que pasa todos los controles. E4 permite recuperar un archivo concreto, sin autorizar por ello todo su chat.

**Aceptación:** en las tres entradas, primer par y corrección aparecen una sola vez y en orden en el HTTP capturado; cero roles system procedentes del histórico; cero mensajes excluidos. Cambiar regla, máscara, departamento, permiso o empresa entre turnos impide la salida correspondiente. Cambiar permisos durante una inferencia retiene la respuesta. Replay/reconexión no añade inferencias ni Response. Adjuntos antiguos no reaparecen automáticamente. La ventana deja pares completos y registra las omisiones. Compactación no recibe el prefijo interturno.

**Riesgo y reversión:** ampliar accidentalmente el contenido autorizado. Revertir la inyección y el escritor v2 conserva mensajes/marcas; probar que las marcas no constituyen por sí solas autorización ni amplían el chat básico. **Fuera:** recuperación masiva del histórico, memoria semántica, resúmenes entre conversaciones, herramientas antiguas en el prompt.

**Puerta de cierre concreta:** el nuevo módulo y las regresiones de historial/pasarela pasan; revisar una captura HTTP sintética con la secuencia `user/assistant/user/assistant/user`, y otra con revocación que registra cero salidas. No cerrar E1 si solo aparecen las marcas en BD pero no los mensajes en el proveedor.

### E2 — Guardar y descargar sin exigir un visor

**Problema y resultado.** Una llamada válida `publish_artifact('/workspace/output/madrid.html', ...)` produce un enlace autenticado que descarga los mismos bytes como `madrid.html`, con tamaño y revisión. Un ZIP con HTML/CSS/SVG inspeccionables funciona; uno cifrado o con contenido sin cobertura suficiente se rechaza. Evidencia: `professional_artifacts.py:MIMES/inspect_file/publish/artifact_data`, `professional.py:inspect_input`, `views.py:download`; Pi no aporta almacenamiento/aislamiento para este caso.

**Archivos/contratos:** nuevo `agents/artifact_formats.py`; `professional_artifacts.py`; `professional.py:inspect_input`; `agents/records.py:AgentArtifact`; migración aditiva siguiente a la última existente; `agents/views.py:download`; `jobs.py:artifact_data`; `static/js/agent-chat.js` (tarjeta mínima); tests de publicación, descarga y migración.

**Pasos:**

1. Trasladar el catálogo actual al registro común, manteniendo DOCX, XLSX, PPTX, PDF, PNG, JPG/JPEG, CSV, JSON, TXT, MD, PY, JS y SH. Añadir HTML/HTM, CSS, SVG y ZIP. Una fila declara familia/lector/cobertura/render; JSON se valida también estructuralmente, Office conserva sus verificadores actuales.
2. Compartir inspección entre publicación, entrada y restauración. Texto UTF-8 completo, incluidos código, atributos, comentarios y URLs, se somete a política; no limitar HTML a texto visible ni SVG a etiquetas textuales. No ejecutar scripts, resolver entidades XML, abrir URLs ni cargar recursos remotos al inspeccionar. SVG rechaza DTD/entidades externas; contenido codificado o recursos embebidos no cubiertos se marca parcial y no se publica si la política exige cobertura completa.
3. ZIP: máximo 200 entradas y profundidad de rutas 16; tamaño comprimido ≤ file_bytes, suma real expandida ≤ min(64 MB, workspace_bytes, 5 × file_bytes), cada entrada ≤ file_bytes, relación expandido/comprimido ≤ 100. Validar antes y durante lectura acotada, incluido CRC. Rechazar cifrado, rutas absolutas/UNC/unidad Windows, `..`, barras inversas, NUL, enlaces, dispositivos, rutas duplicadas tras normalización Unicode/casefold, colisiones archivo/directorio, archivos anidados ZIP y extensiones sin lector admitido. No extraer en el proceso Django. Inspeccionar cada miembro y registrar cobertura agregada y hashes; usar límites inferiores si el perfil los impone.
4. Añadir `filename` y `size_bytes` a AgentArtifact; nombre base sin directorios, controles ni CR/LF, normalizado y con extensión canónica. Conservar el nombre original seguro; no usar el título del modelo para construir cabeceras. Persistir hash de los bytes, tamaño, familia de lector y alcance de comprobación en verification. Ajustar `professional_artifacts.checks()` para no afirmar «contenido activo comprobado» de forma universal: integridad estructural de imagen no acredita lectura semántica/OCR, ni inspeccionar código demuestra que ejecutarlo sea seguro.
5. Desacoplar descarga de render. HTML/CSS/SVG/ZIP se entregan sin conversión a PDF y sin vista previa activa. Responder `Content-Disposition: attachment` con codificación segura del nombre, `Content-Length`, `X-Content-Type-Options: nosniff`, `Cache-Control: private, no-store`; HTML/SVG usan `application/octet-stream` para descarga y una CSP restrictiva (`sandbox; default-src 'none'`). Ningún iframe, object, srcdoc o HTML del archivo se inserta en el origen del chat. Un visor futuro necesitará origen separado sin cookies; no se construye aquí.
6. Tarjeta mínima creada con datos del servidor: nombre, tamaño, revisión, cobertura y descargar. Texto mediante APIs seguras del DOM. Preservar lectores de verification v1 y fallback de nombre para filas antiguas.

**Migración:** añadir campos sin borrar/reescribir contenido, grants ni estados. `size_bytes` antiguo puede permanecer NULL hasta leer bytes verificados; no recorrer todas las filas para descifrarlas en una migración. El antiguo nombre sintético sigue sirviendo como fallback.

**Aceptación:** descarga autenticada con SHA y longitud idénticos tras recarga; nombres Unicode y comillas seguros; HTML/SVG no ejecutan código en el origen del chat; acceso cruzado devuelve 404. ZIP normal aceptado y casos peligrosos anteriores rechazados sin descompresión ilimitada. Una extensión nueva exige una fila y una prueba de familia/cobertura, no nueva clase. Fallos de lector o contenido bloqueado no producen descarga; los formatos existentes siguen funcionando.

**Riesgo y reversión:** cobertura insuficiente de contenido activo/archivos comprimidos. Retirar nuevas entradas del catálogo y bloquear su nueva publicación conserva bytes/revisiones; no reducir comprobaciones para mantener compatibilidad. **Fuera:** antivirus universal, garantía sobre ejecutar un archivo descargado, visor HTML/SVG, ZIP arbitrarios/anidados o formatos opacos autorizados por defecto.

### E3 — Una sola interpretación y comprobación de entrega

**Problema y resultado.** «Crea un HTML de Madrid» exige un HTML accesible. Si el modelo escribe `/workspace/output/madrid.html` pero falla la publicación, el turno queda sin completar y explica el fallo. «Explícame qué es HTML» no exige crear un archivo. Evidencia: `request_contract.interpret`, `service.FILE_REQUEST`, `professional.complete`; patrón Pi: terminar el bucle no acredita entrega.

**Archivos/contratos:** `artifact_formats.py`; `request_contract.py:interpret/check_delivery`; `protocol.py:tool_schema/TOOL_PARAMETERS`; `service.py:infer`; `professional.py:enqueue/complete`; `professional_worker.py:publish_artifact/finalización`; `runtime/professional.md`; `jobs.py:artifact_data/event`; `views.py:_snapshot`; `chat_page.py`; `agent-chat.js`; tests HTTP/contrato.

**Pasos:**

1. Ampliar el contrato versionado con `delivery_required`, `formats`, `operation` (create/edit/download/chat), `references`, requisitos verificables y ambigüedades. Derivar alias de formatos del registro. Detectar intención por acción y objeto, no por aparición aislada de «HTML». «Crea una landing» adopta HTML; «genera un archivo» exige al menos un archivo permitido aunque el formato no sea explícito; «dámelo» exige resolver referencia en E4, y hasta entonces responde ambigüedad si no existe referencia inequívoca.
2. Eliminar la segunda fuente de verdad `FILE_REQUEST`; `service.infer` y prompt consumen el contrato resuelto. El catálogo común alimenta instrucciones, descripción/esquema de publicación, validación backend y tarjeta. La comprobación final compara requisitos con revisiones realmente verificadas; mantiene las comprobaciones actuales de fuentes, páginas y pareja Word/PDF.
3. Persistir el contrato al aceptar y no reinterpretarlo con un texto distinto al reintentar. Añadir a la respuesta de publicación referencias reales emitidas por Django. El modelo nunca suministra una URL de descarga autorizante. Construir siempre las descargas desde esos IDs y rutas del servidor.
4. En `complete`, verificar todos los artefactos referenciados, bytes, estado, permiso y requisitos dentro de la finalización idempotente. Un texto sin herramientas finales no basta. Guardar `decision.delivery` y `Response.evidence.artifacts` en la misma transacción que el estado terminal. Un duplicado devuelve el mismo recibo, sin nuevo Message/Response/publicación.
5. Si falta entrega, devolver códigos concretos al worker y permitir como máximo una reparación, dentro del presupuesto existente; no usar las tres vueltas independientes actuales como presupuesto extra. Al fallar, guardar `delivery.failed` y estado de ejecución fallido. E6 añadirá parcial y límites por tarea. No marcar elegible como respuesta exitosa una falsa entrega.
6. Ajustar textos de estado: «Respuesta completada» para texto; «Archivo generado, pendiente de entrega» durante verificación; «Archivo disponible» solo con recibo válido; «No se pudo entregar el archivo» en fallo. Resolver enlaces de artefactos en servidor y mostrar la tarjeta aunque el modelo omita el enlace en su prosa.

**Datos/migración:** solo JSON versionado. Runs v1 terminados conservan su interpretación histórica; no se les inventa un recibo v2 ni se cambia su estado. Nuevas ejecuciones usan v2. La lectura distingue explícitamente ambos contratos.

**Aceptación:** HTML/CSV/ZIP reconocidos; explicación de HTML sin archivo; formato no cubierto con error explícito; fallo de publicación, referencia ajena y ruta de workspace no producen completed. Replay de finalización devuelve misma respuesta. Las tres entradas muestran el mismo resultado y el enlace sigue funcionando después de recargar.

**Riesgo y reversión:** falsas detecciones de intención. Corpus pequeño de órdenes y contraejemplos; ante ambigüedad, aclarar antes de ejecutar. Revertir nuevos contratos solo para nuevas peticiones y conservar lectores/recibos v2. **Fuera:** clasificador LLM de intención, frontend nuevo, exportaciones remotas nuevas.

### E4 — Continuidad selectiva de archivos y revisiones

**Problema y resultado.** «Dámelo» devuelve la revisión existente sin regenerar; «cambia el color» restaura la revisión y sus dependencias locales, conserva la anterior y entrega una nueva. Recargar o reiniciar el worker no cambia los bytes. Evidencia: AgentArtifact ya tiene identidad/revisión/base/hash, pero `current_artifacts()` se limita al run actual y `_base()` exige selección explícita; `inspect_input()` debe usar E2. De Pi se adapta solo el índice de referencias, no una supuesta persistencia de archivos.

**Archivos/contratos:** `professional_artifacts.py:publish/current_artifacts`; `professional.py:enqueue/bootstrap/complete`; `jobs.py:latest/_base/_bytes`; `checkpoints.py`; `professional_worker.py`; `checkpoint_runner.py`; `protocol.py`; `views.py`; `front/views.py:_web_command` y `api/views.py` para referencias; `purge_agent_data.py`; nuevo comando acotado `recover_agent_file`; tests de continuidad/retención/revisión.

**Pasos:**

1. Usar AgentArtifact para revisiones útiles: verificada para entrega o draft privado para trabajo. El manifiesto cifrado AgentInput contiene `{artifact_id, logical_id, revision, sha256, size_bytes, relative_path, purpose, dependencies}`. `purpose` distingue `deliverable` y `working`; `job` conserva solo ID/digest del manifiesto. `current_artifacts`, complete, tarjetas y download filtran explícitamente entregables; un working puede restaurarse tras revalidación sin hacerse descargable ni satisfacer requisitos de entrega. No guardar una imagen completa del sandbox como memoria de conversación.
2. Al finalizar un límite seguro de operación y antes de destruir el entorno, conservar selectivamente los archivos de salida y los scripts/datos de trabajo referenciados por operaciones completadas. Reutilizar la captura de checkpoint, validando digest/rutas; máximo inicial 32 archivos y min(20 MB, workspace_bytes) acumulados, además de file_bytes por archivo. Excluir temporales, cachés, bytecode, .venv, .packages, .git, checkpoints, enlaces y secretos del runtime. Solo archivos con familia admitida y extracción íntegra pueden reutilizarse; un bloqueado se retiene privado conforme a la retención, nunca se autoriza por estar guardado. La captura fallida o parcial se declara como limitación, no continuidad garantizada.
3. Mantener una identidad por ruta lógica dentro de la conversación. Mismo hash y misma base reutiliza revisión; bytes distintos crean revisión nueva con `base`. Asignar revisiones bajo bloqueo de conversación y restricciones únicas existentes. Captura idempotente con operation_id UUID5 de ejecución+marca+ruta+hash por archivo, sin fingir una herramienta del modelo. Crear manifiestos inmutables con `path='manifest/<digest>'`; `AgentArtifact.source` conserva el origen que tenía, no se reasigna al actualizar el último manifiesto. Un publish que coincide con un draft capturado lo verifica/promueve sin duplicar bytes; registrar la asociación en la operación durable.
4. Definir dependencias sin un gestor de proyectos: ampliar publicación v2 con `related_paths` opcional y acotado a 32 archivos. El servidor valida bytes, rutas y pertenencia; fija cada dependencia por revisión+hash, nunca solo por nombre. Para HTML/CSS, cotejar referencias locales estáticas `src`, `href`, `url()` y `@import` con el conjunto declarado, sin resolver red; si una dependencia local falta, informar y no declarar el conjunto completo. Rutas relativas siempre dentro del conjunto, sin traversal; ciclos mediante conjunto de visitados y cuota agregada. Recursos dinámicos no inferibles se declaran fuera de cobertura y no se presume continuidad de una aplicación compleja. Probar HTML+CSS+SVG, dependencia ausente y revocada.
5. Resolver referencias antes de enqueue: ID/revisión explícitos prevalecen; después nombre exacto; después última entrega inequívoca en la conversación. «Dámelo» sobre una única revisión accesible toma una rama servidor concreta: tras idempotencia, exclusión de conversación y autorización, crear Prompt/AgentExecution terminal/Response con recibo que referencia el artefacto existente, sin cola, sandbox ni AgentInference ficticia. No usar `professional.complete` que exige final_inference_required: compartir con él la validación de referencias y persistencia final. Reintentar devuelve esos registros. Para varias candidatas, mostrar nombres/revisiones y pedir selección. No elegir un archivo por similitud entre empresas o conversaciones.
6. «Edita el anterior»/«cambia el color» fija base y dependencias de su manifiesto. Restaurar solo esas revisiones en `/workspace/input/refs/<id>/...` de solo lectura y, cuando se edite, copiar el conjunto a work conservando rutas relativas. Validar ID+SHA+revisión+acceso+política justo antes de transferir. Crear en la nueva ejecución AgentInput `policy_text` cifrado por revisión, vinculado a ID/SHA y digest de extracción; `_context` debe incluirlos en cada revalidación posterior. No descargar recursos remotos implícitos; marcar archivos restaurados como datos privados y aplicar el cierre de red actual antes de procesarlos. No montar todos los archivos históricos.
7. La revisión nueva hereda logical_id, explicita base_revision y no sobrescribe la anterior. Si cambió la revisión actual desde la selección, devolver conflicto de base obsoleta. La selección del próximo turno usa el manifiesto más reciente autorizado, no un sandbox que pudiera seguir vivo.
8. Recuperación del HTML histórico: comando `recover_agent_file --run-id <id> --member output/madrid_landing.html --actor-id <propietario>` con vista previa por defecto y `--apply` para importar **un miembro seleccionado**. Verificar propietario/empresa, digest de AgentInput, límites/ruta/bytes y política E2; crear revisión con procedencia `checkpoint_file_import` y clave idempotente `(run, digest_checkpoint, member, sha256)`. Ningún `--all` ni grant nuevo. No aplicar `restore_checkpoint`, no cargar sus mensajes ni llamar herramientas/modelo. El watermark de reanudación no se reutiliza como permiso: un snapshot antiguo puede contener un archivo recuperable aunque ya no sea reanudable. Si no existe/caducó, comunicarlo; no reconstruir bytes imaginarios.
9. Reutilizar `purge_agent_data` y sus plazos: vaciar contenido y conservar filas/FK/hashes como ya hace, sin borrar o reordenar bases referenciadas. Incluir nuevos manifiestos, extracts y nombres privados en la purga y marcar sus referencias expiradas. Continuar una conversación no renueva automáticamente la retención de los originales ni permite eludirla copiándolos a una ejecución nueva; conservar su vencimiento de procedencia. Un archivo/dependencia expirado no se restaura ni se regenera silenciosamente. Probar el grafo de revisiones y copias para no conservar bytes fuera de plazo ni tocar datos ajenos.

**Datos/migración:** E2 aporta nombre/tamaño; no nueva tabla. Manifest v2 en AgentInput, verification v2 para propósito/procedencia. Ningún barrido transforma checkpoints anteriores en archivos autorizados. Importación histórica explícita y acotada, idempotente y auditable.

**Aceptación:** secuencia Madrid completa por cada entrada HTTP; descarga inicial y reentrega con hash idéntico, edición con nueva revisión/hash y antigua descargable si sigue autorizada. Reinicio entre cada paso. Dos archivos ambiguos no se eligen solos. Cambio de permiso/empresa impide restaurar/descargar. No reaparecen llamadas, publicaciones ni costes antiguos. Recuperación del miembro HTML crea una revisión y cero inferencias; repetirla no duplica. Drafts, contenido bloqueado y fuentes sin cobertura no se entregan.

**Riesgo y reversión:** convertir restauración en un canal de salida de archivos privados. Revertir selección/restauración para nuevos turnos conserva revisiones y descargas ya autorizadas; no borrar manifests ni archivos. **Fuera:** Git de workspaces, sincronización de carpetas, compartir entre conversaciones, restaurar entornos/paquetes de ejecuciones anteriores y recuperación automática de todo el histórico.

### E5 — Opciones de proveedor explícitas y comprobadas en HTTP

**Problema y resultado.** Una tarea sencilla seleccionada con perfil rápido envía a DeepSeek pensamiento explícitamente desactivado y límite de salida; el recibo muestra qué se envió. La configuración histórica `reasoning=False` ya no se presenta como prueba de que el pensamiento estuviera desactivado. Evidencia: `connectors.py:OpenAIConnector.chat/VercelGatewayConnector.chat`, `service.infer`; patrón Pi `buildParams`.

El [contrato actual de DeepSeek](https://api-docs.deepseek.com/api/create-chat-completion/) y su [guía de pensamiento](https://api-docs.deepseek.com/guides/thinking_mode/) documentan activación predeterminada y el requisito de devolver `reasoning_content` al continuar ciertas secuencias con herramientas. El protocolo actual no lo conserva. **Este P0 no lo incorporará a mensajes, BD, checkpoints ni trazas:** el perfil rápido con herramientas usa pensamiento desactivado; el perfil razonado de DeepSeek se limita a una respuesta sin herramientas, por ejemplo la conclusión final de un cálculo ya terminado. Una combinación no soportada se rechaza antes de salir.

**Archivos/contratos:** `front/connectors.py:BaseConnector/OpenAIConnector/VercelGatewayConnector`; `agents/capabilities.py:Limits/validación`; `professional.py:enqueue`; `service.py:_context/infer`; `agents/records.py:AgentModelProfile` (JSON existente); `front/views.py:_web_command`, `api/views.py:chat_send_message`, plantilla/JS actuales del chat para selección mínima; `governance.py` para recibo; `management/commands/configure_professional_agent.py`; `test_connectors.py` y `test_agent_inference.py`.

**Pasos:**

1. Definir un pequeño contrato de opciones, no un motor de proveedores: `dialect`, `thinking_mode=provider_default|off|on`, `effort`, `max_output_tokens`, `profile_version`, `selection_source`. Separar soporte del modelo de activación solicitada y de presupuesto. Validar valores por modelo/dialecto del catálogo configurado; no deducir soporte de `EngineModel.reasoning` ni aceptar `extra_body` arbitrario del cliente.
2. Añadir perfiles operativos dentro de la configuración existente del agente: `quick` (off, esfuerzo ausente, salida inicial 4096) y `reasoned` (on, esfuerzo high cuando esté admitido, salida inicial 8192). El límite final es el mínimo entre perfil, modelo y política. Son valores iniciales a validar, no garantía de calidad. Por defecto las cuentas existentes conservan `legacy/provider_default`; activar quick/reasoned requiere una selección visible del perfil de agente, sin reescribir EngineModel ni las preferencias globales de cuenta.
3. Propagar por las tres entradas un único campo opcional `inference_profile=legacy|quick|reasoned`; un selector mínimo muestra solo las opciones autorizadas del AgentModelProfile, sin aceptar profile_id ni proveedor arbitrarios. Campo ausente conserva el comportamiento legacy configurado. Incluirlo en fingerprint de idempotencia y authorization_digest. Resolver/fijar opciones en enqueue; cualquier promoción a reasoned debe estar ya autorizada por esa selección y consumir E6. Para un perfil reasoned que usa herramientas, la fase de herramientas mantiene quick y solo la conclusión final sin herramientas usa reasoned; anunciarlo al seleccionar. No escalar silenciosamente por «parece difícil». Revalidar destino/modelo/permisos antes de cada llamada.
4. Traducir en el conector según la tabla siguiente. Para quick/reasoned llamar a `route` con `provider_managed=False` y el máximo efectivo para validar capacidad y conservar la cota/coste disponible; no pasar máximo numérico con provider_managed=True, combinación que el contrato actual rechaza. Esto es resolución local del agente, no modificación del AIConfig guardado. Eliminar la inferencia «booleano reasoning determina nombre del máximo» para opciones nuevas; mantener adaptador legacy para llamantes no migrados. No añadir nuevos proveedores al arnés.
5. Registrar opciones solicitadas, resueltas y campos efectivamente enviados, modelo solicitado/efectivo, versión y origen de la selección. Si el proveedor no confirma el modo aplicado, registrar observación desconocida. Nunca conservar los campos privados `reasoning_content`, `reasoning`, bloques de pensamiento o firmas; solo conteos de uso admitidos.
6. Verificar con SDK real y `httpx.MockTransport` el JSON completo final, incluido el cuerpo tras fusión Vercel. Probar credenciales sintéticas y bloqueo de sockets no simulados. Mantener `max_retries=0` en SDK de proveedor y pruebas de no regresión del chat normal.

| Conector afectado | Traducción elegida y límites |
| --- | --- |
| DeepSeek por OpenAI compatible | `extra_body.thinking={type:'disabled'}` para off; `{type:'enabled'}` y `reasoning_effort` admitido (`low/high/max`) para on; máximo de salida en `max_tokens`. No `max_completion_tokens`. On+tools se rechaza en este P0 |
| OpenAI nativo | `reasoning_effort` solo para modelo/valor admitidos; off se traduce a `none` únicamente si ese modelo lo soporta. `max_completion_tokens` según contrato actual, que incluye razonamiento y salida visible. Un modelo sin pensamiento no necesita campo de esfuerzo; no enviar `thinking` de DeepSeek. [Referencia oficial](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create) |
| Compatible desconocido | No adivinar dialecto por el nombre del modelo. Mantener legacy; opciones explícitas no acreditadas dan error antes de red. Registrar endpoint/dialecto autorizado sin claves |
| Vercel Gateway | Fusionar de forma controlada `extra_body.reasoning={enabled, effort si procede, exclude:true}` con el pin existente `providerOptions.gateway.only=[upstream]`; hoy el conector sobrescribe extra_body. Salida total en `max_tokens` top-level según su [contrato Chat Completions](https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-chat-completions/chat-completions). No confundir `reasoning.max_tokens` con máximo de salida, ni combinarlo con effort. Modelos que requieren reenviar razonamiento privado para herramientas quedan fuera de esa combinación. [Referencia de razonamiento](https://vercel.com/docs/ai-gateway/sdks-and-apis/openai-chat-completions/reasoning) |
| Anthropic del chat existente | El arnés actual no lo admite; no ampliar soporte en este P0. Mantener su `max_tokens` obligatorio y comportamiento legacy, con prueba de no regresión; no trasladarle campos DeepSeek/OpenAI. Si en trabajo posterior se exponen opciones nuevas, requerir mapeo por modelo, no activar pensamiento implícitamente. [Contrato de pensamiento](https://platform.claude.com/docs/en/build-with-claude/thinking) |

**Datos/migración:** opciones versionadas en `AgentModelProfile.limits` y snapshot en job/recibo; sin migración que cambie preferencias. La validación debe aceptar ausencia de nuevos campos. Un perfil compatible antiguo sigue funcionando y queda identificado como legacy.

**Aceptación:** para cada proveedor soportado por el arnés, captura HTTP de quick/reasoned; off explícito en DeepSeek, máximo presente, Vercel conserva upstream, opción incompatible genera cero salidas. Las tres entradas comparten resolución. Razonamiento privado ausente de Response, AgentInference, checkpoint, logs y SSE. `usage` ausente produce coste desconocido, no cero. Una preferencia global anterior permanece idéntica.

**Riesgo y reversión:** perder calidad o enviar opciones incompatibles. Mantener perfiles optativos y corpus de calidad; volver a legacy para nuevas ejecuciones preserva recibos que dicen qué ocurrió. **Fuera:** A/B de pago sin presupuesto, soporte de razonamiento privado persistente, cambio global de modelo, nuevas integraciones Anthropic de herramientas.

### E6 — Presupuesto de trabajo y finalización honesta

**Problema y resultado.** La simulación prepara código, ejecuta, repara solo si hace falta y responde. Al alcanzar el techo, entrega el estado y los resultados disponibles sin inventar éxito ni iniciar otra inferencia para explicar el límite. Evidencia: `capabilities.Limits`, `service.infer`, `data_views.authorize_tool`, `professional_worker` y retry del resumidor instalado. Los límites actuales ya existen: el problema es su selección, consumo coherente y cierre.

**Archivos/contratos:** `capabilities.py`; `professional.py:enqueue/complete`; `service.py:infer/_government`; `data_views.py:authorize_tool`; `general_tools.py:begin`; `worker.py:Lease`; `professional_worker.py`; `runtime/professional.md`; `adapter.py:RegulayModel`; `checkpoints.py`; `jobs.py:fail/_terminal/latest`; `views.py:download/_snapshot`; pruebas de estado, dinero y runtime.

**Perfiles iniciales propuestos.** Son política operativa del agente nuevo, con techo efectivo `min(perfil de tarea, límites administrativos)`. Se activan explícitamente junto con la configuración E5. El chat básico y sus dos intentos de generación no cambian: estos contadores corresponden a ciclos de un agente, no a reintentos libres del generador básico.

| Tarea | Objetivo orientativo | Techo inicial obligatorio | Salida inicial |
| --- | --- | --- | --- |
| Texto sencillo | 1 inferencia, sin herramientas innecesarias | 3 inferencias, 4 herramientas, 60 s | 4096 tokens |
| Simulación/cálculo acotado | 2–4 inferencias; aproximadamente 60 s para repetir el caso 6 con calidad equivalente | 8 inferencias, 16 herramientas, 180 s; 20 s/comando | 4096 tokens; 8192 solo si perfil autorizado lo exige |
| Crear/editar archivos | Publicar en cuanto cumpla lo pedido | 12 inferencias, 24 herramientas, 300 s; hasta 60 s/comando según perfil | 8192 tokens |
| Investigación explícita | Fuentes necesarias y resultado solicitado | 16 inferencias, 32 herramientas, 600 s; web_calls acotado por perfil vigente | 8192 tokens |
| Reentrega de archivo | 0 inferencias, 0 sandbox | Operación determinista con límites de lectura/verificación | No aplica |

No se usa otro LLM para clasificar. El contrato explícito identifica descarga, archivos e investigación; cálculo/simulación por intención textual clara. Una petición ambigua usa un perfil acotado y puede pedir aclaración. Un texto inicialmente sencillo que exige una operación no cubierta pide continuar con el perfil adecuado; no eleva automáticamente su techo.

**Pasos:**

1. Resolver objetivos y techos en enqueue y guardarlos con versión en `job.limits/work_profile`. Ajustar explícitamente la validación: Limits actual exige al menos 4 model_calls y 8 tool_calls; los presupuestos efectivos por tarea admiten enteros positivos inferiores, manteniendo defaults y configuración administrativa existentes. La reentrega determinista no entra en ese loop. Sustituir recálculos independientes de `limits(profile)` en fronteras por esa resolución, sin permitir que un worker la aumente. Un cambio administrativo más restrictivo/revocación detiene; una ampliación posterior no regala presupuesto a una ejecución iniciada.
2. Contar todas las inferencias de generación, compactación, visión y reparación; herramientas, tiempo desde started_at, bytes y dinero. Replays de call_id ya completado devuelven el recibo y no consumen otra llamada. La cola tiene plazo propio E8; no mezclarlo con el tiempo activo. Mantener coste conocido, reservas y coste desconocido separados.
3. Reserva de cierre: una inferencia y 10 s de margen dentro del techo. Al entrar en ella, retirar herramientas y ordenar conclusión. Una sola reparación de entrega dentro del mismo techo. Los objetivos blandos provocan instrucción de cierre; no bloquean una reparación justificada si queda presupuesto. El límite duro se aplica antes de cada efecto, no mediante prompt.
4. Acotar timeout efectivo por `min(restante de ejecución, límite de llamada configurado)` aunque `provider_managed` esté activo: `AgentGovernedCalls.remaining()` aplica el deadline del job incluso cuando la implementación base devolvería None, también para destinos de protección/red. El máximo de salida de E5 es obligatorio para este perfil acotado; documentar en recibo que es un límite de ejecución sin modificar la preferencia global. Un timeout con petición posiblemente enviada queda incierto, sin retry automático.
5. Prompt de simulación: conservar dimensiones/precisión pedidas, escribir un programa, ejecutar, reparar ante error o incumplimiento concreto, responder. No añadir comparación 3D, solución por series, microbenchmark, documentos o verificaciones repetidas sin requisito/fallo nuevo. Mantener comprobaciones obligatorias de seguridad, integridad y entrega.
6. Añadir cierre servidor por límite: usar exclusivamente respuesta ya protegida, operaciones terminadas y archivos verificados; declarar qué terminó y qué falta. Estado `interrupted` con `reason=budget_exhausted` o `deadline_exceeded`; conservar compatibilidad del Prompt que hoy representa interrupción como outcome_unknown, distinguiendo el motivo y la incertidumbre real en el recibo. No enviar otro LLM. Un resultado desconocido no se etiqueta parcial conocido.
7. Adjuntar únicamente revisiones verificadas expresamente incluidas en el recibo parcial. `download`, `latest` y `_snapshot` deben usar ese recibo y autorización del archivo, no abrir indiscriminadamente los artefactos de runs fallidos. Si falta el archivo solicitado, delivery es partial/failed, nunca complete. Excluir respuesta de éxito parcial del historial v2 por defecto; el siguiente turno puede referenciar archivos entregados y el servidor aporta un estado factual acotado de la ejecución anterior.
8. Hacer la compactación idempotente: call_id UUID5 con namespace execution UUID y nombre `compaction:<digest canónico de wire+opciones fijadas>`, reutilizado por reintentos del middleware y transporte interno. El servidor valida el digest y devuelve AgentInference completado; si está procesando/incierto, no genera otro ID ni otra salida. No deduplicar por texto las generaciones normales: son operaciones distintas salvo replay identificado.
9. Checkpoint v2: persistir mensajes, watermark y, si existe, `{cutoff_index, compaction_call_id, summary_digest}`. Como el resumidor instalado devuelve texto y descarta response_metadata, RegulayModel conserva el recibo de compactación completada en contexto privado de ese InternalClient/ejecución; SafeBoundary relaciona el digest del resumen con ese recibo, sin variable global compartida. El servidor verifica y reconstruye `_summarization_event` desde esa AgentInference completada, usando el envoltorio fijo de la versión instalada. Validar rango y parejas herramienta/resultado, no aceptar resumen arbitrario. Restaurar referencia de offload solo si su archivo está acreditado; en otro caso `file_path=null`. Un checkpoint v1 sin resumen sigue utilizable únicamente si su watermark es válido y no implica repetir una compactación acreditada omitida; en caso contrario, declarar recuperación no disponible.
10. Conservar presupuesto, opciones y deadline al reanudar. Si tras un checkpoint hubo una operación o inferencia posterior, no reanudar automáticamente desde él. Si lo único pendiente es persistir la finalización de una inferencia final ya completada, reconciliar desde el recibo de esa inferencia y su contrato sin volver al modelo; cualquier incertidumbre sobre efectos detiene la reconciliación.

**Aceptación:** techos de modelos/herramientas/tiempo y salida se respetan en HTTP real simulado; última llamada sin herramientas; reparación consume presupuesto; truncamiento no se entrega como éxito. Simular inferencia de compactación completada en BD y pérdida de ambas respuestas HTTP internas: retry del middleware devuelve la misma, una llamada al proveedor. Cancelar/reconectar/reiniciar no cambia costes ni repite operaciones. Parcial verificado descargable, archivo faltante no completado, coste desconocido `null` con `complete=false`.

**Riesgo y reversión:** detener una tarea válida demasiado pronto o duplicar trabajo al recuperar. Valores explícitos ajustables solo para nuevas ejecuciones; revertir perfiles conserva límites/recibos anteriores. Si se retira soporte checkpoint v2, impedir su reanudación con mensaje claro, sin convertirlo a v1 perdiendo estado. **Fuera:** optimizador automático de presupuestos, garantía de calidad con menos llamadas, límite universal de cuatro llamadas o 60 s.

### E7 — Sandbox adquirido al primer uso real

**Problema y resultado.** «¿Cuál es la capital de España?» termina sin crear/asignar microVM. «Simula este proceso» obtiene una al llegar a la primera herramienta que necesite archivos/código. La continuidad sigue dependiendo de Django/revisiones. Evidencia: `worker.run/run_job`, montaje anticipado en `run_professional`; instancia E2BSandbox y middleware filesystem instalados.

**Archivos/contratos:** `worker.py:run/run_job/Lease`; `sandbox_pool.py:CleanPool`; `workspace_backend.py:WorkspaceSandbox`; `professional_worker.py:run_professional/SafeBoundary`; `adapter.py:ResultGate`; `checkpoints.py`; eventos en `jobs.py` y presentación mínima `agent-chat.js`; `ops/agent_chat/test_worker.py` y `ops/agent_chat/test_professional_runtime.py`.

**Pasos:**

1. Reclamar/bootstrap sin esperar el pool; crear Lease sin sandbox. Mantener el backend WorkspaceSandbox como instancia, inicialmente sin recurso. No usar BackendFactory: el SDK la resolvería antes de inferir y está deprecada en la versión instalada.
2. En ResultGate, después de `authorize-tool` y antes del handler, llamar a la preparación única para filesystem/execute, web_download, web_browse, install_packages, publish_artifact e inspect_image. `web_search/web_open/web_find/read_output` y respuestas de texto no requieren VM. La lista pertenece a las capacidades del servidor; no al texto del modelo.
3. Preparar bajo lock por ejecución: comprobar lease, adquirir plaza limpia, asociarla al intento, montar tmpfs, restaurar solo entradas/manifiesto autorizados, verificar UID/montajes/red y límites. Volver a comprobar lease/autorización antes de usarla. Si se revoca/cancela durante reserva, destruir la VM y no ejecutar la herramienta. Una operación de resultado incierto no se reintenta para «preparar otra vez».
4. Lease puede adjuntar el sandbox una vez y destruirlo al perder vigencia; renovar también durante espera de capacidad. Mientras no se asigne, emitir `sandbox_waiting`, sin afirmar que está reservado. Preparación idempotente no crea dos microVM si dos herramientas llegan juntas.
5. SafeBoundary guarda checkpoint textual v2 con archive=null solo si la ejecución nunca tuvo workspace, usando identidad de runtime confiable del worker y sin ejecutar `checkpoint_runner`. Al reanudar con archivo pendiente de restauración, conserva su referencia/bytes y watermark anteriores hasta materializarlo; no sobrescribir el snapshot bueno con null por no haber adquirido aún la VM. Con VM conserva snapshot actual. Las escrituras internas del SDK para offload no activan sandbox: devolver fallo controlado que el resumidor instalado admite y dejar file_path=null. No permitir que un hook interno esquive ResultGate.
6. Al terminar, conservar archivos E4 y destruir VM usada. Pool de una plaza como máximo por ahora; desactivar precalentamiento cuando no existe demanda, para que una petición textual en frío cree cero entornos. No reciclar una VM con datos ni mantenerla viva para simular continuidad entre turnos.
7. Emitir inicio/fin reales para adquisición, preparación y ejecución; la inferencia tiene su propio intervalo. Actualizar «En cola»/«Generando respuesta»/«Preparando entorno» en UI existente, sin rediseño.

**Datos/migración:** checkpoint v2 permite archive=null; job conserva metadatos del recurso/intento, nunca token del proveedor. El servidor soporta temporalmente worker v1 con preparación anticipada, pero la aceptación de cero VM exige v2. No cambios de datos históricos.

**Aceptación:** contador de creación/asignación cero en pregunta sencilla y lectura web sin descarga; una VM al ejecutar código, jamás dos por carrera; zero-egress salvo broker/pasarela actuales. Cancelación en cada fase destruye recurso o deja su TTL registrado para limpieza, sin uso posterior. Reinicio entre turnos restaura archivo seleccionado y no inferencias previas. Compactación textual sin VM no la crea indirectamente.

**Riesgo y reversión:** operación filesystem disparada fuera de autorización o recurso huérfano. Fail closed del backend no preparado; tests de todos sus métodos. Revertir adquisición anticipada conserva seguridad/archivos pero pierde la mejora de latencia; drenar ejecuciones activas antes de cambiar la versión del worker. **Fuera:** sandbox compartido, ejecutar código en el host, caché de entornos privados, clasificación extra con LLM.

### E8 — Concurrencia limitada sin monopolizar otros chats

**Problema y resultado.** Con una simulación activa, una pregunta sencilla de otra conversación puede iniciar y terminar antes de que finalice la simulación. Misma conversación conserva un solo escritor. Evidencia: `jobs.claim/reap/cancel`, restricción `agent_one_writer`, `worker.run`, `CleanPool`. El patrón de sesiones de Pi no resuelve admisión distribuida; aquí se reutiliza PostgreSQL.

**Capacidad inicial propuesta:** un proceso worker con `ThreadPoolExecutor(max_workers=2)`, máximo global 2 ejecuciones activas y 2 por empresa, **una microVM** total, hasta 2 inferencias concurrentes por destino solo si lo permiten cuota y ensayo. El ejecutor configurado en `start_worker.sh` tiene 768 MiB, 1 CPU y 128 procesos; no es la memoria del host ni la de la microVM. El servidor configurado usa gthread con cuatro hilos. No aumentar procesos/sandboxes a ciegas.

**Archivos/contratos:** `jobs.py:claim/reap/renew/cancel`; `service.py:infer/start_call`; `worker.py:run/Lease`; `sandbox_pool.py`; endpoints internos en `views.py`; `records.py:AgentExecution.job` y restricciones existentes; settings/arranque del worker; `test_agent_chat.py:AgentChatConcurrencyTests`, nuevo módulo de capacidad y `ops/agent_chat/test_worker.py`.

**Pasos:**

1. Medir en laboratorio RSS pico del worker y servidor, CPU, memoria de host, microVM, tmpfs y page cache, número de procesos, conexiones PostgreSQL y ocupación de los cuatro hilos HTTP. Ensayar 2 turnos con proveedor simulado y un cálculo real aislado; margen mínimo operativo propuesto 25 % de memoria reservada y ausencia de OOM/throttling sostenido. Verificar cuota de concurrencia del proveedor como dato de despliegue, sin hacer llamadas pagadas. Si no permite 2 llamadas simultáneas, declarar pendiente esa capacidad: no prometer que una respuesta evite una inferencia larga ya en curso.
2. Dispatcher con dos plazas, sin compartir InternalClient/token, grafo, lease ni backend entre tareas. Solo reclamar cuando existe plaza local. Conservar loop principal para renovar/recoger resultados y atender señales; no mantener una transacción Django abierta mientras espera HTTP o sandbox. SIGTERM: parar claims, drenar como máximo 30 s, cancelar pendientes, detener sandboxes y registrar interrupción cuando sea posible; TTL y reap cubren caída abrupta. No depender del `__exit__` de ThreadPoolExecutor ni de que `shutdown(wait=False)` permita por sí solo salir de Python con hilos activos. Configurar gracia de supervisor/contenedor de 35 s y terminación forzada del proceso al agotarse, además de timeouts E6; probar esa ruta y conservar registros de efectos en curso.
3. En servidor, bajo advisory transaction lock de PostgreSQL de admisión, reap de vencidos y comprobación+reserva atómica de capacidad global/empresa; después elegir el queued más antiguo elegible con `select_for_update(skip_locked=True)`. Mantener restricción de conversación y credencial derivada de claim_id. El replay del claim se resuelve antes de consumir otra plaza. Un lock local del worker no basta ante dos workers accidentales.
4. Cola acotada inicial: 32 pendientes globales, 8 por empresa; plazo de cola 300 s separado del tiempo activo. Antes de crear un nuevo Prompt, la admisión transaccional rechaza exceso con 429 y Retry-After=5; validar replay previo antes del límite. Runs aceptados no cambian request_id ni se reencolan por recargar. Mostrar causa de espera, sin ETA inventada. Saltar candidatos que excedan cuota empresarial conserva progreso de otras empresas.
5. Reserva de sandbox global bajo el mismo mecanismo de capacidad, en job con reservation_id, worker_id, attempt, sandbox_id, estado y expiración. Esperar una plaza no consume otra microVM; la segunda tarea textual no la necesita. No liberar el recurso por marcar cancelled: liberar tras kill confirmado o TTL. Añadir operación interna de limpieza autenticada por credencial de worker, limitada a confirmar destrucción de esa reserva/worker/intento/sandbox aunque la credencial de ejecución ya esté revocada. Es idempotente y no autoriza herramientas ni inferencia. Un recurso de destrucción incierta conserva ocupación hasta reconciliarlo; otro worker no puede liberarlo ni reservar otra plaza global por tener su propio pool.
6. Admisión de proveedor atómica por destino/credencial autorizada, con inferencias processing y ocupación incierta sin reconciliar, incluso si el run fue cancelado. Separar ocupación física, resultado del efecto y coste: respuesta HTTP terminada sin uso libera plaza, pero mantiene cost=null. Timeout sin prueba de fin conserva reserva; una acción operativa acotada registra evidencia de fin/cancelación o confirma revisión manual del recurso y libera solo ocupación, nunca borra call/ledger/reserva económica ni reenvía la petición. Registrar actor, motivo, referencia de evidencia y hora; no inferir fin solo del TTL del lease. Usar registros existentes y reserva previa a la red; no usar solo el conteo de runs active ni mantener lock durante generación. La cancelación retiene respuestas posteriores, sin prometer que el proveedor deje de generar o cobrar.
7. Cancelación de queued libera su plaza sin efectos; de active invalida intento, detiene comandos mediante Lease y conserva registros/costes. Reap de worker caído interrumpe; no repite herramientas/inferencias inciertas. Recuperación solo con checkpoint seguro E6, permiso y presupuesto vigentes. Cualquier llamada de un intento antiguo se rechaza. Reconectar SSE desde cursor únicamente lee eventos/estado.
8. Emitir intervalos reales de capacidad/cola/preparación/proveedor/herramientas/protección/checkpoint según sección 5. Exponer saturación y parcial en la UI actual. Una conexión SSE no debe consumir indefinidamente todos los hilos necesarios para inferir/cancelar: comprobar configuración ASGI/SSE efectiva del despliegue de prueba y reservar capacidad HTTP suficiente dentro del servidor actual.

**Saturación explícita:** dos tareas activas pueden ocupar las dos plazas; una tercera espera. Si ambas necesitan la microVM, la segunda espera sandbox y no se promete prioridad inmediata para una tercera consulta. Estos P0 garantizan la aceptación con una simulación y otra consulta dentro de capacidad, no preempción ni latencia constante bajo carga ilimitada. Las cuotas, cola acotada y plazos evitan crecimiento ilimitado.

**Datos/migración:** reservas en job y registros existentes; no nueva cola. Mantener `agent_one_writer` y unicidades por claim/call. Usar PostgreSQL en pruebas de carrera, nunca presentar SQLite como validación de exclusión distribuida. Las reservas no se borran al cambiar estado; mantienen evidencia hasta que se libera/reconcilia el recurso.

**Aceptación:** con barrera que mantiene abierta la simulación, otra conversación obtiene respuesta antes de liberarla, con una sola microVM; nunca dos escritores por conversación. Dos workers y claims iguales/distintos respetan todos los límites. Cambio empresa/grant impide bootstrap/inferencia/restauración. Cancelar, SIGKILL y pérdida de respuesta en cada frontera no duplican efecto ni coste. Saturación devuelve/expone lo descrito y la ocupación desconocida no se convierte en cero.

**Riesgo y reversión:** sobrepasar memoria/cuota o liberar capacidad antes de que desaparezca el efecto. Mantener concurrencia configurable y activarla solo tras ensayo; reducir nuevas admisiones a 1 y drenar las ya activas conserva los registros. Si falta capacidad física, la implementación puede quedar probada con simulados, pero la aceptación de concurrencia real sigue pendiente y debe constar. **Fuera:** autoscaling, más workers por defecto, dos microVM sin medición, scheduler distribuido nuevo, prioridad predictiva mediante LLM.

## 5. Verificación obligatoria y rendimiento

### Banco y comandos de ejecución futura

Reutilizar `AgentFixture`, `ProfessionalTests`, `ProfessionalHTTPTests`, pruebas del worker y el laboratorio de namespace existente. Capturar en `httpx.MockTransport` del SDK real, **sin sustituir `connector.chat` ni `.create`** para la aceptación de frontera. Usar claves sintéticas, destinos `.invalid`/fixture y prohibir sockets no previstos. La integración debe recorrer autenticación HTTP → enqueue → claim/bootstrap → gateway → SDK → HTTP simulado → finalización → estado/descarga; no basta llamar directamente `complete()`.

Parametrizar las entradas: POST web `/chat/` (y el adaptador de conversación cuando corresponda), `/chat/send/`, `/api/chat/send/`. Normalizar sus diferencias de respuesta/redirección y consultar el mismo run; no exigir que el POST web devuelva JSON si su contrato es redirigir. El test de E1 verifica la secuencia en el cuerpo HTTP, no solo el historial en BD.

Usar los settings aislados del repositorio. `regulai.ci_settings` apunta a PostgreSQL de CI en loopback:55458 con datos sintéticos y base de test `test_regulai_ci`; no importa credenciales de instalación. Comprobar que el puerto sirve ese laboratorio antes de ejecutar, o provisionarlo siguiendo el procedimiento de CI existente. **No ejecutar estas pruebas con settings de la instalación ni contra sus bases.**

Comandos previstos, desde la raíz y con el Python del entorno de pruebas existente:

```powershell
rtk proxy python regulai/manage.py test front.test_agent_continuity front.test_agent_inference --settings=regulai.ci_settings --noinput --exclude-tag=namespace_integration
rtk proxy python regulai/manage.py test front.test_state front.test_chat_flow --settings=regulai.test_settings --noinput
rtk proxy python regulai/manage.py test front.test_agent_professional front.test_agent_chat front.test_agent_state front.test_agent_frontend --settings=regulai.ci_settings --noinput --exclude-tag=namespace_integration
rtk proxy python regulai/manage.py test front.test_connectors --settings=regulai.test_settings --noinput
rtk proxy python regulai/manage.py makemigrations --check --dry-run --settings=regulai.ci_settings
rtk proxy python regulai/manage.py check --settings=regulai.ci_settings
```

El primer módulo es nuevo en E1. Añadir los módulos nuevos de formatos/capacidad al runner según se creen. La prueba namespace `test_agent_professional_http` y `ops/agent_chat/test_worker.py` requieren su entorno de laboratorio documentado; adaptar sus fixtures al flujo completo y ejecutarlas allí, sin lanzar `start_real_local.py`, refrescar el servicio real ni sobrescribir informes históricos. Guardar evidencias nuevas en una carpeta propia de la entrega futura. Ninguno de estos comandos de implementación se ha ejecutado como parte de este plan.

### Matriz mínima de aceptación

En la columna «entradas» **3 HTTP** significa repetir por los tres adaptadores, no tres llamadas directas al servicio.

| Caso | Entradas/frontera | Aserciones necesarias | Entrega |
| --- | --- | --- | --- |
| Mensaje anterior y corrección | 3 HTTP + proveedor simulado | Roles, orden, una copia, corrección reciente, ninguna elevación a system | E1 |
| Historial manipulado, antiguo, bloqueado o pendiente | 3 HTTP + captura de red | No sale; omisión explícita; no backfill; registros preservados | E1 |
| Madrid → HTML → descargar → cambiar color | 3 HTTP, worker y descarga | Texto contextual, bytes/hash/nombre/tamaño, reentrega sin LLM, nueva revisión con base, anterior preservada | E1–E4 |
| Recarga y reinicio entre turnos | HTTP + worker nuevo | Contexto desde Django y archivos seleccionados, cero dependencia de memoria/VM anterior | E1/E4/E7 |
| HTML histórico en checkpoint | Importación dirigida + descarga | Un miembro, política vigente, una revisión; cero reanudaciones/inferencias/publicaciones repetidas | E4 |
| Archivo solicitado cuya publicación falla | 3 HTTP + error de publicación | No completed falso; código de fallo, reparación acotada, sin enlace inventado | E3/E6 |
| HTML/SVG activo, ZIP malicioso, tipos sin cobertura | Publicación, restauración y descarga | Sin ejecución en origen chat, sin lectura remota, cuotas efectivas, cobertura explícita, bloqueo del paquete si miembro no admisible | E2/E4 |
| Privado y contenido bloqueado | 3 HTTP + todas las salidas simuladas | Control de política, máscara y destino antes de red; original no llega al proveedor ni a búsqueda/paquetes; restauración sella red | Todas |
| Cambiar/revocar permisos entre mensajes o durante operación | 3 HTTP, bootstrap, REST/SSE y download | Usuario/empresa/grant/reglas/máscaras/credencial vigentes; cero nueva salida y retención de respuesta revocada | Todas |
| Cancelar y reconectar | HTTP/SSE + proveedor bloqueado en barrera | Mismo request/call, sin nueva ejecución por reconnect; coste recibido o desconocido conservado, nunca cancelación=cero | E3/E6/E8 |
| Caída antes/después de efecto y claim duplicado | PostgreSQL + worker | Un intento efectivo automático, intento viejo rechazado, incertidumbre no reenviada, watermark exacto al recuperar | E4/E6/E8 |
| Resumen completado, respuestas internas perdidas | SDK/middleware + HTTP | Un call_id estable, una salida/coste, resumen recuperado desde ledger/checkpoint | E6 |
| Pensamiento rápido/razonado | 3 HTTP + SDK real simulado | JSON efectivo correcto por proveedor, salida acotada, incompatibilidad rechazada, razonamiento privado descartado | E5 |
| Límite duro de tiempo/modelos/herramientas | Reloj controlado + HTTP | Parada previa al siguiente efecto, reparación cuenta, parcial honesto y descargable solo por recibo | E6 |
| Texto sin archivos y offload de compactación | Worker con contador de pool | Cero sandbox directo o indirecto; inferencia/protección iguales | E7 |
| Simulación larga + pregunta sencilla en otro chat | 3 HTTP, dos tareas con barreras | Pregunta termina antes de liberar simulación, 1 microVM, 1 escritor por conversación | E8 |
| Saturación, cancelación con proveedor activo, dos workers | PostgreSQL TransactionTestCase | Límites global/empresa/destino/recurso incluso tras cancelación, 429 y Retry-After, sin crecimiento ilimitado | E8 |
| Limpieza tras revocación y apagado | Worker + endpoint de limpieza | Recibo tardío/duplicado válido, ajeno rechazado; SIGTERM con proveedor retenido y sandbox activo no espera indefinidamente | E8 |
| Capacidad frente a coste desconocido | HTTP + ledger de capacidad | Respuesta terminada sin uso libera plaza y conserva cost=null; timeout incierto exige reconciliación de ocupación sin borrar efecto/coste | E8 |
| Coste no informado | Frontera proveedor y recibo | `cost=null`, `known_cost` correcto, `complete=false`; sumas Decimal, sin doble liquidación ni pérdida de reserva | E5/E6/E8 |
| Migración y reversión de lectura | MigrationExecutor + filas sintéticas antiguas | Mismos bytes/hash/relaciones/usuarios/empresas; sin grants ni elegibilidades nuevas; lector v1 funciona | E2/E4 |

La garantía ante fallos externos es **no repetir automáticamente un efecto de resultado incierto**. No se promete exactamente una ejecución en un proveedor que no ofrezca idempotencia/reconciliación. Los tests de replay conocido sí deben observar una única petición HTTP y una única operación/contabilización efectiva.

### Instrumentación y comparación

Persistir intervalos con inicio/fin, execution/attempt/call_id y categoría en AgentEvent/recibo existente; sin prompts, documentos o razonamiento privado. No deducir duraciones por distancia al siguiente evento visual. Categorías:

| Categoría | Medida |
| --- | --- |
| Cola | accepted → claimed; causa de admisión y espera por proveedor/sandbox por separado |
| Preparación | adquisición sandbox, montaje/aislamiento y restauración selectiva |
| Proveedor | comienzo/fin de transporte por inferencia; modelo solicitado/efectivo, salida, uso y costes disponibles |
| Herramientas | autorización/ejecución/resultado por operación; distinguir espera de recurso, ejecución y publicación |
| Protección | evaluación local, clasificación si aplica, máscara, preflight y comprobación final; indicar aciertos de caché |
| Checkpoints/persistencia | captura, transferencia, validación, escritura y recuperación; bytes y cantidad de archivos |

Usar reloj monotónico para duraciones locales y UTC para correlación. Separar tiempo de pared de suma de trabajo: con concurrencia y llamadas anidadas no sumar intervalos solapados como si fueran latencia total. Registrar overhead residual cuando no se pueda atribuir sin inventar exactitud. El rótulo «Entorno preparado» termina antes de empezar generación.

**Comparación offline:** fijar commit, runtime, corpus, perfil, límites y respuestas/latencias del proveedor simulado; ensayar al menos 20 repeticiones por caso/condición y publicar n, mediana, rango y errores. Reportar p95 solo si se calcula de una muestra suficiente e identificada, nunca a partir de los chats 5/6. Las barreras de concurrencia proporcionan una prueba causal aunque las latencias del proveedor sean simuladas.

**Frío/caliente:** frío = worker reiniciado, caché de protección vacía y sin VM creada; caliente = proceso/runtime y cachés permitidas ya preparados, pero siempre sandbox limpio y mismos permisos. Reportar por separado una reserva limpia disponible si se habilitara precalentamiento después; no mezclarla con «cero sandbox para texto». No reutilizar datos privados para mejorar una cifra.

**Objetivos a validar:** texto sencillo con cero VM y normalmente una inferencia; reentrega existente con cero inferencias y bytes idénticos; la pregunta paralela termina antes que la simulación retenida por barrera; caso 6 con 2–4 llamadas y aproximadamente 60 s como meta de calidad equivalente. Ninguno de esos números es un SLA ni una mejora medida todavía.

**Calidad equivalente:** fijar el enunciado original del caso 6 desde evidencia local y una rúbrica previa: dimensiones pedidas, método de simulación, semilla/reproducibilidad, tamaño de muestra/tolerancia justificados, resultado numérico verificable y límites declarados. Comparar también HTML funcional y revisión de color sin perder contenido. Un caso más rápido que elimina requisitos no cuenta como mejora; una comprobación de seguridad retirada invalida la comparación.

**Validación pagada pendiente:** A/B del mismo corpus con quick frente a reasoned/legacy, orden alternado, mismas condiciones y máximo de muestras/coste aprobados antes de llamar. Medir calidad, latencia, tokens, coste conocido/desconocido y fallos. No se hace en esta tarea y no bloquea el plan ni sus tests offline; sí condiciona afirmar una mejora real de calidad/latencia o adoptar un perfil como preferencia general.

## 6. Decisiones tomadas y cuestiones pendientes

### Decisiones listas para ejecutar

1. **Django reconstruye el contexto.** Es la menor solución porque ya contiene identidad, mensajes, permisos y política. Un store LangGraph/Pi adicional no arregla elegibilidad y crea otra fuente de verdad.
2. **Ventana de pares completos; sin nuevo resumen interturno.** Resuelve los casos cortos y preserva roles/correcciones. La compactación existente queda limitada a la ejecución y gobernada, con identidad y recuperación corregidas.
3. **AgentArtifact conserva las revisiones y AgentInput el manifiesto privado.** Reutiliza cifrado, hashes, restricciones y retención. Una tabla Workspace/FileRevision duplicaría mecanismos ya presentes.
4. **Registro de formatos por datos y familias.** Admite ampliación concreta sin clase por extensión; no declara cobertura universal. Descarga y render son capacidades separadas.
5. **Entrega se decide en servidor.** Requisitos y referencias de revisión, no prosa del modelo ni ruta de sandbox. Éxito textual, archivo verificado y entrega son hechos diferentes.
6. **Sandbox lazy en el backend actual.** Preparación después de autorizar herramienta; no clasificador LLM ni ejecución en host. Continuidad por datos, no VM privada persistente.
7. **Un worker con dos tareas y una VM, condicionado a capacidad comprobada.** Es suficiente para el caso de una simulación y otra pregunta sin duplicar sandboxes. La admisión PostgreSQL impide que otro proceso accidental eluda los límites.
8. **Opciones efectivas por ejecución, perfiles visibles y legacy conservado.** DeepSeek rápido manda off explícito; razonado sin herramientas mientras no exista continuidad compatible sin guardar pensamiento privado. No cambiar cuentas en bloque.
9. **Presupuestos concretos y parcial determinista.** Se aprovechan contadores/ledger existentes y se elimina trabajo extra al finalizar. El límite de recursión no sustituye límites de dinero/tiempo/llamadas.
10. **Compatibilidad aditiva y reversión conservadora.** No reautorizar histórico, no borrar contenido al revertir, no reenviar efectos inciertos; mantener lectores de contratos previos.

### Pendientes reales, con propietario y efecto

| Pendiente | Quién/cuándo lo resuelve | Efecto sin respuesta |
| --- | --- | --- |
| Capacidad real para dos tareas, una VM y dos solicitudes al destino | Implementación E8: ensayo offline y configuración de cuota de la instalación | Concurrencia real no se declara terminada; no añadir recursos a ciegas |
| Calidad y latencia reales de quick/reasoned; objetivo del caso 6 | Responsable del piloto, después de aprobar presupuesto A/B | Perfiles siguen optativos; no prometer ahorro o calidad equivalente |
| Disponibilidad al implementar del miembro HTML antiguo y retención | E4: lectura acotada del checkpoint seleccionado | Si expiró, decirlo; no regenerar ni autorizar todo el chat automáticamente |
| Cambios futuros del contrato/versiones de proveedor o runtime | Desarrollador al ejecutar E5/E6: repetir referencias y pruebas si cambió versión | Mantener combinación no acreditada deshabilitada; no adivinar parámetros |

No hay decisiones rutinarias pendientes del usuario para iniciar E1. El primer desarrollador puede crear la fixture, demostrar el fallo en HTTP, aplicar elegibilidad e inyección y cerrar con las aserciones descritas. La tarea actual termina con este plan revisado; implementación, migraciones, pruebas de producto y cualquier validación de pago quedan para su ejecución autorizada posterior.


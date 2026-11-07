# P1 — Skills utilizables, instalación y conversación fluida

**Estado: plan para ejecutar; producto sin implementar en este encargo.** Investigación del 16 de octubre de 2026. Sigue [PROMPT-P1](../../output/harness-audit-20261016/PROMPT-P1.md), [P1-REFERENCIAS](../../output/harness-audit-20261016/P1-REFERENCIAS.md), el [informe del arnés](../../output/harness-audit-20261016/INFORME.md) y el [plan P0](plan-p0-arnes-ia-20261016.md). El vocabulario y las fronteras comunes siguen en [README](README.md); las tareas se registrarán según [issue-tracker](../agents/issue-tracker.md) al ejecutar las entregas, sin duplicar esta especificación.

**Resultado de producto:** una persona descubre una skill compatible, la instala, la selecciona y obtiene un resultado real con recursos y herramientas autorizados. Ve cuándo se cargan las instrucciones, qué trabajo ocurre y texto incremental cuando la política lo permite. Puede descargar y editar archivos existentes sin volver a generarlos. La calidad, los permisos y la contabilidad se conservan y se comprueban en la frontera del proveedor.

Se mantienen Django, PostgreSQL, DeepAgents, LangGraph, el worker aislado, SSE y JavaScript/CSS actuales. No se añaden React, Redis, Celery, una base vectorial, un selector LLM ni un segundo arnés. No hay push, despliegue, publicación, modificaciones de datos reales ni llamadas de pago en esta investigación. Las fuentes externas se leen, no se ejecutan.

## 1. Base comprobada y condiciones de partida

### 1.1 Corte de P0

HEAD inspeccionado: `a16d03984c0a97f400e21093f81eda04a5222c2b`, rama `codex/ocho-p0-arnes`. P0 está principalmente en **cambios locales**, incluidos archivos nuevos, no en ese commit. Por tanto, comparar contra HEAD solo no representa P0. Hay trabajo concurrente de la evaluación P0: la primera entrega debe congelar un manifiesto de los archivos realmente medidos. Se preservan todos los cambios y documentos ajenos.

| Área | Código presente y evidencia | Qué sigue pendiente / consecuencia para P1 |
| --- | --- | --- |
| Historial y ventana efectiva | `agents/history.py`, `jobs.enqueue`, `service.infer`: pares elegibles, snapshot/digests, reserva de salida y comprobación del payload completo. [Tarea 60](tareas/60-p0-arnes-integracion.md), [65](tareas/65-p0-perfiles-presupuestos.md). | P0 no ofrece resumen persistente entre turnos. No rehacer continuidad ni introducir un resumen en cada turno. |
| Artefactos y continuidad | `artifact_formats.py`, `file_continuity.py`, `delivery.py`, `professional_artifacts.py`; migración `0042_agent_artifact_metadata`. HTML/CSS/SVG/ZIP, nombre real, tamaño, revisiones y reentrega determinista. [Tarea 62](tareas/62-p0-archivos-continuidad.md). | El visor activo es P1. La recuperación histórica se probó con datos sintéticos, no se recuperaron archivos reales. |
| Opciones y presupuestos | `inference_options.py`, `capabilities.py`, `runtime_contract.py`: opciones efectivas por proveedor, límites por trabajo, cierre parcial y reparación acotada. | Conservarlos, incluidas compactación, visión y auxiliares en las cuentas. No imponer cuatro llamadas a todos los casos. |
| Compactación y recuperación | UUID5 de compactación; checkpoint v2; resumen reconstruido desde recibo, watermark y recuperación de final sin otra inferencia. `SafeBoundary` restaura estado privado del SDK mediante middleware. [Tarea 66](tareas/66-p0-runtime.md). | Extender únicamente la conservación de skills y la detección de workspace sin cambios. No sustituir el mecanismo de snapshots. |
| Sandbox y concurrencia | Profesional: adquisición después de autorización, texto sin VM, dispatcher limitado, reservas PostgreSQL y reconciliación. El worker documental aún prepara su VM antes del grafo. | E4 difiere también la preparación documental para leer skills sin VM. Ensayo físico RSS/CPU/tmpfs y capacidad real pendientes; todos los workers deben ser v2 para garantías globales. No confundir compatibilidad de checkpoints v1 con convivencia segura de workers v1/v2. |
| Pruebas P0 documentadas | Pasada integrada de 209 casos: 185 OK/24 fallos; correcciones y repetición de 24: 23 OK/1 fallo; última regresión repetida OK. Runtime: 11 nuevas + 3 legacy. | No fue una pasada única de 209 en verde. Aquí se leen código y logs; **no se ha repetido esa suite**. El benchmark causal de 20 repeticiones usa proveedor simulado. |
| Evaluación de diez conversaciones | [Tarea 67](tareas/67-p0-evaluacion-diez-conversaciones.md), corpus `evals/corpora/p0-conversations-20261016/`, [preflight](../../output/p0-real-20261016/preflight/results.json) y [pasada real](../../output/p0-real-20261016/live/results.json). | Trabajo concurrente releído al cierre: preflight con 10 fallos/5 no encolados, cero eventos del proveedor; paquete corregido y pasada real de 19:40:56 a **19:51:30 Madrid**. Resultado registrado: 10 conversaciones/15 turnos, 11 completed, 1 failed, 2 not_enqueued, 1 outcome_unknown y 47 eventos de proveedor. Presupuesto: conocido estimado con tarifas techo 0,0910818 USD; desconocido acotado 0,3098304 USD; comprometido 0,4009122 USD. No es una validación global en verde ni una llamada hecha por esta investigación; evaluación cualitativa/reconciliación e informe final de esa tarea siguen pendientes al corte. |

Las cifras de los chats 5/6 en `live-evidence.json` son **regresiones históricas**. Sirven para escoger casos, no para afirmar ahorro del nuevo P0. Tampoco se vuelve a atribuir a P1 la mejora histórica de `ProtectedHistory` de la tarea 59.

Logs contrastados: [pasada integrada](../../output/p0-e1-e8-20261016/integrated.log), [repetición de fallos](../../output/p0-e1-e8-20261016/affected-regressions.log) y [último replay concurrente](../../output/p0-e1-e8-20261016/concurrent-replay-regression.log). El encabezado del plan P0 todavía dice «propuesta»; se toma el estado de código, tareas y evidencias posteriores. Los perfiles de trabajo son optativos (`work_profiles=true` y selección distinta de `legacy`): registrar selección y límites efectivos en cada comparación, sin cambiar silenciosamente a `quick` para acreditar ahorro.

### 1.2 Versiones comprobadas

Lectura de metadatos locales, además de los locks; no actualización de dependencias:

| Entorno | Versiones relevantes | Decisión |
| --- | --- | --- |
| Aplicación `.venv` | Django 5.2.17, DRF 3.18.1, `openai` 1.102.0, `anthropic` 0.79.0, `httpx` 0.28.1, MCP 1.30.0 | Probar el streaming contra estos SDK y sus cuerpos HTTP reales con transporte simulado. |
| `ops/agent_probe/.venv` | DeepAgents 0.6.12, LangGraph 1.2.14, LangChain 1.4.3, core 1.6.7, langchain-e2b 0.0.6 | Usar APIs presentes en estos archivos. El SDK Anthropic del worker no es el conector de la aplicación; el worker no recibe credenciales del proveedor. |
| Interfaz | Django templates, CSS propio, JS nativo, `agent-chat.js`, `chat.js`, `chat-markdown.js` | Reutilizar tokens, SSE y renderer incremental; ninguna dependencia de componentes React. |

La [documentación actual de DeepAgents](https://docs.langchain.com/oss/python/deepagents/skills) anuncia selección, recarga y otras capacidades posteriores. En el instalado se han leído `SkillsMiddleware.__init__`, `before_agent`, `modify_request` y `_list_skills_with_errors`: acepta `backend`, `sources` y `system_prompt`; descubre con `ls` + `download_files`, conserva `skills_metadata` y resuelve duplicados por nombre con «último gana». **No usar APIs nuevas de pin/reload/tools sin comprobarlas ni aceptar ese override silencioso.**

## 2. Tres recorridos actuales y adaptación mínima

### 2.1 Cargar una skill

Actual: `worker.runtime_prompt()` concatena `system.md`, `documents.md`, `design.md` y SKILL.md documentales según las herramientas. El profesional usa `runtime/professional.md`; `adapter.build_agent()` pasa `skills=None`. Tener archivos en la imagen no los hace descubribles. Además, `data_views.authorize_tool()` solo permite rutas de archivos bajo `/workspace/`: activar un loader sin cambiar esa frontera dejaría `read_file('/skills/...')` denegado.

Propuesto:

1. Django resuelve instalaciones del usuario y empresa, disponibilidad, perfil, permiso vigente y selección del envío. Congela revisiones y el digest de autorización en `AgentExecution.job`.
2. Un backend de skills de solo lectura sirve metadatos/instrucciones/recursos autorizados por operaciones internas. No usa `WorkspaceSandbox` para leer y no concede acceso al filesystem del servidor.
3. `build_agent` añade **una instancia nativa** de `SkillsMiddleware(backend=..., sources=[...], system_prompt=plantilla_compacta)` en su lista de middleware. Se mantiene `skills=None` en `create_deep_agent` únicamente para evitar una segunda instancia predeterminada. La plantilla conserva los tres slots requeridos por 0.6.12. No se copia el loader.
4. El backend compuesto enruta `/skills/<alias>/...` a esa vista y `/workspace/...` al backend actual. La ruta virtual del run queda ligada a una revisión inmutable; no apunta a «latest». Implementar `read/ls/glob/grep/download_files` y variantes async que exija el SDK, con permisos exactos; escritura siempre denegada.
5. Selección explícita: el servidor carga y protege las instrucciones antes de la primera inferencia, sin fabricar una tool call del modelo. Selección automática: el bucle ya existente elige `read_file`; `ResultGate` valida que la llamada fue emitida, y solo tras la lectura completa aprobada se registra la activación.
6. Los scripts se materializan en la VM únicamente después de autorizar ejecución, bajo la misma ruta `/skills/<alias>/...`, con bytes/hash del run, solo lectura. Recursos parciales se obtienen por demanda; una dependencia no instalada no provoca `pip`/`npm` automático.

Puntos de cambio: `adapter.py`, `professional_worker.py`, `worker.runtime_prompt`, `data_views.authorize_tool/tool_result`, `service._context/infer`, `protocol.py`, `checkpoints.py` y nuevos módulos pequeños de catálogo/instalación/backend. El servidor produce la vista canónica de instrucciones; no confía en que el worker devuelva contenido o metadatos equivalentes.

### 2.2 Inferencia con herramienta

Actual: POST web antiguo `/chat/` (y `/chat/<id>/`), `/chat/send/` (y `/chat/<id>/send/`) y `/api/chat/send/` → diccionario de comando normalizado/servicio compartido → `jobs.enqueue` → claim/bootstrap → `worker.run_job` → `professional_worker.run_professional` → grafo → `RegulayModel._generate` → `InternalClient.operation('inference')` → `service.infer` → `AgentGovernedCalls` → conector/HTTP del proveedor. El retorno completo se valida y registra; `ResultGate` llama a `authorize-tool`, ejecuta y pasa por `tool-results`. `AgentInference` acredita las llamadas emitidas; `AgentOperation` registra el efecto antes de ejecutarlo. `general_tools.finish` guarda raw cifrado y una vista que todavía debe protegerse antes del siguiente proveedor.

Propuesto: conservar ese bucle y esos libros de operaciones. El conector recibe eventos tipados del proveedor, acumula cada tool call y **no autoriza ni ejecuta nada**. Solo el JSON completo, validado y registrado en una inferencia terminada puede llegar a `ResultGate`. Los resultados se vuelven pequeños y estructurados. Un error de programa con código de salida distinto de cero no se convierte en éxito porque el transporte haya completado.

### 2.3 Texto al navegador

Actual: `RegulayModel._generate` espera JSON completo; OpenAI rechaza `on_delta` con herramientas. SSE del agente entrega actividad durable, no texto incremental. `AgentWatcher.answer()` espera terminal; `listen()` repinta pasos por evento. Ya existe renderer incremental en `chat-markdown.js`, agrupación por `requestAnimationFrame` en `chat.js` y `delivery_plan/safe_cut/StreamGuard` en chat textual.

**Decisión:** mantener `graph.invoke` y el POST interno de inferencia. Mientras ese POST está abierto, Django recibe el streaming del proveedor, controla los fragmentos y escribe eventos públicos autorizados. El SSE existente los entrega al navegador. Al terminar, el worker recibe **un único resultado final** con texto protegido, herramientas completas y recibo. Esto da streaming real sin construir un segundo canal worker–Django ni trasladar estado/costes al SDK.

```text
Proveedor: texto / argumentos / uso / fin
              ↓ adaptadores específicos, sin efectos
Conector Django → service.infer → autorización + StreamGuard
                         ├─ recibos/AgentInference/Prompt.decision (autoridad)
                         ├─ AgentEvent durable → SSE con cursor → UI incremental
                         └─ resultado JSON final → RegulayModel → ResultGate → herramienta
```

Cambiar a `graph.stream` o implementar `_stream` no es necesario para este objetivo. Si en el futuro otro consumidor necesita chunks del SDK, deberá consumir la misma proyección de servidor; no abrir otra inferencia ni liquidar otro coste. La [API de LangGraph](https://docs.langchain.com/oss/python/langgraph/streaming) orienta los canales, no sustituye el transporte incremental del conector.

## 3. Contratos de catálogo, instalación y ejecución

### 3.1 Estados y selección

| Concepto | Significado verificable | UI |
| --- | --- | --- |
| Disponible | Candidato revisado del catálogo; puede tener requisitos pendientes | «Instalar» o requisito concreto |
| Instalada | Carpeta completa validada, persistida y revisión activa publicada atómicamente | Aparece tras recargar |
| Habilitada | El usuario permite su uso y hoy es compatible con su grant/perfil/política | Switch y disponibilidad efectiva |
| Seleccionada | ID de instalación que el usuario adjunta al **próximo envío** | Etiqueta removible; no dice «activada» |
| Cargada | Django ha añadido instrucciones completas y autorizadas a la inferencia o aprobado la lectura automática completa | «Diseño web · elegida por ti» / «cargada mediante read_file» |

Las etiquetas se consumen al aceptar el envío; quedan en el mensaje como selección histórica. Si el envío falla antes de aceptarse, permanecen en el compositor. No se transfieren al mensaje siguiente. `auto_skills` es una preferencia explícita por conversación, inicialmente activada, guardada en un campo booleano de `Conversation`; modo apagado permite únicamente skills seleccionadas. En modo automático se anuncia el pequeño conjunto instalado, habilitado, compatible y autorizado, nunca el catálogo público. Una skill instalada no añade herramientas al perfil.

Un replay del mismo `request_id` con selección distinta es conflicto, no una actualización silenciosa. Ordenar y deduplicar IDs antes de calcular el digest del envío. Máximo inicial: 3 seleccionadas; 32 habilitadas y elegibles en el catálogo de ejecución, con un máximo adicional de 4.000 tokens de metadatos dentro del presupuesto efectivo. No truncar la lista en secreto: impedir habilitar por encima del límite y explicar qué deshabilitar. Los perfiles sin herramientas no muestran instalación como utilizable; se mantiene el envío textual habitual.

```json
{
  "request_id": "<identidad actual>",
  "message": "Crea una landing para Madrid",
  "skills": {"selected": ["<installation_uuid>"], "auto": true}
}
```

El contrato público admite IDs; no admite cuerpo de SKILL.md, permisos, nombres de herramientas ni revisión elegida por el cliente. El servidor resuelve la revisión al aceptar el trabajo y devuelve la selección efectiva. Las tres entradas HTTP usan esa misma normalización y huella.

### 3.2 Persistencia mínima

No reutilizar `AgentArtifact` como catálogo ni fabricar conversaciones para instalar. Añadir en `agents/records.py`, exportar desde `front/models.py` y crear migraciones aditivas posteriores a la última migración existente al implementar:

| Registro | Campos/índices mínimos | Invariante |
| --- | --- | --- |
| `AgentSkillInstallation` | UUID, company, owner usuario, source_identity, alias, enabled, current_revision, previous_revision, authorization_version, timestamps/tombstone | Único `(company, owner, source_identity)` y alias único vivo por propietario. P1 instala para la cuenta; compartir en toda la empresa queda fuera. |
| `AgentSkillRevision` | installation, UUID, origin URL/ruta, resolved_commit, folder_sha256, manifest, metadatos validados, licencia/atribución, compatibility, bundle cifrado | Inmutable; único instalación + digest + versión de adaptación. Carpeta completa conservada con patrón de contenido privado ya usado en P0. Sin deduplicación entre empresas. |
| `AgentSkillInstallOperation` | UUID/idempotency key, company/owner, action, payload_digest, state, phase, claim/version, lease, result_revision, error_code, timestamps y bytes reales | Intención durable antes de red; una promoción efectiva. Una operación fallida nunca habilita una instalación parcial. |
| Registros existentes | `Conversation.auto_skills`; `AgentExecution.job.skills`; checkpoint con referencias/digests; `AuditLog` para cambios | La caché y el checkpoint no son permisos. Ninguna migración habilita o instala skills a usuarios antiguos. |

`job.skills` contiene revisión/hash y alias elegibles congelados, selección, autorizaciones y ledger de activación; los bytes se conservan en revisiones/entradas privadas, no se multiplican en JSON de eventos. `AgentInput` puede acreditar la vista de instrucciones protegida del run, como ya acredita entradas; no convierte el catálogo en un repositorio de mensajes. `source_identity` = tipo + propietario/repositorio canónico + subruta; un ZIP sin procedencia verificable usa origen «paquete del usuario» y digest, no imita una firma de GitHub.

Los nombres del estándar y los alias de UI son distintos. Dos fuentes con `name: pdf` no se reemplazan: el detalle presenta origen y exige elegir un alias distinto antes de habilitar la segunda. La proyección de metadatos usa nombres únicos resueltos por el servidor; se conserva el nombre original y la carpeta íntegra. No depender de la precedencia «last wins» de DeepAgents. Para el catálogo curado normalizar también directorio y frontmatter.

### 3.3 Instalación coherente sin infraestructura nueva

Biblioteca y estados usan endpoints Django autenticados/CSRF del módulo `agents/skill_views.py` y rutas en `front/urls.py`:

```text
GET  /skills/                              biblioteca HTML / datos filtrados
GET  /skills/catalog/<candidate>/          detalle y requisitos
POST /skills/installations/               candidato, GitHub o ZIP; idempotency key
GET  /skills/operations/<uuid>/            estado de la operación propia
POST /skills/installations/<uuid>/update/  revisión explícita
POST /skills/installations/<uuid>/rollback/
POST /skills/installations/<uuid>/enabled/
POST /skills/installations/<uuid>/uninstall/
```

Elegir un POST **síncrono y acotado** para descarga/validación, con operación durable y consulta de estado concurrente. El navegador crea el UUID antes de enviar y consulta estado durante el POST; un doble clic/reintento encuentra la misma operación. No añadir una cola de instalación ni poner la descarga en un hilo sin propietario. El catálogo P1 contiene paquetes pequeños. Límite inicial de 25 s de red y 30 s total del proceso; si no cabe, error recuperable y alternativa ZIP local. No sostener una transacción de base de datos durante red o extracción.

Proceso único para catálogo, GitHub y ZIP:

1. Verificar actor/empresa/grant y límites; registrar intención con digest. Selección del catálogo requiere un clic «Instalar», sin confirmación adicional salvo exigencia real de la política. Importación ofrece una pantalla de revisión del candidato y una acción final.
2. Resolver GitHub público a commit completo y subruta explícita. Permitir repositorio/ruta de `github.com`, `raw.githubusercontent.com` y descargas oficiales justificadas; validar cada redirect/DNS con `public_web.fetch`, `public_url`, `check_address` y la política de destinos actual. Sin credenciales en URL, esquemas git/SSH, `.git`, hooks, submódulos ni instaladores. Privados en P1: ZIP aportado por el usuario, sin OAuth nuevo.
3. Estados persistidos: `downloading → validating → installed` o `failed`; un paquete local empieza en `validating`. Mostrar bytes si se conocen, nunca porcentajes inventados. Consultar estado no invoca modelos ni reanuda descargas.
4. Staging privado, límites antes y durante descompresión: 10 MiB comprimidos, 50 MiB expandidos, 512 entradas, 10 MiB por archivo y 64 KiB para SKILL.md; límites ajustables solo por configuración del servidor. Rechazar traversal, rutas absolutas/UNC/unidades Windows, `..`, NUL, barras inversas, symlinks/hardlinks/reparse, archivos especiales, colisiones Unicode/casefold, entradas duplicadas y ZIP bombs. No extraer ZIP anidados automáticamente. Aceptar solo UTF-8 para metadatos; assets binarios permitidos y limitados.
5. Validar frontmatter sin tags/objetos YAML, claves duplicadas, alias expansivos ni YAML desmedido; `name/description` válidos, nombre y directorio según la especificación, rutas referenciadas resolubles. Usar PyYAML 6.0.3, ya fijado en el worker, con loader seguro y límites adicionales; falta en los requisitos de aplicación, por lo que E2 fija esa misma dependencia allí. Es una necesidad concreta del formato YAML, sin inventar un parser por regex. Conservar claves del estándar sin interpretarlas como permisos. Guardar carpeta entera y licencia, no solo SKILL.md. Revisar URLs/instrucciones como contenido no confiable, sin obedecerlas durante la importación. Nada se envía a auditorías externas.
6. Manifest ordenado por ruta canónica: `{path, bytes, sha256}` de cada archivo; `folder_sha256 = SHA256(JSON canónico del manifest)`. Excluir metadatos de ZIP como fecha, incluir scripts/references/assets/licencias y modificaciones de adaptación. Guardar digest upstream y digest distribuido por separado. No llamar al hash una firma o auditoría de seguridad.
7. Comprobar requisitos declarados contra capacidades/manifest del runtime instalado. Guardar carpeta aunque falte una capacidad, pero estado efectivo «Instalada · requiere …», no elegible para el modelo. El catálogo curado solo ofrece como «Lista para usar» combinaciones ya ensayadas. El modelo no instala/actualiza paquetes; para sesiones con estas skills se retira `install_packages` del conjunto efectivo salvo una acción humana separada que lo haya autorizado.
8. Publicar revisión y puntero activo en transacción corta condicionada por claim/version y autorización vigente. El staging no es legible por el runtime. Atribución/licencia se ven en detalle y acompañan el paquete. Las descargas públicas registran en el ledger de instalación y `AuditLog` destino, resultado, bytes y `no_api_charge`; esto no afirma coste cero de infraestructura.

Reutilizar evaluación de política/consentimiento y autorización de descargas, sin copiar el `execute` de paquetes que requiere un run y una llamada del modelo. Extraer solo la comprobación común de descarga si hace falta. Las decisiones de instalación no necesitan clasificación/juez LLM. Si la política no permite validar una salida de red localmente, rechazarla con causa y ofrecer ZIP; no hacer un LLM oculto para lograr «un clic».

Interrupción: lease inicial 60 s, fencing por claim/version en promoción. Una recarga consulta la operación; una petición repetida mientras sigue viva devuelve su estado. Tras lease vencido, «La instalación se interrumpió; reintentar» vuelve a adquirir esa operación con nuevo claim, revalida y utiliza staging íntegro verificado o lo descarga de nuevo. Un proceso antiguo no puede promover. Reintentar tras commit devuelve la misma revisión. Limpiar staging vencido con el mantenimiento existente, nunca eliminar bytes aún referenciados.

Actualización explícita: se valida otra revisión, se mueve el puntero y se conserva la previa para rollback. Runs activos mantienen sus bytes fijados; nuevos runs usan la nueva. Deshabilitar/revocar/desinstalar incrementa `authorization_version`: impide cualquier nueva carga, inferencia o ejecución que dependa de ella, incluso con caché caliente. Un run afectado se interrumpe con motivo; no continúa con instrucciones revocadas ya en contexto. Los bytes históricos se conservan mientras los requieran runs/retención, sin seguir dando acceso por estar presentes. Volver atrás cambia el puntero para runs nuevos, no reescribe historial.

### 3.4 Carga eficiente y protección del contexto

La llave de caché combina empresa, propietario, instalación, revisión/hash, grant/version, política/detectores/destino y versión de proyección. Cachear bytes inmutables no cachea permiso. Revalidar al bootstrap, lectura de recursos, cada inferencia y ejecución. Una actualización invalida el catálogo para runs nuevos; una revocación invalida también el run activo.

Reutilizar `SkillsMiddleware` para descubrir y formar metadatos. Si existe `skills_metadata` en checkpoint, comprobar el digest de catálogo antes de reutilizarlo; reconstruir desde servidor si cambió. No aceptar ese estado del navegador. El middleware nativo salta la recarga aun cuando la lista esté vacía; la invalidación es responsabilidad de regulAI. `allowed-tools` se conserva como dato de origen pero no se anuncia como autorización ni modifica `AgentModelProfile.tools`.

Instrucciones explícitas: registrar una entrada canónica por `(run, revision, hash)` antes de generar, colocarla una sola vez en contexto protegido y emitir `skill.activated` con razón `user_selected` cuando esté efectivamente añadida. Automáticas: lectura completa aprobada de SKILL.md, razón `instructions_read`, con `call_id`; una ficha consultada, un `ls`, una lectura incompleta o una recomendación del modelo no producen esa activación. Los recursos se registran por path/digest/rango; una segunda lectura idéntica usa caché de bytes y no duplica instrucciones en contexto. Si la compactación retiró las instrucciones, se rehidratan una vez y se registra `context_restored`.

Mecánica de autoridad: `service.infer` construye el bloque canónico de catálogo e instrucciones desde el ledger; compara/reemplaza la sección que llega del middleware, identificada por campos internos tipados en el protocolo y digest esperado, nunca por delimitadores que un prompt pueda suplantar. Las selecciones explícitas se añaden en servidor, no se aceptan del system prompt del worker. `data_views.tool_result` intercepta lecturas `/skills/` y devuelve bytes/rangos canónicos desde la revisión autorizada, ignorando el raw del ejecutor para esa vista. El prompt compacto indica que las seleccionadas ya cargadas no requieren otro `read_file`.

Para una nueva llamada de lectura repetida, conservar la pareja assistant/tool, pero devolver `{status:'already_loaded', revision_id, instruction_digest}` cuando el cuerpo anterior siga en el contexto acreditado. Un replay devuelve exactamente el resultado original de esa misma llamada; no se cambia retrospectivamente su digest. Tras compactación se rehidrata una única entrada desde servidor. Probar el número de copias del cuerpo en el HTTP final, no solo los hits de caché de archivos.

No se evita que una API sin memoria reciba instrucciones necesarias de nuevo en cada inferencia: se evita **duplicarlas dentro del payload** y rehacer lecturas/protecciones sin cambio. Prefijos estables por revisión y orden determinista permiten medir caché observada del proveedor, nunca prometerla. Todo texto de una skill importada sigue pasando por YARA, ofuscación, destino y límites antes de salir; un archivo privado de skills no se considera público por tener formato SKILL.md.

## 4. Catálogo inicial pequeño y honesto

Seis familias iniciales: hojas de cálculo, DOCX, PDF, PPTX, diseño frontend y revisión web. La simulación es una séptima skill local específica, después de tener contrato y caso de calidad. No publicar fichas ejecutables hasta probar requisitos y tarea completa. Las licencias/documentos upstream son datos de procedencia: no se atribuye una licencia única a `anthropics/skills` entero.

| Candidata y ruta | Revisión / licencia específica | Dependencias y tarea demostrable | Adaptación mínima |
| --- | --- | --- | --- |
| [DOCX local](../../regulai/front/agents/runtime/skills/docx/SKILL.md) | Última modificación `ce33d71d3c2ee94b27a6fb4ab76ea0acbd5a1220`. Original regulAI, [BSL-1.1 del proyecto](../../LICENSE); no Apache por asociación con otras skills. | `document_program.py`, `narrative_program.py`, `corporate.docx`; python-docx 1.2.0, lxml 6.1.0, openpyxl 3.1.5, pypdf 6.19.0, Writer/Poppler. Crear informe y editar solo título/sección, conservando lo demás. | Añadir licencia/NOTICE/compatibilidad y declarar herramientas de documento. No prometer edición Word general. |
| [Excel local](../../regulai/front/agents/runtime/skills/excel/SKILL.md) | `ce33d71d3c2ee94b27a6fb4ab76ea0acbd5a1220`; original regulAI, BSL-1.1. | `spreadsheet_program.py`, pandas 2.3.3, openpyxl 3.1.5, Calc. Tabla `item,amount_cents`, fórmulas recalculadas y renombrado conservador. | Añadir frontmatter y alcance exacto. No anunciar macros, fórmulas de entrada o análisis arbitrario de libros. |
| [PDF local](../../regulai/front/agents/runtime/skills/pdf/SKILL.md) | Modificación local `ff2a947a2e41a9fbe89f3cfb1063308086677900`; adaptada de [OpenAI/skills `49f948faa9258a0c61caceaf225e179651397431`](https://github.com/openai/skills/tree/49f948faa9258a0c61caceaf225e179651397431/skills/.curated/pdf), [Apache-2.0](../../regulai/front/agents/runtime/skills/pdf/LICENSE.txt). Motores propios conservan licencia regulAI. | Motores DOCX/narrativa, Writer/Poppler. Exportar informe, reabrir/renderizar todas las páginas y vincular revisión a hash. | Copiar al paquete el NOTICE hoy en `runtime/NOTICE.md`; conservar revisión visual autenticada. Sin OCR, formularios, PDF/A ni edición libre. |
| [PPTX local](../../regulai/front/agents/runtime/skills/pptx/SKILL.md) | `ce33d71d3c2ee94b27a6fb4ab76ea0acbd5a1220`; adaptación [OfficeCLI `8d079c777ed6bea35b922c3d893758d3c2081137`](https://github.com/iOfficeAI/OfficeCLI/tree/8d079c777ed6bea35b922c3d893758d3c2081137), [Apache-2.0 y avisos](../../regulai/front/agents/runtime/skills/pptx/LICENSE.txt). | OfficeCLI 1.0.155, `presentation_program.py`, narrativa/plantilla, python-pptx 1.0.2, openpyxl 3.1.5, lxml 6.1.0, Impress/Poppler. Gráfico editable con XLSX incrustado y edición localizada, render final. | Normalizar nombre `pptx`, conservar THIRD-PARTY-NOTICES; sin plugins, procesos residentes ni auto-install. |
| [Anthropic frontend-design](https://github.com/anthropics/skills/blob/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/frontend-design/SKILL.md) | `dbd4588f9e1033efb41dad4bef2f7947c8993d44`; [Apache-2.0 específica](https://github.com/anthropics/skills/blob/dbd4588f9e1033efb41dad4bef2f7947c8993d44/skills/frontend-design/LICENSE.txt). | Solo instrucciones y licencia, sin scripts ni dependencia de React/Node. Landing HTML autónoma, responsive, con foco y edición posterior de color. | Añadir encuadre de herramientas/rutas autorizadas y HTML/CSS/JS existentes; no ampliar el encargo ni añadir un crítico por turno. |
| [Vercel web-design-guidelines](https://github.com/vercel-labs/agent-skills/blob/063bee94c3f4df8453406c830b0a7df0f2860278/skills/web-design-guidelines/SKILL.md) | Wrapper `063bee94c3f4df8453406c830b0a7df0f2860278`: [README declara MIT](https://github.com/vercel-labs/agent-skills/blob/063bee94c3f4df8453406c830b0a7df0f2860278/README.md#license), pero su árbol/ZIP no incluyen LICENSE específico. Reglas [web-interface-guidelines `434b7f91364665f2f733b310ec54809bf8f37937/command.md`](https://github.com/vercel-labs/web-interface-guidelines/blob/434b7f91364665f2f733b310ec54809bf8f37937/command.md), con [MIT completo](https://github.com/vercel-labs/web-interface-guidelines/blob/434b7f91364665f2f733b310ec54809bf8f37937/LICENSE). | Lectura de código; navegador existente solo si se solicita comprobación visual. Detectar botón sin nombre, falta de foco y movimiento no reducido, con ubicación/corrección. | El original exige `WebFetch` y reglas de `main` cada vez. Elegimos wrapper original regulAI + snapshot MIT atribuido en `references/`, sin red por turno. Etiqueta «Adaptación regulAI de reglas Vercel», no paquete upstream idéntico. Incorporar el wrapper upstream solo tras completar su aviso de distribución. |

Las versiones de programas anteriores son las fijadas en lock/imagen, no una nueva ejecución del runtime físico. Conservar [NOTICE del runtime](../../regulai/front/agents/runtime/NOTICE.md) y avisos de dependencias; las skills DOCX/PDF/PPTX/XLSX source-available de Anthropic **no sustituyen** estas cuatro locales ni se incorporan por tener el mismo nombre.

Hashes de SKILL.md observados, útiles para detectar cambios antes de empaquetar (no son todavía el hash de carpeta P1):

```text
docx    4130dfdcaa3a4c561171ad48910c369d7dd4c6cfaaa78d17dd457fde0f30dd66
excel   fce15f4ddc781018de9ea8f8da98f0b7d56b37c869f4967d247c2da7627efcfd
pdf     9882230893ea0cde84cbed0791b5faf7ea0e9ab5d6bc563a91997dcc4267de02
pptx    4e271f7e29cff6c552982555d6f3393cd2f3d69debbe8faa021a287c0b5f1499
frontend-design
        d91970639e9f5c37682ac7ab60094d35f1c7c1f38d731bd56396563aee10c1d3
web-design-guidelines upstream
        f4647ca866a3accf763777f83e7682954f0187cd6bea7eea0399796652414e8f
web-interface-guidelines command.md
        d246b026f4f29b5823a9cc857f9edf3d2507002e055e32040cadeaf3b38e0234
```

Normalizar los cuatro paquetes locales antes de registrarlos: Excel hoy no tiene frontmatter y PPTX declara `regulay-pptx` dentro de `pptx`. Los programas y plantillas documentales están fuera de las carpetas SKILL y se copian a `/skills` en la imagen. Decisión: esos cuatro paquetes conservan instrucciones/licencias/avisos y declaran la capacidad documental del runtime fijada por digest; programas y plantillas mantienen su única fuente actual. Las skills importadas conservan íntegra su propia carpeta. No duplicar motores de documentos ni suprimir sus verificadores de artefactos.

Se mantiene el único `AgentAccessGrant` por cuenta. Las cuatro documentales funcionan en el perfil documental compatible; frontend/revisión web/simulación en el profesional compatible. Instalar/seleccionar no cambia perfil ni herramientas. Disponibilidad separa `profile_compatible`, `runtime_ready` y `activation_modes`: sin `read_file` autorizado, una documental admite selección explícita, pero no se anuncia para activación automática. El catálogo explica «Selección manual» o «Requiere herramientas documentales autorizadas», según corresponda. P1 no unifica ejecutores ni permite cambiar grants desde biblioteca.

La skill local `regulai-simulation` tendrá `scripts/random_walk.py`, `references/model.md`, SKILL.md y licencia BSL-1.1 del proyecto. Revisión/hash se generan en su entrega; no existe una revisión publicada que podamos inventar. Usar NumPy **2.5.3 ya fijado** en `ops/agent_chat/requirements.txt`, sin nueva dependencia, para vectorizar caminantes manteniendo memoria O(caminantes × dimensiones). Registrar `PCG64`, build/versión de NumPy, semilla y forma/orden de llamadas: la [compatibilidad de NumPy](https://numpy.org/doc/stable/reference/random/compatibility.html) no garantiza reproducción entre entornos o algoritmos distintos solo por fijar semilla.

Regresión concreta comparable al chat 6: paseo en dimensiones `[2,3]`, semilla `20261016`, 2.000 caminantes, 2.000 pasos, vecino uniforme entre `2*d`, retorno después del paso cero, conteo de caminantes que volvieron alguna vez y fracción por horizonte. La semilla/carga son especificación reproducible nueva, no parámetros históricos demostrados. Un comando `run --spec … --out …` y otro `check …` devuelven JSON acotado; CSV/gráfico solo si se piden. Oráculo independiente con trayectorias pequeñas; rango [0,1], acumulado no decreciente, retornos en pasos pares, límites/cancelación y distinción entre simulación finita y afirmación asintótica. No añadir otra dimensión, series exactas ni microbenchmark. El caso `c09` del corpus P0 es inventario determinista y prohíbe azar: se conserva como caso distinto, no reemplaza esta regresión.

## 5. Trabajo que se elimina y cómo demostrarlo

| Trabajo actual / evidencia | Sustitución mínima | Métrica | Prueba de calidad y frontera |
| --- | --- | --- | --- |
| Buscar/instalar desde lenguaje natural; UI sin catálogo | Endpoints deterministas y manifiesto curado | **0 llamadas LLM** por listar, buscar, detalle, instalar, actualizar y deshabilitar | Transporte del proveedor que falla ante cualquier petición; estado/bytes/licencia correctos tras recargar. |
| Reentrega de archivo | Conservar endpoint y resolución determinista P0; tarjetas lo invocan directamente | 0 LLM, 0 herramienta y 0 VM para descarga/reentrega de artefacto persistido | SHA y permisos iguales; no adjudicar este ahorro nuevo a P1. Listar archivos significa el manifest persistido del chat, no escanear una VM apagada. |
| Skills documentales completas concatenadas por conjunto de tools | Catálogo compacto + carga explícita/automática por revisión | Bytes/tokens del system prompt, lecturas, cargas y duplicados | Captura del proveedor: instrucciones de la elegida, ninguna de las no activadas; recursos reales disponibles. |
| Modelo decide activar una selección ya hecha | Preload determinista de selección | 0 inferencias de selección; 0 tool calls de lectura de SKILL.md explícito | Primera petición al proveedor ya contiene las instrucciones correctas. |
| Relecturas y protección repetidas | Caché revisada + `ProtectedHistory` existente + ledger de carga | Hits/misses/bytes, llamadas locales de protección y tokens duplicados | Revocar con caché caliente impide el siguiente efecto; no hay salto de controles al proveedor. |
| Crear sobre archivo existente, borrar/recrear a ciegas | Contratos `create`, `edit`, `replace` con hash esperado | Reparaciones por conflicto, operaciones destructivas y llamadas totales | `write_file` conserva crear-exclusivo; añadir `replace_file(file_path, expected_sha256, content)` atómico. Error incluye código, revisión/digest actual autorizado y acción sugerida. `edit_file` conserva texto exacto y añade precondición opcional. |
| `general_tools.finish` mete stdout/stderr serializado dentro de `output` | Proyección tipada pequeña, referencia a `read_output` | Tokens de resultado, errores detectados sin otra lectura | Código de salida real, truncado coherente y paginado del contenido protegido; no ejecutar ni tratar logs como instrucciones. |
| Muchas lecturas independientes | El modelo puede emitir varias lecturas en una inferencia; el backend agrupa `download_files` de skills | Llamadas de modelo y viajes internos, p50/p95 de lectura | Cada llamada retiene su autorización, registro y resultado. ResultGate serial por defecto; no paralelizar execute/mutaciones ni dependencias. Un `read_files` nuevo solo si el perfil medido acredita ahorro adicional. |
| Generar utilidades/plantillas cada vez | Scripts y plantillas de la skill fijados | Código generado, intentos de ejecución, resultados correctos | Mismos inputs/seed/oráculo; no dar por mejor una utilidad porque tenga menos llamadas. |
| `SafeBoundary` comprime/transfiere workspace antes de cada modelo cuando existe | Medir captura primero; reutilizar archive previo si ninguna operación pudo modificar workspace | Captura/compresión/transferencia/servidor por separado, bytes y skips | Dirty epoch conservador: write/edit/replace, execute arbitrario, descarga, materialización y efecto incierto ensucian. Lecturas de skills/texto no. Mismo epoch + runtime + manifest + recibo permite referenciar archive previo. Un `execute` desconocido nunca se considera lectura. |

Contrato de resultado propuesto, construido por servidor/runner y protegido antes del modelo o UI:

```json
{
  "status": "completed", "succeeded": false, "exit_code": 2,
  "code": "file_exists", "summary": "El archivo ya existe; usa edit_file o replace_file con su hash.",
  "output_ref": "<call_id emitido>", "truncated": true, "next_offset": 2048
}
```

Máximo inicial de resumen: 2 KiB, ajustado al presupuesto vigente; resultados completos siguen en el almacenamiento cifrado existente. Diagnósticos de contenido no entran sin protección al panel. `operation_details` hoy devuelve argumentos y `result_view`; sustituir su proyección pública por metadatos y extractos expresamente revisados, sin descargar raw al navegador para esconderlo con CSS.

No añadir planificador, crítico o resumidor por petición. Reparaciones solo por fallo concreto y dentro de límites P0, contadas. Primero probar eliminación de trabajo con fixtures, después medir tiempo total. El streaming se mide aparte: mejora la espera percibida, no acredita ahorro de generación.

## 6. Streaming gobernado y durable

### 6.1 Transporte del proveedor y recepción

Ampliar el contrato de conectores de forma compatible: mantener `chat()` final y el callback textual anterior; añadir un consumidor interno de eventos normalizados para texto público, fragmentos de argumentos, fin y uso, además de apertura/cierre cancelable. OpenAI/compatible: agrupar por índice de tool call e ID y capturar el uso final del dialecto verificado. **Alcance P1 del agente: proveedores OpenAI/compatibles que ya soportan sus herramientas.** `AnthropicConnector.chat` hoy rechaza herramientas y opciones explícitas del agente; no resolver esa integración adicional para afirmar streaming universal. Conservar sus pruebas y streaming de chat textual. Un futuro adaptador de herramientas Anthropic requeriría `content_block_start/delta/stop`, `input_json_delta`, uso y opciones efectivos verificados; queda fuera del camino crítico. Modelos/hosts sin soporte incremental verificado conservan modo completo con causa visible.

Acumulación por `call_id/index`, límites por llamada y total tomados de los presupuestos actuales. Rechazar índices/IDs inconsistentes, JSON incompleto, argumentos fuera de esquema, exceso y tool calls inválidas. Una respuesta truncada por límite/EOF autoriza **cero herramientas**, aunque un fragmento recuperado sea JSON parseable. Validar al `finish_reason`/cierre correspondiente y registrar recibo terminal antes de autorizar ejecución. `reasoning_content`, thinking/signatures, tokens internos y trazas crudas no se envían a SSE, logs de UI ni mensajes. Uso/coste se normalizan una sola vez en `AgentGovernedCalls`, nunca sumando cada frame como otra inferencia.

El POST interno sigue devolviendo el resultado final protegido a `RegulayModel`; su retry conserva `call_id`. Un recibo iniciado sin resultado terminal devuelve incertidumbre, no abre otro stream al proveedor. El cierre de conexión del navegador no cancela automáticamente la ejecución; el botón Detener sí lo hace. Worker y navegador tienen canales distintos.

### 6.2 Qué texto puede salir

Reutilizar `delivery_plan`, `safe_cut`, `StreamGuard`, `detect_spans` y las protecciones del agente, con estos cambios previos obligatorios:

1. El comentario actual admite retirar texto tras un fallo final; eso **no revierte la exposición**. P1 no usa retract como control de privacidad. La elegibilidad decide antes de emitir, y cada lote se autoriza antes de persistir/publicar.
2. `_prefix_decidable` examina condiciones YARA, no acredita que la respuesta completa pueda publicarse ni acota todos los patrones. Primera versión conservadora: cualquier regla aplicable cuyo efecto de bloqueo/consentimiento o evaluación necesite el texto completo fuerza `complete`. No construir un analizador general de regex/YARA. Reglas futuras aptas para prefijos requieren una clasificación explícita y pruebas del patrón/condición; no basta `any of them`.
3. `safe_cut` usa un margen normalizado de 96 caracteres y protección de campos, etiquetas y bloques de clave. Revalidar contra **todos los patrones reales** de `local_masking.detect_spans`, en todos los puntos de corte, incluyendo Unicode y valores separados por espacios. Ese margen no se extrapola a detectores nuevos/remotos. Si cambia el detector y no acredita estabilidad, modo completo.
4. La protección del agente incluye aliases y `preserve_aliases`; `StreamGuard.mask` hoy no reproduce ese recorrido. Añadir un callback protector común que preserve aliases emitidos y enmascare texto libre antes de publicar; no desenmascarar un alias con datos privados en UI. Mantener preflight del destino/política y comprobación de permisos en cada lote, incluso fuera del bucle de máscaras.
5. JSON, citas/documentos que necesiten revisión completa, evaluación semántica, compactación y máscara remota se retienen. UI: «Generando · el texto se mostrará tras comprobarlo». Se permiten eventos reales de actividad, no escritura simulada de la respuesta ya recibida.

Para las políticas locales compatibles, el texto se recibe mientras se genera y los prefijos estables autorizados llegan antes del fin. Para respuestas cortas que no superen el margen, es correcto recibirlas completas. Si aparece un error posterior, conservar únicamente lo ya autorizado con marca «Respuesta incompleta» y detener la emisión; no convertirlo en mensaje histórico elegible ni completar el turno. Una revocación impide nuevas lecturas del snapshot/eventos y la continuación, pero no puede borrar lo visto antes de revocarse.

### 6.3 Contrato pequeño de eventos

Extender `AgentEvent`, no crear otro bus. Mantener el frame SSE `event: progress` y el envelope actual `id/kind/data/created_at`; añadir versión/run/attempt sin romper eventos v0. `id` actual es cursor/identidad creciente global, **no una secuencia contigua por ejecución**. Cada append bloquea brevemente la fila `AgentExecution` para ordenar commits de escritores concurrentes; un consumidor no debe avanzar más allá de un evento que aún no haya hecho commit. Migrar al helper único todos los productores, incluidos `jobs.event`, `AgentGovernedCalls.complete_call`, `general_tools.finish` y `checkpoints._interval`. Añadir clave de deduplicación única por ejecución y campo cifrado para texto público; `data` almacenado sigue siendo metadatos acotados y la serialización autorizada añade el texto descifrado al envelope. Snapshot/retención usan el mismo acceso y borrado de la conversación.

```json
{
  "v": 1, "id": 1042, "seq": 1042,
  "execution_id": "<run>", "attempt_id": "<attempt>",
  "kind": "text.delta", "created_at": "<UTC>",
  "data": {"inference_id": "<call_id>", "message_id": "<segmento estable>",
           "offset": 384, "text": "prefijo ya autorizado"}
}
```

| Evento | Campos adicionales esenciales | Cuándo existe |
| --- | --- | --- |
| `inference.started` / `inference.finished` | call_id, propósito, modo/causa de entrega; al fin estado, duración, referencia de uso | Antes de HTTP tras reserva / al registrar resultado o incertidumbre |
| `text.delta` | inference_id, message_id, offset en bytes UTF-8, texto autorizado | Lote validado y persistido; nunca argumentos ni razonamiento; frames terminan en límite de carácter, no usar `string.length` de JS como bytes |
| `skill.activated` | installation/revision, nombre mostrado, reason enum, call_id si automático | Instrucciones realmente incluidas/aprobadas |
| `tool.started` / `tool.finished` | operation/call_id, nombre, fase, status/exit_code, duración | Intención autorizada / resultado registrado; una reconexión no lo genera |
| `artifact.available` | artifact_id, logical_id, revision, metadatos autorizados y acciones permitidas | Artefacto verificado y accesible; no candidato sin comprobación |
| `error` | code, ámbito, efecto, recoverable, acción válida | Fallo controlado sin stack/raw |
| `run.finished` | estado terminal, recibo/entrega, cursor al cierre, coste conocido/desconocido | Cierre idempotente del trabajo; la liquidación tardía puede actualizar después el recibo |

Reutilizar eventos/intervalos actuales para `queued`, capacidad, preparación y controles; no crear eventos token a token para tiempos. Emisiones de inferencias con herramientas se muestran como texto público de actividad ligado a su inferencia; el resultado final tiene su propio segmento estable. No concatenar razonamientos ni repetir ese texto al pintar `Response` final. La finalización confirma/reconcilia IDs y texto, no añade otra respuesta visual.

### 6.4 Agrupación, recuperación y cancelación

- Agrupar inicialmente cada 120 ms: lote de persistencia máximo 16 KiB y frames SSE máximos de 4 KiB; flush final inmediato. Un lote puede guardar varios frames en una transacción. El callback bloqueante deja de leer upstream cuando llena el pendiente y lo drena al siguiente flush; no descarta texto ni abre una cola ilimitada. Las ráfagas no pueden provocar una escritura por token al superar un umbral de caracteres. Medir y ajustar 80–200 ms con presupuesto de controles. Un buffer crudo se acota por bytes/salida del perfil; al exceder, cancelar y registrar incompleto, no crecer sin límite.
- SSE actual consulta cada segundo y `_snapshot` incluye `reap`, contexto y cálculo de recuperación. Crear `fetch_event_batch` ligero con autorización vigente y cursor; separar reaper/snapshot completo. Para proveedor activo, consulta cada 150–200 ms aun si está silencioso; backoff solo en cola o sin generación activa, heartbeats de 15 s. No abrir una conexión DB duradera por navegador ni una tarea por token. Objetivo inicial ≤8,4 lotes de persistencia/s/inferencia más el cierre; filas/frames dependen también de bytes (≤4 por lote). DB/UI se miden aparte.
- El callback del proveedor espera a que el lote esté persistido antes de publicarlo. Un cliente lento consume el log por cursor y no retiene todo el stream en RAM. Retención inicial de deltas activos/recientes 24 h, siempre dentro de la política de conversación; después snapshot de respuesta final o parcial autorizada y marcador de expiración. No conservar raw en eventos.
- Reconexión/recarga usa `Last-Event-ID` y cursor actual. GET de estado devuelve `high_watermark` + snapshot cifrado/autorizado consistente bajo el mismo orden de append. Cliente aplica solo eventos posteriores y deduplica por ID; `offset` comprueba continuidad de texto. Un hueco de offset o cursor expirado solicita snapshot. Nunca vuelve a enviar el mensaje ni llamar a inferencia.
- Detener cambia el estado durable; un vigilante acotado del run consulta cancelación/lease durante el stream y cierra el HTTP del proveedor aun si no llegan tokens. Reutilizar `StreamGuard.opened/closed` y el patrón de lease; objetivo fixture: cierre solicitado ≤1 s. Terminar herramientas cuando el runner lo permita; un efecto no confirmado queda incierto. Desconexión no equivale a reembolso ni a coste cero.
- Caída del worker/aplicación: conservar intención, deltas autorizados, operación/coste inciertos y watermark. Recuperación P0 solo continúa cuando sus invariantes lo permiten; un `AgentInference` iniciado sin respuesta final no se repite automáticamente. Recibos tardíos se liquidan una vez conservando estado de cancelación.
- El cliente puede cerrar SSE al terminar el trabajo, pero si hay coste pendiente consulta el endpoint de recibo con backoff al abrir detalle/recargar. `run.finished` no significa «nunca habrá otra escritura financiera». Una liquidación tardía no crea otro mensaje ni cambia el éxito de un trabajo cancelado.
- Verificar `StreamingHttpResponse`, ASGI, configuración de Gunicorn/proxy, `Cache-Control: no-store`, `X-Accel-Buffering: no`, compresión y flush real en un servidor/proxy de prueba. Cabeceras por sí solas no acreditan ausencia de buffering.

## 7. Dirección de producto y wireframes

### 7.1 Lenguaje visual común

Conservar los tokens de `static/css/chat.css`: superficie blanca/gris, texto `#101828`, acento `#635bff`, equivalentes oscuros existentes; sin fuentes remotas. Segoe UI Variable/Segoe UI/system para interfaz y Cascadia/Consolas para código. Escala: cuerpo 15–16 px/1,5; secundario 13 px; títulos 24/32 px, peso 600; líneas de lectura de 46 rem. Espaciado 4/8/12/16/24/32 px; tarjetas radio 12 px, controles 8–10 px, foco visible de 2 px, acciones principales de 44 px táctiles. Estados con texto e icono, nunca solo color. Contraste AA y modo reducido sin animaciones de escritura ni desplazamiento forzado.

Componentes compartidos: cabecera con buscador, pestañas, filtro compacto, tarjeta de skill, badge de disponibilidad, fila de requisito, botón con estado real, menú de revisión, chip removible, actividad desplegable, tarjeta de artefacto y drawer. Usar templates parciales y CSS del producto; la [referencia Tool de shadcn](https://ui.shadcn.com/docs/ai-elements/base/tool) inspira divulgación progresiva/estados, no instala su stack. [Skills.sh](https://www.skills.sh/docs) inspira descubrimiento; popularidad no es compatibilidad ni garantía.

### 7.2 Biblioteca de skills

Acceso «Skills» visible en navegación y desde el selector del chat. Disponibles/Instaladas, búsqueda por nombre/utilidad/origen y filtros Categoría + «Listas para usar / Requieren configuración». Catálogo pequeño servido por Django y filtrado localmente con debounce 100 ms; si crece, paginación por 24 con filtro servidor. Sin consultas LLM ni catálogo público masivo.

```text
┌ regulAI ─ Chat · Skills ──────────────────────────────────────┐
│ Skills                          [Importar GitHub o ZIP]       │
│ [Buscar por nombre o tarea____________________________]      │
│ Disponibles  |  Instaladas (3)    Categoría ▾  Disponibilidad ▾│
│ ┌ Diseño frontend ────────────┐ ┌ Hojas de cálculo ──────────┐│
│ │ Crea una landing adaptable │ │ Construye y comprueba XLSX ││
│ │ Anthropic · Lista para usar│ │ regulAI · Instalada        ││
│ │ [Ver detalle]              │ │ [Usar en chat]       [⋯]   ││
│ └────────────────────────────┘ └────────────────────────────┘│
│ Sin resultados: ajusta filtros. [Limpiar filtros]             │
└─────────────────────────────────────────────────────────────┘
```

No instalar al clicar la tarjeta: abre detalle. Vacío instalado: «Aún no tienes skills» con acceso a disponibles. Candidato incompatible explica herramienta/dependencia concreta; no habilita un botón que vaya a fallar tras una inferencia.

### 7.3 Detalle e instalación

```text
┌ ← Skills                Diseño frontend                     ┐
│ Crea interfaces y landings con jerarquía y adaptación móvil. │
│ Anthropic · Apache-2.0 · Diseño                              │
│ [Instalar]                                                  │
│ Ejemplos: “Landing de Madrid con una sección de precios”     │
│ Requisitos: ✓ archivos/código autorizados ✓ HTML local       │
│ Incluye: instrucciones · licencia · adaptación regulAI       │
│ ▸ Origen y versión técnica (commit, hash, cambios, licencia)  │
├ Estado real ────────────────────────────────────────────────┤
│ Descargando → Comprobando → Instalada     [Usar en chat]      │
│ Error: el ZIP supera 50 MiB al expandirse. No se instaló.    │
│ [Elegir otro paquete]                                       │
└─────────────────────────────────────────────────────────────┘
```

Tras instalar, CTA pasa a «Usar en chat», sin cerrar automáticamente el detalle. Navegar de vuelta conserva estado. «Usar» vuelve al chat de origen con etiqueta; desde biblioteca sin chat, abre conversación nueva y conserva la selección. Importación GitHub resuelve múltiples SKILL.md y deja elegir **una carpeta**; no instala todo el repositorio. ZIP ofrece la misma revisión y los mismos errores. Actualización muestra cambios/requisitos y una sola acción «Aplicar actualización»; rollback visible en menú de revisión.

### 7.4 Selector del compositor

```text
┌ Mensaje____________________________________________________┐
│ Crea una landing para Madrid                               │
│ [Diseño frontend ×]  ← solo próximo mensaje                 │
├ [+]  [Skills ▾]   Automático [sí]        [Perfil ▾] [Enviar] ┤
│     ┌ Buscar skills instaladas_________________________┐    │
│     │ ✓ Diseño frontend          Anthropic             │    │
│     │   DOCX                     regulAI               │    │
│     │ Revisión web · requiere permiso de lectura       │    │
│     │ [Explorar biblioteca]                            │    │
│     └──────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

Combobox/listbox con flechas, Enter selecciona, Escape cierra y devuelve foco. Quitar chip tiene nombre accesible completo. Switch automático persiste en el chat; cambiarlo no altera un run ya aceptado. Evitar confundirlo con la selección de perfil/modelo de P0. Si una skill se deshabilitó desde otra pestaña, rechazar selección obsoleta antes del proveedor y ofrecer quitarla, sin cambiar en secreto a otra skill.

### 7.5 Chat con resultado abierto

```text
┌ Chat ─ Madrid ───────────────────┬ madrid_landing.html · v2 ┐
│ Tú: cambia el color a azul       │ 18,4 KiB · HTML          │
│ Diseño frontend · elegida por ti │ Vista previa | Código    │
│ Generando · 3,2 s           [▾]  │                         │
│ Texto autorizado que va llegando│ ┌ vista aislada ──────┐ │
│                                 │ │ Madrid              │ │
│ [madrid_landing.html · v2]        │ │ ...                 │ │
│ HTML · 18,4 KiB  [Abrir][↓]      │ └─────────────────────┘ │
│ ▸ Actividad y tiempos            │ [Descargar] [Revisión ▾]│
│ Cola 0,1 · Modelo 3,2 · Tools 0,8 │                         │
│ Controles 0,2 · Preparación 0,0   │                         │
├ [Escribe…]                [↑]   ┴─────────────────────────┤
└───────────────────────────────────────────────────────────┘
```

Los números del wireframe son ilustrativos. La implementación los deriva de intervalos, nunca del hueco entre eventos. Actividad resumida: esperando capacidad, generando, ejecutando, comprobando y terminado; preparación solo entre inicio/fin de preparación. Detalle separa cola, HTTP del proveedor, herramientas, controles, captura/transferencia/checkpoint; los intervalos anidados pueden solaparse y no se suman como si fueran exclusivos. Contadores separados: inferencias, herramientas y controles locales.

Tarjetas a partir de `AgentArtifact` P0: nombre real, formato, bytes, revisión, estado y acciones autorizadas. Una ruta de workspace o borrador no produce tarjeta descargable. Visor lateral 480–640 px a 1440, con ancho ajustable y mínimo legible; a 768 es drawer; a 360 ocupa pantalla con botón volver y foco restaurado. Descarga autentica de nuevo y conserva los bytes; vista previa es una proyección distinta.

HTML/SVG: iframe de origen opaco, `sandbox` sin `allow-same-origin`, inicialmente sin scripts, formularios, navegación superior ni popups. Documento de preview con CSP `default-src 'none'`, sin red, solo recursos empotrados permitidos (`img-src data: blob:`, estilos locales/inline revisados); sin cookies ni almacenamiento del chat. No abrir HTML original inline en el origen autenticado. Para P1, páginas que dependan de JS muestran explicación y código/descarga; habilitar ejecución JS en preview es mejora posterior con pruebas propias. PDF/Office reutiliza renders verificados existentes. Código se trata como texto, no `innerHTML` del artefacto.

El renderer de Markdown existente conserva nodos estables; reutilizarlo y su escape de HTML/protocolos. Actualizar solo el bloque activo por `requestAnimationFrame`, tablas/código con scroll local, y resaltado diferido al cerrar bloque. Si el usuario está leyendo arriba, no mover su scroll; botón «Ir al último mensaje» y contador. `aria-live` anuncia cambios de estado, no cada token. Detalles y drawer tienen teclado, Escape, foco inicial y retorno. Errores: causa + efecto + siguiente acción, por ejemplo «Se perdió la respuesta del proveedor. El coste aún no está confirmado. Consultar estado»; no un botón genérico que repita toda la tarea.

Validación visual requerida a **360, 768 y 1440 px**, claro/oscuro, teclado, zoom 200 %, movimiento reducido, respuesta larga, tabla ancha, código abierto/incompleto, fallo de instalación y catálogos vacíos. Esos wireframes son especificación; no se presenta aquí una UI implementada ni capturas de verificación.

## 8. Contexto, identificadores y medición

### 8.1 Completar P0 sin rehacerlo

Conservar ventana del modelo efectivo, selección de pares y compactación por umbral de P0. Ampliar la estructura conservada del resumen con objetivos/correcciones/decisiones relevantes, IDs de archivos y revisiones, skills cargadas y sus hashes. Los IDs y registros de archivos/skills los reconstruye el servidor; el resumen LLM no puede inventarlos. Ante recuperación, validar recibo de compactación, watermark y permisos actuales. No añadir memoria global por usuario ni resumen interturno en P1 por defecto; medir omisiones reales antes de abrir esa ampliación.

`service._protect_message` ya separa role, IDs de tool calls, nombres e image_ref del texto. Pero `args` y strings de contenido pasan por `_protect_tree`: comprobar `base_revision`, `logical_id`, `read_output.call_id`, referencias de skills y artefactos con valores que parezcan teléfonos/DNI. Crear una proyección tipada de campos estructurales: preservar solo un ID **emitido por el servidor y resuelto con acceso vigente**; proteger títulos, rutas libres, texto, números y UUID aportados por el usuario. No exención global por regex ni por llamar a un campo `id`.

### 8.2 Métricas y protocolo de comparación

Usar `Prompt.decision.calls`, `AgentInference`, `AgentOperation`, eventos/intervalos P0 y el exportador de evaluación existente. Añadir campos a esos recibos, no otra plataforma. Timestamps de pared UTC para correlación; duración monotónica en cada proceso; medir cruce navegador/servidor por sus relojes respectivos sin restar relojes no sincronizados.

| Medida | Definición |
| --- | --- |
| Primer evento | Envío aceptado → primer estado durable mostrado; puede ser cola |
| Primera emisión proveedor | Inicio HTTP proveedor → primer delta recibido, registrando solo clase (texto/argumentos/thinking), sin contenido privado |
| Primer texto público proveedor | Inicio HTTP → primer fragmento del canal textual público; separado de thinking y argumentos |
| Primer texto útil autorizado | Envío → primer lote sustantivo autorizado visible; no puntos, spinner, «voy a…» prefijado ni evento de actividad |
| Tiempo total | Envío → terminal con entrega/estado verificable |
| Trabajo y coste | Generación/compactación/visión/auxiliares por separado; tools; reparaciones; tokens entrada/salida/cache observada; coste conocido, desconocido y exposición reservada |
| Subsistemas | Cola/admisión, preparación VM, proveedor, protección, captura/compresión/transferencia de checkpoint, persistencia, entrega SSE y render |
| Skills | Descarga/validación/instalación, bytes, cargas reales, hits/misses, metadatos/instrucciones/recursos en tokens, cero VM de lectura |

Antes de fijar objetivos de latencia real, E1 captura base P0 por escenario y condiciones. Fixtures de proveedor con chunks/latencias controlados: al menos 20 repeticiones cuando se comparen distribuciones, frío/caliente, contexto corto/largo y una/dos conversaciones; reportar mediana y máximo, p95 con tamaño muestral visible. Los tiempos simulados acreditan overhead, orden y eliminación de trabajo, no velocidad ni calidad semántica del proveedor.

Objetivos iniciales **de ingeniería en fixtures**, sujetos a registrar equipo/carga: catálogo local p95 ≤200 ms, instalar catálogo sin actividad LLM, primer evento ≤500 ms sin cola, publicación autorizada → render p95 ≤350 ms bajo conexión local y un cliente, ≤1 render activo/frame y cero reconstrucciones del historial por delta. Si la base excede un objetivo, registrar causa y objetivo ratificado antes de optimizar; no rebajar aceptación de seguridad/calidad. Con conversación de 200 mensajes y respuesta de 20.000 caracteres, los nodos antiguos conservan identidad y no se vuelven a parsear por lote.

Calidad bloqueante: todos los oráculos funcionales/seguridad/estado/dinero, ausencia de regresiones del corpus y requisitos de los artefactos. Ahorros duros: 0 llamadas LLM de UI, 0 llamadas de selección explícita, 0 sandbox para catálogo/lectura, 0 duplicados de instrucciones por revisión dentro del payload. Simulación: mismo problema/semilla/precisión y comparar contra P0 capturado; enumerar qué llamadas se eliminaron. Un total menor solo se acepta si pasa ese oráculo; no hay factor universal ni objetivo heredado de 60 s.

El A/B real queda descrito pero **pendiente de presupuesto explícito**: mismo corpus sintético y políticas, orden alternado P0/P1, opciones/proveedor fijados, máximo de llamadas y USD aprobado antes de arrancar, reserva conservadora, parada inmediata por coste desconocido, sin retries ocultos ni exposición de datos privados. Reportar costes reales y errores, no extrapolar los fixtures. La ejecución de este plan no autoriza ese A/B ni despliegue.

## 9. Ocho entregas en orden de dependencia

Cada entrega termina con un cambio revisable y sus pruebas focalizadas. Los nombres de archivos nuevos siguientes son propuestas concretas, no archivos implementados. Publicar tareas locales solo al iniciar la ejecución, usando el siguiente número libre; no reservar números que puedan colisionar con el trabajo P0 concurrente.

```text
E1 base y prueba de transporte
 ├─ E2 paquetes/revisiones → E3 biblioteca/importación → E4 activación real
 │                                                      ↓
 │                                                 E5 menos trabajo
 └─ E6 streaming servidor ───────────────────────────────┤
                                                       ↓
                                              E7 chat y resultados
                                                       ↓
                                              E8 aceptación integrada
```

E6 puede prepararse después de E1 en paralelo con catálogo, manteniendo una sola persona responsable de `service.py`, `protocol.py` y migraciones al integrar. E7 espera ambos contratos. No desarrollar ocho ramas sobre la misma autoridad de estado a la vez.

### E1. Base reproducible P0 y prueba del recorrido incremental

**Resultado visible:** informe de una conversación corta, una landing y una simulación con llamadas/tiempos desglosados y limitaciones; prueba que demuestra qué recibe hoy el navegador antes del final. Permite comparar las siguientes entregas contra el P0 real del checkout. No cambia el producto del usuario ni llama al proveedor real.

**Archivos/funciones:** reutilizar `test_agent_continuity.py`, `test_agent_profiles.py`, `test_connectors.py`, `test_chat_streaming.py`, `ops/agent_chat/test_p0_runtime.py`, el exportador de evaluación P0 y `scripts/run_ci_tests.py`. Añadir `front/test_agent_p1_baseline.py` y fixtures sintéticas de eventos HTTP en `evals/corpora/p1-harness/`; evidencia de ejecución en una carpeta nueva de `output/`, sin sobrescribir P0.

**Pasos concretos, listos para empezar:**

1. Leer de nuevo tarea67 y estado git. Guardar HEAD, hashes de archivos tracked/untracked relevantes, versiones Python/SDK, configuración sintética y `selection/work_profiles/effective_options`. Excluir secretos, PDFs privados y `.env`. No esperar a la evaluación real para ejecutar fixtures; sus resultados parciales no se incorporan como benchmark final.
2. Crear PostgreSQL descartable exclusivo con nombre/puerto libres y `ci_settings` sintéticos; verificar host/base antes de migrar. No reutilizar la base o contenedores de otra tarea. Comprobar instalación del paquete worker y presencia de `sandbox_runner.py`/`checkpoint_runner.py` antes de ejecutar el SDK. E1 evita el fallo de empaquetado descubierto en tarea67.
3. Fixture `public_text`: HTTP del SDK emite un texto largo conocido en chunks, con barrera tras el primer prefijo apto y otra antes del uso/final. Fixture `tool_interleaved`: dos herramientas con argumentos entrelazados y fin controlado. El mock está en `httpx.MockTransport`/transporte de SDK, no sustituyendo `connector.chat` por un dict. Denegar cualquier red no local/no fixture.
4. Ejecutar el mismo envío por `/chat/`, `/chat/send/`, `/api/chat/send/` y sus variantes con conversación. Capturar payload real al proveedor, llamadas, roles, uso, tool calls, eventos y recibo final. En P0 se registra honestamente el rechazo de tools+stream y la ausencia de texto del agente antes del terminal; no escribir un test que falle en main solo por pedir una función futura.
5. Reutilizar Madrid → HTML → descarga → color de P0. Añadir el caso de paseo de §4 como especificación separada de `c09`; P0 y P1 recibirán los mismos datos/semilla/criterios. Para la base de coste de orquestación, proveedor simulado con secuencia explícita de tools; para calidad algorítmica, utilidad/oráculo local independiente. No llamar «benchmark de calidad LLM» a eso.
6. Registrar controles y checkpoint servidor ya presentes. Preparar medida de captura/compresión/transferencia del worker en fixture, sin inferirla por resta del total. Ejecutar 20 repeticiones únicamente para las comparaciones de latencia seleccionadas, con frío/caliente y carga identificados. Conservar fallos y condiciones, no borrar outliers.
7. Escribir baseline con IDs de corrida, hashes y estado terminal de cada fixture; fijar objetivos de §8. Si el código P0 cambió durante la corrida, marcar esa base inválida para A/B y repetir solo escenarios afectados. Cerrar/eliminar exclusivamente recursos de test propios.

**Contratos/datos:** solo fixtures/export de evidencia, sin migración productiva. Campos de medida `first_provider_event_kind`, `first_provider_public_text_ms`, `first_authorized_text_ms`, `model_calls_by_purpose`, `repairs`, `checkpoint_capture_ms`, `checkpoint_transfer_ms`; ausente significa no medido, nunca 0.

**Pruebas:** suites P0 focalizadas de continuidad, ventana, perfiles, estado/dinero y SDK runtime; proveedor simulado, bloqueo de red externa y paquete worker. Los checks de PostgreSQL no se sustituyen por SQLite. Un smoke de servidor ASGI+cliente real de SSE comprueba el orden de los frames con barreras, sin esperar un tiempo fijo como prueba de streaming.

**Aceptación:** tres entradas capturadas, ningún gasto/red externa, baseline versionada reproducible, descarga 0 LLM, texto P0 profesional 0 VM y evidencia separada de simulación/orquestación. Todos los valores no medidos son explícitos. No exigir que una pasada real concurrente incierta pase para continuar con catálogo offline.

**Reversión:** retirar únicamente fixtures/instrumentación de esta entrega; no tocar datos ni resultados P0. Nada que revertir en producción.

### E2. Paquetes íntegros y revisiones instalables

**Resultado visible:** API autenticada instala el paquete curado frontend-design, lo lista tras recargar y permite deshabilitar/desinstalar/volver a la revisión anterior. El detalle mínimo muestra origen/licencia/compatibilidad. Todavía no se presenta como activado en una conversación.

**Archivos/funciones:** nuevos `agents/skills.py` (resolución/catalogue/availability), `agents/skill_installation.py` (`validate_bundle`, `folder_digest`, `install`, `set_enabled`, `activate_revision`), `agents/skill_views.py`; `records.py`, `models.py`, `urls.py`, migración aditiva y `requirements.txt` para PyYAML 6.0.3. Manifest curado en `agents/runtime/skill_catalog.json` y paquete/frontend-design fijado con licencia. Reutilizar cifrado, `AuditLog`, permisos de cuenta y patrón de recibos, sin falsear un `Prompt`.

**Pasos:** implementar registros/constraints de §3; validador único y hash de carpeta; instalar desde bundle curado local; publicar atómicamente; idempotencia/doble clic, claim y error accionable; actualización y rollback de puntero; revocación/versionado; consumo de estado por GET. El proveedor, sandbox y motor de paquetes no participan.

**Contratos/datos:** registros de §3.2, API de §3.3 y códigos `invalid_skill`, `path_denied`, `license_missing`, `dependency_unavailable`, `install_in_progress`, `source_conflict`, `authorization_changed`. Desconocer licencia permite conservar staging para revisión, no publicar una ficha «lista» ni inventar licencia.

**Pruebas:** migrar desde la base P0 con usuarios/artefactos/recibos existentes y comprobar bytes/hash/FK/grants intactos; 2 usuarios misma empresa y 2 empresas; instalación duplicada concurrente en PostgreSQL; fallo tras staging y antes/después de commit; recursos y licencia preservados; actualización modifica asset pero no SKILL.md y cambia hash.

**Aceptación:** una instalación efectiva por idempotency key, ninguna parcial utilizable, cero LLM/VM, hashes iguales tras recarga, rollback recupera bytes anteriores. Migración no concede accesos ni llena automáticamente el catálogo instalado de usuarios existentes.

**Reversión:** flag de catálogo desactivado para nuevas acciones; conservar tablas/revisiones y recibos. No hacer rollback destructivo de migración con datos. Retirar rutas nuevas sin afectar chats P0.

### E3. Biblioteca, importación y selector con estados reales

**Resultado visible:** las tres superficies de §7 funcionan: descubrir → detalle → instalar → seleccionar; GitHub/ZIP pasan por la misma validación, fallos y reanudación coherentes. Seleccionar deja preparado el siguiente mensaje, sin afirmar carga hasta E4.

**Archivos/funciones:** `skill_views.py`, `skill_installation.py`, `public_web.py` (reutilización o extracción mínima del guard de descarga), `front/templates/skills/{library,detail}.html`, parciales de tarjeta/estado; `partials/nav_items.html`, `chat/chat.html`, `static/js/skills.js`, `chat.js`, `static/css/chat.css`; diccionario de comando de `chat_service.send_chat_message`, `_web_command`, API y `jobs.enqueue` para transportar selección/huella. Añadir `Conversation.auto_skills` aditivamente.

**Pasos:** filtro/búsqueda y vacíos; detalle/licencia/dependencias; POST con UUID previo y GET estado; importación pública fijada a commit o ZIP; errores/límites de §3; menú de actualización/rollback; selector accesible con chips y preferencia automática; estado y borrador conservados al regresar de biblioteca. Hasta E4, envíos con selección devuelven `skills_runtime_unavailable` antes de red o permanecen bajo feature flag de pruebas, nunca ignoran silenciosamente la elección.

**Contratos/datos:** digest de request incluye selección normalizada; actor/empresa se obtienen de sesión, no del body. El catálogo curado muestra disponibilidad calculada, no reportada por frontend. Deshabilitar afecta siguiente envío y revoca runs dependientes conforme §3.3.

**Pruebas:** descarga pública mock con redirect a IP privada, rebinding, error 429/timeouts y bytes excedidos; ZIP malicioso y árbol con enlaces/collisions; cierre de pestaña durante descarga y proceso antiguo que intenta promover después del lease. Test de interfaz a 360/768/1440, teclado, doble clic, reload, catálogo vacío/incompatible/fallido. Las acciones UI tienen transporte LLM prohibido.

**Aceptación:** instalación compatible con una acción final, sin prompts adicionales salvo política real; estados proceden de servidor; ningún porcentaje ficticio; cero LLM en navegación/instalación; búsqueda local p95 dentro de objetivo E1; URL/ZIP producen mismo digest de carpeta si sus contenidos son iguales.

**Reversión:** ocultar acceso/selector por flag; operaciones iniciadas terminan o expiran bajo fencing; mantener historial/revisiones. Retirar nueva importación no afecta skills ya instaladas ni las hace automáticamente autorizadas.

### E4. Skills cargadas de verdad, sin VM para leer

**Resultado visible:** al elegir frontend-design aparece su activación antes de generar; la inferencia contiene sus instrucciones correctas. El modo automático carga una skill relevante mediante el bucle existente. Las cuatro documentales y revisión web solo están disponibles en combinaciones de runtime/perfil ensayadas.

**Archivos/funciones:** nuevos `agents/skill_backend.py` y adaptador de contexto; `adapter.build_agent`, `InternalClient`, `worker.runtime_prompt`, `professional_worker.run_professional/prepare_tool`, `service._context/infer`, `data_views.authorize_tool/tool_result`, `protocol`, `checkpoints`, `jobs.bootstrap`; `ops/agent_chat/Dockerfile.executor` y mecanismo de empaquetado para incluir solo módulos SDK necesarios, sin modelos/credenciales. Normalizar `runtime/skills/excel`, `pptx`, licencia/compatibility/NOTICE y manifest curado. `Dockerfile.spreadsheet`/preparación autorizada deberán exponer la carpeta de scripts instalada como montaje solo lectura, preservando runner y aislamiento.

**Pasos:** API interna de catálogo/lectura restringida por token+attempt+revision; backend sin VM; middleware nativo compacto y catálogo validado por servidor; preload explícito; lectura automática con operación emitida y resultado canónico; ledger/deduplicación/rehidratación de §3.4; rutas read-only por grant; materialización de scripts tras autorización; congelación de revisiones y revocación durante run. Retirar concatenación incondicional de skills documentales solo cuando el nuevo camino esté activado y probado.

En documental, extraer preparación de `worker.run_job` a `ensure_document_runtime()` idempotente: adquisición/montaje/`E2BSandbox` solo desde `ResultGate.prepare_tool` después de autorizar build/edit/export/create/rename. Lectura de skills y `research_sources` no preparan VM. El efecto real `save_revision` conserva su preparación y controles existentes. Para automático documental, permitir en `service._context` el `read_file` **ya configurado por administrador**, conservarlo en `request_contract.allowed_tools` y ramas `jobs.bootstrap` (incluido mock), y limitarlo en servidor exclusivamente a `/skills/` del run. Sin ese grant, no se añade. Exportación determinista no necesita catálogo. El caso canónico de skill en `data_views.tool_result` va antes de bifurcar profesional/documental; el documental no recibe por ello lectura de originales `/workspace`.

**Contratos/datos:** `job.skills`/checkpoint con versión y referencias servidor. Operaciones internas propuestas `run/skills` y `run/skill-resource` en allowlist de `InternalClient` y rutas internas, sin endpoint de filesystem arbitrario. `run/skills` devuelve catálogo canónico autenticado y digest; lectura recibe instalación/revisión/ruta/rango, nunca una URL que el worker quiera descargar. Registrar activaciones como eventos de §6 con reason verificable.

**Pruebas:** SDK 0.6.12 real con backend que falla si prepara VM; instalar paquete con scripts/references/assets, recargar y leer recursos; explícita en primera petición HTTP y 0 inferencias de selector; automático relevante/irrelevante; read incompleto no activa; lectura repetida/replay/compactación sin duplicar cuerpo; todos los perfiles y tres send; actualización durante ejecución; revocación entre catálogo/lectura/inferencia; metadatos/checkpoint/raw manipulados; otra empresa/usuario denegados.

**Aceptación:** 0 VM y 0 red de repositorios para catálogo/instrucciones; 1 cuerpo por revisión activa en contexto; scripts autorizados con hash fijado; ninguna skill aumenta permisos. Una cuenta documental sintética produce un artefacto verificado por cada formato mediante selección explícita, sin inferencia extra; la misma cuenta con `read_file` autorizado permite automático y sigue sin poder leer originales. Primera operación documental prepara exactamente una VM. Una cuenta profesional incompatible recibe causa clara y conserva su grant/perfil intactos.

**Reversión:** desactivar nuevo loader en runs nuevos; drenar runs con revisiones fijadas. El fallback documental anterior conserva sus verificadores y permisos, pero no se aplica silenciosamente a un envío con selección explícita: informar indisponibilidad. Checkpoints nuevos se identifican por versión/capacidades y se rechazan si el runtime anterior no puede interpretarlos.

### E5. Herramientas precisas, simulación reutilizable y menos IO

**Resultado visible:** crear/editar/reemplazar tienen errores útiles; la simulación no regenera su programa en cada turno; actividad distingue salida fallida de éxito. Repetir una lectura o una inferencia sin cambios no dispara trabajo de archivo innecesario.

**Archivos/funciones:** `protocol.TOOL_PARAMETERS/tool_schema/validate_arguments`, `workspace_backend.write/edit` y nuevo `replace`, `professional_worker` herramientas/preparación, `general_tools.finish/read_output`, `data_views`, `service._protect_message`, `runtime_contract`, `checkpoints.save`, `SafeBoundary.before_model`. Skill `runtime/skills/regulai-simulation/` y sus scripts/fixture; contratos de skills ya definidos en E4.

**Pasos:** proyección estructurada de resultados; create exclusivo/replace CAS y errores de edit; preservar IDs tipados resueltos; utilidad de simulación de §4 y requisitos de runtime; medir lecturas `_file` + helper y captura de checkpoints; si el coste es material en E1, dirty epoch + referencia a archive validado. Mantener pares tool-call/result y registro individual cuando el modelo agrupe lecturas; no añadir ejecución paralela general.

**Contratos/datos:** `replace_file` es herramienta nueva que debe autorizarse explícitamente en perfiles opt-in; no se agrega a grants existentes por migración. `read_output` mantiene referencia y paginado. Checkpoint extendido acepta `archive_ref` del mismo run, digest/runtime/epoch/watermark y permiso vigente; un replay no crea archivo ni sustituye incertidumbre. Conservar lectura v1/v2 segura.

**Pruebas:** conflicto de hash, symlinks y escritura concurrente en runner; JSON inválido/exit_code≠0/truncado; UUID emitido con patrón parecido a PII frente a UUID/números de usuario; simulación con oráculo y límites; checkpoint sin mutaciones reduce captura, con `execute` incluso fallido captura de nuevo; crash tras efecto no habilita skip; documentos conservan contenido/revisión.

**Aceptación:** todas las mejoras tienen fila antes/después con calidad constante; simulación reproducible y sin dimensiones/artefactos no pedidos; cero borrado/recreación para reemplazo previsto; ningún ID legítimo se corrompe y secretos libres siguen protegidos. Saltar checkpoint solo con prueba de ausencia de mutación; si la medición no justifica optimizarlo, conservar mecanismo e informar resultado, sin bloquear P1.

**Reversión:** quitar herramienta nueva del catálogo efectivo, conservar archivos/revisiones; desactivar reutilización de archive y volver a captura completa; mantener lector de datos ya generados. Deshabilitar skill local no elimina artefactos ni autoriza replay de comandos.

### E6. Streaming real del proveedor con controles y recuperación

**Resultado visible:** consumidor SSE de prueba recibe texto autorizado antes del fin del proveedor; modo completo muestra actividad real. Reconnect/cancelación no duplican operaciones o cargos.

**Archivos/funciones:** `connectors.OpenAIConnector.chat/_stream` y compatible; `service.infer/AgentGovernedCalls`, `chat_streaming.delivery_plan/safe_cut/StreamGuard`, `jobs.event/cancel`, `general_tools.finish`, `checkpoints._interval`, `records.AgentEvent`, `agents/views.events/run_status`, settings/ASGI/proxy de laboratorio. No cambiar `RegulayModel` a otro transporte.

**Pasos:** callbacks tipados compatibles; acumulador de tool calls y uso; apertura/cierre cancelable; elegibilidad conservadora de entrega; protector agente alineado con final; event append único, idempotencia, texto cifrado, offsets/snapshot; consulta SSE ligera separada del reaper/snapshot pesado; watcher durable de cancelación; retención y acceso; verificación en servidor/proxy real de laboratorio. Activar por flag después de pasar fixtures; mantener fallback completo por proveedor/política.

**Contratos/datos:** §6, migración aditiva de `AgentEvent` con `event_key` nullable para históricos y contenido cifrado; unique condicional para claves no nulas. El ledger financiero sigue en `Prompt.decision`, sin escrituras por token. `AgentInference` solo entrega tools al worker al estar completo/validado. Fallback no intenta otra llamada tras stream incierto.

**Pruebas:** cada punto de corte de PII, aliases, nombres/contactos multilinea, PEM, Unicode/bytes multibyte, JSON; reglas YARA largas/no acotadas; máscara remota/revisión completa; fragments de 2 tools intercalados, IDs inconsistentes, length/EOF/JSON inválido; errores antes/después del primer texto; slow client, dos consumidores, cursor expirado, commit concurrente, crash de worker y aplicación, proveedor silencioso cancelado, resultado/uso tardío. SDK HTTP real con `MockTransport`, más ASGI+proxy local para flush.

**Aceptación:** barrera del proveedor demuestra primer texto antes del fin, cero dato sensible en cualquier frame/snapshot/log UI, cero tools parciales, una inferencia/operación/cargo por identidad, coste desconocido distinto de cero y stop ≤1 s en fixture. Frecuencia de escrituras depende de lotes/bytes, nunca del número de tokens. Modo completo recibe cero `text.delta` antes de autorización final.

**Reversión:** deshabilitar entrega incremental y conservar conector completo para nuevas inferencias. Drenar streams activos o cancelar de forma explícita; no reejecutar los inciertos. Mantener lectura de eventos/recibos creados. No activar la antigua retirada de texto como fallback de seguridad.

### E7. Chat incremental, tiempos reales y visor de artefactos

**Resultado visible:** chat fluido con activación discreta, actividad plegable, tiempos correctos, errores recuperables y resultado abierto en lateral/móvil. No hay reflow del historial por token.

**Archivos/funciones:** `agent-chat.AgentWatcher.listen/answer/paintSteps/snapshot`, `chat.js` agrupación/scroll, `chat-markdown.js` bloques estables; `chat.html`, parciales y `chat.css`; `agents/views.operation_details` con proyección pública y endpoint de preview; `delivery/artifact_formats` solo para tipos/capacidades del visor, sin nuevo store.

**Pasos:** aplicar envelope compatible v0/v1, segmentos/offsets/dedupe; text.delta fuera de paintSteps/snapshot; rAF y actualización del bloque activo; final reconcilia sin duplicar; tarjetas P0 + drawer; preview HTML/SVG aislado; detalle seguro de tool y recibo de costes tardíos; foco/scroll/teclado/móvil y modo reducido de §7.

**Contratos/datos:** vista pública solo con campos aprobados; preview diferente de download, autenticado y vinculado a revisión; `run.finished` conserva cursor al cierre y estado financiero pendiente. Respuestas largas no exigen virtualizar todo el chat: primero mantener nodos y medir parseo del segmento actual.

**Pruebas:** 360/768/1440 claro/oscuro y teclado; instalación fallida/vacíos; respuesta con 200 mensajes previos, código/tabla y bloques abiertos; captura de red del iframe sin acceso al origen/cookies ni destinos externos; CSP/SVG con scripts/event handlers/links hostiles; reload con stream activo, desplazamiento manual, cerrar/reabrir drawer; revisar screenshots, no solo DOM.

**Aceptación:** tiempos proceden de inicio/fin reales y scopes identificados; «preparando» no incluye generación; cartas solo de artefactos reales. Publicación→render objetivo E1, nodos previos estables, ausencia de long tasks >50 ms causadas por reconstruir historial en fixture objetivo; ninguna pérdida de foco/salto al leer arriba. Descarga conserva SHA y cero LLM.

**Reversión:** ocultar preview y desactivar render incremental conservando texto final/tarjetas P0; todos los eventos nuevos tienen fallback de estado conocido. Los archivos originales y revisiones permanecen intactos.

### E8. Aceptación integrada y decisión de activación

**Resultado visible:** un informe reproducible muestra qué está listo, qué mejora en fixtures, qué no se ha medido y cómo activarlo/revertirlo. No despliega ni compra un A/B.

**Archivos/funciones:** corpus P1 y P0, runners/exportadores de E1, tests nuevos por entrega, pruebas de migración y fronteras existentes; `scripts/run_ci_tests.py` descubre módulos una vez. Actualizar la tarea local de cada entrega con resultados y enlazar evidencia; no copiar este plan a ocho documentos.

**Pasos:** una pasada integrada focalizada tras las entregas; repetir solo fallos/cambios pertinentes; matriz §10; comparación por escenario contra manifiesto P0; validación visual; restore de migración/código anterior sin perder nuevas revisiones; preparar secuencia de activación por cuentas sintéticas, luego piloto autorizado, con rollback de flags y drenaje. Revisar nuevamente tarea67 y reconciliar cualquier incertidumbre antes de usar sus datos como referencia real.

**Contratos/datos:** informe con escenario, base_hash/P1_hash, fixture/proveedor, n, frío/caliente, contexto/carga, calidad, llamadas por propósito, tokens/caché observada, costes conocidos/desconocidos y latencias separadas. Adjuntar límites de compatibilidad y requisitos de runtime por skill. La ausencia de un dato nunca se interpreta como éxito/0 ms/0 USD.

**Pruebas:** tres send + SDK HTTP + PostgreSQL; migración desde P0 preservando mensajes, archivos, grants, costes; state machine/replay y cancelación; corpus completo con recursos de skills; tests de UI y proxy. Para ejecutar scripts en aislamiento físico hace falta imagen/laboratorio corregido; no aceptar solo mock como prueba de bwrap/E2B. Un A/B pagado sigue pendiente de autorización/budget propio.

**Aceptación:** matriz completa en verde, calidad sin degradación, cero duplicados/exposición y objetivos de overhead ratificados; ahorros explicados por llamadas/IO eliminados. Cualquier limitación física/externa pendiente se marca y bloquea solo la activación que depende de ella. Ninguna promesa de velocidad/calidad real basada en fixtures.

**Reversión:** flags independientes `skills_catalog`, `skills_runtime`, `agent_text_stream`, `artifact_preview`; detener nuevas admisiones, drenar, conservar recibos/revisiones y reconciliar efectos/costes inciertos. Mantener tablas aditivas y lectores compatibles. Despliegue, publicación y borrado de datos requieren otro encargo.

## 10. Matriz de aceptación bloqueante

| Caso | Punto de observación / criterio | Entregas |
| --- | --- | --- |
| Instalar paquete real con recursos y recargar | Manifest/bytes/licencias iguales; recurso accesible; primera inferencia explícita contiene instrucciones; 0 VM para leer | E2–E4 |
| Selección y automático | Explícita sin inferencia extra; automática relevante mediante read_file; instalado/habilitado/seleccionado/cargado distintos; tarea irrelevante no carga cuerpos | E4 |
| Permisos/revocación | Misma empresa/otro usuario y otra empresa denegados; disable con caché caliente impide proveedor/tool; contenido privado no sale a auditoría externa | E2–E4 |
| Actualización durante run | Run A conserva revision/hash anterior; B usa nueva; rollback solo cambia futuros; revocación sí detiene A; no sustitución por nombre | E2–E4 |
| Importación hostil/interrupción | Traversal, links, ZIP bomb, duplicados, licencia/deps ausentes, redirect privado, lease vencido y double click sin parcial utilizable ni promoción vieja | E2–E3 |
| Madrid → landing → descargar → color | Todas las entradas, reload y revisión base; HTML correcto, nombre/tamaño/SHA; descarga 0 LLM; skill cargada solo cuando corresponde | E4/E7/E8 |
| Simulación comparable al chat 6 | Semilla/algoritmo/build/carga fijados, oráculo de §4 y sin ampliar tarea; comparación P0/P1 identifica llamadas evitadas | E1/E5/E8 |
| Instrucciones/contexto largo | Primera/repetida/replay/compactación/recovery: una copia del cuerpo y permisos vigentes; se conservan correcciones, archivos y referencias reales | E4/E5 |
| Identificadores | IDs tipados emitidos se conservan; iguales cadenas en texto/argumentos libres siguen protegidas; UUID ajeno no se convierte en permiso | E5 |
| Texto partido | Sensibles en todos los cortes y normalizaciones; ningún frame contiene fragmentos no autorizados; aliases coinciden con final | E6 |
| Herramientas fragmentadas | Fragmentos intercalados, fin truncado, JSON parcial/parseable pero incompleto: 0 efectos; solo final validado autoriza | E6 |
| Política de texto completo | Actividad real, causa de retención, ningún delta anticipado; fallo final no depende de retirar contenido expuesto | E6 |
| Reconnect/reload/slow client | Solo GET, snapshot/cursor/offset coherentes, dos pestañas, sin repetir mensaje/operación/cargo | E6–E7 |
| Cancel/crash/recibo tardío | Stop de stream silencioso, operación incierta conservada, recuperación P0 sin replay ciego, coste desconocido no cero, liquidación única | E6/E8 |
| UI y artefactos | Teclado/móvil, foco/scroll, DOM estable, preview aislado sin cookies/red, descarga bytes idénticos y errores accionables | E3/E7 |
| Migración/estado/dinero | PostgreSQL anterior→nuevo; datos/bytes/FK/grants preservados; ningún acceso automático; una reserva/efecto/liquidación por identidad | E2/E6/E8 |

Pruebas de las tres entradas se parametrizan sobre los **tres adaptadores** y variantes con ID; no se confunden dos URLs del mismo handler con cobertura del POST web antiguo. Pruebas de proveedor interceptan HTTP después de serialización SDK e inspeccionan cuerpo/opciones/stream/uso, además de fallos antes/después del despacho. Los asserts de dinero usan decimales y estado de incertidumbre, nunca suma de floats o coste supuesto cero.

## 11. Fuentes investigadas y decisiones adoptadas

Fuentes públicas leídas sin ejecutar instaladores; Pi/Vercel Skills conservan exactamente las revisiones pedidas. Nuevas revisiones de candidatos están en §4. Las copias temporales fuera del repo no son requisito de ejecución; los enlaces fijados y hashes permiten reproducir la investigación.

| Código / función de origen | Problema que resuelve aquí | Adaptación decidida |
| --- | --- | --- |
| [Pi `skills.ts`, `formatSkillsForPrompt` L358](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/skills.ts#L358) | No cargar instrucciones de todas las skills | Catálogo compacto autorizado mediante middleware existente, lectura a demanda y preload explícito. |
| [Pi `loadSkills` L414](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/skills.ts#L414) | Colisiones/procedencia | Identidad de fuente + alias explícito; no copiar seguimiento de symlinks ni tolerancia a metadatos inválidos. |
| [Pi `agent-loop.ts`, `streamAssistantResponse` L381](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L381) | Separar progreso de resultado consolidado | Eventos públicos gobernados + un retorno final al worker. Sus message updates pueden incluir pensamiento/argumentos: no reenviarlos tal cual. |
| [Pi `failToolCallsFromTruncatedMessage` L478](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L478) y [executeToolCalls L508](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/agent/src/agent-loop.ts#L508) | Argumentos cortados y orden de efectos | Cero tools si truncado; autorización/ledger propios; lecturas agrupables, mutaciones secuenciales. |
| [Pi `read.ts` L86](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/tools/read.ts#L86), [bash.ts L243](https://github.com/earendil-works/pi/blob/698a2d23b86a5045dd54554354a5e0cb7e466795/packages/coding-agent/src/core/tools/bash.ts#L243) | Salidas excesivas y releer todo | Paginado/resultado acotado + `read_output`; tamaños de regulAI y referencia opaca, sin copiar límites grandes/rutas locales. |
| [Vercel Skills `parseSkillMd` L80](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/skills.ts#L80), [discoverSkills L180](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/skills.ts#L180) | Descubrir carpeta y metadatos | Validación estricta adicional del estándar, permisos y límites; no ejecutar CLI ajena. |
| [Vercel `installSkillForAgent` L300](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/installer.ts#L300), [copyDirectory L513](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/installer.ts#L513) | Conservar scripts/references/assets | Carpeta íntegra en staging → revisión atómica. No copiar limpieza del destino ni desreferenciar enlaces. |
| [Vercel `LocalSkillLockEntry` L14](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/local-lock.ts#L14), [computeSkillFolderHash L154](https://github.com/vercel-labs/skills/blob/13e4063a1cf913f5606d57d42ab83a86f5001e04/src/local-lock.ts#L154) | Identidad/hash de todos los recursos | Manifest canónico con separación inequívoca y digest en PostgreSQL. No otro lock manager ni hash solo de SKILL.md. |
| DeepAgents instalado `middleware/skills.py`: `_list_skills_with_errors` L573, `SkillsMiddleware` L752, `modify_request` L913, `before_agent` L941 | Loader ya disponible | Reutilización con backend de solo lectura, catálogo canónico, invalidación propia y nombres únicos. |
| [Agent Skills specification](https://agentskills.io/specification) | Interoperabilidad de carpetas/frontmatter/recursos | Formato externo compatible; permisos, pinning, instalación y controles pertenecen a regulAI. |
| [OpenCode skills](https://opencode.ai/docs/skills/) | Descubrimiento vs activación, disponibilidad | Skills denegadas no se anuncian; lectura bajo demanda. No importar su servidor/arnés. |
| [LangGraph streaming](https://docs.langchain.com/oss/python/langgraph/streaming) y core instalado `_should_stream`/`stream` | Evitar falso streaming al cambiar un método | El transporte real se implementa en conector/servidor; grafo conserva invoke. No protocolo v3 experimental. |
| [Skills.sh](https://www.skills.sh/docs), [shadcn Tool](https://ui.shadcn.com/docs/ai-elements/base/tool), [referencia anterior AI Elements](https://elements.ai-sdk.dev/components/tool) | Descubrimiento y actividad legible | Biblioteca/detalle/selector, línea de actividad y detalle desplegable. La referencia nueva usa Trace/TraceCollapsible/CodeBlock; adaptar visualmente sin React ni raw en UI. |

Mapa local de puntos exactos, con líneas del árbol inspeccionado (pueden moverse por P0 concurrente):

| Archivo / función | Evidencia relevante |
| --- | --- |
| [adapter.py](../../regulai/front/agents/adapter.py), `RegulayModel._generate` L122, `ResultGate` L179, `build_agent` L218 | Inferencia completa, gate y `skills=None` L232. |
| [worker.py](../../regulai/front/agents/worker.py), `runtime_prompt` L24 | Concatenación documental actual; lease renueva cada 15 s, insuficiente como única señal de cancelación ≤1 s. |
| [data_views.py](../../regulai/front/agents/data_views.py), `authorize_tool` L17/131, `tool_result` L210 | Llamada emitida, restricción `/workspace` y proyección que ampliar con ruta canónica de skills. |
| [service.py](../../regulai/front/agents/service.py), `_protect_message` L395, `ProtectedHistory` L434, `infer` L578 | Separación parcial de IDs, caché existente, autoridad de inferencia/gobierno/uso. |
| [connectors.py](../../regulai/front/connectors.py), OpenAI `chat` L142 / `_stream` L171; Anthropic L243 | Bloqueo tools+delta y ausencia de protocolo agente Anthropic; compatibilidad que preservar. |
| [chat_streaming.py](../../regulai/front/chat_streaming.py), `delivery_plan` L85, `safe_cut` L116, `advance` L211 | Base reutilizable; revisar seguridad incremental, no retirar después para proteger. |
| [professional_worker.py](../../regulai/front/agents/professional_worker.py), `SafeBoundary.before_model` L230 | Captura completa con backend preparado; punto de medida/skip conservador. |
| [views.py de agents](../../regulai/front/agents/views.py), `_snapshot` L156, `operation_details` L245, `events` L255, `download` L324 | SSE durable, coste de snapshot/reaper, detalles a redactar y descarga P0 aislada. |
| [agent-chat.js](../../regulai/static/js/agent-chat.js), `paintSteps` L496, `answer` L644, `listen` L855 | Separar deltas de repintado de pasos y aprovechar reconexión. |
| [chat-markdown.js](../../regulai/static/js/chat-markdown.js) L257 y [chat.js](../../regulai/static/js/chat.js) L605 | Reutilización de nodos y requestAnimationFrame ya presentes. |

## 12. Bloqueos reales y mejoras opcionales

**Para ejecutar ahora E1–E4 no falta ninguna decisión rutinaria del usuario.** Licencias/procedencia ya tienen una opción mínima concreta; revisión web usa reglas MIT fijadas con wrapper original. Descargas de fuentes y fixtures no necesitan proveedores pagados. Un conflicto real con cambios P0 se resuelve sobre su árbol final preservando sus datos, no sobrescribiéndolo.

Bloquean solo su aceptación/activación correspondiente: runtime físico sin runners/conversores requeridos para una skill; política que impide su destino/herramienta; falta de estabilidad demostrada para entrega incremental; evaluación con efectos/costes desconocidos sin reconciliar; capacidad física sin ensayo para aumentar concurrencia. Se muestran como requisitos, no como tarjetas que aparentan funcionar. La pasada real P0 terminó con fallos e incertidumbre y aún no acredita una aceptación global; E1 puede avanzar offline con sus propios fixtures y hashes.

Opcionales, fuera de P1 inicial: marketplace público, OAuth para repos privados, catálogo global por empresa, herramientas Anthropic del agente, buscador vectorial, agentes selector/crítico, parser general de YARA, snapshots diferenciales, JS activo en preview, `read_files` si no hay ahorro medido y resumen persistente interturno si el corpus no lo exige. El gate de P1 no depende de esas ampliaciones.

El siguiente trabajo autorizado por este plan, cuando se solicite implementarlo, es **E1 con PostgreSQL y proveedor simulados**, registrando el árbol P0 efectivo y las tres entradas HTTP. Este documento entrega decisiones, contratos, secuencia y aceptación; no activa ninguna de ellas.

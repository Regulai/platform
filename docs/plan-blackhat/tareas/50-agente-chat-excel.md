# 50. Primer recorrido del agente: Excel desde el chat

Estado: implementada y verificada en desarrollo sintético el 7–8 de octubre de 2026; desactivada por defecto y para cuentas actuales.
Blocked by: ninguno para este recorrido acotado; [48](48-agente-prueba-integracion.md) y [49](49-agente-inferencia-y-datos.md) comprobadas con sus limitaciones.
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), apartados de conversación, fluidez, archivos y persistencia del [plan](../../plan-capacidades-agenticas-regulay-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 50. Comprueba la evidencia de 48 y 49 y lee
AGENTS.md y docs/implementacion-agente-regulay-prompts.md.

Entrega un recorrido vertical: un chat nuevo en modo agente recibe CSV/XLSX,
Python calcula en el sandbox, genera un XLSX con fórmulas, lo comprueba y lo
muestra con preview. Usa archivos sintéticos y el modelo simulado para pruebas.

Mantén las tres entradas de envío en send_chat_message. El modo pertenece a la
conversación, se autoriza en servidor y no convierte chats históricos. No metas
los originales en el texto del prompt usando la extracción del chat normal.
Conserva adjuntos autorizados como entradas inmutables y referencias privadas.
Activa esta rama solo mediante configuración explícita de desarrollo/piloto.

Reutiliza Conversation, Message y Prompt. Añade únicamente el estado necesario
de ejecución, eventos y archivos/revisiones; utiliza el registro de alias de 49.
Reclama trabajo atómicamente en PostgreSQL aislado, con un único escritor por
conversación. El ejecutor es un proceso separado y usa solo operaciones internas
autorizadas. Una concesión/intento perdido no puede publicar archivos ni iniciar
efectos nuevos. No ejecutes tareas largas en la petición HTTP ni añadas un broker.
El checkpointer, si hace falta, será el oficial del framework con acceso solo a
su estado; no crees otro historial. Revisa el tratamiento actual de los 240 s.

Desde el primer envío devuelve estado aceptado y muestra actividad inmediata.
Implementa SSE sobre ASGI, eventos persistidos con cursor, reconexión autorizada
y cancelación. Usa progreso humano de operaciones reales. Un sandbox limpio
precalentado se asigna en exclusiva; al liberarlo se destruye y repone. No
recicles entornos usados entre clientes. Explica espera de cola si se agota.

Para XLSX usa pandas/openpyxl y recálculo local con LibreOffice preinstalado.
Reabre, comprueba fórmulas y resultados y contrasta totales independientemente.
Permite reparar errores locales sin aprobación. Publica solo archivos verificados.
Incluye una tabla de preview segura, descarga autenticada y revisiones inmutables
con una identidad lógica estable. Un segundo turno cambia el título de ese mismo
artefacto y conserva los cálculos y formato. Rechaza una edición de versión vieja.

Promueve al paquete del runtime el prompt preparado y las instrucciones/skill
necesarias, con una única fuente de verdad y sus avisos. No cargues las cuatro
alternativas ni un motor Office entero para este recorrido.

Comprueba visualmente la UI y prueba duplicado HTTP, dos pestañas, cancelación,
revocación, acceso cruzado, reinicio del ejecutor y caída de SSE. No reproduzcas
automáticamente efectos inciertos. Ejecuta migraciones en una base aislada y
regresiones de las tres entradas. Registra resultados y detente antes de la 51.
```

## Aceptación

- Subir → calcular → verificar → preview/descarga funciona desde el chat, sin confirmaciones de lectura/cálculo.
- Segundo turno modifica el mismo artefacto lógico sin perder fórmulas ni crear otro análisis completo.
- SSE y precalentamiento presentes; reconectar no repite el trabajo y cancelar impide nuevos pasos.
- Un usuario/chat no puede acceder al estado, eventos, sandbox o archivos de otro.
- Verificación independiente ligada a bytes finales; archivos fallidos quedan como borradores.
- Reinicio se recupera de un punto seguro o declara interrupción, sin inventar éxito ni duplicar efectos.

## Verificación observada

### Recorrido entregado

Un chat **nuevo** puede elegir Agente Excel solo con `DEBUG`,
`REGULAY_AGENT_ENABLED`, `REGULAY_AGENT_DEVELOPMENT` y una entrada explícita en
`REGULAY_AGENT_DEV_ACCOUNTS`, vinculada al usuario `agent-synthetic-*`, empresa y
perfil. Las tres entradas HTTP siguen en `send_chat_message`. La rama se resuelve
antes de la extracción normal del documento y del tratamiento de los 240 segundos.
El envío devuelve **202 accepted**; el modelo y el cálculo no se ejecutan en esa
petición. El chat normal conserva su comportamiento y los chats históricos su modo.

Se reutilizan Conversation, Message, Prompt y los seis registros de 49. La migración
aditiva **0037** incorpora el modo, campos de reclamación/ejecución y solo dos registros
nuevos: eventos y artefactos/revisiones. Originales, borradores, archivos finales y
salidas crudas se guardan privados y cifrados con el mecanismo existente. Los originales
no entran en el prompt ni se resuelven mediante la extracción del chat normal.

El proceso `front.agents.worker` usa Deep Agents real, el adaptador/perfil explícito,
el gobierno, idempotencia, alias y ResultGate de 49. Solo amplía los contratos necesarios:
`build_excel` y `rename_excel`. Python revisado procesa el original dentro de E2B;
el modelo recibe referencias opacas, estructura, ejemplos sintéticos y agregados
comprobados. La vista del usuario contiene las filas originales autorizadas y se
construye con `textContent`, separada de la proyección del modelo. No se ofrecen una
terminal arbitraria ni una herramienta general de reidentificación.

La entrada acotada es CSV UTF-8 o XLSX de una hoja con `item,amount_cents`, importes
enteros, hasta 1000 filas y 2 MB; se aplica el mínimo de grupo del perfil (3 en las
pruebas). Se rechazan fórmulas de entrada, macros y relaciones externas, incluidas
variaciones válidas del XML. pandas calcula; openpyxl crea fórmulas y formato; Calc
preinstalado recalcula. Se reabre con fórmulas y con cachés, y la aplicación contrasta
cada importe y el total con una suma independiente de enteros del original inmutable.
La prueba guarda el SHA-256 de los **bytes finales** y se revalida antes de entregar.
Los candidatos fallidos permanecen como borradores y se puede reparar localmente.

El segundo turno mantiene la identidad lógica y crea otra revisión inmutable. El
cambio de título modifica únicamente A1 en el XML de la hoja: en el ensayo real, todos
los demás miembros ZIP permanecen idénticos, incluidas fórmulas, cachés y formato.
La aplicación exige la revisión vigente; una segunda pestaña con la anterior recibe
409. Descarga autenticada, `no-store`, `nosniff` y autorización actual en cada lectura.

### Concurrencia, autoridad y recuperación

- PostgreSQL reclama con `select_for_update(skip_locked=True)` y una restricción
  parcial permite un único trabajo vivo por conversación. No hay broker.
- Cada concesión dura 60 segundos y se renueva cada 15, con límite absoluto de una
  hora. Solo el token/intento aún vigente puede renovar. Repetir el mismo `claim_id`
  recupera la misma credencial tras perder una respuesta, **sin ampliar su caducidad**.
  Ni la credencial del worker ni un intento antiguo pueden revivir una concesión.
- Cada fase obtiene autorización y se registra antes de iniciarse; repetir esa fase
  no vuelve a ejecutarla. La publicación revalida la concesión bajo bloqueo después
  de verificar el candidato. Cancelar/revocar impide nuevos pasos y publicación;
  una operación local ya iniciada puede terminar antes de destruir el entorno.
- SSE se sirve sobre **ASGI/Uvicorn**, con eventos persistidos, cursor y
  `Last-Event-ID`, reautorización por lote y cancelación. Caer/reconectar no reclama
  trabajo ni produce otra inferencia. La UI presenta aceptación inmediata, operaciones
  reales y espera explícita cuando no hay un entorno limpio.
- Un solo sandbox limpio precalentado se asigna en exclusiva. El usado se destruye
  y luego se repone; nunca vuelve al pool. SIGTERM limpia los entornos. Tras SIGKILL,
  un sandbox huérfano puede durar hasta su TTL de 180 segundos: en esta VM pequeña
  eso puede retrasar la reposición, y se muestra espera.
- No hace falta un checkpointer para este recorrido. No se guarda otra historia del
  grafo: sin un punto seguro, una ejecución abandonada termina **interrumpida**, con
  el estado incierto del recibo conservado, sin repetir efectos ni inventar éxito.

### Evidencia comprobada

Directorio: [task50-chat-excel-20261007](../../../evals/reports/task50-chat-excel-20261007/README.md).
Cada `.result.json` registra comando, salida y duración; se conservan los fallos
intermedios. Las pruebas usan datos sintéticos y el SDK OpenAI real con transporte
HTTP simulado. No se hizo ninguna llamada nueva de pago.

| Comprobación | Resultado |
| --- | --- |
| Relectura de 48 y 49 | Implementación, locks, pruebas y limitaciones contrastados con el código instalado |
| SDK de 48 | 15 pruebas pasan; lock original de 73 distribuciones sin cambios |
| Adaptador de 49 | 5 pruebas pasan; puerta de resultados, compactación, visión y errores simulados |
| Agente, HTTP, estado y migraciones en PostgreSQL | **32 pruebas pasan**, sin omisiones, en 49,668 s; incluye concurrencia real, renovación, revocación, cancelación durante verificación, idempotencia y migraciones 0036/0037 reversibles |
| Último endurecimiento del contrato XML | 9 pruebas de chat pasan en 6,327 s, incluidas relaciones externas con comillas simples y fórmula disfrazada de texto |
| Cierre de revocación e idempotencia | Las **13 pruebas de 50** pasan de nuevo en PostgreSQL en 11,948 s; el duplicado HTTP también reautoriza y se rechaza tras revocar la conexión |
| Límites del parser CSV | Campos sobredimensionados y comillas sin cerrar se rechazan como errores de entrada; CSV válido conservado (`final-csv-parser-bounds.log`) |
| Gobierno y chat normal | **196 pruebas pasan** en 86,947 s: tres entradas, privacidad/destinos, conexiones, límites, estado, dinero/presupuestos y frontend |
| Pool y prompt del SDK | 2 pruebas pasan; asignación exclusiva, destrucción/reposición y solo procedimiento Excel |
| E2B real + ASGI real + PostgreSQL real | CSV y XLSX, valores negativos/cero, fórmulas, Calc, preview, descarga, cambio de título y rechazo de versión vieja |
| Fallos sobre procesos/sockets reales | Duplicado HTTP, desconexión/reconexión SSE con cursor, cancelación durante inferencia, revocación, acceso cruzado y SIGKILL/reinicio pasan en `live-cases.json` |
| Muerte del ejecutor | Un solo evento `claimed`, misma identidad de intento, interrupción a los 60,088 s y ningún cálculo ni archivo posterior; un envío nuevo tras el reinicio completa correctamente |
| Contexto del modelo | Auditoría de 9 llamadas del ensayo y 2 del envío final: marcadores originales, filas maliciosas sintéticas, bytes y logs no aparecen en las solicitudes |
| UI | Verificada visualmente en escritorio y a 390 px, sin desbordamiento horizontal; preview, descarga, actividad y rechazo en una segunda pestaña. Consola sin errores en el recorrido final |
| Configuración/esquema | `check`, `makemigrations --check --dry-run`, `git diff --check`; configuración habitual: enabled=false, development=false, allowlisted_accounts=0 |
| Limpieza | Cero sandboxes E2B restantes; contenedores PostgreSQL, web, worker, redes/reglas y túnel de 50 retirados; VM apagada preservando el volumen de 48 |

En el ensayo estable los HTTP aceptaron en **32,59–179,60 ms**. La cola con slot
preparado tardó 0,319–0,979 s; construir/recalcular/verificar, 7,34–7,50 s; renombrar y
verificar, 4,88–5,00 s. El envío final registró **0,636 s** para crear/preparar un
sandbox limpio y 6,353 s de ejecución. Son mediciones de archivos pequeños en este
laboratorio, no una previsión de capacidad. Una espera inicial de 187,251 s ocurrió
mientras se corregía la plantilla; se conservó como espera real, no progreso ficticio.

### Aislamiento real y limitaciones heredadas

El ejecutor solo alcanza Regulay 31049 y E2B 3000/3002 por la red interna. No tiene
Django, drivers de base de datos, módulos de correspondencias, socket Docker ni claves
de proveedor. El cálculo real dentro de Firecracker usa UID 1000, capacidades
efectivas 0, entradas de solo lectura y carpetas de trabajo/salida escribibles.

La ampliación de sockets encontró una limitación **no acreditada por la prueba 48**:
`deny_out=0.0.0.0/0` bloqueaba el receptor IPv4 pero permitía el endpoint de metadatos
`169.254.169.254:80` dentro de la microVM. El kernel fijado tampoco dispone de
`xt_owner`; ese intento de regla se conserva como fallido. La preparación añade una
ruta kernel `prohibit 169.254.0.0/16` antes de asignar datos. Con ella pasan receptor
IPv4, IPv6 desactivado, puerto de base de datos y metadatos, tanto desde el ejecutor
como desde el sandbox. El receptor responde desde su red antes y después. Evidencia
válida: `real-network-metadata-fenced-vm.log` y el informe de red con `passed=true`.

Se conserva la limitación **NoNewPrivs=0 dentro de la microVM** de 48; no se presenta
como aislamiento probado de Python arbitrario. Este recorrido solo permite las dos
operaciones revisadas, elimina setuid/setgid y monta las instrucciones como solo
lectura. Las garantías no cubren canales laterales universales ni inteligencia de
un modelo real. La prueba histórica global de 48 tenía dos `unexpected successes`
previos; no se declara retrospectivamente verde.

Se heredan también las restricciones de 49: perfil explícito OpenAI compatible,
clasificación/verificación local y rechazo de política obligatoria incompatible;
no se relajan políticas ni destinos para hacer pasar el agente. El mínimo de filas
no demuestra anonimato ni personas distintas. No hay Word/PDF/PPTX, MCP, editor
Office general, reparación arbitraria de cualquier libro ni piloto con usuarios reales.

### Versiones, material y reproducción

SDK fijado de 48: Deep Agents **0.6.12**, langchain-e2b **0.0.6**, E2B **2.53.1**,
LangChain **1.4.3**, langchain-core **1.6.7**, LangGraph **1.2.14**. Lock SHA-256
`dfbe209fa61f49afc01e94c3846bffd3f23e4571c1e3718bab03eaed6fa8de62`, sin cambios.
Aplicación: Python **3.12.11**, Django **5.2.17**, OpenAI **1.102.0**, psycopg **3.3.6**,
PostgreSQL **17**, Uvicorn **0.35.0**. Sandbox: pandas **2.3.3**, openpyxl **3.1.5**,
NumPy **2.5.3**, LibreOffice **25.2.3.2**, paquete Calc
`4:25.2.3-2+deb13u8`. Los nuevos locks contienen hashes; sus digests están en
`lock-digests.json`. No se modifica el lock del ejecutor ni las dependencias de cuentas.

El prompt de sistema preparado, instrucciones comunes/Excel y una skill original
residen en [front/agents/runtime](../../../regulai/front/agents/runtime/NOTICE.md),
con procedencia y avisos; las rutas anteriores apuntan a esa fuente. El ensamblado
no carga las cuatro alternativas. Calc y dependencias están preinstalados; no se
descargan paquetes durante una conversación.

La plantilla se construye desde una imagen local por digest, que E2B importa mediante
un servidor loopback temporal de solo lectura. No hay push ni publicación. Se
conservan los fallos por recursos y caché: la construcción por capas agotaba las
hugepages de la VM pequeña, y una etiqueta mutable reutilizaba una imagen antigua.
La solución preinstala todos los archivos y Calc, usa digest y reserva 3 GiB de
hugepages. El host/backend sigue siendo el de 48, no otro sandbox.

Comandos principales desde la raíz; usar nombres de evidencia nuevos:

```powershell
rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_probe/verify_sdk.py --output NUEVO-48
rtk proxy ops/agent_probe/.venv/Scripts/python.exe -m unittest discover -s ops/agent_probe -p test_governed_adapter.py -v
rtk proxy .venv/Scripts/python.exe regulai/manage.py migrate --settings=regulai.agent_chat_test_settings --noinput
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_chat front.test_agent_inference front.test_agent_state --settings=regulai.agent_chat_test_settings --noinput
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_pipeline front.test_pipeline_privacy front.test_required_masking front.test_ai_connections front.test_difficulty_routing front.test_local_masking_integration front.test_state front.test_smoke front.test_evaluation_budget front.test_calibration_budget front.test_backend_hardening front.test_connectors front.test_frontend_chat front.test_frontend_resources --settings=regulai.test_settings --noinput
rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_chat/test_runtime.py
rtk proxy python ops/agent_chat/bundle.py
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/prepare_vm.sh --log NUEVO-build.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/start_lab.sh --log NUEVO-start.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/run_live_cases.sh --log NUEVO-live.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/refresh_executor.sh --log NUEVO-network.log
rtk proxy python ops/agent_chat/collect.py --output NUEVA-EVIDENCIA
rtk proxy .venv/Scripts/python.exe regulai/manage.py makemigrations --check --dry-run --settings=regulai.test_settings
rtk git diff --check
```

Preparación, uso y limpieza en [ops/agent_chat/README.md](../../../ops/agent_chat/README.md).
Los PostgreSQL de pruebas son desechables y aislados (puerto local 55450); las
migraciones no se ejecutaron sobre datos actuales. Se conserva la copia inicial y
el informe de comparación del trabajo local previo. No hay commit, push, despliegue,
publicación, escritura externa real ni nuevas llamadas de pago.

**Parada antes de 51.** No se modifican ni se habilitan las tareas posteriores.

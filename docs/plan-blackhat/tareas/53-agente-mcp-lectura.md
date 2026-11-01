# 53. Un conector documental mediante MCP

Estado: implementada y verificada técnicamente el 13 de octubre de 2026; cuenta externa autorizada pendiente, conector real deshabilitado.
Blocked by: [52](52-agente-powerpoint.md).
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), sección de conectores del [plan](../../plan-capacidades-agenticas-regulay-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 53. Lee AGENTS.md y
docs/implementacion-agente-regulay-prompts.md. Reutiliza el ejecutor, gobierno,
puerta de resultados y artefactos ya verificados.

Integra un cliente MCP mantenido y un único servidor documental de lectura.
Comprueba primero qué conexión autorizada existe en el entorno del piloto.
Prioriza Google Drive si ya está disponible; si el piloto usa Microsoft 365,
usa ese destino. No construyas ambos conectores ni supongas que las conexiones
del asistente de desarrollo son credenciales de los usuarios de Regulay.

El recorrido es buscar un documento autorizado, obtenerlo, conservarlo como
entrada privada y producir un informe. Las credenciales viven en el módulo de
herramientas de confianza; el modelo y el terminal reciben referencias opacas.
Los documentos descargados pasan por las mismas vistas y alias que los adjuntos.

La configuración administrada define servidor, operaciones y alcance. Expón solo
búsqueda/lectura/descarga autorizadas. Revalida identidad y permisos en cada paso;
no confíes en el indicador read-only del servidor. Un cambio de catálogo o schema
no amplía permisos. No habilites sampling/inferencia de MCP por defecto ni una
salida de red alternativa. Los procesos stdio no heredan secretos del servidor.

Usa una configuración versionada sencilla; no marketplace, instalación autónoma,
descubrimiento ilimitado de servidores ni sincronización completa de cuentas.
Fija una versión del adaptador MCP compatible con Deep Agents y traduce errores
a mensajes útiles sin volcar respuestas crudas o credenciales.

Prueba el contrato con un servidor MCP real de fixtures y transportes externos
simulados: revocación entre búsqueda y descarga, documento ajeno, cambio de
esquema, instrucciones maliciosas y error con datos sensibles. Este banco no
acredita que la conexión externa del piloto esté habilitada: deja esa comprobación
pendiente si no hay cuenta autorizada. No solicites aprobar cada lectura permitida.

Si la integración elegida exige un alta o autorización humana que falta, prepara
la configuración concreta y completa las pruebas independientes; no inventes
credenciales ni actives otra integración por tu cuenta. Registra resultados y
detente antes de la 54. No implementes aún escrituras externas.
```

## Aceptación

- Un único conector/servidor seleccionado; buscar/obtener/procesar usa el recorrido existente.
- Revocación, alcance y datos cruzados se comprueban por operación, no solo al conectar.
- Sin credenciales en prompts, resultados, logs o sandbox; sin inferencia MCP fuera de Regulay.
- Lecturas autorizadas sin confirmaciones; configuración administrada y permisos explícitos.
- Se distingue claramente evidencia del servidor de fixtures y prueba de la cuenta externa.

## Verificación observada

Se selecciona exclusivamente Google Drive. No se ha aportado una concesión de
cuenta/carpeta para usuarios de Regulay; el plan también mantenía ese dato pendiente.
La configuración de aplicación no contenía MCP/Drive/Microsoft 365 y no se han
usado las conexiones del asistente. `REGULAY_AGENT_MCP_ENABLED=False` y cada
`AgentDocumentConnection.enabled=False` por defecto. No hay escrituras en esta tarea.

El SDK oficial **mcp 1.26.0**, rama 1.x mantenida, ejecuta un servidor real
`regulay-drive-v1` sobre streams de memoria dentro del módulo de confianza.
Se fija identidad/versión y el catálogo completo de esquemas; no se incorpora
un servidor remoto con instalación/discovery, proceso stdio, sampling, roots,
elicitation ni inferencia. El servidor solo usa HTTPS de Drive v3, sin redirects,
proxies del entorno o reintentos. [Configuración administrada](../../../ops/agent_mcp/config.json)
y [lock universal con hashes](../../../ops/agent_mcp/requirements.txt).
El lock web es Linux; el ejecutor Deep Agents 0.6.12/E2B 2.53.1 no añade MCP.

La concesión por usuario/empresa cifra token, permissionId y carpetas directas.
Cada búsqueda/descarga revalida membresía, vigencia, versión y usuario de Drive;
cada documento debe permanecer en una carpeta autorizada, descargable y no borrado.
Se comprueba otra vez después de transferir. IDs originales permanecen cifrados
en referencias efímeras de diez minutos. Las respuestas/errores del proveedor no
son contenido del modelo. Se aceptan CSV/XLSX del mismo contrato `item,amount_cents`
del adjunto; Google Docs nativos, recursión de carpetas y formatos arbitrarios no
están soportados. No se simula una capacidad de lectura documental general.

En el chat se busca y selecciona una referencia opaca; las tres entradas HTTP
resuelven esa referencia y crean el mismo `AgentInput` privado. Desde ahí se
reutilizan alias, gobierno, SDK, E2B, revisión visual, previews y descargas.
No se pide aprobar la lectura. El diseño corporativo de 51/52 no se modifica.

### Comandos y resultados

Evidencia nueva: [task53-mcp-20261013](../../../evals/reports/task53-mcp-20261013/).
Todos los comandos lanzados con `rtk`, bases aisladas y transporte externo simulado.

- `rtk proxy python ops/agent_chat/record.py --output-dir evals/reports/task53-mcp-20261013 final-state rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_mcp front.test_agent_chat front.test_agent_inference front.test_agent_state --settings=regulai.agent_chat_test_settings --noinput`: **40 OK**, 49,247 s totales. PostgreSQL real; incluye tres entradas, aislamiento, SSE, concurrencia, estado y dinero.
- `... mcp-migration ... test front.test_agent_mcp ...`: **9 OK**, 7,231 s totales; catálogo cambiado, identidad, documento ajeno, revocación entre búsqueda/descarga y durante transferencia, errores sensibles/redirect, caducidad y migración reversible 0038↔0039. La migración preserva empresa/conversación; no crea cuentas ni concede permisos.
- `... governance ... test front.test_pipeline ... front.test_frontend_resources --settings=regulai.test_settings --noinput`: **196 OK**, 58,089 s; comando íntegro en el JSON de resultado. No se reintroducen límites de generación.
- `... sdk-prior ... ops/agent_probe/verify_sdk.py --output .../sdk`: **15 OK** con SDK real y transportes simulados; no se cuenta como prueba E2B.
- `rtk proxy uv pip compile ... --generate-hashes`; `uv pip check`: dependencias compatibles. `makemigrations --check --dry-run`: sin cambios; `git diff --check`: limpio.
- `bundle.py`, `remote.py provision.sh`, `start_mcp_lab.sh`, `start_worker.sh`, `forward.py`, `mcp_live.py begin/review`: **recorrido HTTP → MCP real → Drive simulado → E2B real → DOCX verificado**. Se inspeccionaron las dos páginas antes de registrar su revisión. Descarga SHA-256 `fc62434b10747e7d19b73f2142f78cf1a70c720dc3fcd1d903c793cea6f82fd6` igual a la revisión privada. [Registro, DOCX y páginas](../../../evals/reports/task53-mcp-20261013/live/http.json).
- `remote.py refresh_executor.sh --log .../network.log`: **sockets reales OK**, controles positivos IPv4/IPv6 antes/después; ejecutor y sandbox sin acceso a receptor ajeno, PostgreSQL ni metadatos. UID 1000, capacidades cero y entradas de solo lectura; continúa el límite histórico NoNewPrivs=0 dentro de Firecracker.
- Búsqueda/selección inspeccionadas en móvil y escritorio. [Móvil](../../../evals/reports/task53-mcp-20261013/ui-search-mobile.jpg), [escritorio](../../../evals/reports/task53-mcp-20261013/ui-selected-desktop.jpg).

Se conservan intentos fallidos: una cuenta de fixture incompleta y un lock inicial
Windows que incluía pywin32 en Linux. Se repararon antes de la verificación final.
El primer ASGI de laboratorio se interrumpió al arrancar; el arranque posterior y
el recorrido completo pasaron. Ninguno de esos intentos se cuenta como éxito.

### Límites y paso a 54

La cuenta real de Drive, consentimiento OAuth readonly y carpeta autorizada se
mantienen **pendientes**. El token se provisiona por administración; no hay alta
OAuth automática ni renovación silenciosa. No se ha habilitado ninguna cuenta
real, llamado a modelos de pago ni atribuido calidad generativa a fixtures.
La 53 queda técnicamente verificada antes de iniciar la 54; esta podrá usar el
transporte simulado sin conceder permisos externos reales.

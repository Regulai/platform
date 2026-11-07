# 59. Chat y agente: respuesta progresiva y actividad legible

Status: Aplicado en la rama `claude/aplicar-rediseno-chat`, publicado en `JaviCKP/RegulaiV.2` (`main`) y desplegado en la instalación local `regulai-v2-vm` con autorización del usuario (2026-10-15). Incluye el motivo de fallo real, la duración de las ejecuciones interrumpidas y el enmascarado de datos personales de páginas públicas. Sin ensayo nuevo con el proveedor real.
Blocked by: Nada para lo desplegado. Pendiente de decisión del usuario: si mostrar los borradores verificados de ejecuciones interrumpidas, si acotar la memoria de WSL2 y si retirar la regla duplicada #8. Los ensayos con proveedores reales necesitan autorización de gasto.

Numeración: se creó como «57» en el worktree del rediseño; se renumera a 59 porque la 57 del checkout principal es la activación real y la 58 el instalador.

Especificación: encargo del 2026-10-14. Es un rediseño real del chat y del modo agente:
- menos texto redundante, con la conversación y los entregables en primer plano;
- respuesta progresiva real;
- actividad del agente comprensible;
- complejidad plegada bajo demanda.

Se conservan conversaciones, adjuntos, documentos, revisiones, descargas, citas, permisos por
empresa y aprobaciones. Sin dependencias nuevas, sin push ni despliegue y sin llamadas a APIs de pago.

## Aceptación

- El texto aparece mientras se genera, y solo después de las mismas comprobaciones de salida
  que la respuesta final: enmascarado local, YARA y destinos. Si una comprobación final
  falla, se retira y no se persiste. Cuando el control necesita el texto completo, se entrega
  completo y se muestra el motivo.
- Detener, reenganchar tras un corte o una recarga y cambiar de conversación no repiten la
  inferencia ni crean otro envío.
- Las tres entradas HTTP sin `stream=1` mantienen su contrato JSON. Se conservan los
  invariantes de estado y dinero: el coste desconocido nunca aparece como 0.
- Cada estado tiene un aviso con sus acciones, también tras recargar: bloqueado,
  consentimiento, error, cancelado y en curso.
- El agente muestra en cada turno los eventos registrados, las herramientas y la duración
  medida por el servidor, sin plan, porcentaje ni verificación inventados. La comprobación
  técnica, la revisión visual humana y la autorización de exportación siguen separadas.
- Se verifica en navegador real, en escritorio y móvil: teclado, foco, contraste,
  movimiento reducido, adjuntos y estados.

## Secuencia de trabajo

1. [hecho] Streaming en el backend: conectores OpenAI y Anthropic, `StreamGuard`, motivos de
   entrega completa, registro en memoria, reenganche y parada (`chat_streaming.py`,
   `chat_service.py`, `chat_ui.py`).
2. [hecho] Interfaz:
   - plantillas `chat.html` y `_turn.html`;
   - proyección `chat_page.py`;
   - `chat.css`;
   - `chat-markdown.js`, `chat.js` y `agent-chat.js`.
3. [hecho] Laboratorio aislado: proveedor simulado, semilla, capturas y verificación con Playwright.
4. [hecho] Reescritura de las pruebas de interfaz con un navegador sin red
   (`front/offline_browser.cjs` y `.py`), conservando cada invariante de las antiguas.
5. [hecho] Suite completa en serie y comparación con `fa375ad`.
6. [hecho] Verificación en navegador, capturas «después», este documento y el informe.
7. [pendiente externo] Aplicar el parche en el checkout principal y ensayarlo con worker y
   PostgreSQL y con proveedores reales bajo autorización.

## Verificación observada

### Pruebas de aplicación

- **En verde:**
  - `test_frontend_chat` 19;
  - `test_agent_frontend` 17;
  - `test_chat_page` 7;
  - `test_chat_streaming` 20;
  - `test_chat_ui` y `test_pipeline`.

  Las de navegador ejecutan la plantilla real y los tres scripts. `innerHTML` lanza un
  error, y unas comprobaciones que no terminan cuentan como fallo.
- **Consentimiento tras recargar.** Lo que envía la página (misma petición, token y
  selección de modelo) lo acepta el servidor como la misma petición, con una sola inferencia.

### Suite completa en serie

- En `a0a5078`: 700 pruebas, 23 fallos + 31 errores. Las 51 pruebas distintas que fallan se
  ejecutaron sobre una copia `git archive fa375ad` y fallan igual: todas son de módulos
  agent, `ai_connections` o `review_regressions` que exigen PostgreSQL. La línea base
  documentada era 675 pruebas, con 46 fallos + 23 errores.
- La única regresión del WIP fuera de esos módulos (notificaciones de seguridad en
  `test_backend_hardening`) se corrigió.
- Resultado sobre `dd7dba9`: 700 pruebas en 194 s, 23 fallos + 31 errores. Son 52 pruebas
  distintas: 51 son las preexistentes de `fa375ad` y 1 es intermitente.
- La intermitente es `LiveStreamingTests.test_stop_closes_a_silent_provider_stream_at_once`.
  - Falló su última aserción: el servidor simulado no detectó el socket cerrado en 5 s.
  - La parada en menos de 5 s, el estado `cancelled` y el coste desconocido sí se cumplieron
    en esa misma ejecución.
  - Pasó en la ejecución completa de `a0a5078`, 3/3 veces aislada y 20/20 con su módulo.
  - Es una prueba de la sesión anterior que usa hilos y sockets reales. Se deja sin tocar y
    se anota como inestable bajo carga.

### Navegador (Chromium con Playwright)

`ops/chat_ui_lab/verify.cjs` dio 13/13 sobre el laboratorio, con un proveedor simulado en
loopback y BD sintética:

- texto antes del final y parada con retirada;
- recarga con reenganche y un solo envío;
- cambio de conversación;
- móvil;
- teclado y foco;
- cajón con fondo inerte;
- movimiento reducido;
- contraste AA de 489 elementos;
- adjuntos (txt, formato no admitido, arrastre, y CSV/XLSX en modo agente);
- selector de Drive;
- envío en modo agente;
- consola sin errores.

Evidencia, contrato de eventos, librerías evaluadas, capturas «antes» y «después» y
limitaciones: [frontend-overhaul-20261014](../../../evals/reports/frontend-overhaul-20261014/README.md).

## Defectos del WIP corregidos en la verificación

- **Markdown:**
  - recursión infinita con URLs;
  - enlaces con paréntesis cortados;
  - `plain()` solo sustituía un marcador;
  - marcadores crudos en listas o encabezados en streaming.
- **Títulos con medio valor sensible.** El valor quedaba cortado en el carácter 50 y se
  veía en la barra lateral, la cabecera, `<title>` y la página de borrado. Ahora se enmascara
  el primer mensaje entero y después se recorta. Los títulos explícitos se conservan.
- **Entradas JSON.** Un `PipelineStop` en la llamada de generación terminaba como
  `provider_failed` por un `AttributeError`.
- **Paridad:**
  - alertas recientes para el personal de seguridad;
  - selector de Drive al empezar en modo agente (solo con `REGULAY_AGENT_MCP_ENABLED`).
- **Agente:**
  - el paso agrupado mostraba la primera frase;
  - el error salía duplicado;
  - concordancia de número;
  - el reenganche con 404 decía «sigue registrada»;
  - un recibo antiguo sin `calls` mostraba «0».
- **Accesibilidad:**
  - dos pares de color por debajo de AA (4,35:1 y 4,51:1);
  - fondo inerte con el cajón abierto;
  - enlace de salto con foco explícito.

## Decisiones y límites de la entrega

- **Sin dependencias nuevas.** AI Elements, assistant-ui y Motion se usaron como referencia
  (ver el informe). Se eligió CSS y WAAPI nativos y un Markdown propio que solo crea nodos DOM.
- **Entrega completa cuando el control necesita el texto entero:**
  - verificación semántica;
  - citas;
  - JSON;
  - enmascarado remoto;
  - proveedores sin streaming verificado;
  - YARA no decidible por prefijo.
- **Texto en directo.** Siempre se retienen 96 caracteres. El texto parcial vive solo en
  memoria y nunca se persiste.
- **Varios workers.** El reenganche desde otro proceso solo ve el resultado final guardado
  (espera hasta 60 s).
- **Detener.** En streaming corta el stream del proveedor al momento; en entrega completa se
  aplica al volver la llamada. El coste queda siempre desconocido, nunca 0.
- **Agente.** No tiene plan explícito; las duraciones son solo las medidas por el servidor.
  El SSE del agente exige ASGI; sin él, se consulta cada 2,5 s.
- **No verificado aquí:**
  - ejecución real del agente (SQLite sin worker: queda «En cola»);
  - proveedores reales;
  - lectores de pantalla.
- **Pendiente, fuera de alcance.** `log_action` guarda el título crudo al borrar una conversación.

Entrega: `entrega/frontend-overhaul.patch` (código, pruebas, documentación y laboratorio) y
`entrega/frontend-overhaul-capturas.patch` (PNG), ambos sobre `fa375ad`.

## Aplicación sobre el checkout principal (2026-10-14)

La instalación real (`regulai-v2-vm`, tareas 57 y 58) se construyó desde `codex/tasks-53-54`, que
no tenía este rediseño: el chat real seguía con la interfaz anterior. Se aplica en la rama
`claude/aplicar-rediseno-chat`, sin commit y sin tocar el trabajo previo sin commitear.

- **Fusión.** Desde `fa375ad`, el checkout principal solo cambió dos archivos del parche:
  `chat.html` (el chat nuevo abre el agente profesional por defecto) y `agent-chat.js` (activa
  ese modo al cargar). Se toma el rediseño y se conserva ese comportamiento: «Agente» queda
  marcado cuando `agent_professional`, y `chat.js` ya aplica al cargar el modo marcado. El resto
  se copia tal cual de `22c50d7`. Recursos con versión `overhaul-5`, para no reutilizar en el
  navegador copias del laboratorio.
- **`test_b10`.** Buscaba el `sendMessage` en línea que el rediseño retiró. Se reescribe sobre el
  navegador sin red con la página real: sin `crypto.randomUUID`, el envío lleva un UUID v4.
  Falla si se quita el respaldo de `chat.js`.
- **Franja rosa al cargar.** La tarjeta del agente creaba el aviso de error visible y vacío hasta
  el primer estado del servidor. Ahora nace oculto, igual que los límites. Nueva prueba con el
  estado retenido; falla sin la corrección.
- **Agente profesional sin buscador.** Sin clave Tavily, `bootstrap` retira `web_search`, pero las
  instrucciones daban por hecho un buscador. Si se ofrece `web_open` sin `web_search`, Regulay
  añade una instrucción: abrir direcciones de referencia conocidas y no atribuir contenido a
  páginas no abiertas. Prueba nueva. **No ensayado con el modelo real.**
- **Motivo de fallo falso.** La petición real sobre la desamortización (`1c9b3c34…`) sí leyó seis
  fuentes con `web_open` (dos de Wikipedia, una búsqueda HTML de DuckDuckGo y dos PDF). La cuarta
  inferencia fue rechazada por Regulay con `security_check_failed`: en `governance.preflight`,
  la política evaluada con el texto leído no quedó en `allow`/consentimiento ya aceptado. Después,
  `jobs.fail` usaba `research.consulted_sources` (catálogo, `kind='research'`) para todas las
  ejecuciones y la etiquetó como «ninguna fuente consultada».
  - `jobs.fail` cuenta las fuentes web (`web_tools.consulted_sources`) en ejecuciones profesionales.
  - Si la última inferencia fue rechazada, el motivo pasa al usuario: `security_check_failed` usa el
    nuevo `agent_security_check_failed`; otros códigos con mensaje en `ERRORS` se muestran tal cual.
  - El fallo profesional sin ninguna fuente leída usa `agent_research_no_sources_web`, sin mencionar
    el catálogo del agente de documentos.
  - Tres pruebas nuevas por la vía real (regla de bloqueo y texto leído que la activa). Las dos de
    etiquetado fallan con la lógica anterior.
  - No se identificó qué regla de la empresa activó el texto leído: requiere leer contenido
    privado de la instalación y no se ha autorizado.

### Verificación observada

- Suite por módulos como CI, con PostgreSQL 17 desechable para `test_agent*`: 65 módulos,
  724 pruebas, sin fallos. Con el código final se repitieron los módulos `test_agent*` y los de
  chat e interfaz: todos en verde (`test_agent_professional` 36, `test_agent_frontend` 18).
- `test_chat_streaming` falló una vez de seis ejecuciones, con el laboratorio y dos PostgreSQL
  en paralelo; las otras cinco, incluidas cuatro seguidas, pasaron. No se cambió ese código.
  Es coherente con la prueba de sockets reales ya anotada arriba como inestable bajo carga.
- `makemigrations --check --dry-run`: sin cambios.
- Laboratorio (`ops/chat_ui_lab`, puerto 8801, BD sintética nueva) en escritorio y móvil:
  chat nuevo con «Agente» por defecto; conversación profesional con fuentes; ejecución fallida
  sin fuentes, con pasos desplegados; página de inicio con la plantilla base; consola sin errores.
- `ops/agent_chat/preview_document_ui.py` y `preview_professional_ui.py` pasan el contexto
  antiguo (`messages`, `agent_initial`) y ya no muestran los turnos. La vista previa de
  referencia pasa a ser el laboratorio.

### Despliegue en `regulai-v2-vm` (2026-10-14, autorizado por el usuario)

- **Comprobaciones previas.** Sin ejecuciones `queued`/`active`/`outcome_unknown`. El código de la
  VM solo difería de la rama en los 16 archivos nuevos y 19 modificados del rediseño y sus
  arreglos; ninguno existía solo en la VM. El worker en marcha usaba una imagen ya borrada, pero
  su código y su `pip freeze` eran idénticos a `regulai-v2-worker:local`.
- **Respaldos.**
  - Imágenes `regulai-v2-web:before-redesign-20261014` y `regulai-v2-worker:before-redesign-20261014`.
  - Copia `/opt/regulai/source-before-redesign-20261014`.
  - Contenedores anteriores parados y renombrados con el sufijo `-before-redesign-20261014`.
- **Código y construcción.** Copiado con `setup.bundle()`; 856 archivos idénticos a la rama.
  Imagen web reconstruida. El worker salió entero de la caché: su Dockerfile solo copia
  módulos del SDK, ninguno cambiado.
- **Contenedores.** Recreados con los argumentos de `install.py`.
- **Verificación.**
  - `verify_web.py` correcto.
  - `verify_sandbox.py`: renderizado DOCX/PDF y aislamiento de salida en microVM E2B real, sin
    llamadas al modelo.
  - Por el túnel del 8800: login de `admin`, chat con el rediseño, «Agente» por defecto y la
    conversación de la desamortización. Sin errores de consola.
  - No se envió ningún mensaje, para no generar llamadas de pago.
- **Volver atrás.** Recrear `regulai-v2-web` con los argumentos de `install.py` sobre la imagen
  `regulai-v2-web:redesign-20261014` (despliegue del 14) o `regulai-v2-web:before-redesign-20261014`
  (antes del rediseño), y el worker sobre `regulai-v2-worker:before-redesign-20261014`. El código
  anterior sigue en `/opt/regulai/source-before-redesign-20261014`. Los contenedores parados de
  respaldo se retiraron el 15 tras verificar la versión nueva.

### Caída del equipo y redespliegue (2026-10-15)

- **Qué pasó.** Windows registró un apagado inesperado durante la noche (Kernel-Power 41, sin
  BugCheck) y no volvió hasta las 8:24. La consola de la VM termina mientras el chat 3 seguía en
  marcha. Docker Desktop no reinicia `regulai-v2-vm` (sin política de reinicio): el 8800 quedó caído
  hasta ejecutar `setup.py start`.
- **Chat 3 (simulación de paseos aleatorios 2D/3D).** 35 inferencias en unos 17 minutos:
  - el entregable se publicó y verificó a los 14 minutos;
  - la simulación tardaba unos 68 s y se relanzó tres veces mientras se corregía el código;
  - hubo respuestas de hasta 13.600 tokens (75 s);
  - el contexto llegó a unos 105.000 tokens por llamada;
  - después leyó seis páginas web que no se pedían.
  - La ejecución quedó `active` con la sesión caída y el worker la cerró como `interrupted` al
    arrancar (`reap`), sin repetir nada. Una ejecución interrumpida no muestra sus borradores
    verificados: es la regla de entrega vigente.
- **Duración de ejecuciones interrumpidas.** La interfaz mostraba «10 h 24 min», porque contaba
  hasta que se detectó el abandono. Ahora mide hasta el último evento registrado (17 min 20 s).
  Prueba nueva en `test_agent_frontend`; recursos `overhaul-6`.
- **Memoria.** El equipo tiene 31,8 GB y WSL2 puede usar hasta la mitad (sin `.wslconfig`), con
  una VM de 9 GB, E2B y los sandboxes. La presión de memoria es la causa más probable de la
  lentitud y del bloqueo, aunque no está demostrada. Acotar WSL2 es una decisión del usuario.
- **Verificación.**
  - `setup.py start` completo: web, PostgreSQL y E2B; renderizado en microVM real y worker.
  - Login y chat en el 8800, con la duración corregida.
  - 57 pruebas de interfaz en verde.
  - CI de `RegulaiV.2` en verde para `f706147`.

### Datos personales en páginas públicas (2026-10-15)

- **Causa del bloqueo de la desamortización.** Comprobado con autorización expresa del usuario
  para leer esa conversación y las reglas. La regla #6 «Correo electrónico o DNI: pedir
  consentimiento» (`consent`) coincidía con los correos de los autores de un PDF de Redalyc. La
  petición inicial no tenía datos sensibles y se autorizó sin consentimiento; a mitad de tarea
  el agente no puede pedirlo, y `governance.preflight` detuvo la inferencia
  (`security_check_failed`). No fue un tiempo de escaneo: 0,01 s por comprobación. Las reglas
  #4 y #8 son idénticas.
- **Decisión del usuario: enmascarar y seguir.** `web_tools` aplica las reglas `consent` activas
  (aplicables a `prompts` o `both`) al resultado de `web_open`, `web_find` y `web_search`
  antes de guardarlo como vista del modelo.
  - Cada coincidencia se sustituye por `[dato personal omitido]`, y el resultado indica
    `masked_personal_data`.
  - URL, referencia y hash se conservan para que las citas sigan cuadrando, y la fuente
    original sigue cifrada en `web_source`.
  - Las reglas `block` no se enmascaran y siguen deteniendo la inferencia.
  - Si el escaneo falla, el texto sigue sin enmascarar y la pasarela lo detiene como antes.
  - Fuera de alcance: los archivos descargados con `web_download` y procesados en el sandbox.
- **Pruebas.** Dos nuevas en `test_agent_professional`:
  - el texto enmascarado continúa, y como control el original se detiene;
  - una regla de bloqueo en una página pública sigue deteniendo.
  - La de enmascarado falla sin el cambio.

### Lentitud de las ejecuciones largas (2026-10-15)

- **Causa medida.** Cada inferencia reenvía la conversación entera, y se volvía a proteger mensaje
  a mensaje: alias, comprobación previa y una llamada de enmascarado por máscara, más dos
  escrituras del recibo completo. El coste crecía de forma cuadrática con los pasos. Simulación
  local de 35 pasos como los del chat 3, con proveedor simulado:

  | | Sin reutilizar | Reutilizando |
  |---|---|---|
  | Preparación total | 251,15 s | 21,05 s |
  | Último paso | 14,96 s | 0,6 s |
  | Llamadas de enmascarado | 1260 | 104 |
  | Recibo | 1011 KB | 120 KB |

  La hipótesis de memoria anotada arriba sigue abierta, pero el coste que crecía en cada paso era este.
- **Arreglo.** `ProtectedHistory` (`agents/service.py`) reutiliza, dentro de una ejecución, los
  mensajes ya protegidos.
  - Clave: la ejecución y un resumen del intento, el vínculo de autorización, la huella de la
    política, las máscaras y el mensaje exacto. Cualquier cambio de política, regla, máscara,
    permiso o intento vuelve a protegerlo.
  - Vive solo en la memoria del proceso, limitado a 32 MB, y se olvida al terminar la ejecución
    (`jobs._terminal`).
  - Se mantiene lo demás: la llamada de generación comprueba la carga completa en cada paso, los
    mensajes nuevos se protegen uno a uno y la respuesta del modelo se protege siempre.
  - Cada llamada del recibo indica cuántos mensajes se reutilizaron y cuántos se protegieron.
  - `_validate_tool_history` carga los resultados de herramientas con una consulta por inferencia.
- **Interfaz.**
  - El estado de la ejecución ya no envía el recibo dos veces.
  - El navegador solo lo reconstruye si cambia y no cierra las secciones que el lector abrió.
  - Las listas de más de 40 llamadas se construyen al abrirlas. Recursos `overhaul-7`.
- **Pruebas.** Nueve nuevas: seis en `test_agent_inference`, una en `test_agent_professional` y
  dos en `test_agent_frontend`. Cada una falla si se rompe lo que comprueba (verificado mutando
  el código).
- **Verificación.** Suite por módulos como CI, con PostgreSQL 17 desechable para `test_agent*`:
  65 módulos y 741 pruebas.
  - `test_agent_professional` dio dos errores porque se lanzó otra prueba contra la misma base
    de datos. Repetido solo: 41 de 41.
  - `test_agent_presentations` falló 2 de unas 97 ejecuciones. Es anterior a este cambio y está
    reproducido de forma determinista. El detector local `CARD` (Luhn, admite guiones) toma por
    tarjeta cerca del 0,27 % de los UUID aleatorios. Al enmascarar la respuesta del modelo,
    `be10ca83-6211-4869-9889-7535cb677985` queda como `be10ca[[R_CARD_…]]cb677985` y
    `authorize_tool` rechaza la llamada (`unissued_tool_call` en la prueba). En producción
    afectaría a un 0,3–0,5 % de las llamadas a herramientas con identificadores. Pendiente en
    una tarea aparte.
- **Desplegado** en `regulai-v2-vm` el 2026-10-16: solo la imagen web, el worker no cambia.

### Agente directo, «sota, caballo y rey» (2026-10-16)

- **Petición del usuario.** El chat 3 «tomaba decisiones malísimas»: tenía que ser más directo.
- **Decisiones del chat 3** (lectura de sus inferencias). Se pidió ejecutar una simulación del
  teorema de Pólya. El agente:
  - abrió Wikipedia en dos idiomas y MathWorld sin que se pidieran fuentes;
  - añadió un cálculo exacto por series que se volvió inestable y rehízo con enteros;
  - ajustó parámetros con arneses de tiempo;
  - generó un informe DOCX no pedido, con figuras y tres publicaciones;
  - citó fuentes que no había abierto, y la comprobación final le hizo abrir otras seis.
  - Lo directo era un script, una ejecución y la respuesta en el chat.
- **Prompt del worker** (`runtime/professional.md`). Nuevo párrafo de trabajo directo:
  - solo lo pedido y por el camino más simple;
  - chat si no se pide un archivo;
  - investigar solo si hace falta, sin citar nada no abierto;
  - un script vectorizado de menos de 20 s, sin repeticiones para afinar;
  - paquetes solo si falla una importación;
  - entregar y terminar.
  - La investigación pasa a ser condicional, y las fuentes solo se entregan si se investigó.
- **Instrucciones del servidor** (`service.infer`), según la petición real:
  - Sin formato, número de páginas ni palabras de archivo (doc, documento, informe, PDF…): «no
    pide ningún archivo: entrega el resultado en el chat». El contrato no reconoce «doc», de
    ahí la lista de palabras.
  - Si `research_required` es falso: «no pide fuentes: no navegues…», salvo que falte un dato
    imprescindible.
  - Prueba nueva: la petición del chat 3 recibe ambas instrucciones; la de la desamortización
    ninguna.
- **No ensayado con el modelo real.** Su efecto en las decisiones de DeepSeek se comprobará
  repitiendo la petición del chat 3.

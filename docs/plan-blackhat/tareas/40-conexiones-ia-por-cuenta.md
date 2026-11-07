# 40. Conexiones IA por cuenta

Estado: corregida según aclaración del usuario y verificada, 5 de octubre de 2026.
Blocked by: ninguno.

## Petición y aceptación

Configurar Claude, Mistral, Gemini, ChatGPT/OpenAI y TypeSafe Jev desde Settings,
con claves independientes y aisladas por cuenta y una cuenta local de prueba.
Regla aclarada por el usuario: las cuatro claves de generación son nativas del proveedor;
solo Jev utiliza la clave de Vercel AI Gateway. No usar clave común ni BYOK para esos cuatro.

- `Settings > Conexiones IA`, `/settings/ai/`, accesible al administrador de empresa
  sin privilegios de operador global. «Cuenta» conserva el ámbito Company existente;
  los usuarios de esa empresa comparten conexiones.
- Cinco campos visibles e independientes. Campos vacíos conservan claves;
  editar Claude no cambia Gemini, Mistral, OpenAI ni Jev. Guardado cifrado, sin valores en HTML,
  mensajes o auditoría. Borrado explícito incluso con modelos desactivados.
- Cuatro motores de API directa, comprobando endpoint y conector antes de guardar.
  Gemini usa la compatibilidad OpenAI de Google, sin atravesar Vercel.
  Jev conserva el cliente TypeSafe
  existente y su campo cifrado. Una política TypeSafe directa no recibe una clave
  de Gateway: primero hay que revisar el transporte en la política.
- Guardar no llama a proveedores ni modifica destinos, presupuestos, consentimiento
  o enmascarado. La configuración inicial de seguridad sigue siendo necesaria para
  que una empresa nueva envíe mensajes.
- Migración 0034 aditiva: no sustituye motores anteriores, no crea credenciales ni
  autoriza empresas. Revertir conserva catálogo y referencias. Los precios iniciales
  se dejan desconocidos: un operador debe revisar tarifas por millón, tramos y términos
  de su cuenta antes de usar presupuestos acotados.

## Fuentes y configuración

Modelos iniciales directos: `claude-sonnet-4-5`, `gemini-2.5-flash`,
`mistral-small-latest`, `gpt-4.1-mini`. Jev sigue siendo `typesafe-ai/jev`.

- [Gemini con cliente compatible OpenAI](https://ai.google.dev/gemini-api/docs/openai)
- [Identificadores de Claude](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions)
- [API de Mistral](https://docs.mistral.ai/getting-started/quickstarts/studio/activate-and-generate-api-key)
- [Jev existente por Gateway](../jev-gateway.md)

La migración 0033 ya se había aplicado en local: se conserva junto con su conector por
compatibilidad, pero esta pantalla no los utiliza. Se observaron cero credenciales de
esos motores en la base local antes de aplicar la corrección. Nunca se convierten claves
de Vercel en claves nativas. Los POST del antiguo campo común se rechazan explícitamente.

## Verificación observada

- Diez pruebas de la sección: permisos, CSRF, aislamiento, cifrado, claves no reflejadas,
  rotación y borrado, conservación de TypeSafe directo, bloqueo de endpoints ajenos,
  migración reversible sin pérdida y doce envíos simulados (cuatro proveedores por
  tres entradas HTTP), cada uno con su clave y endpoint nativos. Prueba HTTP adicional
  de Jev con su clave de Vercel exclusivamente. El coste desconocido permanece desconocido.
- `check` sin incidencias; `makemigrations --check --dry-run` sin cambios pendientes.
- Suite anterior a la aclaración: `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front api
  --settings=regulai.test_settings --noinput`: 461 tests en 188,338 s,
  `OK (expected failures=2)`. Cero llamadas reales en los bancos simulados.
- Pruebas específicas después de la corrección: `front.test_ai_connections front.test_jev
  front.test_frontend_resources`, 33 tests OK en 3,269 s.
- Suite completa de la corrección: 462 tests en 193,419 s, `OK (expected failures=2)`.
  Tras reforzar la aserción de correspondencia exacta entre clave y proveedor, las diez
  pruebas de `front.test_ai_connections` volvieron a pasar (2,013 s).
- Navegador: login de la cuenta solicitada, navegación desde Settings, los cinco campos,
  validación sin reflejar claves, guardado vacío, móvil y escritorio sin desbordamiento.
- Base local identificada: `regulai/community-local.sqlite3`, DEBUG activo. Copia SQLite
  consistente previa: `community-local.before-gateway-20261005-095211.sqlite3`.
  Migraciones 0029–0034 aplicadas. Segunda copia previa a 0034:
  `community-local.before-direct-keys-20261005-100803.sqlite3`.
  Cuenta `j@g.c`, empresa «Pruebas de Javi», Admin de
  empresa y staff; sin superuser ni permisos globales. No tiene claves ni política activa.
  Contraseña de prueba entregada al usuario; no se añade a fixtures ni al registro público.
- No se ha desplegado, publicado, hecho push ni realizado llamadas de pago.

La primera suite completa encontró solo la ausencia de los dos enlaces de ayuda de
Vercel en la allowlist de navegación externa; se añadieron sin permitir recursos remotos.

## Corrección del bloqueo inicial de chat

El recibo `7acd6963-230b-4fea-bb6d-c89def9d19cb` fallaba con
`policy_configuration_invalid`, cero llamadas y cero coste. La empresa local tenía
`ai_config={}`, cero conexiones, máscaras y grupos de reglas. Guardar claves no resolvía
por sí solo el resto de prerrequisitos; el indicador fijo «Configured» era engañoso.

Se añadió un segundo paso explícito «Activar chat básico» para empresas nuevas, tras
guardar al menos una clave generadora. La revisión explica destinos, selección manual,
suelo interno sin clasificación semántica, límite de 1.000 tokens y ausencia de presupuesto
monetario. No permite Jev ni documentos. Genera máscara local PII+secretos y reglas YARA
de bloqueo de credenciales, sin permitir reglas vacías ni reemplazar las existentes.
Las políticas o máscaras previas se remiten a configuración avanzada. La revisión está
firmada y ligada a empresa, credenciales, destinos, modelos y detector; caduca en 30 minutos.
La activación es transaccional, auditada y no hace llamadas externas. El chat muestra
un aviso con enlace a Settings cuando falta la política.

Verificación de esta corrección:

- Suite completa: 465 tests, `OK (expected failures=2)`.
- Después de reforzar las comprobaciones del detector, destino y PII: 25 tests de
  `front.test_ai_connections front.test_frontend_resources`, OK en 8,320 s.
- Reproducción del fallo con «j» y posterior éxito por las tres entradas HTTP usando
  proveedor simulado y detector local real; correo original ausente del cuerpo externo,
  secreto bloqueado, Jev y destinos ajenos denegados. Sin llamadas reales de pago.
- Activación sin clave, token ausente, revisión de otra cuenta, clave rotada, proveedor
  cambiado, detector ausente y repetición de activación rechazados sin alterar la política.
- Navegador: aviso del chat y página con los dos pasos verificados visualmente.
- La cuenta local sigue sin claves; no se ha inventado ninguna ni se ha autorizado salida
  automáticamente. El usuario debe guardar su clave y activar el chat básico para probarlo.

## Reglas locales solicitadas para pruebas

El 5 de octubre se creó en «Pruebas de Javi» el grupo «Reglas básicas para pruebas»
(id 4), con cuatro reglas activas para prompts y archivos:

| Regla | Acción | Ejemplo sintético |
| --- | --- | --- |
| Credenciales y claves privadas | Bloquear | `password=synthetic_secret123` |
| Documentos marcados como confidenciales | Bloquear | `CONFIDENCIAL: ejemplo inventado` |
| Correo electrónico o DNI | Consentimiento | `prueba@example.com` / `12345678Z` |
| Prueba de bloqueo | Bloquear | `REGULAI_TEST_BLOCK` |

Se comprobó antes de escribir que la base era `community-local.sqlite3`, con DEBUG,
y se guardó una copia consistente `community-local.before-test-yara-20261005-103642.sqlite3`.
Las reglas se validaron y guardaron en una transacción con auditoría `test_yara_setup`.
Pasaron 14 casos locales (siete textos por dos tipos de contenido) y el bloqueo en las
tres entradas HTTP, sin llamadas externas. Las conversaciones sintéticas se revirtieron.
Los casos de consentimiento/permiso se evaluaron con una política efímera solo en memoria;
la política real de la cuenta sigue vacía y no se modificaron claves ni enmascarado.
Para probar consentimiento y respuestas se requiere guardar una clave y activar el chat.
El bloqueo YARA sí funciona antes de esa activación. Las cuatro reglas se verificaron
visibles y activas en `/rules/` con el usuario `j@g.c`.

## DeepSeek y Jev: configuración y prueba real solicitada

El usuario entregó dos credenciales y autorizó expresamente usarlas para comprobar
DeepSeek y Jev el 5 de octubre. Este permiso corresponde a esta comprobación concreta;
no reabre los bancos históricos ni autoriza ejecuciones periódicas. Las claves se
recibieron por entrada oculta, sin argumentos de shell ni archivos de texto, y se
guardaron cifradas solo en «Pruebas de Javi». Copia previa de SQLite:
`community-local.before-live-keys-20261005-104402.sqlite3`.

Se añadió DeepSeek a Conexiones IA para permitir su futura sustitución desde la misma
pantalla. Migración 0035 aditiva, sin transformar conexiones existentes ni credenciales:
`DeepSeek · API`, endpoint `https://api.deepseek.com`, modelo `deepseek-flash`.
El catálogo nuevo deja precios desconocidos; en esta cuenta local se fijaron las tarifas
pico sin caché observadas el 5 de octubre: entrada 0,30 y salida 1,20 USD por millón,
como estimación conservadora ([documentación](https://api-docs.deepseek.com/quick_start/pricing/)).
Jev usa el [transporte TypeSafe de Vercel](https://vercel.com/changelog/ai-gateway-now-supports-typesafe-clients-and-http-api-for-jev),
modelo `typesafe-ai/jev`. Sus costes se leen de los metadatos del proveedor; no se inventó
un límite contractual por llamada ni un presupuesto monetario.

Se activó la política básica local y se autorizó Jev para verificación `enforce`,
umbral 0,8, destinos públicos/internos, generador DeepSeek manual, sin fallback y
salida máxima de 1.000 tokens. La clasificación inicial sigue siendo local, suelo
interno: esta comprobación no acredita clasificación semántica ni calidad documental.
Se conservaron las reglas YARA existentes y se activó el enmascarado local obligatorio.
Los cambios quedaron auditados con `ai_keys_save`, `ai_basic_chat_activate` y
`test_deepseek_jev_setup`.

Resultado observado por `/chat/send/`, petición
`8077554e-b025-42c6-9c9b-201a54b1d7e1`, conversación local 8:

- Entrada sintética: «Responde solamente con estas dos palabras: Prueba correcta.»
- Salida: «Prueba correcta.», HTTP 200, estado `completed`, verificación `passed`.
- Una generación DeepSeek Flash: 44 tokens de entrada, 90 de salida;
  estimación de tarifa 0,00012120 USD.
- Una verificación Jev: 348 tokens de entrada, 44 de salida;
  coste comunicado 0,000014616 USD.
- Dos etapas de enmascarado local, coste configurado cero; ningún reintento.
- Total registrado 0,000135816 USD, **estimado**, duración 5.047 ms.

Validación adicional: 37 tests de conexiones, Jev y recursos frontend, OK en 5,420 s;
incluyen quince envíos HTTP simulados con la clave propia de cada proveedor.
`makemigrations --check --dry-run` sin cambios. Lectura de base confirma cifrado de
ambas claves; HTML, auditoría y recibos no contienen las credenciales en claro.

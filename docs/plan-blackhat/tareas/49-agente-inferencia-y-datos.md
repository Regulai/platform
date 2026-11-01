# 49. Inferencia gobernada y vistas de datos

Estado: implementada y verificada en laboratorio el 7 de octubre de 2026; modo agente desactivado.
Blocked by: ninguno para 49; [48](48-agente-prueba-integracion.md) comprobada de nuevo antes de integrar.
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), secciones de modelo/datos/seudónimos del [plan](../../plan-capacidades-agenticas-regulay-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 49, una vez verificada la 48. Lee AGENTS.md,
la guía docs/implementacion-agente-regulay-prompts.md y las tareas 44 y 47.

Integra un adaptador de modelo de Deep Agents con una operación interna de
inferencia de Regulay. Empieza por un protocolo compatible con el conector ya
existente y el perfil de agente; no implementes una pasarela universal. El perfil
de agente es explícito y no cae silenciosamente al modelo económico del chat.
No cambies las conexiones ni límites de las cuentas actuales.

Extrae de chat_service.run_pipeline solo el gobierno que deba reutilizarse:
autorización actual, destinos, protección, recibo de inicio, consumo y cierre de
llamada. Haz pasar el chat normal y el agente por esa misma implementación.
Extiende el contrato de mensajes con tool calls, tool results e IDs sin romper
sus consumidores existentes. Valida esquemas; no aceptes endpoints, identidad,
modelo o permisos suministrados libremente por el ejecutor.

Autentica cada operación interna y vincúlala a usuario, empresa, conversación,
ejecución e intento vigente. Haz idempotentes los reintentos de transporte:
repetir una llamada identificada no debe generar ni cobrar otra inferencia.
Un envío de resultado incierto queda incierto, no se reintenta a ciegas.
Incluye compactación y visión si están habilitadas. El ejecutor carece de claves
de proveedor; la red impide llamar fuera de Regulay.

Añade alias opacos estables por conversación para campos y patrones explícitos.
Normaliza por tipo; no fusiones personas por parecido ni reintroduzcas el NER
generalista retirado en la tarea 47. Guarda el registro de correspondencias, con
sus originales cifrados, fuera del acceso del modelo y del sandbox. Los archivos
autorizados pueden procesarse localmente sin dar acceso a ese registro. Resuelve
referencias solo dentro de operaciones de confianza; no expongas una herramienta
general de reidentificación.

Implementa una única puerta de resultados para las herramientas. Python puede
procesar originales, pero el modelo recibe vistas autorizadas: estructura,
referencias, ejemplos sintéticos y agregados comprobados. Controla también
lecturas de archivo, stdout, stderr, excepciones y resúmenes. Conserva salidas
crudas fuera del contexto. No presentes una regex como garantía contra cualquier
codificación de datos por código arbitrario; limita las vistas a sus contratos.

Prueba el SDK real con HTTP simulado, revocación entre dos pasos, alias repetidos,
chats distintos, errores que contienen datos sintéticos y salida directa denegada.
Ejecuta regresiones del gobierno por las tres entradas HTTP y de estado/dinero.
No actives el modo agente. Registra evidencia y detente antes de la 50.
```

## Aceptación

- Llamadas nativas completas, gobierno compartido y una sola contabilización por llamada identificada.
- Nueva autorización en cada salida; claves y originales fuera del ejecutor no confiable y del modelo.
- Mismo dato reconocido mantiene alias en el chat y cambia en otro; no se altera el comportamiento de 44/47.
- Canales de salida probados, incluidos errores y compactación; restricciones de red verificadas sobre el entorno real.
- El chat normal conserva sus contratos y pasa las regresiones relevantes.

## Verificación observada

### Implementación y alcance

`front/governance.py` contiene la autorización actual, destinos, protección, presupuesto,
recibo previo al efecto y contabilización/cierre extraídos de `chat_service.run_pipeline`.
El chat normal y el servicio de agente llaman a esa implementación. Las decisiones
Flash/Pro, Jev y los límites de 44 del chat permanecen en su flujo anterior. La extracción
se revisó contra una copia del estado local inicial, que incluía los cambios de 44/47.

El protocolo interno v1 y `RegulayModel` usan las versiones del ejecutor de 48.
`ChatMessage`/`ChatResponse` incorporan campos opcionales para llamadas nativas,
argumentos, nombre e ID; los consumidores de texto anteriores conservan sus valores
por defecto. El primer protocolo de proveedor es OpenAI compatible, incluido Vercel;
Anthropic nativo rechaza explícitamente mensajes de herramientas en este tramo.
El catálogo de herramientas y sus esquemas pertenecen al servidor. El ejecutor manda
nombres permitidos, sin poder sustituir esquemas, credenciales, endpoint o modelo.

Tres operaciones internas separadas (`inference`, `authorize-tool`, `tool-results`)
requieren un token aleatorio de ejecución y `X-Regulay-Attempt`. Solo se guarda el hash
del token; caduca en un máximo de 15 minutos. El servidor vincula ejecución/intento a
`Prompt`, usuario, empresa, conversación, perfil, instrucciones, historial elegible,
política, máscaras y conexión/modelo. Revalida antes de cada operación/salida y antes
de entregar la respuesta. Las cookies del navegador no autorizan estas operaciones.

`AgentModelProfile` requiere una conexión y un modelo concretos de la empresa. No
consulta los modelos predeterminados del chat ni degrada la ruta. Los perfiles nacen
desactivados y no se creó ninguno en cuentas existentes. `REGULAY_AGENT_ENABLED=False`
se comprobó también con la configuración local real. `begin_execution` es una función
de orquestación de confianza, sin entrada pública de inicio: **no se implementó 50**.

La migración **0036** añade seis registros privados: perfil, ejecución, inferencia,
entrada autorizada, resultado de herramienta y alias de conversación. La unicidad de
`(execution, call_id)`, el digest del contenido y una reclamación atómica por ejecución
impiden enviar o contabilizar dos veces un reintento identificado. No se mantiene una
transacción durante HTTP. Una respuesta interna perdida recupera el resultado guardado;
un timeout del proveedor o una reclamación abandonada conserva incertidumbre. No hay
reenvío automático ni coste cero inventado. Los recibos de todas las llamadas, incluidas
las máscaras, contienen ejecución, intento e ID de operación. El historial de usuario
sigue siendo el existente; el resultado persistido sirve a idempotencia, no a otro chat.

### Alias y puerta de resultados

Los alias son aleatorios y opacos, con ámbito de empresa, propietario y conversación.
El índice usa HMAC con ámbito y versión; los originales se guardan con el campo cifrado
existente. DNI/cuenta/teléfono eliminan separadores; el dominio de email se normaliza sin
suponer que su parte local ignore mayúsculas. Los nombres conservan NFC y coincidencia
exacta. Son alias de **valores**, no entidades personales: no hay unión de personas,
correlación nombre–DNI, semejanza de nombres ni NER. Los secretos se redactan sin crear
correspondencias recuperables, incluso si aparecen dentro de un campo explícito.

Se rechazan tokens desconocidos o de otra conversación. D2 conserva los tokens
registrados incluso si sus dígitos aleatorios coinciden con una tarjeta válida; los
marcadores temporales usados durante la protección no salen hacia el modelo. La única
resolución de originales es una función de aplicación para una operación local concreta,
con revalidación; no existe endpoint ni herramienta general de reidentificación.

`ResultGate` intercepta herramientas incorporadas y propias, `ToolMessage`,
`Command.update`, artefactos, metadatos, stdout/stderr y excepciones. Se autoriza la
llamada emitida antes de ejecutar y se conserva el resultado crudo cifrado en Regulay.
La inferencia rechaza resultados de herramientas no emitidas, alterados o sin vista
aprobada. Ninguna lectura genérica de archivo ni salida de terminal entra directamente
en contexto; tampoco se reenvían estados arbitrarios de `Command`.

Los contratos iniciales son estructura/referencias y ejemplo sintético de CSV, más
el total fijo de céntimos y número de filas. La aplicación comprueba el agregado contra
el CSV autorizado, con mínimo de filas; el programa Python de 48 sigue calculando en
el sandbox. No acepta como prueba una cifra declarada por código arbitrario. Visión
usa referencias a renders creados en la aplicación a partir de una vista ya aprobada;
no admite URLs, base64 ni previews crudas aportadas por el ejecutor. Compactación,
visión y fallback de streaming pasan por el mismo adaptador y gobierno.

### Resultados reproducidos

Evidencia en [task49-inference-20261007](../../../evals/reports/task49-inference-20261007/README.md).

| Comprobación | Resultado observado |
| --- | --- |
| Prueba SDK original de 48 | 15 pruebas pasan; mismo lock de 73 distribuciones |
| Prueba original sobre E2B/Firecracker | Dos sandboxes reales, frío/preparado, cálculo CSV correcto, destrucción confirmada y bloqueos IPv4/IPv6 |
| SDK nuevo con HTTP interno simulado | 5 pruebas pasan; incluyen las ocho herramientas incorporadas, errores/Command/artefactos, salida grande, compactación síncrona/asíncrona, visión, streaming y rechazo de redirects/incertidumbre |
| Aplicación + SDK aislado + SDK OpenAI real con proveedor HTTP simulado | Incluido en las 19 pruebas de agente/estado; pérdida de respuesta interna, revocación tras la herramienta y excepción con datos sintéticos |
| Agente/estado en PostgreSQL real | 19 pruebas pasan, sin omisiones, en 43,142 s; concurrencia de inferencia y alias, costes exactos y migración reversible sobre datos sintéticos |
| SQLite | 19 pruebas, 18 pasan y la concurrencia PostgreSQL se omite expresamente; no se usa SQLite como prueba de bloqueo de filas |
| Regresiones del gobierno | 176 pruebas pasan en 75,721 s: tres entradas HTTP, SDK/proveedores, destinos, privacidad, límites de 44, texto de 47, estado, migraciones y presupuesto/dinero |
| Configuración y esquema | `check`, `makemigrations --check --dry-run`, `git diff --check` correctos; agente desactivado en configuración local |

El nuevo adaptador también se ejecutó con sockets reales dentro de la VM de 48, en una
imagen derivada de su ejecutor fijado. Alcanza únicamente el control HTTP interno
permitido en `172.30.50.1:31049`; los puertos E2B permitidos siguen siendo 3000/3002.
El receptor controlado exterior falla con `ENETUNREACH` por IPv4 e IPv6; un puerto no
permitido del host falla con `EHOSTUNREACH`, y `169.254.169.254` con `ENETUNREACH`.
El receptor responde desde su red antes y después. No hay claves de proveedor, acceso
a base de datos, módulos de correspondencias ni montajes del host en ese ejecutor.
El control HTTP de esta prueba de red es **sintético**; la autorización/contabilidad
Django se prueba por separado con el servidor HTTP real de tests. No se confunden esas
dos evidencias. La repetición E2B acredita además los sockets dentro de Firecracker.

Se conservaron los fallos intermedios y se corrigieron: compatibilidad con respuestas
antiguas sin `tool_calls`, rechazo de configuración de máscara fuera del manejo de
errores original y marca `lc_source=summarization` del SDK. En el ensayo de red se
ajustó la comprobación para admitir la clave **pública** GPG de la imagen Python y se
cambió el puerto inicialmente elegido, ocupado por `dashboard-api` de E2B, por 31049.
Los resultados válidos son los logs `verified-*`, `final-sdk.log`,
`final-adapter-network.log` y `real-e2b-recheck/report.json`.

### Versiones y comandos

Aplicación: Python **3.12.11**, Django **5.2.17**, OpenAI **1.102.0**, Pydantic **2.11.7**.
Para PostgreSQL se instaló localmente **psycopg[binary] 3.3.6**, ya fijado en
`ops/pilot/requirements.txt`. Base aislada en un contenedor PostgreSQL 17 Alpine,
publicado solo en `127.0.0.1:55449`; ninguna migración se aplicó a datos existentes.

Ejecutor sin cambios de dependencias: Deep Agents **0.6.12**, langchain-e2b **0.0.6**,
E2B **2.53.1**, LangChain **1.4.3**, langchain-core **1.6.7**, LangGraph **1.2.14**,
Anthropic **1.12.0**, Pydantic **2.13.5**. `uv pip check` pasa. SHA-256 del lock:
`dfbe209fa61f49afc01e94c3846bffd3f23e4571c1e3718bab03eaed6fa8de62`.
El adaptador sigue el punto de extensión de [modelo personalizado de Deep Agents](https://docs.langchain.com/oss/python/deepagents/customization), contrastado con el código instalado y la prueba de 48.

Comandos principales ejecutados desde la raíz (los JSON `.result.json` guardan comando,
código de salida y duración):

```powershell
rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_probe/verify_sdk.py --output evals/reports/task49-inference-20261007/task48-recheck
rtk proxy uv pip check --python ops/agent_probe/.venv/Scripts/python.exe
rtk proxy ops/agent_probe/.venv/Scripts/python.exe -m unittest discover -s ops/agent_probe -p test_governed_adapter.py -v
rtk proxy uv pip install --python .venv/Scripts/python.exe 'psycopg[binary]==3.3.6'
rtk proxy docker run --detach --rm --name regulay-task49-postgres --label regulay.task=49 --network bridge --publish 127.0.0.1:55449:5432 --env POSTGRES_USER=lab --env POSTGRES_PASSWORD=synthetic-task49-only --env POSTGRES_DB=regulai_task49 postgres:17-alpine
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_inference front.test_agent_state --settings=regulai.agent_postgres_test_settings --noinput
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_pipeline front.test_pipeline_privacy front.test_required_masking front.test_ai_connections front.test_difficulty_routing front.test_local_masking_integration front.test_state front.test_smoke front.test_evaluation_budget front.test_calibration_budget front.test_backend_hardening front.test_connectors --settings=regulai.test_settings --noinput
rtk proxy .venv/Scripts/python.exe regulai/manage.py check --settings=regulai.test_settings
rtk proxy .venv/Scripts/python.exe regulai/manage.py makemigrations --check --dry-run --settings=regulai.test_settings
rtk git diff --check
```

La infraestructura sigue los comandos de [48](../../../ops/agent_probe/README.md):
`vm/start.py`, `vm/provision.sh`, `vm/bundle.py`, `vm/run_live.sh` y `vm/collect.py`.
Para la comprobación adicional de 49:

```powershell
rtk proxy python ops/agent_probe/vm/task49_bundle.py
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_probe/vm/task49_network.sh --log evals/reports/task49-inference-20261007/final-adapter-network.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_probe/vm/check_final.sh --log evals/reports/task49-inference-20261007/real-lab-final-checks.log
```

Usar un nombre nuevo de log al reproducir: el recolector no sobrescribe evidencia.
Las redes, reglas y receptor temporales se retiran en `finally`. Se conserva la imagen
y el volumen de 48 para reproducir; al terminar se apaga la VM y se retira el PostgreSQL
desechable de 49.

### Límites explícitos y punto de parada

- El perfil inicial bloquea las políticas que exigen clasificación remota o verificación
  semántica obligatoria: `agent_policy_incompatible`. No las ignora ni modifica la
  configuración de esas cuentas. La integración inicial soporta política/clasificación
  local, el catálogo OpenAI compatible y los destinos expresamente autorizados.
- Visión exige perfil y modelo habilitados y límites gestionados por el proveedor;
  un perfil con visión acotada sin una cota específica de imágenes se rechaza. Solo se
  renderizan vistas aprobadas; revisar documentos visualmente se amplía en 51.
- El contrato CSV comprueba sumas enteras y un mínimo de filas, no anonimato ni número
  de personas distintas. Los alias de nombre no prueban identidad. No se admiten
  predicados arbitrarios ni agregados declarados por el modelo.
- Las salidas de Python arbitrario quedan retenidas. Un esquema/regex no demuestra
  ausencia universal de codificación o de canales laterales de tiempo/éxito; los datos
  que exijan garantías más fuertes requieren operaciones revisadas. No se publica
  una herramienta para leer originales del registro de alias.
- No se evaluó inteligencia/calidad con modelos de pago ni se habilitó un piloto real.
  Los reinicios con efecto incierto requieren resolución de estado; esta tarea no
  añade reconciliación del proveedor, un planificador, renovación de trabajos largos,
  SSE, UI, adjuntos desde el chat ni entrega de Excel.

**Parada antes de 50.** Cambios locales anteriores conservados; conexiones, límites,
datos y secretos existentes intactos. Cero llamadas nuevas de pago, push, despliegues
o escrituras en servicios externos reales.

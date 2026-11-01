# Agente profesional: operación de la implementación local

Tarea 56, 14 de octubre de 2026. Código integrado sobre el trabajo local de la
tarea 55. Su aceptación original usó proveedores simulados. La activación
posterior con cuenta administradora, PostgreSQL, DeepSeek y E2B reales está
documentada en [la tarea 57](../../docs/plan-blackhat/tareas/57-activacion-real-local.md).
La [matriz original de aceptación](../../evals/reports/task56-professional-20261014/README.md)
conserva el alcance de aquellas pruebas; no acredita por sí sola llamadas reales.

## Recorrido y decisiones

Las entradas `/chat/`, `/chat/send/` y `/api/chat/send/` conservan el servicio de
chat, autenticación, política y registros existentes. Un `AgentAccessGrant`
explícito selecciona un `AgentModelProfile` profesional. Django autoriza cada
inferencia y herramienta; el ejecutor usa Deep Agents y E2B sin claves del modelo,
del buscador ni de la base de datos. Los resultados protegidos vuelven a la
pasarela antes de otra inferencia. No se aceptan objetos que actualicen el estado
privilegiado desde la salida de una herramienta.

Herramientas conectadas: `ls`, `read_file`, `write_file`, `edit_file`, `glob`,
`grep`, `execute`, `web_search`, `web_open`, `web_find`, `web_download`,
`web_browse`, `install_packages`, `publish_artifact`, `inspect_image` y
`read_output`. El bootstrap retira las no habilitadas por perfil, interruptor o
política. El código Python, Node y shell procede de argumentos nuevos del modelo;
no hay un catálogo obligatorio de programas. Los fixtures de `ops/agent_chat/`
no forman parte del runtime profesional ni se copian a su imagen.

Se eligió un adaptador Tavily pequeño: consulta `basic`, respuesta generativa
desactivada, parámetros automáticos desactivados, sin reintentos ni fallback.
Así la búsqueda no introduce otra inferencia fuera de Regulay. Admite consultas
libres, máximo de resultados y actualidad; idioma orienta el texto de consulta,
no garantiza el idioma de los resultados. La paginación no está soportada por
este adaptador y se declara así. La navegación pública no requiere registrar
cada dominio. El catálogo histórico de `research_sources` queda para el recorrido
documental anterior.

El broker valida URL, DNS y cada redirección; conecta a la IP pública validada
con Host/SNI originales. Rechaza credenciales en URL, protocolos alternativos,
puertos ajenos a 80/443, redes privadas y direcciones IPv6 de transición inseguras.
Comprueba también el contenido saliente de rutas/consultas antes de resolver DNS.
Chromium usa un contexto efímero, namespace sin red y recursos GET suministrados
por el broker; no hereda cookies. No admite formularios POST, WebSockets, sesiones
autenticadas, CAPTCHA ni muros de pago. Un recurso fallido produce cobertura
parcial. La extracción HTML admite UTF-8; PDF registra páginas, cobertura y
referencias. **OCR no está instalado**: un PDF escaneado devuelve esa limitación.

El código generado nunca tiene red directa. Con originales privados, el primer
acceso al workspace cierra de forma irreversible la búsqueda, descargas,
navegación e instalación durante esa ejecución. La investigación y las
dependencias deben prepararse antes. La inferencia posterior sigue pasando por
la política y el enmascarado de Regulay. Esta separación impide utilizar el código
o paquetes para enviar originales a un sitio arbitrario.

Los paquetes se descargan por el broker desde PyPI/npm con versiones exactas y
hashes, se guardan con procedencia y se instalan offline. Hay que declarar las
dependencias transitivas con versiones exactas. Python admite wheels compatibles
con Linux/Python 3.12; no compila sdists. npm ejecuta con `--ignore-scripts`, sin
auditoría ni acceso de red. Paquetes que necesiten scripts de instalación o
descargas adicionales pueden no funcionar; el error vuelve al agente.

## Activación de una cuenta existente, pendiente de autorización operativa

Estos pasos son un procedimiento, **no acciones realizadas durante la tarea**.
Primero se necesita autorización para desplegar y cambiar permisos. La prueba
final necesita además autorización nueva y un tope de gasto para modelo/buscador.

1. Preparar una instancia aislada PostgreSQL y aplicar la migración
   `0041_agent_professional`. Añade tablas/campos con acceso deshabilitado; no crea
   grants ni cambia credenciales. Verificar antes la conexión elegida. Las pruebas
   de la tarea aplican y revierten la migración solo en una base desechable.
2. Construir `Dockerfile.spreadsheet` y `Dockerfile.executor`, registrar el template
   en el E2B existente y validar el aislamiento en **ese kernel**. Los ficheros
   lock usan versiones/hashes; Node tiene SHA256 fijado. No se construyó esta
   imagen: Docker Desktop local no arranca por un socket inaccesible. La base OCI
   fijada se inspeccionó en el registro público y es Debian 13/trixie. El ensayo
   WSL no sustituye el build ni la prueba de microVM. Un fallo de `bwrap`/UID
   impide iniciar comandos; no hay modo sin aislamiento.
3. Elegir usuario, empresa, conexión y modelo de la misma empresa. Crear un perfil
   **deshabilitado** dedicado a esa cuenta si no existe. Desde una consola Django
   administrativa, `AgentModelProfile.objects.create(company_id=COMPANY_ID,
   name='Agente profesional', connection_id=CONNECTION_ID, model_id=MODEL_ID)`
   produce ese perfil sin conceder acceso. Comprobar previamente que el modelo
   pertenece al motor de la conexión. No reutilizar un perfil compartido si no se
   pretende cambiar las capacidades de sus otros grants.
4. Mantener claves en el servidor Django. Para búsqueda, un fichero privado fuera
   del repositorio contiene `{"provider":"tavily","api_key":"CLAVE_REAL",
   "call_cost_bound":"TECHO_POR_CONSULTA_USD"}`. El techo debe ser positivo y
   justificarse con el contrato actual; no se proporciona una tarifa inventada.
   El comando almacena ese JSON cifrado y nunca imprime la clave. Un fichero
   opcional de límites puede contener `{"model_calls":48,"tool_calls":120}`.
5. Revisar la política de empresa: destino `engine:<id>` elegido, enmascaradores,
   Jev si es obligatorio y destinos `research:web` / `research:packages` en los
   niveles de sensibilidad autorizados. Estos son destinos de capacidad; no son
   listas de dominios. Mantener el presupuesto monetario en `ai_config.limits` y
   precios verificables del modelo. No cambiar la clasificación ni quitar el
   enmascarado para conseguir que pase una prueba.
6. Previsualizar el grant sustituyendo los IDs y las rutas privadas:

   ```powershell
   rtk proxy .venv/Scripts/python.exe regulai/manage.py configure_professional_agent --profile-id PERFIL --user-id USUARIO --search-config-file RUTA_PRIVADA --limits-file RUTA_LIMITES
   ```

   Revisar la salida; repetir el mismo comando con `--apply` únicamente en la
   activación autorizada. Sin `--apply` no persiste cambios. Para retirar solo el
   grant, usar `--disable --apply`; conserva el perfil y los demás grants.
7. En un módulo de settings del entorno autorizado establecer
   `REGULAY_AGENT_ENABLED`, `REGULAY_AGENT_WEB_ENABLED`,
   `REGULAY_AGENT_PACKAGES_ENABLED` y `REGULAY_AGENT_BROWSER_ENABLED` a `True`.
   Los defaults siguen a `False`; estas constantes no leen variables de entorno
   automáticamente. Configurar `REGULAY_AGENT_WORKER_TOKEN` desde un secreto de
   al menos 32 caracteres. No hace falta `DEBUG=True`, `REGULAY_AGENT_DEVELOPMENT`
   ni un usuario con prefijo sintético.
8. Ejecutar el worker con su JSON privado: `internal_endpoint` termina en
   `/internal/agents/`; `worker_token_file` apunta al mismo token; `api_url`,
   `sandbox_url`, `api_key_file` y `template` describen el E2B privado existente.
   Restringir su conectividad a Django/E2B, sin montar claves de modelos. Confirmar
   la ruta con `front/urls.py` antes de arrancar el proceso.
9. Entrar con la cuenta autorizada, seleccionar modo agente, comprobar sus
   capacidades y ejecutar las peticiones de la sección siguiente. Guardar los
   recibos y comprobar los cargos reales antes de ampliar el piloto.

La visión necesita `profile.vision`, modelo con `supports_vision` y el modo de
presupuesto `provider_managed` que admite la pasarela existente. No se habilita
con originales privados, porque no se enmascaran píxeles. Ese modo no ofrece un
techo monetario local: requiere límites de cuenta en el proveedor. Si la política
exige un techo local o restringe imágenes, se omite la herramienta y la revisión
visual queda como no realizada; no se cambia la política automáticamente.

## Límites efectivos y dinero

| Recurso | Default | Aplicación |
| --- | --- | --- |
| Inferencias / herramientas | 48 / 120 | Servidor, acumuladas entre reanudaciones |
| Duración de ejecución | 1.800 s | Desde el inicio original; máximo configurable 3.600 s |
| Comando | 120 s | Reloj, CPU por proceso y muerte del grupo/namespace al vencer |
| Memoria / procesos | 1.024 MiB / 64 | RLIMIT_AS por proceso, RLIMIT_NPROC por UID |
| VM de la receta actual | 1 CPU / 1.024 MiB | Límite agregado E2B; pendiente de probar la imagen nueva |
| Workspace | 512 MiB | tmpfs del trabajo, máximo configurable 1 GiB |
| Archivo / entrega conjunta | 20 MB | Transferencia y suma del documento, PDF y páginas publicadas |
| Salida de comando / fragmento | 1 MiB / 16.000 caracteres | Truncamiento explícito; `read_output` pagina lo conservado |
| Web | 40 operaciones, 10 MB, 25 s | Por ejecución / respuesta / petición; browser hasta 50 recursos y 10 MB totales |
| PDF | 100 páginas | Lectura/render, máximo configurable 200 |
| Reparaciones finales | 3 | Separadas del ciclo normal de herramientas |
| Checkpoint | 20 MB comprimidos, 20.000 entradas | Workspace máximo; sin Pickle ni permisos de escritura heredados |
| Retención | 30 días | Por perfil, terminales únicamente |

Los valores configurables se validan en `capabilities.Limits`. Un límite de
memoria de perfil mayor no aumenta los 1.024 MiB físicos del template actual.
Los ensayos WSL comprueban namespaces/rlimits y procesos; no acreditan el límite
agregado de memoria/disco de una microVM desplegada. No hay cuotas diarias nuevas:
se conservan presupuesto por ejecución, un escritor por conversación y un slot
limpio por worker. La capacidad agregada depende del número de workers provisionado.

Cada llamada pasa por Regulay: proveedor/modelo solicitado y efectivo, propósito,
ruta, fallback, duración, Jev y coste disponible. El coste de Tavily es un techo
configurado **estimado**, no una factura; un fallo sin recibo mantiene coste
desconocido. El HTTP público declara ausencia de cargo API, sin afirmar coste cero
de infraestructura. Sandbox/ancho de banda se muestran como no reportados. Las
respuestas duplicadas no vuelven a facturarse; una operación incierta no se repite.

## Artefactos, recuperación y limpieza

`publish_artifact` acepta formatos generales y conserva revisiones inmutables.
DOCX/PDF/PPTX se renderizan dentro del namespace mediante LibreOffice/Poppler; el
servidor verifica hashes, páginas, contenido activo y cobertura de texto. El Word
ofrece el PDF derivado como descarga adicional. En una reparación se entrega la
última revisión de cada archivo y se conserva el historial. Para editar desde el
chat, usar **Editar esta revisión**; se revalida la base y se registran las partes
OOXML que cambiaron. Esto no garantiza por sí solo que se haya respetado toda la
intención semántica de una edición.

Las comprobaciones de integridad, instrucciones, maquetación, fuentes y seguridad
tienen alcances separados. Enviar los píxeles exactos al modelo acredita revisión
automática, no un juicio favorable universal. La revisión humana registra otro
recibo y solo se exige cuando `human_review=true`. Las fuentes descubiertas,
abiertas, parcialmente leídas y fallidas tienen estados distintos. No se habilita
exportación profesional a Drive ni otras escrituras externas mediante este cambio.

Antes de cada inferencia se guarda un checkpoint cifrado de mensajes y archivos.
Se copian ficheros regulares y directorios; los enlaces a ejecutables de `/usr`
se conservan únicamente como referencias al runtime de solo lectura cuyo hash
debe coincidir al restaurar. Se rechazan enlaces al host y descendientes de
enlaces. Si el estado excede los límites, no se promete un checkpoint nuevo.
**Reanudar** aparece cuando hay una frontera durable sin acciones posteriores o
inciertas. Conserva plazo, consumo y autorización; admite como máximo tres
reanudaciones y restaura en un sandbox nuevo. Un checkpoint antiguo no autoriza
repetir trabajo externo de resultado desconocido.

Cancelar revoca la ejecución. El heartbeat del worker detecta la revocación y
destruye la VM; un timeout mata el grupo de procesos y sus hijos. Ante pérdida de
transporte, el TTL de E2B de 180 s es el respaldo. Nunca se devuelve un sandbox
usado al pool. La cancelación del proceso y los hijos se probó en Linux; la
destrucción de la microVM nueva debe repetirse al validar E2B.

Para limpieza, previsualizar y aplicar después a ejecuciones terminales caducadas:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py purge_agent_data
rtk proxy .venv/Scripts/python.exe regulai/manage.py purge_agent_data --apply
```

Admite `--run-id UUID` repetible. Borra contenidos cifrados de entradas,
checkpoints, herramientas, operaciones, respuestas del modelo y artefactos;
revoca descarga/preview y conserva metadatos mínimos de auditoría. El historial
general de chat y el registro de alias mantienen su política de retención propia:
este comando no equivale a borrar toda la conversación. No se ha programado un
cron ni ejecutado una purga sobre datos existentes.

## Ensayos adicionales con proveedores vivos

La prueba documental real local de la tarea 57 no completa toda esta matriz.
Con configuración, despliegue y gasto expresamente autorizados, usar peticiones
nuevas sin pasar al modelo el fixture ni una secuencia de herramientas. Incluir:

- Investigar energía, turismo y documentación técnica; descubrir nuevos dominios,
  abrir un PDF y contrastar afirmaciones con citas verificables.
- Descargar un dataset público elegido durante la búsqueda, calcular con Python
  y Node nuevos, provocar/corregir un error e instalar una dependencia ausente con
  versión exacta. Entregar gráfico, cálculo reproducible y referencias.
- «Crea un informe de consultoría en español, de cinco páginas, sobre computación
  cuántica y ciberseguridad, en Word y PDF, sin cifras inventadas». Confirmar todas
  las páginas, coherencia y recibos visuales efectivos.
- Adjuntar un CSV de columnas distintas y un XLSX con varias hojas; editar después
  una sección del Word, una fórmula del Excel y una diapositiva, preservando las
  demás partes. Preparar dependencias antes de leer los originales privados.
- Cancelar durante un comando; reiniciar un worker en una frontera durable;
  repetir el mismo request ID y verificar revisiones, recibos y ausencia de cargos
  duplicados. Probar también credenciales ausentes, 429 y fuentes inaccesibles en
  un entorno de fallos controlado, sin manipular cuentas productivas.

Registrar IDs de ejecución, configuración/versiones sin secretos, URLs y hashes,
costes conocidos/estimados/desconocidos, archivos y capturas. Solo esos resultados
permitirán evaluar la planificación y depuración de un modelo vivo. Los contratos
y renders locales entregados aquí no sustituyen ese ensayo.

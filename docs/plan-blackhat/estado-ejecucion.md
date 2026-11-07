# Estado observado de la implementación

## Banco adversarial nuevo — 3 de octubre de 2026

[Dataset de 44 casos y 17 documentos](../../evals/adversarial/community-20261003/README.md), con cinco niveles de sensibilidad,
DNI/PII ficticia y diez inyecciones con procedencia, congelado antes de ejecutar. Detector real: 37/44 casos cumplen anotaciones,
27/32 valores sensibles eliminados y 61/66 cadenas preservadas. Tres HTTP y dos perfiles de proveedor simulado: 258/264 controles.
Cuatro casos dejan pasar valores a los transportes simulados; dos documentos se rechazan porque la máscara altera citas válidas.
[Interpretación y ejemplos](../../evals/reports/adversarial-community-20261003-03/README.md); [seguimiento de límites](tareas/33-limites-del-detector-adversarial.md).
Esa batería local no hizo llamadas pagadas: clasificación, generación y juez son fixtures, sin medida de resistencia semántica real.

La integración `128d66a` añade extensión explícita del ledger y pasada única, conservando gasto y reservas anteriores.
[Cinco puertas nuevas](../../evals/reports/adversarial-gates-20261003-01/manifest.json): **400 tests**, 150 controles offline,
check, migraciones y auditorías de dependencias correctos; fuentes estables, sin CI remoto.
[Dos pasadas reales autorizadas](informe-adversarial-community-20261003.md): ocho casos distintos en economy/strong/router,
24 combinaciones, 46 llamadas externas y 35 transformaciones locales. Una respuesta entregada con citas, 15 bloqueos y ocho rechazos del verificador.
Exposición acumulada **0,038440878 USD** del máximo conjunto de 1 USD, incluida reserva incierta histórica 0,003 USD sin repetir.
El manifiesto del ensayo anterior permanece detenido. Las dos extensiones preservan gasto y datos anteriores.
`1af809f` corrige después la frontera decimal de un rechazo observado; los resultados reales de `128d66a` permanecen intactos.
[Cinco puertas finales](../../evals/reports/adversarial-gates-20261003-02/README.md): **404 tests OK**, check/migraciones,
150 simulaciones offline sin fallos ni llamadas reales y auditorías de dependencias correctas. Sin CI remoto.
[Tarea 32](tareas/32-banco-adversarial-y-datos-personales.md), [fallo numérico](tareas/35-frontera-numerica-del-umbral.md)
y [calibración pendiente](tareas/34-bloqueos-semanticos-en-casos-benignos.md).

## Preparación nueva del piloto — 3 de octubre de 2026

El [informe del piloto](informe-piloto-community-20261003.md) y [checkpoint](piloto-checkpoint.md) recogen el candidato `972edb8`: 387 tests y cinco puertas con código 05 correctas, 117 pruebas PostgreSQL y recuperación sintética. D2 local obligatoria, corpus de 12 archivos y navegador verificados; detector 16/18 con omisiones/falsos positivos. Ensayo vivo Vercel autorizado:8/24 combinaciones y 17 llamadas, detenido ante clasificación incierta; ledger conservado. Diagnóstico seguro corregido después, sin repetir llamadas. Dos perfiles simulados por petición del usuario, separados de participación humana. Office nativo, revisión humana y cierre del recorrido real siguen pendientes. No hubo despliegue ni CI remoto.

## Histórico de las correcciones anteriores — 3 de octubre de 2026

Código técnico recibido: `51f4ee5`; original `6a0f667`; inicio `4400f0b` (mismo código que `4b10778`). D1–D7 aprobadas. B1–B10/C1–C2 y hallazgos adversariales resueltos; tareas 09–19 done con pendientes externos explícitos. [Tabla de pruebas y commits](informe-correcciones-community.md); [revisiones originales Standards y Spec](revisiones-correcciones/README.md). R cerrada: Spec sin hallazgos y condición de máscara activa corregida en `52bdc8d`, con verificación independiente. Las [cinco puertas posteriores a la documentación](../../evals/reports/community-fixes-docs-verification-20261003/README.md) terminaron con exit 0: **302 tests OK en 62,428 s**, check sin incidencias, migraciones sin cambios, 150 offline/0 fallos/0 llamadas reales y pip-audit sin vulnerabilidades conocidas.

| Integración observada | Suite front/api | Otras cuatro puertas |
| --- | --- | --- |
| D, `90000c6` | 295 OK en 58,250 s | check sin incidencias; migraciones sin cambios; 150 offline, 0 fallos/llamadas reales; pip-audit sin vulnerabilidades conocidas |
| F, `c373c87` | 296 OK en 60,252 s | Mismos cuatro resultados; exit 0 |
| Q, `21c291e` | 297 OK en 71,258 s | Mismos cuatro resultados; exit 0 |
| O, `51f4ee5` | **302 OK en 65,158 s**, sin expected failures ni omitidas | check sin incidencias; No changes detected; 150 offline, 0 controles fallidos/llamadas reales; No known vulnerabilities found; cinco puertas exit 0 |

Las doce regresiones finales fallaron como doce AssertionError en `4400f0b`, sin errores de preparación ni skips. Los recuentos parciales de distintas revisiones no se suman. El banco Q negativo usa una copia development: 90 ejecuciones, 52 fallos, cero reserved y exit1 tras guardar sus cinco informes; no son fallos del banco normal ni etiquetas ajustadas.

[Recorrido visual actual: siete imágenes](../../evals/reports/ui-community-fixes-20261003/README.md): consentimiento complete_text_only por una imagen con cero llamadas antes de confirmar, 10 euros y extracto en párrafo 2, dos generaciones/cinco llamadas sintéticas, evidencia con Enter, ficha/límites tras recarga, cliente móvil 375/scroll375, bloqueo local cero llamadas, motor/destino real y formulario POST/CSRF de máscara. DOCX generado con Python; maqueta advisory/renewal auxiliar sin prueba backend, distinta de regresiones HTTP.

No hubo llamadas reales/pagadas durante estas correcciones, push, despliegue, publicación ni operaciones sobre bases del usuario. Pendientes: Office/LibreOffice real, ensayos humanos, calibración y E2E vivo con autorización/presupuesto/tarifas revisadas; PostgreSQL sin driver/servidor, CI remoto no ejecutado, Gunicorn no arrancado en Windows. Migraciones y recifrado solo en bases aisladas. [Arranque](arranque-y-demo.md) y [rotación](rotacion-claves.md).

## Verificación final conservada

La ejecución final de ASTRA sobre `12ca58d3a2b5a6570840ca80676a1799f6eac097` (mismo comportamiento técnico que `51f4ee5`, solo ajuste de EOF) pasó las cinco puertas con exit 0: **302 tests en 66,767 s**, check sin incidencias, migraciones sin cambios, 150 simulaciones/0 controles fallidos/0 llamadas reales y pip-audit sin vulnerabilidades conocidas. [Registro de cinco gates y logs](../../evals/reports/community-fixes-verification-20261003/README.md), [JSON exacto](../../evals/reports/community-fixes-verification-20261003/gates.json), [22 etapas históricas](../../evals/reports/community-fixes-verification-20261003/integration-gates.json), [regresiones y rojo base](../../evals/reports/community-fixes-verification-20261003/regressions.json) y [banco final/manifiesto](../../evals/reports/offline-community-fixes-final-20261003/report.md).

Solo tres etiquetas development cambiaron por D3 con [justificación por caso](cambios-banco-correcciones.md); no se tocó reserved ni umbrales para aprobar. La prueba negativa de la suite fuerza seis controles fallidos y la prueba CLI 52, por diseño; ninguna representa un fallo del banco final.

## Registro de verificaciones anteriores

Las secciones fechadas siguientes conservan las integraciones parciales del 3 de octubre y la entrega original del 2 de octubre. Los 129 tests, la conducta antigua de clasificación ambigua, las limitaciones de recursos/teclado y los hashes originales pertenecen a esa revisión; el estado actual está arriba. Las llamadas reales se hicieron bajo otra autorización puntual y no forman parte de este encargo. El script de `jev_verification_component` no está versionado: sus resultados no acreditan reproducibilidad E2E.

## Correcciones iniciadas el 3 de octubre de 2026

Rama `codex/community-fixes` desde `4400f0b`; [contratos, propiedad y decisiones D1–D7 aprobadas](correcciones-community.md). La base se volvió a ejecutar: check sin incidencias; 129 tests OK en 21.060 s; migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas.

Primera integración de regresiones: ASTRA reprodujo B1–B10/C1–C2 sin decoradores en base, con 12 AssertionError y cero errores/omitidas. Suite integrada: 141 tests OK (12 expected failures) en 22.900 s; check/migraciones/evaluación150/auditoría correctos. No son doce correcciones terminadas: los decoradores se retirarán con su implementación. [Tarea10](tareas/10-regresiones-revision.md).

Clasificación y documentos integrados: política ordinal conservadora, avisos de ambigüedad, formatos comunes y cobertura declarada. B3 y B7 ya no tienen expectedFailure. La última puerta integrada (`9f58dbf`) pasó check, 180 tests en 29.446 s (10 expected failures pendientes), migraciones sin cambios, 150 controles offline y pip-audit sin vulnerabilidades conocidas. [Clasificación](tareas/12-clasificacion-conservadora.md), [documentos](tareas/11-cobertura-documental.md).

Verificación integrada (`e042461`): 199 tests OK (9 expected failures) en 31.721 s y las cinco puertas correctas. B8 retirado; ocho reproducciones independientes en rojo, cero errores de preparación. No se han modificado etiquetas del banco offline. [Citas y conectores](tareas/13-citas-estructuradas.md).

Seguridad integrada (`48fdba9`): 214 tests OK (8 expected failures) en 32.148 s; check, migraciones, evaluación offline150 y pip-audit correctos. B2 retirado y once regresiones adicionales reproducidas con AssertionError en la base. Rotación probada solo en bases aisladas; ningún secreto existente modificado. [Seguridad backend](tareas/14-seguridad-backend.md).

Migraciones 0029–0031 integradas y probadas una por una, incluida reversión. Última puerta (`f677d54`): 218 tests OK (8 expected failures) en 32.687 s y check/migraciones/offline150/pip-audit correctos. Ninguna base de datos del usuario se modificó. [Histórico y política inicial](tareas/15-onboarding-historico.md).

Frontend integrado tras reproducir y revertir un fallo de bytes CRLF en vendor. La corrección conserva hashes originales y añade una prueba de checkout con autocrlf. Puertas `10-frontend-fixed`: 233 tests OK en 35.501 s (siete expected failures de P), check/migraciones/offline150/pip-audit correctos. [Interfaz](tareas/16-interfaz-recursos.md).

Onboarding integrado en `2cea782`: 246 tests OK en 35.521 s (siete expected failures de P), check sin incidencias, migraciones sin cambios, 150 controles offline correctos y cero llamadas reales, pip-audit sin vulnerabilidades conocidas. Administrador por empresa, borrador conservador sin activación automática y auditoría histórica visible de solo lectura. P y Q siguen en implementación; aún falta la revisión adversarial final.

Operación integrada en `2ffb355`: check sin incidencias; 252 tests OK en 35.773 s (siete expected failures de P); migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Los logs y la auditoría de excepciones omiten contenido. Gunicorn y CI tienen configuración validada localmente; no se ejecutaron Actions ni PostgreSQL. [Operación](tareas/17-operacion-ci.md).

Pipeline integrado en `eb8fde7`: **275 tests OK en 43.918 s, sin expected failures**, check sin incidencias, migraciones sin cambios, 150 controles offline correctos y cero llamadas reales, pip-audit sin vulnerabilidades conocidas. Las doce regresiones finales fallan por AssertionError en `4400f0b` y pasan aquí. Solo tres expectativas development cambiaron por D3, con justificación previa por caso. Revisión adversarial y documentación final aún pendientes. [Pipeline](tareas/18-pipeline-privacidad.md).

Revisión adversarial en curso con SOL nuevos por carril. Las correcciones de autorización P (`95dfb77`) pasan las cinco puertas: **279 tests OK en 46.899 s**, check sin incidencias, migraciones sin cambios, 150 controles offline correctos/cero llamadas reales y pip-audit sin vulnerabilidades conocidas. Los hallazgos D/C se han reproducido y están en corrección. [Tarea19](tareas/19-revision-final.md). Se ha comprobado la [interfaz offline y las citas con teclado](../../evals/reports/ui-community-fixes-20261003/README.md); siguen pendientes documentos guardados con aplicaciones Office reales y ensayos humanos.

El registro histórico que sigue corresponde a la implementación anterior; no acredita cambios de esta rama.

2 de octubre de 2026. Rama local `codex/community-blackhat`, base `6a0f667`. Sin push, despliegue ni publicación. Los planes conservan la especificación original y anotan su implementación. [Arranque y guion](arranque-y-demo.md); [tracker local](tareas/00-base.md).

## Entorno y datos

Python 3.12.11; Django 5.2.17 LTS; DRF 3.18.1. Una lista raíz de 45 paquetes fijados; la interior remite a ella. Se sincronizó el entorno con `uv pip sync`. La auditoría inicial encontró 96 avisos en 12 paquetes; tras actualizar, `pip-audit` informó cero vulnerabilidades conocidas. No es una garantía de ausencia de vulnerabilidades. [Versiones y auditoría](dependencias-verificadas.md).

Preparación histórica: el primer test esperaba una alerta del validador puro y falló `0 != 1`; se corrigió para comprobar coincidencias y ausencia de efectos. Las alertas se prueban ahora desde HTTP. `scripts/bootstrap_local.py` creó configuración y SQLite de desarrollo una sola vez, sin sustituir bases o secretos existentes. `MESAS_RETIRO.pdf` permanece ajeno a la implementación.

Migraciones 0026–0028 añaden procedencia/estados, configuración IA, catálogo y empresa de auditoría. Las pruebas de migración conservan mensajes legacy sin autorizarlos para contexto. No se cambian claves de cifrado. Credenciales guardadas en campos cifrados; nunca en los ejemplos JSON.

## Implementación disponible

- Las tres entradas web/API/POST antiguo llaman al servicio compartido. YARA inválida, documento ilegible, política ausente y destino denegado detienen la salida. `consent_confirmed` no autoriza: confirmación firmada vinculada a contenido, empresa, archivo, contexto y destinos; `request_id` estable para confirmar, cancelar y repetir.
- Solo turnos enlazados y autorizados entran en el historial. El propietario ve los mensajes legacy, con aviso, pero no se envían a proveedores. Prompt/AuditLog legacy sin procedencia de empresa quedan fuera de los listados de personal; se conservan en la base.
- Extracción acotada con cobertura, digest y fragmentos estables. PDF textual, DOCX, XLSX, CSV y textos admitidos; archivos corruptos/cifrados, bombas y límites producen estados explícitos. Imágenes y XLS no admitidos; sin OCR ni ruta visual implícita.
- Clasificación Jev, router y verificación integrados: contrato HTTP estricto, catálogos activos de la empresa, calidad configurada, capacidad, precio, presupuesto y plazo. Máximo dos generaciones; ambas se verifican. Bloqueos locales se aplican también antes del juez y de la integración de enmascarado existente.
- Ficha pública de decisión y evidencia con filtrado de campos, costes desconocidos explícitos y permisos de propietario/empresa actual; descargas preservadas. Las citas deben pertenecer al archivo y tener extractos reales; el respaldo semántico requiere un juicio específico.
- Simulador con borradores JSON/YARA temporales y señales sintéticas explícitas que no rebajan el mínimo local de sensibilidad. La ruta reserva también el coste de clasificación y jueces obligatorios. Modo semántico opcional bajo la política vigente y presupuesto acotado, sin generador. Activación separada revalida destinos y versión/digests; la auditoría de empresa conserva configuración y fuentes YARA antes/después para recuperación, sin muestra ni credenciales.
- Administración global/Django admin limitada a operadores activos con `is_staff`, `is_superuser` e ID en `PLATFORM_ADMIN_USER_IDS`. Administradores de empresa usan ámbitos propios y no pueden resetear ni borrar el perfil del operador. Archivos privados y avatares validados por rutas autenticadas; sin alias público de media.

## Evidencia automatizada

Suite final: `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front api --settings=regulai.test_settings`: **129 pruebas correctas en 19,891 s**. `makemigrations --check --dry-run --settings=regulai.test_settings`: sin cambios. `rtk proxy uv pip check --python .venv/Scripts/python.exe`: 45 paquetes compatibles. Los resultados parciales siguientes se observaron en distintas revisiones y no deben sumarse como tests únicos:

Reproducción desde cero: `rtk proxy uv venv --python 3.12.11 .claude/reproduction-venv-20261002` y sincronización de la lista raíz instalaron los mismos 45 paquetes. Desde ese intérprete, `test front api --settings=regulai.test_settings`: **129 correctas en 39,764 s**; `check --settings=regulai.test_settings`: cero incidencias; `run_demo --settings=regulai.demo_settings --seed-only`: correcto. El bootstrap se repitió y preservó los settings locales existentes. `migrate --check` terminó con código 0. Esta comprobación no reemplaza el recorrido visual, realizado con el entorno original.

| Comando desde la raíz, con `rtk proxy .venv/Scripts/python.exe regulai/manage.py` | Resultado observado |
| --- | --- |
| `test front.test_policy_simulator --settings=regulai.test_settings` | 14 correctas; incluye mínimo local de sensibilidad, reserva de jueces y fuentes YARA para recuperación |
| `test front.test_documents front.test_chat_ui front.test_policy_simulator --settings=regulai.test_settings` | 27 correctas |
| `test front.test_policy_simulator front.test_pipeline front.test_chat_flow --settings=regulai.test_settings` | 40 correctas |
| `test front.test_demo front.test_evaluation api front.test_runtime --settings=regulai.test_settings` | 21 correctas |
| `test front.test_policy_simulator front.test_smoke front.test_evaluation_budget --settings=regulai.test_settings` | 21 correctas: 14 simulador, seis smoke y una de presupuesto/concurrencia |

Se probaron las tres entradas HTTP, el límite de proveedor HTTP/SDK, migración legacy, confirmaciones solapadas, idempotencia, cambios de empresa/contexto/política, coste incierto y ausencia de reintentos ocultos. Las pruebas usan SQLite aislado y proveedores simulados, sin llamadas pagadas.

El [JSON de configuración](ai-config-example.json) se validó mediante `AIConfig.model_validate_json` en `manage.py shell --settings=regulai.test_settings`: correcto, sin destinos y con presupuesto cero. No activa llamadas ni contiene claves.

Banco final [offline-2026-10-02-04](../../evals/reports/offline-2026-10-02-04/report.md), ejecutado tras los últimos cambios Jev/simulador/smoke: 50 casos × tres configuraciones = **150 ejecuciones**, 150 controles correctos, cero salidas prohibidas y cero llamadas reales. Casos de desarrollo/reservados, manifiesto, hashes SHA-256 de los bytes exactos de los archivos ejecutados, resultados por caso y resúmenes conservados. Se volvieron a comprobar los seis hashes y coinciden con los archivos actuales; no normalizan saltos de línea. El commit del manifiesto (`023c7ef`) era el HEAD al ejecutar sobre cambios locales; los archivos probados quedaron después en `cfa29fa`. Los informes 01–03 se conservan como ejecuciones previas. Costes y respuestas son fixtures; latencia local. **No demuestra precisión de Jev, calidad factual ni ahorro real.**

La regresión de metadatos Jev se reprodujo en rojo y pasó tras aceptar `provider_metadata` y `providerMetadata` con la misma validación; si ambos aparecen y discrepan, se rechaza la respuesta. No se convierten metadatos inválidos en uso/coste de confianza.

## Pruebas reales acotadas y calibración pendiente

Presupuesto conjunto autorizado: **1 USD**, con registro persistente `.claude/real-provider-budget.sqlite3`. El usuario autorizó la repetición («venga prueba ahora») como excepción puntual a la prohibición general de nuevas llamadas pagadas, manteniendo ese límite. No se compraron créditos ni se hicieron recargas automáticas.

Una llamada sintética DeepSeek resolvió `2 + 2` como `4`: 25 tokens de entrada y uno de salida, estimación superior con tarifa punta **0,00000870 USD**. Es una comprobación de integración y contabilidad, no un benchmark. [Informe real 01](../../evals/reports/real-smoke-2026-10-02-01/report.json).

Los tres intentos Gateway/Jev iniciales devolvieron HTTP 403: «Free tier users do not have access to this model. Upgrade to paid credits…», con `providerAttempts: 0`. Los informes reales 01/02 recogen los dos primeros; el tercero fue diagnóstico de acceso. El [export histórico](../../evals/reports/real-budget-2026-10-02.json) conserva esa evidencia y **0,03 USD de reservas inciertas**, que no se convierten en gasto confirmado ni en cero.

En el [smoke real 03](../../evals/reports/real-smoke-2026-10-02-03/report.json), Jev completó la clasificación sin 403: **917 tokens de entrada/251 de salida**, coste comunicado por Gateway **0,000038514 USD**. La categoría obtuvo confianza **0,49 < 0,8** y el pipeline devolvió `classification_ambiguous` antes de generar: respuesta documental entregada **0/1**. Se restauró la configuración. El acceso está resuelto; la clasificación necesita revisión y calibración, sin rebajar umbrales.

El [ensayo real de verificación de componente](../../evals/reports/real-jev-verification-2026-10-02-01/report.json) aceptó una afirmación de 17 días y rechazó otra de 30 frente a la misma fuente sintética de 17 días (**2/2 expectativas**). Usó las tres preguntas de producción, umbral **0,8**, con `noul` de omisión/contradicción/afirmación **0,13/0,05/0,03** para la correcta y **0,67/0,98/0,98** para la falsa. Cada llamada: **473 tokens de entrada/62 de salida**, **0,000019866 USD** comunicado por Gateway. Se enviaron estados y respuestas prefijadas solo a Jev, sin DeepSeek, generación ni clasificación del pipeline; no es un recorrido de extremo a extremo ni una calibración.

Las tres nuevas llamadas suman **0,000078246 USD**; el [snapshot actualizado de presupuesto](../../evals/reports/real-budget-2026-10-02-02.json) registra **0,000086946 USD** conocidos (incluida la estimación DeepSeek anterior) y **0,03 USD** inciertos, dentro del límite de 1 USD. [Contrato y resultados Gateway](jev-gateway.md).

Siguen pendientes la calibración real de sensibilidad y jueces con casos representativos y conjunto humano reservado, comparación de economy/strong/router, ahorro observado y respuesta documental con citas verificada de extremo a extremo en vivo. El impedimento actual es de verificación/calibración, no el 403 inicial. Los dos casos de componente y los umbrales/calidades sintéticos no demuestran calidad general ni ahorro real.

## Navegador y demo

Servidor local normal: `127.0.0.1:8765`; usuario sintético `community-local-demo`, contraseña pública local `Local-demo-only-2026!`. La configuración de IA se restauró a `{}` para impedir gasto accidental. En navegador se confirmó `policy_configuration_invalid`, HTTP 503, ficha y cero llamadas.

Demo separada: `run_demo --settings=regulai.demo_settings`, `127.0.0.1:8001`, base `regulai/community-demo.sqlite3`, medios y cookies propios. Usuario `community-demo`, contraseña pública sintética `community-demo-only`. Siembra repetida sin resetear datos; un fixture modificado se conserva y causa error. Proveedores simulados y salida HTTP/socket del servidor bloqueada solo dentro de ese comando. El navegador puede pedir glifos a Iconify; no se afirma aislamiento completo de red del navegador.

En navegador offline `8001` se comprobó adjuntar el contrato, respuesta de 10 euros y cita de la línea 2, dos generaciones/cinco llamadas simuladas, y persistencia al recargar. `SYNTHETIC_SECRET_DEMO` quedó bloqueado con cero llamadas. La advertencia de consentimiento mostró cero llamadas antes de confirmar. Cancelar terminó en `cancelled`, sin respuesta; confirmar con el archivo original devolvió `10 euros [1]`, con una única burbuja de usuario y evidencia de línea 2. Capturas: [evidencia documental](../../evals/reports/ui-2026-10-02/document-evidence.jpg), [bloqueo](../../evals/reports/ui-2026-10-02/blocked.jpg) y [documento confirmado/interfaz adaptable](../../evals/reports/ui-2026-10-02/confirmed-document.jpg). Son resultados de la demo offline, no proveedores en vivo.

La escena sencilla devolvió `Hola`, con ruta automática y tres llamadas simuladas. El simulador se probó en otra empresa local sin claves ni destinos: comparación interna/restringida con bloqueo y sus motivos, semántica no evaluada y cero llamadas reales; activación separada correcta, revisión 2. La auditoría SQLite conservó revisión anterior 1 y nueva 2 para recuperación, cero intentos semánticos y cero `Prompt`. [Captura](../../evals/reports/ui-2026-10-02/simulator-activated.jpg) y [registro visual](../../evals/reports/ui-2026-10-02/README.md).

Teclado: Enter envió el mensaje y abrió la ficha; Espacio alternó la ruta automática, restaurada activa. **Pendientes:** apertura de citas con teclado y dos ensayos completos con otra persona. La herramienta de navegador rechazó reabrir la URL local y no permitió cerrar la comprobación de citas; no se atribuye ese resultado al producto. Los ensayos humanos son un requisito externo aún no realizado. No hay despliegue autorizado.

## Revisiones locales conservadas

`18ecca7` preparación; `75ec867` Django LTS/dependencias únicas; `b99434a` dependencias vulnerables/pypdf; `853d495` documentos; `48a25e8` Jev/router/verificación; `2a5bd40` estados/configuración/procedencia; `023c7ef` recursos locales; `bbb86a5` runtime compartido; `6496ef7` presupuesto/smoke; `cfa29fa` evaluación/demo; `9e438fc` evidencia final y README. Son commits locales, sin push; la documentación final se revisa por separado. El [registro de verificación final](../../evals/reports/release-verification-2026-10-02.json) conserva comandos, resultados de ambos entornos y pendientes.

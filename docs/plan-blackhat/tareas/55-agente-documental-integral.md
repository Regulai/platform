# Agente documental de extremo a extremo

Estado: implementación y verificación local completadas. Bloqueada por: ninguna
para este alcance. No desplegada ni activada en la instancia existente; no se
han realizado inferencias con proveedores de pago.

Petición: corregir la creación sin adjuntos, producir el formato y extensión
pedidos, investigar por una vía autorizada, distinguir Jev/enrutamiento y las
comprobaciones, y cuidar la interfaz. Conservar cambios, datos, cuentas y secretos;
sin push, despliegue ni nuevas llamadas de pago.

## Aceptación

Un informe de cinco páginas sin adjunto produce Word/PDF con cinco páginas
comprobadas sobre el PDF final y contenido sin tabla económica inventada. Un
Excel ficticio requiere petición explícita. Las fuentes se corresponden con
consultas registradas; los límites de respaldo factual permanecen visibles.
Cada ejecución muestra llamadas, decisiones y verificaciones reales.

## Plan y estado

- Completado: contrato de petición, generación desde texto y preservación de revisiones.
- Completado: consulta de fuentes primarias autorizada y referencias trazables.
- Completado: Jev y secuencia de llamadas, modelos efectivos y costes.
- Completado: interfaz, tarjetas, estados, menús y controles de teclado.
- Completado: regresiones HTTP/proveedor/estado/dinero y renders/UI reales locales.
- Completado: revisión final y [guía de la cuenta/configuración existente](../../../ops/agent_chat/DOCUMENTS.md).

## Decisiones y hallazgos

- Se conservan todos los cambios locales recibidos, incluidos los tres PDF
  ajenos. No se habilitan perfiles ni destinos de cuentas existentes.
- El generador previo de Word/PDF dependía de `item,amount_cents` y de una
  plantilla económica. Se necesita una ruta de contenido narrativo real.
- La revisión visual humana ligada al hash sigue separada de los controles
  técnicos. No se convierte el mero render en aprobación visual automática.
- Las inferencias de prueba usarán transporte simulado y bases aisladas.

## Verificación observada

- 224 pruebas en PostgreSQL 17 desechable: agente, Excel/Word/PDF/PPTX,
  investigación, Jev, gateway, las tres entradas HTTP, reintentos, cancelación,
  revisiones, aislamiento, políticas, privacidad, costes, rutas y migraciones.
  Tras el último refuerzo de coherencia PDF se repitieron las 14 pruebas de
  informes, todas aprobadas. Se rechaza también texto extra o duplicado en PDF.
- 25 pruebas de interfaz/chat y 6 del SDK fijado: 255 pruebas distintas aprobadas.
  `manage.py check`, `makemigrations --check --dry-run`, sintaxis JS y
  `git diff --check` sin incidencias. No se requieren nuevas migraciones.
- Regresión roja antes del cambio: petición de informe sin adjunto concedía
  Excel ficticio. Se corrigió y se verifica por `/chat/`, `/chat/send/` y
  `/api/chat/send/`, hasta descarga Word/PDF y recibos.
- El grafo real Deep Agents/LangChain descubrió que faltaba `run/research` en
  la lista de operaciones del cliente interno. La regresión se reprodujo antes
  de corregirlo. Las pruebas SDK simulan la E/S del sandbox; el render se
  comprueba por separado con el programa real.
- Writer/Impress y Poppler reales, imagen fijada y red deshabilitada: informe de
  cinco páginas, dos ediciones, presentación de tres diapositivas y su edición.
  Verificación de bytes, texto exacto, fuentes incrustadas, paginación y partes
  preservadas. Se inspeccionaron las cinco páginas y las tres diapositivas, así
  como las páginas modificadas; las restantes imágenes son idénticas por bytes.
  La inspección motivó aumentar legibilidad/densidad del informe y tipografía de
  las diapositivas. No hay portada vacía, recorte ni referencias fabricadas.
- Lecturas públicas reales de las cuatro páginas NIST por el transporte nuevo,
  sin inferencia. Recibos, extractos, fecha y hashes conservados.
- Chromium real a 1440×1000 y 390×844: envío, cancelación, revisión, error, vistas,
  ambas barras laterales, teclado, detalles Jev/14 llamadas y descargas. Estados,
  respuestas, costes y aprobaciones fueron simulados. Una imagen que no carga
  impide aprobar la revisión. Descargas comparadas con los bytes del fixture.

Evidencia: `evals/reports/task55-agent-documents-20261013/`, incluidos
`backend-tests.log`, `report-final-tests.log`, `frontend-tests.log`,
`sdk-tests.log`, `verification.json`, `primary-sources.json`, `report/`, `deck/`
y `ui/qa-observations.json`. El contenido del informe es un fixture explícito,
no una medición de la calidad de redacción de un modelo real.

## Límites y operación

- Catálogo inicial acotado a NIST; no hay búsqueda general ni lectura remota PDF.
  Fuentes no disponibles/deshabilitadas/denegadas se explican sin inventar datos.
- Español/inglés, hasta veinte páginas/diapositivas, bloques narrativos acotados.
  La importación tabular y las ediciones conservan el alcance de las herramientas
  revisadas; no se anuncia un editor universal de Office.
- Formato, longitud y coherencia se comprueban; cumplimiento semántico completo y
  verificación factual completa figuran como no realizados. La revisión visual
  del usuario queda vinculada a hashes y separada de integridad y Jev.
- El contrato real de Jev devuelve señales estructuradas, no explicaciones ni
  recomendaciones textuales. Se muestra esa ausencia. El perfil fija la ruta y
  no introduce fallback automático.
- Cuenta, empresa, credenciales, datos e imágenes existentes conservados. La
  nueva imagen y el código deben actualizarse por el responsable de la instancia
  antes del ensayo con la cuenta habilitada; no se hizo despliegue ni push.
- Servidor/navegador de UI, temporales propios y PostgreSQL desechable retirados.
  La VM preexistente y otros contenedores se
  preservan. Los tres PDF ajenos no se modifican.

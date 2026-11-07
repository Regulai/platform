# 51. Word desde plantillas y PDF comprobado

Estado: implementada y verificada en laboratorio sintético (8 de octubre de 2026). Sin activar cuentas reales.
Blocked by: [50](50-agente-chat-excel.md).
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), [investigación documental](../../investigacion-prompts-skills-documentales-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 51 sobre el recorrido verificado de la 50.
Lee AGENTS.md, docs/implementacion-agente-regulay-prompts.md, la investigación
documental y docs/agent-assets/sources.json.

Añade DOCX desde plantilla corporativa y PDF al mismo ejecutor, catálogo de
skills, registro de artefactos, progreso y preview. No crees otro flujo de chat.

Evalúa BrandDocs con una plantilla sintética representativa antes de integrarlo.
Si cumple conservación y verificación, fija el motor compartido y brand-docx,
con licencia y NOTICE. Deshabilita aprendizaje global y descargas en tiempo de
ejecución. Si falla un requisito crítico, documenta el caso y usa un procedimiento
acotado con python-docx/plantilla; no construyas un framework alternativo de marca.

Adapta la copia Apache 2.0 de la skill PDF pública de OpenAI. Conserva atribución
y señala cambios. Usa las rutas, herramientas y política de datos de Regulay;
no ejecutes sus instrucciones genéricas de instalación durante una conversación.
Preinstala conversores, bibliotecas y fuentes con tildes, ñ y símbolos monetarios.

Valida el recorrido Excel → informe DOCX → PDF usando resultados locales.
Conserva estilos, tablas, cabeceras, pies y numeración. Reabre los archivos y
renderiza las revisiones finales. Comprueba páginas, texto esperado, tablas
cortadas, fuentes y restos de la plantilla. No aceptes que una revisión visual
degrade silenciosamente a comprobaciones estructurales. El hash del archivo
verificado debe coincidir con el entregado.

Los perfiles de plantilla y renders también pueden contener datos. Sus originales
se quedan locales; únicamente vistas protegidas autorizadas llegan al modelo.
La preview autenticada para el usuario no se reutiliza como entrada de visión.
Continúa ante errores reparables, sin preguntar por cada conversión o cálculo.

Un segundo turno debe poder cambiar el título o una sección y publicar una nueva
revisión del mismo artefacto, conservando el resto. Prueba entradas malformadas,
plantilla multipágina, tabla larga, caracteres españoles y fallo del conversor.
Comprueba visualmente archivo y UI. No incorpores aún otro motor de presentaciones
ni un editor Office embebido. Actualiza la evidencia y detente antes de la 52.
```

## Aceptación

- XLSX → DOCX → PDF comprobado y previsualizable en el chat; una edición conserva identidad y diseño.
- Plantilla, conversores y fuentes pasan casos reales locales con datos sintéticos.
- Reapertura/render obligatorios, reparación y comprobación de la revisión final.
- Procedencia conservada; ninguna skill instala dependencias ni elude el gobierno del modelo.
- No salen originales ni renders reales al contexto del modelo.

## Verificación observada

El mismo chat, perfil explícito, SDK y ejecutor E2B permiten crear DOCX/PDF desde
la plantilla corporativa, cambiar el título o el resumen y exportar el DOCX a PDF.
`AgentArtifact` conserva identidad, revisiones, bytes cifrados y renders privados.
La migración aditiva 0038 mantiene los XLSX anteriores con su formato por defecto.
Las tres entradas siguen en `send_chat_message`; no hay otro historial ni broker.

### Motor y procedencia

Se evaluó BrandDocs `97a6e384cb0664cd44ba8113c0b80c9761700670`: motor compartido y
`brand-docx`, 73 blobs contrastados con sus hashes Git. `doctor` y `extract` pasan;
`generate --qa strict` falla. La inspección de los renders reales confirmó título
duplicado, `{{TITLE}}` sin sustituir y una segunda página casi vacía. La prueba
Linux incluyó LibreOffice/Poppler y cinco renders; el intento Windows sin conversor
se conserva separado y no se cuenta como verificación visual. Se elige el fallback
acotado con python-docx y plantilla, sin BrandDocs activo ni aprendizaje global.
[Resultado y logs](../../../evals/reports/task51-word-pdf-20261008/branddocs-linux/result.json),
[licencia, NOTICE y manifiesto](../../../evals/reports/task51-word-pdf-20261008/branddocs-source/).

La skill PDF pública de OpenAI, SHA `49f948faa9258a0c61caceaf225e179651397431`,
se adapta en `regulai/front/agents/runtime/skills/pdf/`, con Apache-2.0 y cambios
explicados en el NOTICE del runtime. La copia histórica es referencia; únicamente
el catálogo del runtime se carga. No hay instalaciones ni descargas durante el chat.

Imagen comprobada: Python 3.12.11; python-docx 1.2.0; lxml 6.1.0; pypdf 6.19.0;
Pillow 12.3.0; LibreOffice Writer/Calc `4:25.2.3-2+deb13u8`; Poppler
`25.03.0-5+deb13u4`; Liberation `1:2.1.5-3`. Dependencias Python fijadas con hashes;
versiones Debian fijadas a las observadas. El lock Deep Agents 0.6.12 no cambia.
[Inventario y digest de imagen](../../../evals/reports/task51-word-pdf-20261008/document-versions.log).

### Verificación de archivos y UI

El programa local termina conversión/render antes de sellar el paquete en un proceso
separado. El servidor reabre los documentos y contrasta partes de plantilla, tabla
e importes, páginas, texto, fuentes incrustadas y hashes. El render no equivale a
revisión cualitativa: el candidato sigue como borrador hasta que el visor privado
autenticado registra la revisión de todas las páginas y los bytes exactos. El modelo
y la credencial del ejecutor no pueden autoaprobar esa revisión. Las reparaciones
locales se realizan sin una aprobación por cálculo o conversión.

Se inspeccionaron realmente las 3 páginas de cada una de las revisiones DOCX inicial,
título, resumen y PDF, y las 4 páginas del caso de tabla larga. Cabeceras, pies,
numeración, estilos, tabla, tildes, ñ y símbolos €, £ y $ se conservan. La tabla de
65 filas repite cabecera al cambiar de página, no corta filas y suma 81,25 €.
La UI se comprobó en anchura móvil y escritorio, incluyendo revisión y descarga.
[Captura móvil](../../../evals/reports/task51-word-pdf-20261008/ui-docx-mobile.jpg),
[captura escritorio](../../../evals/reports/task51-word-pdf-20261008/ui-pdf-desktop.jpg).

La identidad `d95137f8-b42c-401c-96e9-9b1be36053c4` mantiene XLSX r1 → DOCX r4 →
título r5 → resumen r6 → PDF r7; r2/r3 son borradores fallidos conservados.
Cambiar título/resumen altera exclusivamente el campo solicitado en document.xml;
exportar preserva el DOCX. Todas las descargas HTTP coinciden con sus hashes.
DOCX r4: `59ada4bfd80e397cd5cb20e9acc2ee8260484391397e589ed3db92ab9af91a97`.
PDF r7: `1e3e89a8125c43832934f56debcad94d517e5a7ddc4c3daa33f6213161e02076`.
[Archivos, renders, eventos y revisión ligada al hash](../../../evals/reports/task51-word-pdf-20261008/document-runs/audit.json).

Un fallo real del conversor en E2B (PATH sin LibreOffice, inyectado solo por el
harness) conserva el DOCX como borrador no descargable. La segunda llamada nativa
repite la conversión con el conversor disponible y produce la revisión 2 de la tabla
larga, reabierta/renderizada y revisada. Los logs crudos del fallo quedan fuera del
modelo; solo recibe `document_not_verified`. No se recupera una verificación de un
candidato anterior si el último falla. Caducidad, cancelación, revocación, identidad
o hash incorrectos bloquean nuevos pasos/revisión/publicación.

Se corrigieron dos fallos detectados en los ensayos iniciales: contrato interno de
`review-status`/`local-fields` y rechazo de `/OpenAction` pasivo de zoom de Writer.
Se admite únicamente el destino `/XYZ`; acciones y contenido activo se rechazan.
Los logs iniciales se conservan, no se cuentan como ejecuciones correctas.

### Comandos y resultados

Todos los comandos siguientes se ejecutaron con prefijo `rtk`; los scripts de
infraestructura verifican hostname y usan exclusivamente la VM/laboratorio sintéticos.

- `rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_probe/verify_sdk.py --output evals/reports/task51-word-pdf-20261008/recheck48`: 15 pruebas SDK reales con modelo y transporte E2B simulados; el backend real se prueba aparte.
- `rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_probe/test_governed_adapter.py` y `ops/agent_chat/test_runtime.py`: adaptador y pool/runtime. El intento conjunto con `-m unittest` falló por el import local `test_probe`; ejecutar los scripts resuelve la ruta sin cambiar código.
- `rtk proxy python ops/agent_chat/fetch_branddocs.py`, `document_eval_bundle.py`, y `ops/agent_probe/vm/remote.py ops/agent_chat/evaluate_documents.sh --log ...`: evaluación estricta rechazada, fallback documentado.
- `rtk proxy python ops/agent_chat/bundle.py`; `remote.py ops/agent_chat/prepare_vm.sh`, `start_lab.sh`, `refresh_lab.sh --log ...`: imagen local, plantilla E2B y ASGI/ejecutor separados.
- `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_documents front.test_agent_chat front.test_agent_inference front.test_agent_state --settings=regulai.agent_chat_test_settings --noinput`: **40 OK** en PostgreSQL aislado; 47,721 s de pruebas. Incluye malformed/relaciones externas, preservación, autoridad visual, cancelación/caducidad/revocación y borradores.
- `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_documents.DocumentMigrationTests --settings=regulai.agent_chat_test_settings --noinput`: **1 OK** adicional con un XLSX existente; ida/vuelta 0037↔0038 conserva bytes, recibo y formato.
- Regresiones de pipeline, privacidad, conexiones, routing, estado, presupuestos, conectores y frontend: **196 OK**; comando completo en [registro](../../../evals/reports/task51-word-pdf-20261008/regression-governance.result.json).
- `remote.py ops/agent_chat/refresh_executor.sh --log ...`: **sockets reales OK**, controles positivos IPv4/IPv6 antes/después y negativos desde ejecutor/E2B; sin acceso a receptor externo, PostgreSQL ni metadatos. [Evidencia](../../../evals/reports/task51-word-pdf-20261008/document-network.log).
- `remote.py ops/agent_chat/run_document_regressions.sh --log ...`: **14 comprobaciones HTTP reales OK**: tres entradas, duplicados, SSE/reconexión, edición, stale 409, cancelación, revocación, otro usuario, muerte/reinicio sin replay. Se usa otra carpeta para preservar el marcador/evidencia de 50.
- `remote.py ops/agent_chat/collect_document_audit.sh --log ...`; `collect_documents.py document-runs`: **5 descargas DOCX/PDF** iguales a su hash, **3 borradores inaccesibles**, stale 409 y acceso cruzado rechazado. Marcadores originales y renders ausentes de las solicitudes al modelo. [HTTP](../../../evals/reports/task51-word-pdf-20261008/document-runs/http.json).

### Límites

Plantilla corporativa incluida, tres secciones, tabla acotada y edición de título o
resumen; no editor Word general, comentarios/control de cambios, OCR, formularios,
PDF/A ni redacción de PDF. Entrada CSV/XLSX del contrato de 50; máximo 40 páginas y
20 MB por paquete documental. La revisión visual cualitativa requiere el visor
autenticado; no se envían originales/renders a visión remota ni se sustituye por
un chequeo de PNG. La concesión se renueva mientras se revisa, con máximo de una hora.

Modelo simulado, SDK y backend reales; esto acredita el procedimiento y sus fronteras,
no calidad generativa con un modelo real ni paridad con Claude. Siguen vigentes los
límites de 48–50 (incluido NoNewPrivs=0 dentro de Firecracker y operaciones revisadas).
Rama desactivada por defecto, cuentas/conexiones actuales intactas, cero llamadas de
pago o escrituras externas. La tarea 51 queda verificada antes de comenzar la 52.

### Ampliación visual solicitada durante la tarea 52

Después del cierre de 51 en `ff2a947`, el usuario pidió mejorar el formato e
investigar skills públicas. Se consultó `drharunyuksel/docx-report-skill`, MIT,
commit `efbd76eecad7e1aa070a8ca17dffc51a685833d7`: jerarquía tipográfica, paleta
contenida, márgenes y tratamiento de tablas. Se conserva la
[referencia y licencia](../../agent-assets/upstream/docx-report-design/source-manifest.json).
No se ejecutan sus helpers Node ni se instala otro motor. Las reglas originales
compartidas se cargan desde `regulai/front/agents/runtime/design.md`.

La plantilla incluida pasa a la versión 2: título Liberation Serif, cuerpo Sans,
verde oscuro y neutros, filas alternas, total destacado, importes alineados y
espacio interior en celdas. El informe corto ocupa dos páginas (dos secciones),
con notas bajo la tabla; la tabla de 65 filas ocupa cinco. Los resultados de
tres/cuatro páginas anteriores siguen describiendo la versión 1, no esta plantilla.
La plantilla anterior se conserva byte a byte en `corporate-v1.docx`, y una prueba
edita el título de un artefacto anterior sin migrar ni alterar su diseño.

Se reabrieron, renderizaron e inspeccionaron realmente las dos páginas del caso
corto y las cinco del largo; cabeceras repetidas, filas completas, numeración y
total 81,25 € correctos. [Revisión independiente de las siete páginas Word y doce
PPTX](../../../evals/reports/task52-powerpoint-20261008/visual-review-design-v3.md).
En el chat con SDK/E2B reales se creó otro DOCX, se revisaron sus dos páginas y se
exportó a PDF bajo la misma identidad; también se inspeccionaron ambas páginas
del PDF final. Las descargas HTTP coinciden con los bytes verificados:

- DOCX `e80c0d87-0999-4643-a0dc-c50f515656a5`, SHA-256 `b8fdadf185f21ad2fc9da0f1018443d6eb0b37219f800186b318ba13bfa7f772`.
- PDF `147bc595-bc0f-49dc-8344-64527f442945`, SHA-256 `603deda5fca3d8b01476ce3ca027b18e9ccc2183a39fce2822e0ac9fbdfdc85d`.

[Archivos, renders y registro de revisión](../../../evals/reports/task52-powerpoint-20261008/presentation-runs/audit.json).
[UI del PDF rediseñado](../../../evals/reports/task52-powerpoint-20261008/ui-pdf-redesign.jpg).
La batería final conjunta pasa **51 pruebas en PostgreSQL**; las **196 regresiones**
de gobierno/estado/dinero también pasan. Comandos y límites compartidos quedan en
[la tarea 52](52-agente-powerpoint.md). La mejora visual no acredita calidad
generativa de DeepSeek: las respuestas del proveedor siguen simuladas.

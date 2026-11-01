# 52. PowerPoint editable con revisión visual

Estado: implementada y verificada en laboratorio sintético (8 de octubre de 2026). Sin activar cuentas reales.
Blocked by: [51](51-agente-word-pdf.md).
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), candidatos y corpus del [informe documental](../../investigacion-prompts-skills-documentales-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 52. Lee AGENTS.md, la guía de ejecución y la
investigación documental. Parte del mismo recorrido de archivos de 50/51.

Añade PPTX como cuarta skill, sin un segundo agente ni otra UI. Empieza por
OfficeCLI, fijando versión y licencia. Prueba antes de adoptarlo: crear una
presentación breve, modificar una plantilla y cambiar solo una diapositiva.
La comprobación debe inspeccionar el PPTX final y renderizarlo, no solo mirar el
HTML previo a la exportación.

Conserva maestros/diseños cuando haya plantilla. Texto, tablas y gráficos deben
seguir siendo editables donde lo requiera la tarea. No rasterices toda la
presentación para ocultar problemas. Verifica contenido, número de diapositivas,
objetos fuera del lienzo, solapamientos y legibilidad. Vacía los procesos
residentes antes de que el verificador lea y calcule el hash del archivo.

Si OfficeCLI falla un requisito de esos tres casos, compara solo ese caso con
BrandDocs ya disponible o dom-to-pptx, según sea conservación de plantilla o
creación desde HTML. Elige una implementación principal; no dejes tres motores
activos, un selector genérico y una batería combinatoria. Documenta la limitación
real si ninguno cumple, sin prometer compatibilidad completa con PowerPoint.

Adapta la skill al catálogo, fuentes, imagen y rutas de Regulay. Retira instalación
automática y uso no autorizado de imágenes externas. Elige los recursos del
usuario o locales; no hagas nuevas llamadas de pago de imagen o inferencia.

Integra preview de diapositivas, descarga y edición sobre la misma identidad de
artefacto. Prueba que cambiar el título no altere el resto del deck y que una
reparación vuelva a validar la revisión final. Mantén renders reales fuera del
modelo y comprueba la UI. Ejecuta los cuatro casos PPTX del corpus; la variante
con modelo simulado no cuenta como medida de calidad generativa.

Registra motor elegido, resultado de las comprobaciones y limitaciones. No
añadas animación avanzada, colaboración en diapositivas o editor visual salvo
que sean imprescindibles para un caso ya solicitado. Detente antes de la 53.
```

## Aceptación

- Crear, editar y renderizar PPTX dentro del mismo flujo del chat.
- Una implementación elegida, dependencias fijadas y licencia registrada.
- Contenido editable y preservación de la plantilla comprobados para los casos admitidos.
- Cambio localizado sin regresiones en otras diapositivas; reparación seguida de nueva verificación.
- Los cuatro formatos conviven sin ampliar permisos o exponer datos a la vista del modelo.

## Verificación observada

La tarea 51 se cerró y verificó en el commit local `ff2a947` antes de iniciar esta
tarea. PPTX comparte chat, SDK Deep Agents, perfil explícito, autorización,
ejecutor separado, E2B, pool, eventos SSE y registro de artefactos con los otros
tres formatos. Las tres entradas HTTP conservan `send_chat_message`.

### Motor y comparación acotada

Se elige **OfficeCLI 1.0.155**, commit
`8d079c777ed6bea35b922c3d893758d3c2081137`, Apache-2.0. Binario oficial Linux x64
SHA-256 `1a5da5cb7e9d995db7a6560beb7466760c79617648f72e65f4ce55897c407f67`,
contrastado con `SHA256SUMS` y fijado en el `ADD --checksum` de la imagen.
La [referencia fijada](../../agent-assets/upstream/officecli-pptx/source-manifest.json)
conserva la skill, licencia y avisos de terceros. Solo se carga la adaptación de
`regulai/front/agents/runtime/skills/pptx/`; no hay instalación, plugins, proceso
residente, imagen remota ni otro motor PPTX activo.

Antes de integrarlo se ejecutaron los tres casos exigidos: deck nuevo con tabla y
gráfico nativos, plantilla externa sintética con maestro y cambio exclusivo de la
tercera diapositiva. Se renderizó el PPTX final con Impress y Poppler, tras cerrar
OfficeCLI. La primera composición mostró desbordamientos y cambios de metadatos
ajenos a la edición. `view issues` puede devolver código cero con incidencias;
el procedimiento exige además `Found 0 issue(s)`. El adaptador restaura las partes
inmutables del ZIP después de cerrar el CLI; el servidor contrasta su igualdad
byte a byte. La edición localizada comprueba también la estructura de la
diapositiva, enmascarando únicamente el texto solicitado.
[Tres casos y hashes](../../../evals/reports/task52-powerpoint-20261008/officecli-final/result.json).
Los fallos iniciales se conservan en `officecli-first` y no se cuentan como éxito.

OfficeCLI creaba un gráfico nativo con caché, pero sin libro incrustado para editar
los datos. Se comparó **solo ese caso** con BrandDocs
`97a6e384cb0664cd44ba8113c0b80c9761700670`: `doctor`, `extract` y `generate --qa strict`
pasan y producen un gráfico con los valores 1,25/2,50/3,75 en un XLSX incrustado.
Su render se inspeccionó: representa los datos, pero conserva un formato básico
y puntos decimales. [Comparación, comandos y archivo](../../../evals/reports/task52-powerpoint-20261008/chart-comparison/result.json).

Se mantiene OfficeCLI y se completa ese hueco mediante un adaptador OOXML acotado:
añade el libro local, sus relaciones y fórmulas de referencia al gráfico existente.
Openpyxl escribe únicamente ese libro; python-pptx reabre/verifica el archivo y
crea el fixture de plantilla, no es otro generador de presentaciones del runtime.
El servidor contrasta por separado caché del gráfico, libro realmente relacionado,
etiquetas visibles, tabla y total contra los céntimos originales. Rechaza fórmulas
incrustadas incluso si incluyen una caché numérica que coincide con los datos.

### Diseño y corpus final

Tras la petición del usuario de mejorar el formato, se aplicó una familia visual
común con Word/PDF: títulos Liberation Serif, texto/datos Liberation Sans, tinta
verde oscura, fondos claros, acento dorado para la cifra principal, tabla con
importes alineados a la derecha y etiquetas del gráfico en español con unidad €.
Las reglas viven en `runtime/design.md` y se aplican en el procedimiento local;
su ejecución no depende del criterio estético del proveedor del modelo.

| Caso del corpus | Comprobación observada |
| --- | --- |
| Plantilla con maestros | Tres diapositivas; maestro, once diseños, tema y demás partes originales preservados. |
| Presentación nueva | Portada, tabla nativa y gráfico nativo con libro XLSX editable; total 7,50 €. |
| Cambio localizado | Título y cuerpo editados en turnos sucesivos, misma identidad y revisiones inmutables; las demás partes no cambian. |
| Tabla/gráfico y texto largo | Cuerpo largo con tildes, ñ y €, £, $ legible y dentro del lienzo; valores de tabla y gráfico iguales a la fuente. |

Los cuatro casos finales están en [design-v3](../../../evals/reports/task52-powerpoint-20261008/design-v3/).
La [revisión independiente](../../../evals/reports/task52-powerpoint-20261008/visual-review-design-v3.md)
abrió realmente sus doce PNG y las siete páginas de Word/PDF del rediseño:
**19/19 sin cortes, solapamientos o problemas de legibilidad**. Se corrigieron
defectos de una iteración anterior (decimales/unidades, alineación monetaria,
estilo del título Word y resumen sintético incorrecto), conservando su evidencia.
Los archivos finales se reabrieron y verificaron tras esos cambios.

### Recorrido real y autoridad

La UI muestra diapositivas privadas, revisión pendiente, enlace de tamaño completo
y descarga PPTX autenticada. El servidor solo publica después de la verificación
estructural y de una revisión visual registrada por el actor autenticado, ligada
al hash final y todas las páginas. Modelo y ejecutor no pueden autoaprobarla.
Los originales, mapas de alias, salidas crudas y PNG permanecen fuera del modelo.

El chat sintético ejecutó creación, edición de título y edición de cuerpo sobre la
misma identidad `04fa2832-cb92-4009-9015-f302abae3599`, revisiones 1–3. Se inspeccionó
cada una de sus tres diapositivas antes de aceptar. También se ejecutaron la
plantilla corporativa y el texto largo, con revisión de todas sus diapositivas.
[UI de edición y descarga](../../../evals/reports/task52-powerpoint-20261008/ui-pptx-desktop.jpg).

La auditoría final reúne siete ejecuciones completas: cinco revisiones PPTX y el
DOCX/PDF rediseñado. **Siete descargas HTTP** coinciden con sus hashes; un borrador
fallido permanece inaccesible; revisión antigua devuelve 409 y otro usuario no
puede obtener archivos, renders ni aprobarlos. La descarga real del navegador
del primer PPTX coincide también:
`15542a68a4d8d57025070be57d40f4760911f22ef2329eec6bd9903fd17bd3a9`.
[Auditoría](../../../evals/reports/task52-powerpoint-20261008/presentation-runs/audit.json),
[HTTP](../../../evals/reports/task52-powerpoint-20261008/presentation-runs/http.json).
Las **19 páginas/diapositivas de esas siete revisiones** se abrieron realmente en
el navegador; sus bytes coinciden con los hashes del verificador.
[Registro visual del chat](../../../evals/reports/task52-powerpoint-20261008/ui-visual-review.json).
Es otra revisión distinta de los 19 renders del corpus offline.

En el caso corporativo, el harness ocultó las herramientas del PATH durante el
primer render real de E2B. El fallo observado es `officecli` no encontrado al
cerrar/validar, antes de Impress; no se cuenta como un fallo de LibreOffice en PPTX.
El fallo específico de LibreOffice se verificó en DOCX durante la tarea 51.
El PPTX fallido se conservó como borrador, fuera de la descarga.
La segunda llamada autorizada reconstruyó, convirtió, reabrió y verificó la
revisión 2; se revisaron sus tres renders antes de entregarla. La reparación no
reutiliza la aprobación ni el hash del primer candidato. Cancelación, caducidad,
revocación y una revisión de base antigua impiden pasos nuevos o publicación.

### Versiones, comandos y pruebas

Imagen documental comprobada:
`sha256:9cd8c59b006b788d989114beb96e03380013f2500a03d294bfd4d283cbc5d420`.
Python 3.12.11; OfficeCLI 1.0.155; python-pptx 1.0.2; XlsxWriter 3.2.9;
Impress/Writer/Calc `4:25.2.3-2+deb13u8`; Poppler `25.03.0-5+deb13u4`;
Liberation `1:2.1.5-3`. Se conserva Deep Agents 0.6.12 y el resto de pins anteriores.
[Inventario y hashes de plantillas](../../../evals/reports/task52-powerpoint-20261008/presentation-versions.log).

Todos los comandos comienzan con `rtk`. Los scripts remotos comprueban el hostname
del laboratorio y no usan cuentas reales:

- `rtk proxy python ops/agent_chat/pptx_eval_bundle.py`; `rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/evaluate_pptx.sh --log ...`: evaluación previa de tres casos.
- `remote.py ops/agent_chat/compare_pptx_chart.sh --log ...`: comparación acotada con BrandDocs, sin red ni otro motor en producción.
- `remote.py ops/agent_chat/presentation_design_eval.sh --log ...`; `collect_pptx.py design-v3 design-v3`; `check_presentation_fixtures.py`: cuatro casos PPTX finales y dos casos Word, renderizados y contrastados.
- `bundle.py`; `remote.py ops/agent_chat/prepare_vm.sh --log ...`; `refresh_lab.sh`: imagen local y plantilla E2B con ejecutor separado.
- `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_presentations front.test_agent_documents front.test_agent_chat front.test_agent_inference front.test_agent_state --settings=regulai.agent_chat_test_settings --noinput`: **51 OK** tras el último cambio del contrato, 54,764 s de pruebas. [Resultado final](../../../evals/reports/task52-powerpoint-20261008/final-postgresql.result.json). El primer intento de la batería nueva encontró una ruta HTTP incorrecta en el test; se corrigió para usar la entrada por conversación y su respuesta 202. Las ejecuciones posteriores pasan; no se presenta ese fallo del harness como fallo del producto.
- Regresiones de gobierno, privacidad, conexiones, routing, estado y dinero: **196 OK**. Adaptador: **5 OK**. Pool/runtime: **2 OK**. La revalidación SDK de 51 sigue fijada a las mismas dependencias: **15 OK**.
- `remote.py ops/agent_chat/refresh_executor.sh --log ...`: **sockets reales OK** con la imagen ampliada, controles IPv4/IPv6 positivos antes/después y negativos desde ejecutor y E2B hacia receptor, PostgreSQL y metadatos. Sin claves de proveedor, acceso a la BD o módulos de alias en el ejecutor. [Log](../../../evals/reports/task52-powerpoint-20261008/presentation-network.log).
- `remote.py ops/agent_chat/run_presentation_regressions.sh --log ...`: **14 comprobaciones HTTP reales OK**, con tres entradas, duplicados, SSE/reconexión, cambios de título, stale 409, cancelación, revocación, aislamiento entre usuarios y muerte/reinicio sin replay. [Resultado](../../../evals/reports/task52-powerpoint-20261008/http-regression/live-cases.json). El laboratorio devuelve aceptación en 49–111 ms en esta batería; no es un benchmark de producción.
- `remote.py ops/agent_chat/collect_presentation_audit.sh --log ...`; `collect_pptx.py presentation-runs presentation-runs`: siete descargas y privacidad verificadas. Duración de las ejecuciones del chat, incluida la espera de revisión humana: 34–150 s; no se atribuye ese tiempo al modelo o al conversor.

### Límites explícitos

Procedimiento acotado a tres diapositivas, la plantilla incluida o una composición
nueva, 1–6 conceptos y etiquetas de hasta 30 caracteres sin comas/barras inversas.
Título de hasta 70 caracteres; cuerpo hasta 140/65/340 según diapositiva. No es un
editor Office general ni importa plantillas arbitrarias de usuarios. Máximo 20 MB
descomprimidos por paquete. Los límites de texto no sustituyen el render y la
revisión visual obligatorios.

Texto, tabla y gráfico son objetos editables; los datos del gráfico viven en un
libro XLSX incrustado. Las etiquetas directas en español son textos nativos:
editar los valores externamente requiere actualizarlas y volver a verificar el
documento. No se ha probado interacción en PowerPoint de escritorio ni equivalencia
de render entre todas sus versiones. No hay animaciones ni colaboración en slides.

Modelo simulado, SDK y E2B reales: acredita el procedimiento, conservación y
fronteras, **no calidad generativa de DeepSeek ni comparación con Claude**.
Siguen los límites de 48–50, incluido NoNewPrivs=0 dentro de Firecracker y ejecución
de operaciones revisadas. Rama desactivada por defecto y cuentas actuales intactas;
sin llamadas de pago, push, despliegues, publicaciones o escrituras externas.
No se ha iniciado la tarea 53.

### Limpieza

Retirados los contenedores PostgreSQL/web/worker del ensayo, redes y reglas de
firewall propias, túnel de localhost:8500, imágenes de evaluación y descargas
temporales. Eliminados los clones/binarios provisionales y los perfiles de
LibreOffice usados para renderizar. La VM de 48 vuelve a estar apagada, como al
inicio; se conservan su volumen, stack E2B y la imagen/plantilla final revisada
como caché reproducible. No se borró el árbol previo de task50 ni los contenedores
ajenos. Los tres PDF originales del workspace siguen sin modificaciones.
[Estado final](../../../evals/reports/task52-powerpoint-20261008/cleanup-state.json),
[recursos propios retirados](../../../evals/reports/task52-powerpoint-20261008/cleanup-files.json).

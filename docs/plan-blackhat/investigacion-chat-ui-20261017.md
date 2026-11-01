# Chat regulAI: componentes, movimiento y prompt de renovación

Investigación del 17-10-2026. [Tarea 78](tareas/78-investigacion-chat-ui.md).
[Prompt preparado](../../output/chat-ui-research-20261017/prompt.md).
Estado: propuesta sustentada en código y documentación; diseño aún no implementado.

**Recomendación.** Migrar la interfaz del chat a React y TypeScript, compilada
con Vite e integrada en Django. Usar los componentes actuales de shadcn/ui y
sus patrones AI Elements, una única familia Base UI, Motion para movimiento
y Lucide para iconos. Un único componente ChatMarkdown encapsulará la política
de contenido; Streamdown es el renderer preferido si supera la equivalencia
con los marcadores, citas, enlaces y controles existentes. Django conserva
autenticación, permisos, ejecución, archivos, estado autoritativo y dinero.

**Autorización incorporada.** Después del primer reconocimiento, el usuario
aclaró: «Que si hay que migrar a otra cosa de frontend se hace eh». Esto permite
revisar la exclusión histórica de React para el chat. El prompt autoriza y
documenta esa excepción concreta; no exige otra confirmación para ejecutarla.
La investigación permanece separada de la implementación: aún no se ha
migrado ni instalado nada.

La razón para elegir React aquí es reutilizar los componentes originales y
organizar estados/transiciones de una renovación extensa. Es una recomendación
de encaje y mantenimiento, no una afirmación de mayor rendimiento. Añade build,
dependencias y adaptación de pruebas. Mantener vanilla también sería viable,
pero obligaría a portar y mantener los comportamientos de los kits elegidos.

**Lo que aportaría un profesional antes de decorar.** Diseñaría un inventario
de estados reales y sus transiciones: qué sabe el usuario, qué puede hacer y
qué evidencia permite mostrarlo. Trabajaría primero con mensajes, eventos SSE,
errores, adjuntos y archivos reales del contrato, anonimizados o reproducidos
en laboratorio; después con los componentes. Mediría cuánto tarda la interfaz
en representar un evento recibido, si conserva el foco y si el lector pierde
su posición. El número de animaciones no es una medida de calidad.

El material de partida más directo es el DOM actual, los handlers de envío,
los payloads públicos, los tests de recuperación y las capturas existentes.
Las demos de las bibliotecas sirven para estudiar interacción; no acreditan
streaming, seguridad, costes ni calidad de un proveedor en regulAI.

**Lo que muestra el repositorio.** Reconocimiento sobre HEAD compartido
`a16d03984c0a97f400e21093f81eda04a5222c2b` y su árbol de trabajo, que contiene
cambios concurrentes. Se conserva todo ese trabajo. La tarea 77 documenta el
producto local previo; no debe deducirse el producto efectivo sólo de HEAD.

| Evidencia | Consecuencia para el rediseño |
| --- | --- |
| [README, decisiones compartidas](README.md): Django, exclusión histórica de nueva interfaz React. | El usuario ha autorizado revisar esta decisión para el chat. Registrar la excepción durante la implementación; Django y las demás fronteras permanecen. |
| [chat.html](../../regulai/front/templates/chat/chat.html), [chat.js](../../regulai/static/js/chat.js), [agent-chat.js](../../regulai/static/js/agent-chat.js). IIFE y DOM compartido; no build frontend de aplicación. | Separar las responsabilidades de transporte, estado y presentación sólo donde lo requiera el trabajo. Evitar propietarios duplicados del mismo DOM. |
| [test_frontend_resources.py](../../regulai/front/test_frontend_resources.py): recursos locales y hashes. | Dependencias fijadas y servidas localmente, con licencias. No copiar los CDN de las demos. |
| [streaming.py](../../regulai/front/agents/streaming.py): secuencias, recuperación y exclusión de contenido privado. | Renderizar únicamente eventos públicos autorizados; conservar retracciones y reconciliación. |
| [chat.js](../../regulai/static/js/chat.js): un adjunto mediante fetch/FormData. | Estados discretos fiables; no existe progreso de subida en bytes. No introducir multiarchivo sólo porque el kit lo muestre. |
| [artifact-viewer.js](../../regulai/static/js/artifact-viewer.js): permisos, hash/revisión, saneado y sandbox. | Nueva tarjeta y visor conservan esas fronteras. Un clic de descarga no prueba que el archivo se haya guardado. |
| [skills.js](../../regulai/static/js/skills.js) y agent-chat.js: activación contextual y evento skill.activated. | Mantener el diseño discreto de la tarea 77; no recuperar barras ni contadores. |
| [service.py](../../regulai/front/agents/service.py) y [chat_ui.py](../../regulai/front/chat_ui.py): recibos de uso final. | Un eventual desglose de tokens usa cifras autorizadas del servidor. No inferir tokens contando caracteres ni costes desde una librería. |

Las capturas previas del chat a
[360 px](../../output/p1-skills-ux-20261016/auto/live-screenshots/chat-360.png) y
[1440 px](../../output/p1-skills-ux-20261016/auto/live-screenshots/chat-1440.png)
muestran margen para reducir la introducción, las sugerencias y la competencia
entre modo, compositor y foco violeta. Son una referencia visual anterior,
no una nueva comprobación del estado servido ni una maqueta del resultado.

**Bibliotecas contrastadas.**

| Biblioteca | Aportación | Encaje y decisión |
| --- | --- | --- |
| [AI Elements / shadcn/ui](https://ui.shadcn.com/docs/ai-elements) | Patrones de chat compuestos con Message, Message Scroller, Attachment, Input Group y Trace. Código copiado al proyecto. | Elección principal: incorporar componentes React originales y adaptar su presentación a regulAI, conservando el transporte existente. |
| [assistant-ui](https://www.assistant-ui.com/docs/runtimes/custom/external-store) | Componentes React y runtime visual; ExternalStoreRuntime admite estado externo y callbacks de envío/cancelación. | Alternativa si se decide adoptar también su modelo de estado. En regulAI exige un adaptador que conserve IDs, estados y permisos; no instalarlo junto a otro runtime de conversación. |
| [Prompt Kit](https://github.com/ibelick/prompt-kit) | Componentes React copiables para prompt, mensajes, archivos y actividad. | Buena referencia complementaria. Menos estado impuesto, más integración propia. No mezclar su sistema visual completo con el de shadcn AI Elements. |
| [Motion](https://motion.dev/docs/react-accessibility) | Animación para React, con control de movimiento reducido; también tiene API JavaScript. | Usar en entrada/salida y transiciones coordinadas. CSS basta para hover/focus; importar sólo lo necesario y medir su coste. |
| [Lucide](https://lucide.dev/guide/) | Iconos SVG consistentes. | Usar sólo los iconos necesarios como recursos locales; nombres accesibles en los botones. Evitar un catálogo completo en cada página. |
| [Streamdown](https://streamdown.ai/docs/animation) | Renderer React para Markdown progresivo, con animación opcional. | Candidato preferido dentro de ChatMarkdown. Su adopción exige equivalencia de política de contenido y funciones propias; si falla, encapsular el renderer existente. |

[shadcn documenta Vite](https://ui.shadcn.com/docs/installation/vite) y permite
elegir una familia de primitivas. Se propone Base UI para evitar mezclar
variantes de componentes. Tailwind y sus tokens deben quedar aislados al chat,
incluidos los portales, sin aplicar un reset global al resto de Django.

La portada del [antiguo AI Elements](https://elements.ai-sdk.dev/) anuncia su
traslado a shadcn/ui y deprecación a finales de noviembre de 2026. Por eso la
referencia elegida es el destino actual, no el registry antiguo. El código ya
copiado por otros proyectos sigue siendo suyo; esta noticia no demuestra que
los componentes instalados dejen de funcionar.

Licencias consultadas: [shadcn/ui MIT](https://github.com/shadcn-ui/ui/blob/main/LICENSE.md),
[assistant-ui MIT](https://github.com/assistant-ui/assistant-ui/blob/main/LICENSE),
[Prompt Kit MIT](https://github.com/ibelick/prompt-kit/blob/main/LICENCE.md),
[Motion MIT](https://github.com/motiondivision/motion/blob/main/LICENSE.md),
[Lucide ISC, con avisos MIT para iconos derivados de Feather](https://lucide.dev/license).
La alternativa [Streamdown usa Apache-2.0](https://github.com/vercel/streamdown/blob/main/LICENSE).
El [AI Elements antiguo usa Apache-2.0](https://github.com/vercel/ai-elements/blob/main/LICENSE).
Conservar los avisos de cada recurso y verificar dependencias transitivas al
instalar. Motion+ y sus recursos comerciales no forman parte de la propuesta.
Esta investigación no instala ni fija versiones nuevas; hacerlo requiere
resolver y probar versiones exactas en el entorno de implementación.

**Piezas concretas que tomar como referencia.**

- [Prompt Input](https://ui.shadcn.com/docs/ai-elements/base/prompt-input): una
  superficie de escritura con adjunto y envío; adaptar teclado e IME existentes.
- [Chat](https://ui.shadcn.com/docs/ai-elements/base/chat): conversación y scroll
  que siguen la respuesta mientras el usuario permanece al final.
- [Attachment](https://ui.shadcn.com/docs/components/base/attachment): adjunto
  compacto con nombre, estado y acción contextual.
- [Trace](https://ui.shadcn.com/docs/components/base/trace): actividad plegable
  con fases de forma consistente. En regulAI representará herramientas y pasos
  públicos; no pensamiento privado del modelo.
- Archivos generados: composición propia de tarjeta y acciones, conservando
  el visor existente. La tabla de migración de shadcn no ofrece un reemplazo
  directo del antiguo Artifact.

El [Message actual](https://ui.shadcn.com/docs/ai-elements/base/message) no
incluye un renderer Markdown: es presentación. No confundirlo con el antiguo
MessageResponse ni instalar dos pipelines de Markdown. La política de regulAI
debe vivir en un único adaptador comprobable.

**Precauciones surgidas del código, no de una lista genérica.** El
[ResponseStream de Prompt Kit](https://raw.githubusercontent.com/ibelick/prompt-kit/main/components/prompt-kit/response-stream.tsx)
puede animar texto ya completo; ese modo no es streaming de red. Su
[FileUpload](https://raw.githubusercontent.com/ibelick/prompt-kit/main/components/prompt-kit/file-upload.tsx)
escucha drop global y el handler observado no aplica disabled/accept como lo
hace el input. Copiarlo exigiría adaptar ese recorrido y mantener validación
del servidor. No son evaluaciones de todo el proyecto ni versiones instaladas.

[Streamdown documenta imágenes externas permitidas por defecto](https://streamdown.ai/docs/security).
Si se adoptara, habría que conservar el saneado, desactivar HTML crudo y aplicar
la política de imágenes/URLs existente, además de probar que el navegador no
realiza solicitudes no autorizadas. Cambiar rehypePlugins reemplaza su lista
predeterminada; no se puede eliminar accidentalmente el saneado.

**Diseño propuesto: cada gesto corresponde a un hecho.**

| Momento | Interacción propuesta | Evidencia necesaria |
| --- | --- | --- |
| Abrir el chat | Una invitación corta y compositor como foco principal; menú secundario para opciones. | Funciones principales descubribles sin párrafos de instrucciones. |
| Escribir/enviar | Altura estable, foco visible discreto, botón enviar que pasa a detener al aceptar el envío. | Un único envío; borrador preservado ante error; IME no envía por accidente. |
| Recibir texto | Aparición suave de fragmentos nuevos; bloques previos estables. | Deltas autorizados, sin máquina de escribir artificial ni animación del historial. |
| Leer mensajes anteriores | Se detiene el seguimiento; aparece un botón pequeño para volver a lo nuevo. | Posición y selección conservadas durante streaming y recuperación. |
| Adjuntar | Dragover sólo en la zona de chat; chip que transita de seleccionado a enviando y recibido/error. | Sin porcentaje mientras no exista telemetría real de bytes. Cancelar no equivale a revertir un envío ya aceptado. |
| Activar skill | Aviso breve junto al turno y detalle accesible posteriormente. `/` sigue disponible. | skill.activated auténtico, deduplicado; sin clasificador extra ni contador global. |
| Usar herramientas | Una línea de actividad actual con detalle al desplegar. | Eventos públicos; duraciones sólo si hay marcas temporales. Esperar datos no se etiqueta como razonar. |
| Entregar archivo | Tarjeta compacta con nombre/tipo y vista previa/descarga. Metadatos al abrir detalles. | Sólo archivos y revisiones autorizados; descargar no muestra un éxito de guardado que el navegador no conoce. |
| Copiar o recuperarse | Confirmación breve en el propio botón; error corto con acción pertinente. | Clipboard confirmado; reintentos respetan la identidad de petición y las reglas existentes. |
| Consultar uso | Resumen final bajo demanda. | Uso/coste del servidor; desconocido no es cero y consumo histórico no es ocupación de contexto. |

Dirección visual: neutros cálidos o grises, texto grafito, acento actual moderado,
bordes suaves y tipografía local bien jerarquizada. Mensajes con espacio para
leer; no convertir cada fragmento en una tarjeta. Transiciones orientativas de
120–200 ms, desplazamientos pequeños y opacidad. Estas duraciones son una
decisión de diseño que debe probarse, no un estándar demostrado. Movimiento
reducido elimina desplazamientos y animaciones decorativas; nunca el estado.

**Método y prueba de que funciona.** Inventario de estados y componentes;
prototipo vertical de compositor→respuesta→actividad→archivo; pruebas de
contratos y recorridos; captura y vídeo antes/después con Playwright; perfil
de navegador y revisión independiente. Abrir documentación actual de las
herramientas antes de ejecutarlas. Un ensayo de tareas con personas que no
conocen la implementación permitiría validar comprensión y elegancia; aún no
se ha realizado y no se sustituye por la opinión del autor.

La aceptación técnica debe comprobar tres entradas HTTP y el transporte HTTP
del proveedor simulado, además de persistencia, permisos y dinero. En UI:
360/768/1440 px, teclado/IME, lector de pantalla para estados, movimiento
reducido, respuesta larga, Markdown incompleto, desconexión, revocación,
cancelación y retorno al historial. Capturas de fixtures deben etiquetarse.

Medir antes/después bytes JS/CSS, tareas largas y tiempo evento recibido→DOM
actualizado en escenarios reproducibles. Reportar entorno, corpus y muestras;
estos datos describen coste del frontend, no latencia ni calidad del proveedor.
No se prometen cifras de mejora sin ejecutar esa comparación.

**Integración propuesta y puntos que pueden romperse.** [React documenta
montaje en páginas existentes](https://react.dev/learn/add-react-to-an-existing-project)
y [Vite permite integrar un backend mediante manifiesto](https://vite.dev/guide/backend-integration).
La isla abarca la experiencia del chat y sus menús/visor; Django sigue sirviendo
el documento, autenticación, CSRF y endpoints. No requiere Next.js, AI SDK,
Gateway, Cloud ni un runtime nuevo de inferencia.

1. Los IIFE actuales arrancan al encontrar sus IDs. Sustituir los montajes de
   chat.js, agent-chat.js y skills.js para el DOM migrado. Un solo bootstrap,
   un solo propietario y cleanup idempotente de SSE/fetch/listeners, también
   al desmontar/remontar o bajo StrictMode. Extraer transporte/estado a módulos
   sin autoarranque; no superponer useChat a los envíos actuales.
2. El estado inicial está repartido entre chat/_turn.html y agent-runs
   json_script. Definir un bootstrap JSON público y allowlisted que conserve
   consentimiento, IDs, proveedor/modelo fijados, historial y evidencias. No
   serializar modelos ORM enteros ni reconstruir estado leyendo HTML de React.
3. Los estilos globales vienen de base.html y chat.css también viste la
   biblioteca de skills. Aislar reset, tokens, utilidades y destino de portales;
   no dejar diálogos sin estilo/foco ni borrar estilos de páginas no migradas.
4. Añadir versiones de Node/package manager, lockfile, build reproducible y
   manifiesto JS/CSS/chunks a CI y empaquetado. Verificar el artefacto servido
   por staticfiles sin dev server. Las pruebas actuales que sólo ejecutan los
   IIFE antiguos no acreditan el bundle React: adaptar el navegador de pruebas
   para ejecutar el producto nuevo y mantener las regresiones HTTP/estado/dinero.
5. ChatMarkdown debe conservar [[REGULAI_*]], citas por request/claim, copia,
   URLs y retracciones. Probar desaparición de contenido revocado de DOM,
   portapapeles disponible y acciones, además de cero peticiones externas al
   renderizar. Si Streamdown falla un requisito, mantener el renderer seguro
   encapsulado con propiedad DOM bien delimitada hasta resolverlo.
6. Las skills conservan Auto=false persistente, catálogo diferido sin GET al
   abrir chat vacío, slash literal/caret/IME/Escape, borrador y selección
   pendiente al volver de la biblioteca. Un default React no debe resetear
   preferencias ni introducir llamadas extra.

Estos puntos proceden de la revisión independiente del código local y de
[integración Vite](https://vite.dev/guide/backend-integration) y
[portales Base UI](https://base-ui.com/react/overview/quick-start). El prompt
pide probarlos antes de retirar el recorrido anterior. Ninguna de estas
comprobaciones de migración está todavía ejecutada.

**Verificación realizada en esta investigación.** Dos reconocimientos
independientes, fuentes oficiales y código público de componentes, lectura de
contratos locales y capturas previas. El sitio de Prompt Kit devolvió 403 al
revisor; su repositorio oficial permitió contrastar documentación y código.
No se ejecutaron nuevos tests de producto, benchmarks, instalaciones ni
llamadas de pago. El prompt siguiente pide esas verificaciones para la futura
implementación y conserva los límites actuales.

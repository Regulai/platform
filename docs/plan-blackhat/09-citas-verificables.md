# 09. Respuestas documentales con citas que se puedan comprobar

**Estado:** evidencias implementadas y probadas localmente; juicio real pendiente. **Prioridad:** P1. **Depende de:** [04](04-documentos-y-respuestas-completos.md) y [07](07-verificacion-y-escalado.md). **Resultado:** una afirmación importante de una respuesta documental lleva a un fragmento real, con localización y respaldo comprobado.

## Evidencia de implementación — 2 de octubre de 2026

`front.test_verification`; `front.test_chat_ui`; `front.test_pipeline`. IDs vinculados al documento, citas literales y localización validadas, evidencias solo del propietario y empresa actual. En navegador se abrió con clic la cita de la línea 2 que respalda los 10 euros del contrato y se comprobó persistencia al recargar; [captura](../../evals/reports/ui-2026-10-02/document-evidence.jpg). Confirmar el multipart conservó el archivo original y devolvió la misma evidencia, con un turno de usuario y uno de asistente. Una cita literal no demuestra por sí sola respaldo semántico. El acceso Jev ya funciona y el [ensayo real del juez](../../evals/reports/real-jev-verification-2026-10-02-01/report.json) aceptó una afirmación de 17 días y rechazó otra de 30 días contra la misma fuente de 17 días. Es una prueba de componente con respuestas redactadas previamente; el flujo completo en vivo quedó detenido por clasificación ambigua. Ese día quedó pendiente teclado por la herramienta; el 3 de octubre citas y evidencia se abrieron con Enter en Django offline, con [capturas](../../evals/reports/ui-community-fixes-20261003/README.md).

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Alcance pequeño

Empezar por preguntas y resúmenes sobre el documento adjunto de ese turno. No requiere RAG, embeddings ni un almacén vectorial. Tampoco se pretende demostrar cualquier afirmación de conocimiento general de un modelo.

Los fragmentos ya proceden del extractor del plan 04. Ejemplos de localizador: página 3 de PDF, párrafo 12 de DOCX o hoja “Ventas”, celda B7 de XLSX. Un formato sin páginas no recibe números de página inventados.

## Implementación

1. **Identificar las fuentes en servidor.** Asignar un ID determinista a cada fragmento de esta petición, ligado al digest del documento, localización y versión de extracción. No aceptar una URL, ruta o identificador de otra conversación como evidencia solo porque lo haya emitido el modelo.
2. **Pedir un resultado acotado.** Para el modo documental, estructurar afirmaciones y referencias a IDs disponibles. Usar salida estructurada nativa cuando esté probada para ese modelo; en los demás, JSON validado con las dependencias existentes. Un fallo de formato es fallo de respuesta, no una cadena a ejecutar ni a reparar con sustituciones arbitrarias.
3. **Comprobar existencia y literalidad.** El servidor resuelve IDs y localizadores y obtiene los extractos de la fuente. Si el generador propone una cita literal, verificar que exista con normalización documentada y conservadora. Una coincidencia de palabras no prueba que respalde la afirmación.
4. **Comprobar relación con la afirmación.** Integrar en el juicio de 07 una pregunta por afirmación relevante: respaldo, contradicción o evidencia insuficiente. No enviar documentos enteros de nuevo si basta el fragmento autorizado, pero no recortar de forma que cambie el sentido. Las citas inválidas o no sustentadas hacen fallar la verificación obligatoria y consumen el mismo único escalado, no otro bucle.
5. **Entregar evidencia legible.** Marcadores en la respuesta y un desplegable con localizador y extracto. En API, devolver referencias estructuradas. El servidor genera el texto y enlace de la evidencia; la UI no interpreta HTML ni enlaces externos del modelo como fuentes confiables.
6. **Conservar lo mínimo.** Ampliar `Response` con un JSON de evidencias validadas: versión, IDs, localizadores y extractos mínimos autorizados para mostrar al propietario. Sin persistir otro documento completo. Aplicar a estos extractos los mismos permisos, retención y borrado que a la conversación. La ficha de 08 solo referencia IDs, no copia extractos.

Si se necesita comprobar de nuevo una cita tras borrar el original, pedir que se vuelva a adjuntar y comparar su digest. Una evidencia histórica capturada no equivale a disponer todavía del documento original. Un resumen basado en una selección debe indicar ese alcance.

## Aceptación y pruebas

- [x] Cada ID de cita corresponde a una fuente de la petición actual.
- [x] Una página o un extracto inventados invalidan la respuesta documental.
- [x] Un texto literal real que no respalda la afirmación no basta para aprobarla.
- [x] No encontrar la respuesta en las fuentes produce abstención, no una cita decorativa.
- [x] Referencias con instrucciones, rutas externas o HTML se rechazan o muestran como texto inocuo.
- [x] Citas de otra empresa o conversación no pueden resolverse.
- [x] API y web devuelven las mismas referencias; la evidencia se abrió con clic y persistió tras recargar.
- [x] Evidencias y citas abiertas con Enter en navegador Django offline el 3 de octubre; no acredita ensayo humano.

Tests deterministas para resolución, permisos y formato; conjunto humano de afirmación/fuente para medir la verificación semántica. No usar exclusivamente el mismo juez como referencia de su propia calidad.

## Entrega y recuperación

Migración aditiva nullable para evidencias; las respuestas anteriores muestran “sin citas verificadas”. Activar el modo documental solo en familias y modelos evaluados. Si la verificación falla, volver a una respuesta explicativa de evidencia insuficiente; no etiquetar una respuesta sin comprobar como respaldada.

Documentar el formato de referencias, los localizadores admitidos y qué significa “respaldada por el documento”. La mejora de demo es inmediata: abrir la cita y mostrar la fuente real, incluida una cita falsa rechazada por el sistema.

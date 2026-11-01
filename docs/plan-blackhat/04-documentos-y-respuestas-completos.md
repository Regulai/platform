# 04. Saber qué se ha leído y cuándo una respuesta quedó cortada

**Estado:** implementado para formatos acotados, probado localmente. **Prioridad:** P0. **Depende de:** [03](03-flujo-unico-web-api.md). **Resultado:** el usuario distingue un documento analizado, uno parcialmente legible y uno que no pudo analizarse; una respuesta cortada no aparece como completa.

## Evidencia de implementación — 2 de octubre de 2026

front.test_documents; front.test_pipeline. TXT/MD/JSON/PY/JS, CSV, PDF textual, DOCX y XLSX. Límites de bytes, expansión, unidades, texto y proceso; sin recorte silencioso. Imágenes y XLS no admitidos; no hay OCR.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Actualización de cobertura — 3 de octubre de 2026

Cuatro estados y consentimiento complete_text_only, codificaciones adicionales, cachés de fórmulas, cambios aceptados y límites del juez integrados: [contrato y límites actuales](informe-correcciones-community.md#cobertura-y-límites-efectivos). Los controles sintéticos no cierran el requisito de ejemplos guardados con Word, Excel y LibreOffice reales: todavía no aportados. La especificación histórica siguiente no equivale a validación con esas aplicaciones.

## Problema concreto

El envío web incluye `file_content_text[:10000]` en el contexto del generador, aunque YARA recibe el texto extraído completo. Algunos errores de extracción se convierten en texto y la conversación puede continuar. Los conectores devuelven `finish_reason`, pero las vistas usan un límite fijo de 1.000 tokens sin interpretar ese final.

“No encontrado en la parte leída” no permite concluir “no existe en el documento”. Esta diferencia afecta tanto a seguridad como a calidad.

## Implementación

1. **Unificar validación y extracción.** Reutilizar [file_security.py](../../regulai/front/file_security.py) para límites de subida, tipo y nombre; integrarlo expresamente en cada entrada. Extraer la lectura de archivos de las vistas a `front/documents.py`. Resultado concreto: texto, fragmentos con localización, hash, formato, estado actual `complete/complete_text_only/partial/unreadable`, unidades leídas y avisos.
2. **Definir formatos honestamente.** Empezar por texto, PDF con texto extraíble, DOCX, CSV y XLSX con pruebas reales. `.xls` no es equivalente a `.xlsx`: rechazarlo mientras no exista lector compatible. Un PDF escaneado, una página sin texto o OCR no disponible produce cobertura desconocida/parcial; no un documento vacío aprobado. Jev no recibirá imágenes directamente.
3. **Acotar trabajo y recursos.** Límites de bytes, páginas, filas, expansión de archivos comprimidos y longitud extraída antes de generar grandes estructuras. Los parsers que necesiten un límite duro de tiempo se ejecutan en un proceso local terminable; un timeout de un hilo no detiene su trabajo. No ejecutar macros, fórmulas ni referencias externas. Mantener fuera del alcance los formatos que no puedan procesarse con esos límites.
4. **Preparar contexto sin recortes invisibles.** Evaluar seguridad sobre todo el contenido procesable. Para la primera edición, si no cabe el documento completo en el modelo admitido, pedir uno menor o una selección explícita. No enviar el primer tramo bajo la etiqueta de documento completo. Una selección para responder no reduce automáticamente el material que debe comprobarse para autorizar una salida.
5. **Interpretar el final del proveedor.** Normalizar `finish_reason` / `stop_reason` en `complete`, `truncated`, `refused` o `unknown`. `length` y `max_tokens` indican corte; finales de herramientas no soportadas no son éxito. Ajustar el presupuesto de salida según tarea, modelo y presupuesto de petición. Sin bucle automático de “continúa”.
6. **Mostrar el resultado.** “Texto extraído de 8 de 10 páginas; faltan 2” y “Respuesta interrumpida por límite de salida”. Si la revisión de seguridad exige todo el documento, detener antes de cualquier servicio externo. No ofrecer un botón genérico que ignore el fallo.

Una extracción marcada completa solo significa que se procesaron las unidades admitidas sin incidencias conocidas. No certifica que un parser haya recuperado toda la información visual de un PDF. Documentar esa limitación y excluir de la demo documental formatos mixtos sin cobertura fiable.

En imágenes, OCR y comprensión visual son cosas distintas. Si la política exige revisar todo el contenido y solo se ha extraído texto, detener la salida de la imagen. Mantener conversación con visión únicamente bajo una política que autorice expresamente ese tratamiento y muestre su cobertura; nunca declarar una revisión visual completa realizada por Jev.

## Presupuesto de contexto

Contabilizar instrucciones de sistema, historial elegible, pregunta, documento, preguntas del juez y reserva de salida. `EngineModel.max_tokens` no debe confundirse con la ventana de contexto; el plan 06 añade ese dato separado. Usar el contador oficial del proveedor cuando exista; si se emplea estimación, guardar su carácter estimado y margen conservador. Un error de contexto del proveedor se maneja explícitamente, sin recortar datos en secreto.

## Aceptación y pruebas

- [x] Una evidencia después del carácter 10.000 se analiza o causa un límite explícito, nunca una falsa lectura completa.
- [x] PDF parcialmente escaneado, corrupto o cifrado: no se etiqueta como totalmente revisado.
- [x] Archivo con extensión falsa, expansión excesiva o formato `.xls`: rechazo controlado.
- [x] Los fragmentos conservan página, párrafo o celda sin mezclar documentos.
- [x] Un final por longitud se muestra como incompleto y no pasa la verificación del plan 07.
- [x] La misma extracción y cobertura se observan en web y API.

Usar archivos pequeños sintéticos, incluyendo un caso real de cada formato anunciado. No basta con simular que el extractor devuelve `complete`.

## Entrega y recuperación

La extracción trabaja en memoria o temporal acotado, eliminado también en errores. No añade almacenamiento permanente de documentos. La cobertura se incorpora a `Prompt.decision`. Si un formato da problemas, deshabilitar ese formato conservando la explicación; no volver al recorte silencioso.

Documentar la tabla de formatos, límites y significado de cobertura. [El catálogo de Jev](https://docs.typesafe.ai/models) confirma que su entrada es textual y que tiene límites propios; deben validarse aparte de los del generador.

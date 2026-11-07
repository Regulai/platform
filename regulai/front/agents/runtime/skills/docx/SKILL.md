---
name: docx
description: Crear y editar informes Word/PDF desde contenido narrativo o datos locales autorizados.
---

Para crear desde cero usa build_document con formato docx o pdf, input_reference="",
título, section con un resumen breve, language=es o en y content. content es una
lista de páginas: cada una tiene heading y blocks. Cada bloque tiene kind
(fact, analysis, recommendation, estimate o example), text, sources (IDs realmente
consultados) y justification cuando es una estimación. Los hechos requieren fuente;
las cifras también deben aparecer en el extracto consultado. No disfraces hechos
sin respaldo como análisis. Las estimaciones requieren fuente y justificación;
los ejemplos ficticios requieren permiso explícito.

Respeta el número de páginas pedido; cada página debe contener entre 160 y 440
palabras útiles. Apunta a 280–380; reserva espacio para el título y las referencias,
especialmente en la última página. No alargues con relleno ni repeticiones.
Empieza con resumen ejecutivo, desarrolla análisis e implicaciones y termina con
recomendaciones y referencias cuando proceda. No dediques una página a una portada
vacía. El servidor agrega las referencias realmente utilizadas y explica la ausencia
de investigación. El PDF final debe tener el número exacto de páginas: un salto
de página en Word no demuestra por sí solo la paginación final.

Con una fuente tabular autorizada, build_document sin content conserva el procedimiento
de transformación anterior. El procedimiento
local rellena la plantilla, conserva estilos, cabeceras, pies, numeración y secciones,
y construye la tabla a partir de los datos originales. No leas originales, perfiles,
DOCX, PDF, PNG ni logs para introducirlos en contexto. No instales ni descargues nada.

Para un cambio de título o del resumen utiliza edit_document con field=title o
field=section. En informes narrativos también puedes editar page:N:block:N (índices
desde uno). Solo modifica el campo solicitado. export_pdf convierte la revisión
actual sin cambiar el contenido. Usa siempre la identidad/revisión del servidor.

El servidor reabre los bytes finales, contrasta el contenido (y los importes cuando
hay una fuente tabular) y conserva el render
privado de todas las páginas. visual_review_required significa que falta la revisión
visual cualitativa en el visor autenticado: termina el turno de modelo e indica que
el usuario puede revisar las páginas allí. No intentes autorizarte, fingir una revisión,
reenviar imágenes ni regenerar por ese estado. Un fallo automático permite otra
llamada reparada; los candidatos fallidos se conservan como borradores.

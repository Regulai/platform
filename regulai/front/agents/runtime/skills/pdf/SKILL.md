---
name: pdf
description: PDF de informe con reapertura y revisión de todas las páginas finales.
---

Adaptado de OpenAI, skills/.curated/pdf/SKILL.md, revisión
49f948faa9258a0c61caceaf225e179651397431, Apache-2.0. Véanse LICENSE.txt y NOTICE.md.

1. Usa export_pdf para convertir un DOCX autorizado o build_document para un informe
   nuevo. LibreOffice Writer y Poppler están preinstalados; no ejecutes instalaciones.
2. Cierra el conversor antes de reabrir y renderizar el PDF final. Renderiza todas las
   páginas. Comprueba texto esperado, fuentes incrustadas, símbolos, páginas y tablas.
3. Revisa alineación, espaciado, legibilidad, cortes, solapamientos, cabecera/pie y
   restos de plantilla en el visor privado. Las comprobaciones estructurales y la
   mera existencia de PNG no equivalen a revisión visual cualitativa.
4. Cada reparación crea otro candidato y repite conversión, reapertura y render.
   El servidor vincula las verificaciones y la revisión visual al hash entregado.
5. Solo entrega revisiones verificadas. Mantén los fallos como borradores. Para
   visual_review_required termina el turno del modelo: la revisión ocurre en el
   visor autenticado y el ejecutor espera con su concesión vigente.

Los originales y renders privados no son entradas de visión del modelo. Las vistas
permitidas pasan por la puerta única de resultados y el gobierno de Regulay. No
hay OCR, formularios, eliminación de información, PDF/A ni edición general de PDF
en este procedimiento acotado. No prometas esas capacidades.

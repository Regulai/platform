# Evidencia de la mejora documental · 13 de octubre de 2026

Resultados finales en `report/final.docx` y `report/final.pdf`: el mismo informe
con cinco páginas PDF comprobadas. `report-edit` y `report-edit2` contienen dos
cambios sucesivos de título. `deck` y `deck-edit` contienen tres diapositivas y
la edición de la segunda. Los paquetes `candidate.zip` son fixtures funcionales
de las pruebas y deben conservarse junto a los JSON de contenido y fuentes.

`verification.json` registra seis entregas verificadas por el contrato real, sus
hashes, páginas, comprobaciones y páginas de revisiones idénticas por bytes.
La aprobación visual del producto no se ha falseado: el JSON mantiene
`visual_review: required`. Las aprobaciones de los tests HTTP son simuladas.
La inspección de imágenes realizada durante esta tarea es evidencia separada.

Se inspeccionaron las cinco páginas del informe, las tres diapositivas y las
páginas modificadas. La primera versión del informe tenía demasiado blanco;
se ajustaron tamaño de letra y densidad de contenido útil. La presentación
breve pasó a tipografía de 26 puntos cuando cabe. Los renders finales muestran
jerarquía legible, numeración, márgenes, referencias y límites sin recortes.

Los hechos del fixture proceden de las lecturas públicas NIST guardadas en
`primary-sources.json`. El contenido se escribió para la prueba: no fue generado
por un proveedor real. La investigación real no acredita una revisión semántica
automática de todo el informe.

Pruebas aprobadas: 224 backend/PostgreSQL, 25 interfaz/chat y 6 SDK. Tras endurecer
el control de texto extra en PDF se repitieron las 14 pruebas de informes. Logs
en los archivos `*-tests.log`. Las respuestas de proveedores y Jev se simulan en
la frontera de red; no se simulan los verificadores finales de los nuevos
informes ni su render.

`ui/` conserva capturas e inventario de Chromium real. Sus estados, inferencias,
costes y aprobaciones son simulados. Las capturas de la presentación preceden
al ajuste final de tipografía; `deck/page-*.png` muestra la composición final.
Las descargas de UI se compararon con los archivos existentes durante esa
sesión; sus hashes pueden diferir del ZIP Office recompuesto más tarde. La
prueba final de descargas HTTP usa los paquetes actuales y comprueba su SHA-256.

Reproducción y alcance para la cuenta existente:
[DOCUMENTS.md](../../../ops/agent_chat/DOCUMENTS.md). No se desplegó la mejora ni
se habilitó ninguna cuenta, permiso o proveedor.

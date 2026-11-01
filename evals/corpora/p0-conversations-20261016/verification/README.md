# Comprobación del corpus, sin modelo

El 16 de octubre de 2026 se generaron y reabrieron las ocho fixtures. `builder.py --verify-only` confirma 10 conversaciones, 17 turnos, rutas, hashes, oráculos y formatos. Una segunda generación después de normalizar los identificadores internos de relaciones del XLSX mantuvo idénticos los ocho SHA256 (`changed_on_rebuild: []`).

Se renderizaron e inspeccionaron visualmente las dos hojas y las dos páginas del PDF: contenido legible, sin cortes ni superposición. Poppler avisó de fuentes no usadas en el documento que no estaban disponibles; las páginas renderizadas con Helvetica se ven correctamente. La normalización del ZIP del libro no cambia celdas ni formato, y el libro final vuelve a abrirse con openpyxl.

Resultados numéricos de control: pedido 81,52 EUR; ventas 256,00 EUR; existencias finales A=9, B=4, C=4; reposición B=1; simulación 26 unidades atendidas, 5 perdidas, existencias finales 0; ventas ciertas 275,00 EUR y cobros válidos 270,00 EUR; tras aclaración de O5, ventas 315,00 EUR y pendiente 45,00 EUR.

No se ha ejecutado ninguna conversación, llamado a un modelo, consultado la URL pública ni modificado datos de aplicación. Estos resultados validan la preparación del corpus, no el comportamiento del agente.

Después de confirmar que la entrada acepta un solo `file`, c10 se adaptó a `reconciliation-inputs.zip`. La comprobación focalizada verificó sus dos miembros, CRC, identidad byte a byte con las fuentes, hash estable al regenerar y esquema de 10 conversaciones/17 turnos con máximo un adjunto por turno. El manifiesto final contiene nueve fixtures. Los oráculos se conservaron idénticos; no se repitieron los renders.

# Corpus documental y ensayos del piloto

Fecha: 3 de octubre de 2026. Todos los datos y documentos de esta entrega son
sintéticos. Las expectativas se redactaron antes de ejecutar la extracción y no
proceden de un juez de IA ni de participantes humanos. No se mide calidad de
proveedores reales, precisión OCR, fidelidad visual general ni ahorro económico.

## Corpus y procedencia

[Corpus reproducible](../../evals/documents/pilot-20261003/README.md),
[expectativas](../../evals/documents/pilot-20261003/expectations.json) y
[manifiesto de bytes](../../evals/documents/pilot-20261003/files/manifest.json).

| Caso | Expectativa anterior a la extracción | Límite explícito |
| --- | --- | --- |
| PDF textual | `complete`, preaviso de 17 días en página 2 | Texto sencillo, no fidelidad de diseño |
| PDF con tabla | `complete`, conserva los dos planes y precios 10/25 | No acredita estructura tabular ni aritmética |
| PDF con texto e imagen | `complete_text_only`, declara `images_unread` | El valor 73 de la imagen no forma parte de las fuentes |
| PDF de imagen sin texto | `partial`, `page_without_text` | Escaneo simulado por raster; no escáner ni OCR |
| PDF blanco | `unreadable`, `blank_page` y `empty_document` | No inventar una respuesta sobre página vacía |
| PDF con página blanca intermedia | `complete`, cláusula final en página 3 | La página blanca no es pérdida de texto |
| Word con revisiones | `complete`, vista de cambios aceptados: 17 días | Los 30 días eliminados siguen en el ZIP, fuera de la extracción |
| Word con numeración multinivel | `complete`, 1, 1.1, 1.2, 2 y 2.1 | Numeración decimal controlada, no todos los estilos de Word |
| Word con imagen | `complete_text_only`, consentimiento antes de salir | Texto disponible; imagen omitida con localizador |
| CSV con campo multilínea | `complete`, celdas y salto de línea conservados | Separador y comillas sintéticos conocidos |
| XLSX con fórmula y caché | `complete`, resultado 10 en la fuente | Caché inyectada en OOXML; no recalculada por Excel |
| XLSX sin caché | `partial`, `formula_coverage_unknown` | La fórmula se analiza para seguridad, no se ofrece como resultado |

Se usaron Python, reportlab, python-docx, openpyxl, Pillow y pypdf, con versiones
en el manifiesto. La modificación OOXML de revisiones, numeración y caché es
construcción de fixtures. **Ninguno se presenta como guardado desde Word, Excel
o LibreOffice.** Las comprobaciones de PATH, COM, carpetas de instalación y
registro de desinstalación no encontraron esas aplicaciones. El complemento
de reuniones de Teams para Office no acredita Word o Excel. El renderizador
Word falló explícitamente porque `soffice.exe` no está disponible. Las nueve
páginas PDF sí se renderizaron con Poppler y se inspeccionaron visualmente.

La reproducción inicial descubrió que openpyxl actualizaba la fecha interna
`modified`; el generador fija ese único metadato. La segunda reproducción
coincidió byte a byte en los doce archivos y en su manifiesto. No se ajustaron
las expectativas de extracción. La primera prueba HTTP nueva contenía un
error del test (`responses` en vez de la relación OneToOne `response`),
corregido sin modificar el producto ni las expectativas.

## Ejecución automática y navegador

El [informe con evidencias](../../evals/reports/pilot-documents-20261003-01/README.md)
separa extracción, pruebas HTTP, navegador y pendientes externos. El runner
[pilot_document_demo.py](../../scripts/pilot_document_demo.py) crea una base
**nueva** bajo `.claude`, utiliza los views reales de Django y los transportes
sintéticos de la demo, y mantiene bloqueada la salida HTTP/socket del servidor.
Rechaza reutilizar un directorio existente. No modifica la base habitual ni la
base de demo que ya pudiera existir.

```powershell
rtk proxy .venv/Scripts/python.exe scripts/pilot_document_demo.py --workspace .claude/pilot-document-new-run --port 8766
```

Abrir `http://127.0.0.1:8766/login/` con las credenciales públicas sintéticas
`community-demo` / `community-demo-only`. Cada repetición debe elegir un
directorio nuevo. Terminar el proceso con Ctrl+C al concluir. Conservar la
salida de evidencia necesaria; no mover ni borrar bases ajenas.

## Dos recorridos humanos completos preparados

**Estado de ambos: no realizados.** La automatización del navegador no cuenta
como ensayo humano. No se han contactado participantes. Para realizarlos hacen
falta una persona distinta del operador, su disponibilidad y el registro de
lo que realmente suceda. Usar alias, sin nombres ni datos personales reales.

### Ensayo H1 con acompañamiento

Preparación: operador y participante confirman el banner offline, revisión,
hash del corpus, nueva base y ausencia de claves de producto. El participante
anota qué cree que significan «comprobaciones superadas» y «contenido omitido»
antes de comenzar. Iniciar un cronómetro y registrar la hora.

1. Iniciar sesión, conversación nueva y enviar `Devuelve el saludo Hola.`.
   Abrir la ficha. El participante identifica el destino y distingue coste
   sintético de factura y resultado prefijado de calidad medida.
2. En otra conversación enviar `SYNTHETIC_SECRET_DEMO`. Buscar motivo de bloqueo
   y cero llamadas. El participante explica por qué confirmar no debe permitirlo.
3. Adjuntar `text-and-image.docx` y preguntar `Cual es el precio del contrato?`.
   Antes de confirmar, localizar qué imagen se omitió y que hay cero llamadas.
   Cancelar con teclado y comprobar estado `cancelled`, sin respuesta.
4. Repetir la misma carga en conversación nueva y confirmar. Leer el resultado
   de 10 euros, abrir la cita con Enter, localizar párrafo 2, distinguir primer
   intento rechazado y segundo intento. No interpretar el juez sintético como
   garantía de veracidad.
5. Exportar la ficha JSON, recargar la conversación y volver a abrir ficha y
   evidencia. Contrastar destino, cobertura, avisos y número de generaciones.
6. Adjuntar `formula-uncached.xlsx`, pedir el total y comprobar que la falta de
   caché impide enviar. Recuperarse con `formula-cached.xlsx` y explicar que su
   caché es un fixture; la demo puede pedir aclaración para documentos ajenos
   al guion de 10 euros y no prueba su semántica.
7. Reducir a 375 px o usar dispositivo móvil, abrir ficha y localizar las
   acciones sin desplazamiento horizontal. Registrar ayudas, fallos y tiempo.

Cierre: el participante explica con sus palabras qué salió, qué no se leyó y
qué acredita la cita. El operador anota expresiones literales breves y los
puntos que hubo que aclarar. Completar el formulario H1 sin inferir respuestas.

### Ensayo H2 sin instrucciones durante los pasos

Preparación: otra base nueva y sesión limpia. Entregar solo este objetivo al
participante: «Obtén el precio del contrato disponible, comprueba su fuente y
guarda la decisión. Demuestra también cómo cancelar o rechazar una entrada
que no deba procesarse». El operador observa y registra, sin completar acciones
ni explicar etiquetas hasta finalizar cada paso.

1. Entrar y enviar `Devuelve el saludo Hola.`; identificar la simulación y abrir
   la decisión con teclado. Registrar si se encuentra sin ayuda.
2. Adjuntar `text-and-image.docx`, preguntar el precio y dejar la confirmación
   pendiente más de 300 segundos medidos por reloj. Durante la espera, abrir
   otra pestaña, enviar `SYNTHETIC_CONSENT_CANCEL` y cancelar con teclado.
3. Regresar a la primera pestaña y confirmar la petición caducada. Debe
   renovarse como `pending_consent`, con razón `consent_expired` y cero llamadas;
   conservar el identificador y archivo. Confirmar de nuevo de forma consciente.
4. Abrir la evidencia de 10 euros con Tab y Enter, exportar la ficha, recargar y
   encontrar de nuevo la evidencia. Registrar cualquier pérdida o confusión.
5. En conversación nueva, subir `simulated-scan.pdf`. Explicar el bloqueo por
   falta de texto; no prometer OCR. Mostrar `blank-and-final-clause.pdf` y
   localizar manualmente sus 17 días en página 3 como control de comprensión,
   sin atribuir a la demo una respuesta semántica que no tenga programada.
6. Enviar `SYNTHETIC_SECRET_DEMO`; localizar cero llamadas y motivo. Repetir la
   inspección de ficha en móvil. Recuperarse volviendo al guion offline sin
   cambiar reglas, permisos, claves ni presupuesto.

Cierre: detener cronómetro, recoger respuestas sin sugerirlas y completar H2.
Un bloqueo correcto cuenta como control correcto; no como respuesta generada.

## Criterios y registro

Usar el [formulario de los dos ensayos](../../evals/reports/pilot-documents-20261003-01/human-rehearsal-form.md).
Un ensayo solo se marca realizado si tiene participante, fecha, duración y
observaciones reales. Éxito práctico: puede distinguir simulación/realidad,
omisión/cobertura y comprobación/garantía; encuentra bloqueo, cancelación,
confirmación, cita y exportación; no confunde una respuesta rechazada con una
aceptada. Registrar ayudas y fallos aunque el recorrido termine. Dos ensayos
no son una muestra estadística ni cierran calibración de clasificación o juez.

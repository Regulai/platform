# Corpus sintético documental, 2026-10-03

Doce archivos pequeños con expectativas redactadas antes de ejecutar el extractor.
`expectations.json` define estado, avisos, texto y localizadores; `files/manifest.json`
registra sus hashes, versiones y procedencia por archivo. Ninguno contiene datos
reales ni fue guardado desde Word, Excel o LibreOffice.

El generador usa Python, reportlab, python-docx, openpyxl, Pillow y pypdf. Las
revisiones de Word, numeración y caché XLSX se construyen mediante OOXML. El PDF
«escaneado» es una imagen raster sintética. No se ha medido OCR ni recálculo nativo.

## Reproducir

Ejecutar desde la raíz del repositorio. El Python empaquetado de Codex contiene las
bibliotecas de generación, sin añadirlas a las dependencias del producto. Elegir
un directorio de salida nuevo; el generador rechaza sobrescribir uno existente.

```powershell
rtk proxy C:/Users/javi/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe evals/documents/pilot-20261003/generate_corpus.py --output .claude/pilot-corpus-new
rtk proxy .venv/Scripts/python.exe evals/documents/pilot-20261003/verify_corpus.py --output .claude/pilot-extraction-new.json
```

La segunda orden verifica los archivos versionados usando el extractor público de
Django y escribe un informe nuevo; no abre una base de usuario ni llama a un
proveedor. Para otra máquina, localizar el runtime equivalente y conservar las
versiones del manifiesto. La coincidencia byte a byte se verificó en este entorno,
no se garantiza entre versiones distintas de las bibliotecas.

Resultado observado: 12/12 expectativas satisfechas. Dos generaciones finales
coincidieron en los doce archivos y manifiesto tras fijar el metadato `modified`
que openpyxl actualizaba. Las expectativas no cambiaron para conseguir ese resultado.

[Resultados y límites](../../reports/pilot-documents-20261003-01/README.md).
[Protocolos de dos ensayos humanos todavía pendientes](../../../docs/plan-blackhat/documentos-y-ensayos-piloto.md).

# Procedencia y límites

system.md y documents.md proceden del material original de Regulay preparado en
docs/agent-assets/prompts el 7 de octubre de 2026; esta es su fuente de ejecución.
La skill Excel y spreadsheet_program.py son código/instrucciones originales del
proyecto. No se incorpora texto privado de Claude Desktop/Cowork, ni se carga la
copia de referencia como instrucciones de instalación ni motores alternativos.

El texto no concede permisos. Autorización, alias, gobierno, aislamiento de red,
concesión y verificación se aplican en código. La rama está desactivada por defecto
y limitada a cuentas sintéticas de desarrollo. No acredita calidad de un modelo
real ni un piloto con clientes. No hay paquetes descargados durante una ejecución.

pandas (BSD-3-Clause), openpyxl (MIT) y LibreOffice (MPL-2.0 y componentes con sus
propios avisos) se preinstalan y conservan los avisos/licencias de sus paquetes.
Se mantiene sin cambios el lock del SDK de 48 y el adaptador/gobierno de 49.

La skill PDF se adapta de OpenAI/skills, carpeta skills/.curated/pdf, commit
49f948faa9258a0c61caceaf225e179651397431 (Apache-2.0); licencia en skills/pdf/LICENSE.txt.
Cambios de Regulay: rutas privadas, conversores preinstalados, herramientas acotadas,
prohibición de renders originales en contexto y revisión autenticada ligada al hash.
La copia histórica de docs/agent-assets/upstream conserva la procedencia; solo esta
versión se carga en el runtime. DOCX/programa y plantilla sintética son originales
de Regulay; python-docx (MIT), lxml (BSD-3-Clause), pypdf (BSD-3-Clause), Pillow (MIT-CMU) y
Poppler (GPL-2.0-or-later) conservan licencias/avisos en sus paquetes preinstalados.
BrandDocs se evaluó en el commit del manifiesto y falló la conservación/render
estrictos del fixture; no se incorpora ni activa como motor de producción.

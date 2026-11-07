# 62 — P0 E2/E4: archivos y continuidad selectiva

**Status:** implementación y verificación focalizada completadas; integración conjunta E1–E8 a cargo de la tarea coordinadora.
**Blocked by:** ninguna decisión rutinaria. La aceptación HTTP integrada se registra con el conjunto E1–E8.
**Especificación:** [plan de los ocho P0, E2–E4](../plan-p0-arnes-ia-20261016.md).

## Aceptación implementada

- Catálogo común por familias para formatos existentes y HTML/HTM, CSS, SVG y ZIP. Texto fuente íntegro para política, sin render, ejecución ni lectura remota; SVG sin DTD/entidades. Cobertura parcial explícita para contenido codificado y visual sin OCR.
- ZIP acotado por número, rutas, expansión real, tamaño y relación de compresión; rechaza enlaces/dispositivos, cifrado, corrupción CRC, colisiones Unicode/casefold, archivos anidados y miembros sin cobertura completa.
- Migración aditiva `0042`: nombre cifrado y tamaño nullable, sin descifrar ni reescribir histórico, grants, contenidos, relaciones o estados. Lectores conservan fallback para v1.
- Contrato general v2 distingue charla, creación, edición y descarga; exige archivo aunque no haya extensión explícita. El catálogo aporta alias, y `delivery_problems` contrasta revisiones verificadas.
- Revisiones por identidad lógica de conversación/ruta y bloqueo de conversación. Reutilización por hash, promoción del draft sin duplicar bytes y asociación durable de publicación. Entregables y trabajo privado se separan expresamente.
- Manifiestos cifrados inmutables, vinculados por ID/digest a la revisión para que otra publicación/captura no cambie sus dependencias. Comprobación de referencias locales HTML/CSS/SVG y restauración selectiva de revisiones+hash, revalidando acceso, extracción, política y caducidad. Extracts cifrados para las posteriores comprobaciones de `_context`.
- Captura selectiva de checkpoints: salidas y rutas de operaciones completadas; máximo 32 archivos y 20 MB (o cuota menor), exclusiones del runtime y declaración de captura parcial.
- `recover_agent_file` previsualiza por defecto e importa exclusivamente el miembro indicado con `--apply`, propietario y política actuales; idempotencia independiente del watermark de reanudación, cero inferencias. No se ejecutó sobre datos históricos reales.
- Purga de contenidos, nombres, manifests y extracts heredados al vencer el origen; conserva filas, hashes y enlaces de base, sin renovar retención por copiar a otro turno.
- Tarjetas con nombre, bytes, revisión y cobertura mediante DOM textual. Descargas v2 ligadas a recibos completos/parciales; HTML/SVG sin visor activo. Preparación y generación separadas, duración solo desde intervalos explícitos.

## Verificación observada — 16/10/2026

Entorno `.venv/Scripts/python.exe`, `regulai.test_settings`, datos sintéticos en SQLite efímero, red de proveedor simulada en SDK real. Estas pruebas no acreditan exclusión distribuida; las carreras PostgreSQL pertenecen a la integración conjunta.

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_files --settings=regulai.test_settings --noinput --verbosity=1
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_frontend --settings=regulai.test_settings --noinput --verbosity=1
```

- **14 tests de archivos OK**: intención, lectores, ZIP peligroso/CRC/cifrado, promoción y replay, política en atributos/comentarios, permiso revocado y conversación ajena, restauración de dependencias tras otra captura, vencimiento y purga heredada, importación selectiva idempotente sin inferencias y `MigrationExecutor` 0041→0042 con bytes/hash/FK/grant conservados.
- **23 tests frontend OK**: incluye los dos casos nuevos de tarjeta v2 y duración sin atribuir la espera del proveedor al sandbox. El navegador offline prohíbe inserciones de HTML.
- Dudas concretas posteriores: el replay de publicación compara el digest de archivos/render y rechaza contenido distinto con el mismo call; su test focalizado pasa. La purga conserva `_capacity`, para que borrar texto privado no libere una ocupación incierta del proveedor; test focalizado de retención pasa.
- Comprobación visual real con Chromium instalado y `playwright-cli` existente: temas claro/oscuro, 1280 px y 390 px; estados entregado, parcial con nombre largo, pendiente y texto sin archivos. Se abrió el detalle de comprobaciones. Sin desbordamiento observado; el nombre largo se recorta y los controles siguen accesibles. Sin errores JavaScript; únicamente favicon ausente del fixture estático. Browser y servidor temporal cerrados.
- Capturas locales: `output/playwright/p0-files/light-desktop.png`, `light-mobile.png`, `dark-desktop.png`, `dark-mobile.png`; fixture reproducible `make_preview.py`. Son datos sintéticos y los CSS/JS reales, sin conexión a la instalación.
- Cierre E1: **3 tests focalizados de ventana de historial OK** (`front.test_agent_history_window`): conserva pares completos, adjuntos v2 `text_only` sin bytes/nombre originales y compactación sin prefijo con UUID estable y replay sin otra inferencia ni coste.
- Cierre visual E5: se renderizó el bloque real del composer con `inferenceProfile` y sus tres opciones en Chromium a 390 y 1280 px, claro y oscuro. El texto largo cabe sin desbordar; se seleccionaron las tres opciones. Se corrigió el contraste oscuro del control nativo usando los tokens de texto, fondo y borde de `chat.css`, y se comprobaron de nuevo los cuatro renders. Capturas `output/playwright/p0-files/selector-{light,dark}-{mobile,desktop}.png`, fixture `make_selector_preview.py`. Sin errores ni avisos de consola; browser y servidor temporal cerrados. Es un render sintético de plantilla/CSS reales, no una navegación autenticada ni una inferencia. No se amplió la suite por este ajuste CSS.

## Reversión y límites

Desactivar las nuevas entradas del catálogo o la selección/restauración para nuevas peticiones conserva los bytes y las revisiones existentes. No aplicar una reversión destructiva de datos. La inspección no certifica ejecución segura de scripts, OCR ni recursos dinámicos; recursos externos no se descargan al inspeccionar/restaurar. No se han usado APIs pagadas, datos reales, push ni despliegue.

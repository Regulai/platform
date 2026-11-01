# Agente documental: alcance y prueba local

La creación sin adjuntos interpreta el formato, el idioma y el número de páginas
antes de conceder herramientas. Un informe usa contenido narrativo; Excel con
datos inventados requiere una petición explícita. «Sin datos mockup» no concede
ese permiso. Para datos reales se conserva la entrada tabular `item,amount_cents`
de las tareas anteriores: no se fabrica una tabla cuando falta una fuente.

## Comportamiento implementado

- Word/PDF desde instrucciones, con bloques de hechos, análisis, recomendaciones,
  estimaciones justificadas y ejemplos expresamente pedidos. Los hechos requieren
  identificadores de fuentes consultadas. El servidor incorpora las referencias;
  el modelo no puede aportar URL o títulos de fuentes inventadas.
- Investigación por catálogo de fuentes primarias, permisos de empresa y pasarela
  de Regulay. Configuración y límites en [RESEARCH.md](RESEARCH.md).
- DOCX y PDF coherentes a partir del mismo contenido; se comprueba el texto de
  cada página del PDF final, su número de páginas, fuentes incrustadas, integridad
  del paquete y render. No se publica un Excel para una petición de informe.
- Edición de título o bloque narrativo; preservación de las demás partes OOXML,
  estilos y geometría. Las fuentes y extractos consultados sobreviven a ediciones
  sucesivas. Exportar a PDF conserva exactamente el DOCX de origen.
- Presentaciones narrativas editables y la ruta tabular anterior. Edición de título
  o cuerpo de una diapositiva sin reemplazar el resto. XLSX conserva sus pruebas de
  fórmulas, importes enteros y revisión de título.
- Tarjetas, previsualización, descargas Word/PDF, revisiones, cancelación, menús
  ocultables y detalle de llamadas. Jev muestra sus señales reales y la política
  aplicada; una autorización local no se presenta como respuesta de Jev.
- Cada llamada registra propósito, proveedor, modelo solicitado/efectivo, ruta,
  duración y coste disponible. Las lecturas públicas se distinguen de inferencias.
  La ruta del agente sigue fijada al perfil y no activa fallback automático.

## Probar con la cuenta existente

Esta tarea no ha cambiado cuentas, claves, permisos ni procesos de la instancia
existente. Tampoco ha reconstruido o desplegado sus imágenes. El cambio del
Dockerfile incorpora `narrative_program.py` en la próxima imagen de documentos;
el web y el worker también deben ejecutar este código antes de probar esa ruta.
Actualizar una instalación queda fuera de esta entrega local.

Con esa actualización autorizada hecha, entra con la misma cuenta y abre **Chat →
Agente**. El acceso sigue sujeto a las restricciones de desarrollo existentes:
DEBUG, habilitación del agente y correspondencia explícita de cuenta, empresa y
perfil en `REGULAY_AGENT_DEV_ACCOUNTS`, para cuentas `agent-synthetic-*`. No se ha
ampliado el acceso de cuentas ordinarias. Si la cuenta no está en esa lista, esta
tarea no la ha incorporado ni ha creado una alternativa.

El perfil debe autorizar `build_document`, `edit_document`, `export_pdf` y, para
presentaciones, `build_presentation` y `edit_presentation`. Para fuentes también
se necesita `research_sources`, el indicador de configuración y destinos
`research:<id>` permitidos por la empresa. Las políticas obligatorias siguen
aplicándose; una verificación semántica obligatoria que esta ruta no implementa
bloquea la ejecución.

1. Sin adjunto: «Crea un informe Word y PDF de cinco páginas sobre el impacto de
   la computación cuántica en la ciberseguridad, en español, con fuentes NIST».
2. Revisa las cinco páginas del visor. La aprobación registra exclusivamente la
   revisión visual de esos bytes. Después aparecen ambas descargas.
3. Sobre la revisión actual: «Cambia el título a Programa de transición cuántica».
   Comprueba que el contenido y las referencias permanecen.
4. «Crea un Excel con datos ficticios de ejemplo» debe etiquetarlo como ficticio.
   «Crea un Excel con ventas reales» sin fuente debe explicar qué archivo falta.
5. Abre el detalle de Jev y de llamadas. Una respuesta sin motivos textuales se
   identifica como tal; un coste desconocido no se convierte en cero.

Enviar esas peticiones en una instalación conectada usa su proveedor configurado.
No se ha realizado ninguna de esas llamadas de pago durante esta tarea.

## Verificación reproducible sin gasto de proveedores

Desde la raíz del repositorio, las pruebas funcionales usan PostgreSQL desechable
en `127.0.0.1:55455`, base `regulai_task55`, usuario `lab`, contraseña pública
`synthetic-task55-only`. El contenedor de esta sesión se retira al terminar.
No apuntar `agent_documents_test_settings` a una base existente.

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_reports front.test_agent_chat front.test_agent_mock_excel front.test_agent_documents front.test_agent_presentations front.test_agent_inference front.test_agent_transparency front.test_agent_research front.test_agent_state --settings=regulai.agent_documents_test_settings --noinput
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_frontend front.test_frontend_chat front.test_chat_ui --settings=regulai.test_settings --noinput
rtk proxy ops/agent_probe/.venv/Scripts/python.exe -m unittest discover -s ops/agent_chat -p test_*.py -v
rtk proxy .venv/Scripts/python.exe ops/agent_chat/verify_narrative_check.py
rtk proxy .venv/Scripts/python.exe ops/agent_chat/preview_document_ui.py
```

El último comando abre un servidor de muestra sólo en loopback; no modifica la
cuenta existente. Visita `http://127.0.0.1:8765/chat/?state=completed` y detén el
proceso al terminar. El aviso visible identifica los estados simulados.

`report_fixture.py` prepara contenido de prueba escrito explícitamente para el
ensayo. `render_narrative_check.py` lo compone con Writer/Impress y Poppler reales
en la imagen fijada disponible dentro de la VM local de la tarea 48, con red
deshabilitada. No inicia un web, worker ni nueva microVM E2B. Sus directorios
temporales tienen un identificador único y se eliminan al recuperar resultados.
Los paquetes finales quedan en `evals/reports/task55-agent-documents-20261013`.

## Límites explícitos

La consulta no es un buscador general: el catálogo inicial contiene cuatro
páginas NIST y admite HTML/texto público. Los hechos llevan procedencia y se
comprueban cifras contra el extracto; no existe un verificador semántico completo
de cada afirmación ni de todas las instrucciones. Ambas comprobaciones figuran
como no realizadas, con el alcance parcial explicado. Renderizar tampoco aprueba
automáticamente la calidad visual: sigue requiriendo revisión en el visor.

La composición narrativa admite español/inglés, hasta veinte páginas o
diapositivas, y bloques de texto acotados. No es un editor universal de archivos
Office subidos: la importación de datos continúa limitada al esquema CSV/XLSX
existente. Las ediciones son de campos/bloques concretos. Cambiar un documento
narrativo a una hoja de cálculo no tiene herramienta autorizada. La maquetación
de una salida concreta se valida sobre sus bytes, no por una promesa del prompt.

Los proveedores, Jev, aprobación de pruebas y estados de UI se simularon. Sí se
ejecutaron el gateway/SDK y los verificadores, PostgreSQL aislado, render offline,
consultas públicas de las cuatro fuentes NIST y Chromium real. No se ha medido
la calidad de redacción de un modelo real ni actualizado la instancia existente.

# Diez conversaciones para los P0

Corpus sintético de **10 conversaciones y 17 turnos**. Evalúa respuestas reales; no contiene respuestas de modelo prefijadas ni certifica que las mejoras funcionen. `cases.json` es la entrada del ejecutor. `oracle.json` y las rúbricas son datos del evaluador: **nunca se envían al agente**.

| Caso | Dificultad | Recorrido | Turnos |
| --- | --- | --- | --- |
| c01 | Fácil | Datos del evento, corrección y recuperación del contexto | 3 |
| c02 | Fácil | Aritmética y redondeo explícito | 1 |
| c03 | Media | CSV, devoluciones, archivo resultado y reentrega | 2 |
| c04 | Media | Cruce de dos hojas de un libro por clave | 1 |
| c05 | Media | PDF de dos páginas, citas y datos desconocidos | 1 |
| c06 | Media | HTML autónomo, reentrega y revisión del color | 3 |
| c07 | Compleja | ZIP con dependencias relativas, edición y reentrega | 2 |
| c08 | Media | Consulta real de una página pública fija | 1 |
| c09 | Compleja | Ejecución de simulación determinista de diez días | 1 |
| c10 | Compleja | ZIP con dos fuentes: duplicados, cancelación, contradicción y aclaración posterior | 2 |

Los documentos son pequeños y no contienen PII, credenciales, datos del usuario ni instrucciones ocultas. El PDF incluye expresamente dos datos que no pueden conocerse; el libro requiere leer ambas hojas; la reconciliación contiene errores deliberados. La imagen del ZIP es un SVG local sin código activo. La página web de IANA es una dependencia externa, no se ha descargado al construir el corpus. Un fallo de acceso se registra como bloqueo externo y no como respuesta semántica correcta.

**Limitación observada de entrada:** el flujo actual admite un solo adjunto en el campo `file`. Por eso c10 entrega explícitamente un ZIP único con `orders.csv` y `reconciliation.json`. El caso evalúa el análisis conjunto de sus miembros; no demuestra soporte de dos adjuntos HTTP simultáneos. Las fuentes sueltas se conservan para generar y comprobar el paquete, pero no se adjuntan además del ZIP.

## Contrato del ejecutor

- Abrir una conversación nueva por caso y conservarla para sus turnos. Enviar exclusivamente `prompt` y los adjuntos enumerados en `attachments`; las rutas son relativas a esta carpeta. No volver a adjuntar documentos en los turnos de seguimiento.
- `desired_work_profile` describe la intención (`short_text` o `bounded`), no sustituye el perfil efectivo del servidor. `preferred_entry` reparte los casos entre web síncrona, web en streaming y API; registrar el adaptador realmente utilizado.
- Ejecutar secuencialmente para comparar tiempos y facilitar la atribución de costes. No repetir un fallo automáticamente. Las conversaciones independientes pueden continuar tras un fallo funcional si quedan presupuesto y capacidad confirmados.
- El presupuesto monetario debe ser un número autorizado por el usuario y estar fijado antes de cualquier llamada pagada. El corpus no asigna ni autoriza gasto. El límite sugerido de 1.600 tokens de salida por llamada es orientativo; registrar el límite efectivo y los límites de trabajo aprobados.
- La evaluación de idempotencia reutiliza una vez el identificador HTTP de un turno ya terminado, sin crear un turno adicional. Deben permanecer iguales ejecución, respuesta, artefactos y número de llamadas. La reentrega por `Dámelo` es otro mensaje y también exige cero llamadas al proveedor.
- Conservar las verificaciones obligatorias de permisos, datos, idempotencia y costes del sistema. Los intentos de lectura sin permiso se hacen con una cuenta sintética de otra empresa, contra el mismo artefacto, y deben fallar sin llamadas adicionales. No debilitar políticas para lograr un resultado.

## Evaluación y trazas

Evaluar cada turno como `pass`, `fail`, `blocked` o `not_run`, separando contenido, entrega, permisos y recursos. La rúbrica admite frases equivalentes; números, identificadores, hashes y formatos se comparan de forma exacta salvo tolerancia indicada. No utilizar un juez LLM para aprobar datos que pueden comprobarse con código. No confundir una respuesta bien redactada con una descarga válida.

Para cada turno guardar, como mínimo: identificadores de petición/conversación/ejecución; entrada HTTP; perfil solicitado y efectivo; estado final; duración total y de cola; intervalos de protección, proveedor, herramientas y microVM; llamadas por fase y herramienta; tokens; coste conocido o desconocido; motivo de parada; reservas y limpieza; referencias, revisiones, bytes y SHA256 de los archivos entregados. Registrar errores y reintentos explícitos. Las trazas no deben contener credenciales ni razonamiento privado. Conservar por separado la respuesta visible y los archivos sintéticos para revisión.

En c03/c06/c07 descargar los bytes reales y comprobar el mismo hash en la reentrega. En c06 verificar nueva revisión, conservación del contenido y disponibilidad de la anterior. En c07 comprobar estructura, enlaces relativos y hashes sin cambios en los dos miembros no editados. En c09 comparar las diez filas con el oráculo y las invariantes de stock. Un nombre de archivo o enlace inventado falla aunque el texto sea correcto.

El corpus no mide aislamiento físico, carga sostenida ni calidad estadística. Diez conversaciones permiten detectar problemas concretos de uso y orientar optimizaciones; no estimar una tasa general de acierto. No guardar resultados de ejecución dentro de esta carpeta: usar una carpeta nueva de informes por ensayo y conservar el corpus congelado.

## Reproducción local sin llamadas de IA

`builder.py` genera fixtures, casos, oráculos y manifiesto. Los oráculos numéricos se calculan reabriendo los archivos finales con `Decimal`, `openpyxl` (lectura) y `pypdf`; no dependen de una respuesta del agente. El libro se crea con Artifact Tool y el PDF con ReportLab. No se instalan dependencias.

El runtime de artefactos se obtiene con `load_workspace_dependencies`. Su Python incluye ReportLab, openpyxl y pypdf; Node y `@oai/artifact-tool` proceden del mismo runtime. Para regenerar, crear en esta carpeta una unión temporal `node_modules` al directorio de paquetes que devuelve el loader y ejecutar con ese Python:

```powershell
rtk proxy <python_del_runtime> evals/corpora/p0-conversations-20261016/builder.py --node <node_del_runtime>
rtk proxy <python_del_runtime> evals/corpora/p0-conversations-20261016/builder.py --verify-only
```

El proceso escribe únicamente en esta carpeta, no ejecuta el agente, no accede a la red y no modifica bases de datos. Se normalizan las fechas y el orden de los ZIP; el PDF usa metadatos deterministas. `manifest.json` permite confirmar exactamente los bytes evaluados. `verification/` contiene las vistas de los dos tableros y del PDF, no son adjuntos del corpus. Eliminar solo la unión temporal tras la generación; no borrar el directorio de dependencias de destino.

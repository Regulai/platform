# 22: Corpus documental y ensayos del piloto

**Status:** pending external validation — preparación técnica local terminada
**Blocked by:** Word/Excel/LibreOffice no disponibles; dos participantes y ejecución humana pendientes
**Specification:** [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md), [12](../12-demo-y-salida.md).

- [x] Doce casos sintéticos manejables; expectativas previas, procedencia y hashes.
- [x] PDF textual, raster, blanco, imagen, tabla y cláusula final; DOCX revisiones y numeración multinivel; CSV y XLSX con/sin caché.
- [x] Generador reproducible, extracción pública y controles de bloqueo/cita a través de las tres entradas HTTP.
- [x] Inventario de aplicaciones y separación explícita entre fixtures Python/OOXML y guardado nativo.
- [x] Navegador Chromium real con base nueva: consentimiento, cancelación, caducidad, teclado, móvil, citas, ficha, recarga y exportación.
- [x] Reconstrucción sintética de ficha `outcome_unknown`, sin confundirla con interrupción de proceso real ni coste cero.
- [x] Dos recorridos humanos completos y formularios sin rellenar; cero ensayos humanos atribuidos.
- [ ] Guardar y revisar una muestra equivalente desde Word/Excel o LibreOffice reales cuando estén disponibles.
- [ ] Ejecutar H1 y H2 con participantes, tiempos, ayudas y observaciones reales.

[Corpus y protocolos](../documentos-y-ensayos-piloto.md).
[Evidencias y comandos nuevos](../../../evals/reports/pilot-documents-20261003-01/README.md).
Seguimiento independiente: conversión CRLF del corpus reproducida y corregida en `d63731a`. [Export limpio](../../../evals/reports/pilot-corpus-export-20261003-01/README.md): 12 documentos y 14 hashes exactos, sin modificar casos/expectativas; cierre Spec independiente. La [simulación de perfiles](31-simulacion-de-participantes.md) está completada; Office nativo y personas siguen pendientes.
Los 302 tests y 150 casos offline anteriores son antecedentes; esta entrega
solo atribuye las ejecuciones documentadas en su informe. No hubo gasto,
contacto con participantes, publicación ni cambios en bases de usuario.

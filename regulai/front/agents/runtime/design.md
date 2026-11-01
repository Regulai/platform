# Diseño documental de Regulay

Una familia visual para Word, PDF y PowerPoint: tinta 193B45, acento 326D72,
neutros F5F7F5 y DDEBE9; el dorado E4C38E se reserva para cifras sobre fondo oscuro.
Liberation Serif en títulos y Liberation Sans en cuerpo y datos, preinstaladas.

Jerarquía explícita, columnas alineadas, importes a la derecha, coma decimal y
espaciado entre importe y euro. Cabeceras discretas y pies con numeración.
Las tablas largas repiten cabecera y evitan partir una fila. No se añade una
página vacía para simular una portada ni se inventa contenido para ocupar espacio.

Cada gráfico debe identificar conceptos y unidades y permitir editar sus datos.
No rasterizar texto/tablas/gráficos para ocultar fallos de composición. La revisión
visual comprueba calidad, contenido y coherencia además de cortes y solapamientos.

Las plantillas aplican el diseño en código, independientemente del proveedor del
modelo. El modelo propone contenido; no tiene acceso a datos crudos ni renders
privados. Los cambios de plantilla conservan versiones previas para poder editar
artefactos anteriores sin cambiarles el diseño.

Referencia de diseño Word: docx-report-skill de Harun Yuksel, MIT,
efbd76eecad7e1aa070a8ca17dffc51a685833d7. Se reutilizan criterios; no sus helpers
Node ni otro motor. Copia de referencia y licencia en docs/agent-assets/upstream.

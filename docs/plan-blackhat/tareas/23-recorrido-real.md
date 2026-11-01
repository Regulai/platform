# 23: Ejecutar y conservar el recorrido real acotado

**Status:** incomplete — ensayo autorizado ejecutado parcialmente y detenido.
**Blocked by:** conciliación de una llamada incierta y revisión de rechazos semánticos; no falta una clave TypeSafe directa para el destino elegido.
**Specification:** [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md), [12](../12-demo-y-salida.md).

- [x] Ocho casos y tres configuraciones versionados, seed y límites; offline predeterminado.
- [x] Servicio compartido, ledger persistente y reserva/revalidación antes de transportar; incertidumbre conservada.
- [x] Aprobación explícita del usuario para 1 USD y sustitución de TypeSafe directo por Vercel, ligada a versión/datos/destinos/ventana.
- [x] Preparación y revisiones sin red; cinco puertas sobre `698e8f0` antes de gastar.
- [x] Una ejecución real y todos sus resultados conservados, incluida parada y ausencia de factura completa.
- [ ] Completar 24 combinaciones sin ocultar fallos ni repetir automáticamente inciertas.
- [ ] Obtener revisión humana antes de atribuir corrección semántica o calidad comparativa.

La [tarea29](29-ensayo-autorizado-vercel.md) y [evidencia viva](../../../evals/reports/pilot-real-vercel-20261003-01/README.md) conservan 8/24 combinaciones, 17 llamadas externas, 12 transformaciones locales y dos respuestas entregadas. Costes comunicados 0,000312522 USD, estimados 0,00074496 USD, reserva incierta 0,003 USD. No se ha reiniciado ni liberado el ledger para renovar presupuesto.

La [tarea30](30-diagnostico-clasificacion-incierta.md) corrige localmente la pérdida del código de error de Jev; no recupera retroactivamente la causa. Siguiente acción: contrastar el evento Gateway de 15:43:21 UTC, revisar los rechazos y congelar una propuesta de continuación con autorización aplicable. No se cambian los umbrales para conseguir una demo favorable.

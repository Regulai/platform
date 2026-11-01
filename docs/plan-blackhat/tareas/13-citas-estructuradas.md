# 13: Fuentes, citas y conectores

**Status:** done
**Blocked by:** none

## Entrega y aceptación

B8, alias, extractos resueltos desde 1, mínimos, JSON/capacidades y precios por millón.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrado hasta `e042461`. B8 verde; fence JSON único, mínimo de cita de 12 caracteres sin espacios o tres palabras, máximo 30 afirmaciones, alias de fuentes y evidencia desde 1. Parámetros JSON/razonamiento explícitos en conectores; la conexión de consumidores pertenece a P y el campo de modelo a O.

ASTRA ejecutó nueve pruebas observables sobre `4400f0b`: ocho AssertionError, cero errores y un invariante ya correcto. Ajustó la prueba HTTP para afirmar el estado antes de intentar leer JSON. Suite integrada: 199 tests OK (9 expected failures ajenos) en 31.721 s; check sin incidencias; migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Evidencia local: `regulai-wt/evidence/04-verification` y `V-orchestrator-red.log`.

Adaptación del emisor offline: citas prefijadas cortas se amplían con texto literal de la fuente antes de introducir fallos sintéticos. Ninguna etiqueta, partición ni umbral cambió. Anthropic añade su esquema a la entrada facturable: P debe reservarlo; el tamaño del prompt interno del proveedor sigue sin cota publicada.


## Actualización — 3 de octubre de 2026

Consumidores P/O integrados: alias de servidor, citas sobre fuentes realmente enviadas (enmascaradas con servicios activos), parámetros por capacidad y reasoning persistido. Spec V no encontró otro defecto técnico. Unidades documentadas en [Jev](../jev-gateway.md): USD por millón; snapshot histórico, no precio actual. Calidad semántica general/E2E vivo pendientes.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

# 10: Reproducir B1–B10 y C1–C2

**Status:** done
**Blocked by:** 09

## Entrega y aceptación

Pruebas de comportamiento en base con expectedFailure; identificar cada fallo por su aserción.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada

REG creó las doce regresiones B1–B10/C1–C2; ASTRA repitió el harness sobre producto 4400f0b: 12 AssertionError, 0 errores de preparación, 0 omitidas (salida 1 esperada). Integradas en 7f67932 y 899483a. Ningún hallazgo fue falso.

Integración: check sin incidencias; 141 tests en 22.900 s, OK (expected failures=12); migraciones sin cambios; 150 ejecuciones offline, 0 controles fallidos, 0 llamadas reales; pip-audit sin vulnerabilidades conocidas. Todos los gates salida 0. Los decoradores se retirarán al integrar cada corrección.

Pruebas: `front.test_review_regressions.ReviewRegressionTests.test_b01`…`test_b10`, `test_c01` y `test_c02` (nombres completos en el módulo). B3 observa unknown_price después de una llamada Jev; B6 rechaza tamaño después de una generación; B10 ejecuta el JavaScript con Node sin randomUUID y falla en el envío. Los restantes fallan en privacidad, aislamiento, citas, presentación, texto aceptado, renovación o decisión conservadora conforme al encargo.


Seguimiento actual: [correcciones integradas](../informe-correcciones-community.md). Las doce regresiones pasan sin expectedFailure tras P/D/V/C/S/F; los resultados anteriores se conservan como evidencia de la base.

# 11: Cobertura documental explícita

**Status:** done
**Blocked by:** none

## Entrega y aceptación

Formatos corrientes, cambios aceptados, CSV/codificación, agrupación, avisos y bloqueo HTTP de partial.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrado hasta `b61d11d`, con ajuste de fixtures en `9f58dbf`: cuatro estados de cobertura, disclosures, codificaciones, bloques de texto/CSV, cambios aceptados de Word, numeración, cachés de fórmulas y avisos PDF/XLSX. B7 queda sin expectedFailure. La extracción no hace OCR.

ASTRA ejecutó las 17 pruebas nuevas contra el producto `4400f0b`: 15 AssertionError de comportamiento, cero errores y dos invariantes ya correctos. Tras integrar: check sin incidencias; 180 tests OK (10 expected failures ajenos) en 29.446 s; migraciones sin cambios; 150 controles offline correctos, cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Evidencia local: `regulai-wt/evidence/03-documents` y `D-orchestrator-red.log`.

Pendiente externo: ejemplos sintéticos guardados desde aplicaciones Word, Excel y LibreOffice reales. La integración del consentimiento `complete_text_only` corresponde a P/F.


## Actualización — 3 de octubre de 2026

Revisión documental y técnica actual: `f92d5a1`, `520fa3a`, `5701a10`, `4cd129f`, `90000c6` cierran imágenes PDF inline, filas Word borradas, CSV irregular y reinicio decimal. Doce regresiones adversariales, veintidós aserciones rojas sin errores, después verdes. Gate D: 295 OK en 58,250 s y las otras cuatro puertas exit0. Consentimiento complete_text_only integrado P/F. Office/LibreOffice reales siguen como pendiente externo.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

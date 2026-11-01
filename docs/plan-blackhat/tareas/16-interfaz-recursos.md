# 16: Interfaz y recursos locales

**Status:** done
**Blocked by:** none

## Entrega y aceptación

B10, escape, recursos fijados/hashes/CSP y controles por permiso; F2 consume recibo integrado.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

ASTRA reprodujo nueve regresiones en `4400f0b`: nueve AssertionError, cero errores y cero pruebas omitidas. B10 ya no lleva expectedFailure. Se cubren UUID en HTTP, escape de comillas, recursos locales, permisos y campos nuevos de la ficha.

La primera integración falló por normalización CRLF de un recurso fijado y se revirtió en `8ae1b92`. La restauración `679c1a6` incorpora el ajuste `a76b8c5`: `.gitattributes` conserva los bytes de vendor y una prueba clona un fixture con siete assets bajo autocrlf para verificar sus bytes. `b3d9269` oculta el borrado de auditorías históricas. No se cambiaron los hashes para aprobar la prueba.

Puertas de `10-frontend-fixed`: check sin incidencias; 233 tests OK en 35.501 s (siete expected failures de P); migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Los siete hashes locales coinciden. CSP está en modo report-only. Recorrido final y revisión técnica completados; véase actualización abajo.


## Actualización — 3 de octubre de 2026

Revisión F y Standards: límites exportados/recargados en `f778336`, destino real en `c373c87`; tres entradas HTTP y JavaScript servido por Django ejecutado en Node. Gate F: 296 OK en 60,252 s y otras cuatro puertas exit0. [Siete capturas Django offline](../../../evals/reports/ui-community-fixes-20261003/README.md). Prueba Git clona fixture de siete assets, no repositorio completo; CSP solo Report-Only. Office real y ensayos humanos pendientes.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

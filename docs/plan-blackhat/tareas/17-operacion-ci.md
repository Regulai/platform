# 17: Operación y comprobaciones CI

**Status:** done
**Blocked by:** none

## Entrega y aceptación

Logs sin contenido, timeout coherente, CI offline/auditoría; validar sintaxis sin afirmar ejecución remota.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrados `b0212d0`, `c230715` y `2ffb355`: formatter con lista permitida, auditoría HTTP sin texto ni parámetros de URL, Gunicorn gthread y CI. El nuevo módulo se llama `safe_logging.py` para no sombrear la biblioteca estándar en los trabajadores de documentos. Versiones observadas por ASTRA: uv 0.12.3 y pip-audit 2.10.1.

ASTRA reprodujo seis fallos de aserción en `4400f0b`, sin errores de preparación: falta de configuración segura, contenido sintético sensible guardado en la auditoría, falta de empresa capturada y ausencia de configuración operativa. Puertas `12-operations`: check sin incidencias; 252 tests OK en 35.773 s (siete expected failures pendientes de P); migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas.

La sintaxis JSON del workflow (subconjunto de YAML) y sus cinco comandos se validaron localmente. No se ha ejecutado GitHub Actions ni arrancado Gunicorn en Windows. PostgreSQL requiere un driver y un servicio que no forman parte del entorno actual; no se añade infraestructura para simular esa validación. Revisión adversarial completada; véase actualización final abajo.


## Actualización — 3 de octubre de 2026

Revisión Q cerrada en `21c291e`: evaluate_ai guarda cinco informes y termina exit1 si hay controles fallidos. Copia development: 90 ejecuciones/52 fallos, cero reserved; normal150/0 fallos exit0. Gate Q: 297 OK en 71,258 s y otras cuatro puertas exit0. CI remoto, PostgreSQL y Gunicorn Windows no ejecutados.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

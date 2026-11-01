# 12: Clasificación ordinal conservadora

**Status:** done
**Blocked by:** 09, 10

## Entrega y aceptación

C1/C2, probabilidades coherentes, avisos y simulador compartiendo decisión; esquema opcional estricto.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrados 5a14086 y 12d80fe (origen 335fcf8 y 2e1369f). Decide ordinal conserva suelo local, distingue manipulación y rechaza incoherencia; simulador comparte decisión sin ampliar destinos. ASTRA reprodujo siete pruebas HTTP del simulador en 4400f0b: siete AssertionError, cero errores/omitidas. El agente observó rojo/verde por comportamiento y 151 tests correctos en su rama.

Gates de integración: 163 tests en 24.081 s, OK(expected failures=11); check sin incidencias; migraciones sin cambios; 150 ejecuciones offline, cero controles fallidos/cero llamadas reales; auditoría sin vulnerabilidades conocidas. B3 ya pasa sin expectedFailure (f80a14a). C1/C2 todavía requerían P en esa integración; ya pasan como pruebas normales.

Compatibilidad: si no se configura call_timeout_seconds, se limita al deadline antiguo menor que 30 s. classification=local no activa Jev por elegir ruta automática en el simulador; P integró esta regla. Presupuesto+enmascarado sin cota se rechaza antes de cualquier salida. Temporalmente el simulador semántico con máscara activa devuelve masking_required, sin llamadas; P conectó el helper y ledger en la integración posterior.


## Actualización — 3 de octubre de 2026

Pipeline integrado y revisión C cerrada en `d4e1313`, `9840bd6`: calidad mínima de una tarea plausible e instrucción de aclaración ante avisos. C1/C2 pasan sin expectedFailure; simulador semántico con enmascarado integrado cuando hay servicios activos. Clasificación local no activa Jev por auto. Calibración humana pendiente.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

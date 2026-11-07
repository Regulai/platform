# 15: Política inicial e histórico reversible

**Status:** done
**Blocked by:** none

## Entrega y aceptación

Admin por empresa, registro desactivado, bootstrap auditado, migraciones de precios/capacidades/histórico.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Migraciones integradas individualmente y probadas en bases aisladas con ida/vuelta:

- `33a264c`, 0029 precios por millón: 216 tests OK en 33.915 s. El validador reprodujo AssertionError en `4400f0b` antes de integrar.
- `59c820b`, 0030 capacidad reasoning: 217 tests OK en 34.950 s; modelos anteriores conservados y capacidad desactivada por defecto.
- `b95f349` + `f677d54`, 0031 histórico: 218 tests OK en 32.687 s; inferencia por lotes, marca BigInteger, decisiones/relaciones/archivos conservados y reversa que respeta reasignaciones posteriores.

Cada integración pasó también check, migraciones sin cambios, 150 controles offline (cero llamadas reales) y pip-audit sin vulnerabilidades conocidas. Evidencia local: `regulai-wt/evidence/06-price-migration`, `07-reasoning-migration`, `08-historical-migration`. No se migró ninguna base existente del usuario.

Permisos, registro, borrador inicial y consultas históricas integrados en `72c7659`, `515f714`, `4f615ee` y `2cea782`. El bootstrap propone una configuración sin activarla ni inventar calidades; el administrador de empresa compara y activa con auditoría. Los registros históricos siguen siendo de solo lectura. ASTRA ejecutó nueve pruebas en la base: seis AssertionError por los defectos esperados, tres comportamientos existentes correctos y cero errores de preparación.

Puertas de `11-onboarding`: check sin incidencias; 246 tests OK en 35.521 s (siete expected failures todavía asignados a P); migraciones sin cambios; 150 controles offline correctos y cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Revisión adversarial completada; véase actualización final abajo.


## Actualización — 3 de octubre de 2026

Revisión O cerrada en `51f4ee5`: departamentos históricos limitados a empresa de registro/lector; cinco pruebas preservan histórico y departamentos legítimos sin exposición cruzada. Gate O: 302 OK en 65,158 s y cinco puertas exit0. Migraciones solo sobre bases aisladas; PostgreSQL pendiente.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

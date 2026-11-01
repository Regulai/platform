# 69 — P1 E2: paquetes y revisiones

Status: implementado y verificado; integrado en E8.
Blocked by: ninguno para el alcance local autorizado.

Especificación y aceptación: [plan P1, E2](../plan-p1-skills-streaming-20261016.md#e2-paquetes-íntegros-y-revisiones-instalables).

Verificación observada: paquetes completos con manifest y bytes, revisiones cifradas inmutables, licencia/atribución, ZIP/GitHub fijado, operaciones durables con fencing, autorización vigente, idempotencia, actualización/rollback/revocación y aislamiento por cuenta. Diez pruebas de instalación/paquetes y nueve independientes de seguridad/compatibilidad. Se corrigieron cuenta desactivada durante validación y scripts fuera de `scripts/`. La migración aditiva admite código P0 real y conserva datos P1. No se migró ninguna base real.

Evidencia: [seguridad y reversión](../../../output/p1-20261016/e8/security-report.md), [reproducción integrada](../../../output/p1-20261016/e8/reproduction.md), [aceptación](../../../output/p1-20261016/e8/acceptance.md).

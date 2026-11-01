# 72 — P1 E5: herramientas y trabajo evitado

Status: completada en el alcance local autorizado; integración y herramientas físicas comprobadas.
Blocked by: ninguno; no se habilitan runtimes globales ni se declara calidad de proveedor real.

Especificación y aceptación: [plan P1, E5](../plan-p1-skills-streaming-20261016.md#e5-herramientas-precisas-simulación-reutilizable-y-menos-io).

Verificación observada: create exclusivo; replace_file opt-in con SHA esperado,
edición exacta con precondición opcional, helper de mutación bajo lock/O_NOFOLLOW y
reemplazo atómico. No se amplían grants existentes. Una lectura de workspace usa
los bytes ya transferidos y elimina la segunda lectura del helper. Resultados de
execute distinguen exit_code de éxito del transporte y limitan el resumen a 2 KiB;
read_output pagina stdout/stderr conservados. Referencias tipadas emitidas se
protegen estructuralmente sin eximir iguales cadenas en texto libre.

[Pruebas servidor](../../../output/p1-20261016/e4/server-runtime-tools.log):
5 casos E5 correctos dentro de la pasada focalizada de 17. [Grafo SDK real](../../../output/p1-20261016/e4/sdk-tools.log):
replace_file y edit_file llegan al backend con hash esperado después del grant.
[Laboratorio físico](../../../output/p1-20261016/physical/verification.json):
CAS concurrente y symlinks ensayados en bwrap sin E2B ni proveedor real.
[Repetición del helper final](../../../output/p1-20261016/physical/mutations.json):
6/6 casos correctos, incluidos los nombres internos reservados del lock y staging.
La captura completa de checkpoints se conserva: no hay medición física E1 que
justifique introducir dirty epoch/archive_ref; el plan permite esta decisión.
La revisión final añadió corte por bytes UTF-8 sin partir caracteres: el resumen
sí respeta 2 KiB y `next_offset` mantiene la paginación existente por caracteres.
[E8 final](../../../output/p1-20261016/e8/final-focused.log) pasó 37/37, incluidos
los seis casos de herramientas y el flujo SDK/HTTP con ejecución/publicación
físicas y conservación de checkpoints.

## Utilidad de simulación preparada y verificada localmente

Paquete original `runtime/skills/regulai-simulation/` con instrucciones, recursos,
programa `run/check`, licencia BSL-1.1 y procedencia. No concede nuevas herramientas.
[Evidencia y límites](../../../output/p1-20261016/e5/simulation-report.md): 9 pruebas
correctas, 1 omitida porque Windows no permite crear symlinks al usuario actual.
Oráculo independiente escalar de todas las trayectorias de cuatro pasos en 2D y
3D; límites, cancelación, tiempo, creación exclusiva atómica, carrera de escritura,
tampering y reproducción comprobados. Caso exacto del plan: 1.401/2.000 retornos
en 2D y 651/2.000 en 3D, semilla 20261016 y 2.000 pasos, PCG64/NumPy 2.5.3.

La ejecución local se amplió con run/check en el runner real bajo namespaces
Linux y montaje de sólo lectura: [informe físico](../../../output/p1-20261016/physical/report.md).
Los resultados exactos coinciden, CAS/symlinks y timeout se comprobaron físicamente.
El candidato está en el catálogo con Python 3.12.11 y NumPy 2.5.3 requeridos,
sin activar capacidades globales. El laboratorio no acredita una microVM ni
rendimiento/calidad del proveedor; las demás rutas gobernadas constan en E4/E8.

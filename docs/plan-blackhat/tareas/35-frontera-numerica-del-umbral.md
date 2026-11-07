# 35 — Frontera numérica inclusiva de clasificación y verificación

**Status:** done — corrección integrada en 1af809f, cinco puertas correctas y revisión independiente aceptada.
**Blocked by:** ninguna dependencia externa. No se repetirá el ensayo pagado para presentar una mejora retrospectiva.
**Propietarios:** adversarial_runner (implementación), review_local_spec (revisión independiente), root (integración y puertas).
**Especificación:** [verificación y escalado](../07-verificacion-y-escalado.md), [clasificación conservadora](12-clasificacion-conservadora.md),
[banco adversarial](32-banco-adversarial-y-datos-personales.md).

## Fallo observado antes de corregir

En [segunda pasada real, DOC-01/strong](../../../evals/reports/adversarial-real-20261003-02/live-run-01/results.jsonl),
runtime `128d66a`, el juez comunica claims 0,03/0,03, contradicción 0,13 y omisión **0,20** con umbral **0,8**.
La validación de citas pasa. La comparación `score <= 1 - threshold` rechaza 0,20 porque el complemento flotante
es `0.19999999999999996`. El revisor independiente lo reprodujo a partir de la expresión AST del commit fijo.
Este caso explica un rechazo concreto; no explica los otros siete rechazos del verificador ni los bloqueos por manipulación.

## Aceptación

- [x] Regresión roja sobre la función real; comprobar debajo, igualdad y encima, incluida la proximidad inmediata de float.
- [x] Representar fielmente el límite decimal inclusivo sin epsilon, bajar umbral ni cambiar rúbrica o señales.
- [x] Comprobar la misma clase de comparación en clasificación y mantener bloqueo por encima del límite.
- [x] Revisión independiente de commit fijo y cinco puertas del proyecto sobre la integración.
- [x] Conservar resultados vivos y presupuesto; distinguir reproducción local corregida de nueva respuesta del proveedor.

## Verificación observada

`1af809fd209c4260d5314ff55fa090147515b8d0`: chat_service usa límite Decimal y deriva estado de las mismas señales fallidas;
classification suma masas Decimal y elimina el epsilon 1e-12, conservando el rechazo por encima del límite.
Comparaciones directas de confianza y señales, umbral 0,8 y rúbrica permanecen iguales.

[Regresión del implementador](../../../evals/reports/semantic-threshold-boundary-20261003-01/README.md):
rojo cuatro tests con ocho fallos esperados, salida 1; mismos cuatro verdes, salida 0; 94 focales correctos en 37,248 s.
Cero red y SQLite en memoria; tres HTTP, respuesta persistida y señales del segundo intento comprobados.
Corpus, manifiestos y resultados vivos preexistentes conservan hash.

[Cinco puertas de integración](../../../evals/reports/adversarial-gates-20261003-02/README.md): 404 tests OK en 163,419 s,
check, migraciones, 150 offline/0 fallos/0 llamadas reales y auditorías de dependencias correctos; fuentes estables.
No se repitieron llamadas pagadas tras corregir. La utilidad del juez y precisión del detector siguen pendientes en 33/34.

[Spec independiente](../../../evals/reports/semantic-threshold-independent-20261003-01/Spec-review.md) y
[Standards](../../../evals/reports/semantic-threshold-independent-20261003-01/Standards-review.md), base `9e1ae5e`,
commit fijo `1af809f`: cero hallazgos abiertos. Sonda propia: tres tests, salida 0, seis solicitudes por los tres HTTP,
nueve fronteras adyacentes, segundo intento y cola ordinal con varias masas. Reproduce 24 clasificaciones históricas sin cambios
y 11 verificaciones; solo DOC-01/strong cambia de fallo a pase del chequeo, sin editar su resultado histórico.
Root contrastó el diff, logs, alcance y resultados antes de aceptar; no se suman los tests del revisor a los 404 de la suite.

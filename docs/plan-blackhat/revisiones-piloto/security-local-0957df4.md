# Cierre independiente del enmascarado local: 0957df4

**LOCAL-SEC-1 y LOCAL-SEC-2 están corregidos y verificados sobre `0957df45362bc7cbf41c154bb13514d58901763a`.** No se encontró otro hallazgo accionable de seguridad en el diff revisado. Las reproducciones rojas y el [dictamen original de c85d019](security-local-c85d019.md) permanecen íntegros. Este cierre no aprueba un piloto real ni acredita calidad general del detector.

Revisor separado de la implementación, con la misma habilidad `security-reflexes` y condiciones del informe original. Se exportó otro snapshot inmutable; no se comprobó el checkout cambiante. La revisión abarca las correcciones P1/P2, el cambio del evaluador `ac9eb745cf201fd3378799a8a7bb6fab68ab5cb6` incluido en este candidato y los pequeños cambios de formulario/listado/demo. No se modificó producto, no se leyó `local_settings.py` ni se accedió a bases del usuario. Todas las ejecuciones usaron SQLite efímero, credenciales sintéticas, modelos locales ya instalados y red bloqueada.

## Hallazgos cerrados

| Hallazgo | Cambio y prueba independiente |
| --- | --- |
| LOCAL-SEC-1, P1 — valores numéricos JSON omitidos | `local_masking.py` inspecciona el token y su representación entera cuando la normalización está acotada; el valor sensible pasa a marcador JSON. La misma PoC original, sin cambios, ya no captura teléfono/tarjeta en el SDK desde ninguna de las tres entradas HTTP. La prueba adicional incluye exponentes equivalentes, decimales integrales, signo y precisión. Números normales y exponentes extremos no sensibles conservan representación y precisión. |
| LOCAL-SEC-2, P2 — HTTP reactivado por rollback | La operación inversa de 0032 desactiva las filas locales antes de eliminar `backend`. La misma PoC original, con `MigrationExecutor` y el wrapper exacto de `700389c`, pasa: `active=False`, URL y política conservadas, wrapper antiguo rechaza la fila y se capturan cero HTTP. La suite conserva también los HTTP históricos y comprueba la bajada/subida con registros locales. |

La corrección numérica se comprobó primero, de forma independiente, en `be29b6fd084159dd93e88d835e67438cd8a5ab7a`: 3 métodos de la PoC original pasan, exit 0, 6,890 s. Ese resultado previo queda en [su propia carpeta](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-be29b6f/independent-result.json); la revisión final vuelve a comprobar ambas correcciones juntas.

Evidencia final de las PoCs originales: [log](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/original-pocs.log), [resultado](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/original-pocs-result.json), [payloads JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/observations.json), [estado después del rollback](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/rollback-observations.json). Los archivos `review_checks.py` y `rollback_check.py` copiados para esta ejecución conservan el mismo contenido de las reproducciones originales.

## Evaluador, reservas y controles adicionales

Se leyó el delta de `evaluation.py`, `evaluate_ai.py`, `prepare_pilot_manifest.py`, `run_demo.py`, pruebas y configuración de manifiestos. El evaluador incorpora al congelado la fuente del detector, sus versiones y los hashes observados; comprueba correspondencia entre manifiesto, aprobación y modelo instalado. Las transformaciones locales se contabilizan separadas de llamadas externas, sin eliminar las reservas de HTTP ni la incertidumbre de sus resultados. El banco histórico sigue identificado como fixture HTTP; no se presenta como una prueba del detector local.

Se ejecutaron tres controles propios en [delta_checks.py](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/delta_checks.py):

- Los valores equivalentes `6.12345678e8`, `612345678.0`, `-612345678` y `4.111111111111111e15` quedan ocultos. `1.234567890123456789`, `1e100000000`, `-1e-100000000` y `0e100000000` conservan sus tokens; no se expanden exponentes enormes. [Captura](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/numeric-equivalents.json).
- El harness con modo real activado **solo dentro de fixtures sintéticas** recorre las tres configuraciones: clasificador, generador y verificador no reciben los números privados. Se capturan 9 llamadas HTTP/SDK simuladas y 6 transformaciones locales, estas con reserva y coste cero. No hubo llamadas vivas. [Payloads y ledger](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/numeric-evaluator.json).
- Una identidad de modelo cambiada durante la reserva se vuelve a comprobar antes de ejecutar el detector. El lote no se procesa, no se llega a SDK/HTTP y la entrada queda `not_started`, coste `0`, `not_incurred`. La prueba cambia la observación de identidad en memoria; no altera archivos reales del modelo. [Ledger](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/model-drift-during-reserve.json).

Siete controles propios adicionales pasan sobre el candidato final: citas inventadas no se validan por una colisión de marcadores; cambio de backend durante el detector real detiene la salida siguiente; excepciones/logs no revelan los valores sintéticos; exceso de tamaño, JSON malformado y JSON profundo no producen lotes parciales; y un lote numérico de 78.001 bytes con plazo de un segundo se rechaza atómicamente en 1,000 s, libera el detector y permite enmascarar el siguiente lote en 0,063 s. [Controles](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/supplemental-observations.json), [plazo y recuperación](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/numeric-deadline.json).

La inspección de UI cubrió escape de campos y el diff de estilos, sin prueba de navegador propia. El formulario mantiene permisos por empresa y los cambios del listado no introducen HTML sin escapar.

## Ejecución e integridad

**82 métodos de prueba pasan en el candidato final: 68 de regresión y 14 independientes; cero fallos y cero intentos de socket/DNS.** Los sockets bloqueados son `connect`, `connect_ex`, `create_connection`, `getaddrinfo` y `sendto`. Los parches de transporte preservan el SDK y el servicio reales, sustituyendo únicamente la salida de red. No se descargó ni compró un modelo.

```text
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\export_followup.py 0957df45362bc7cbf41c154bb13514d58901763a
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\followup-0957df4\run_review.py --run-name original-pocs review_checks rollback_check
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\followup-0957df4\run_review.py --run-name correction-and-evaluator front.test_local_masking front.test_local_masking_integration front.test_smoke front.test_evaluation_pilot front.test_evaluation_budget front.test_demo
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\followup-0957df4\run_review.py --run-name independent-delta delta_checks.NumericNormalizationControls delta_checks.EvaluatorControls.test_numeric_json_is_masked_for_classifier_generator_and_verifier delta_checks.EvaluatorControls.test_model_identity_drift_during_reserve_stops_before_real_detector
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\followup-0957df4\run_review.py --run-name supplemental-final supplemental_checks availability_check
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\followup-0957df4\audit_snapshot.py
```

| Ejecución | Métodos | Exit | Tiempo completo | Resultado preservado |
| --- | ---: | ---: | ---: | --- |
| PoCs originales | 4 | 0 | 6,579 s | [JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/original-pocs-result.json) |
| Correcciones/evaluador/demo | 68 | 0 | 54,187 s | [JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/correction-and-evaluator-result.json) |
| Delta propio | 3 | 0 | 15,688 s | [JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/independent-delta-result.json) |
| Controles y plazo | 7 | 0 | 7,625 s | [JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/supplemental-final-result.json) |
| Integridad | — | 0 | — | [JSON](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/integrity.json) |

Los `.log` están junto a los JSON. [Manifiesto de fuentes](../../../evals/reports/pilot-independent-local-20261003-01/security/followup-0957df4/snapshot-manifest.json): 1.576 archivos conservan sus hashes, ninguna modificación. SHA256 del archivo Git exportado: `04f9cd4d1c0420dc18cc4be54c484ca0068e1f9654b75f6dbf11508aa35c0694`. Se vuelven a comprobar las 74 versiones instaladas de requisitos, sin discrepancias. Runtime: spaCy `3.8.16`, modelo `xx_ent_wiki_sm` `3.8.0`, detector `regulai-local-v2`; hash observado de datos del modelo `4f5b7a5c5baf29c9e940befeb1f02a3021acc22806e3c1cbcef48e2078a2477a`.

**Limitaciones conservadas:** detección probabilística con omisiones conocidas; no hay garantía universal. En un control adicional, NER marca como persona la clave JSON inglesa `card`, ajena a las claves protegidas del protocolo: es un falso positivo observado que también limita la preservación semántica de JSON arbitrario, no otra fuga ni una reapertura de P1. La estructura de citas del protocolo se conserva en las pruebas. Los límites temporales de CPU siguen siendo cooperativos y estas mediciones no son un ensayo de capacidad. El hash de archivos instalado es observado, sin nueva descarga del wheel para autenticar su correspondencia. No auditoría remota nueva de paquetes, proveedores vivos, gasto real, PostgreSQL/infraestructura, navegador, Office o calibración humana. La ausencia de hallazgos adicionales se limita a los cambios y casos revisados.

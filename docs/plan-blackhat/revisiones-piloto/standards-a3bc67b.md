# Standards — addendum independiente de a3bc67b

Base revisada: `c1e3a360e7ba3051bb8f0bda487b005dd29834a0`. Corrector fijo: `a3bc67b25b341cb28172bebd5001ef48c5b8d34f`. Fecha: 3 de octubre de 2026. Este addendum complementa y conserva el [informe original](standards-c1e3a36.md).

## Dictamen focalizado

**S1 cerrado en a3bc67b. Sin nuevos hallazgos Standards en el corrector.**

La comprobación de generación pasa al preflight común: `a3bc67b:regulai/front/chat_service.py:474–486` vuelve a exigir credencial activa y de la empresa, modelo activo del motor original, relación de motores e identidad inalteradas. `start_call()` transmite el modelo seleccionado y repite esa comprobación después del observador, en 513. La comprobación anterior se elimina; no se duplica ni se abre una transacción durante la red. Esto satisface las reglas citadas en S1.

No se cierra por el informe del autor. El probe independiente, adaptado a la expectativa de cero transportes, se ejecutó contra ambas fuentes fijas. En `c1e3a36` falla para motor desactivado, modelo desactivado y clave sustituida; en `a3bc67b` las tres variantes producen `authorization_changed`, cero llamadas SDK, generación `not_started`, coste `0` y procedencia `not_incurred`. Un control sin revocación completa con una llamada al transporte simulado.

Un segundo probe usa `LedgerObserver` y `EvaluationBudget` reales: reserva `0.00228200`, conserva esa cota y liquida la generación no iniciada con exposición `0` y saldo `1`. No se exige al usuario un coste inexistente ni queda una reserva pendiente.

**Resultado:** 60 tests focales OK en 34,333 s, exit 0: 58 del repositorio y dos probes propios. Incluyen las diez mutaciones del nuevo test del autor, privacidad en las tres entradas HTTP, pipeline, presupuesto, evaluación y estados. La prueba previa falla como se esperaba: un test, tres fallos, exit 1.

**Límites:** SQLite aislado, datos sintéticos, SDK sobre transporte simulado y sockets bloqueados. No se ejecutaron proveedores vivos, PostgreSQL/Docker ni suite completa. No se modificó producto. Este cierre solo corresponde a S1 y al corrector fijado.

## Comandos y evidencia propia

```powershell
rtk proxy git diff --name-status c1e3a360e7ba3051bb8f0bda487b005dd29834a0...a3bc67b25b341cb28172bebd5001ef48c5b8d34f
rtk proxy git diff --unified=10 c1e3a360e7ba3051bb8f0bda487b005dd29834a0...a3bc67b25b341cb28172bebd5001ef48c5b8d34f -- regulai scripts ops .gitattributes
rtk proxy .venv\Scripts\python.exe -B .claude\review-standards\followup-a3bc67b\run_probe.py --baseline probe_tests.ObserverDestinationRevocationProbe.test_revocation_during_external_reservation_has_zero_sdk_transports
rtk proxy .venv\Scripts\python.exe -B .claude\review-standards\followup-a3bc67b\run_probe.py probe_tests front.test_required_masking front.test_pipeline front.test_evaluation_budget front.test_evaluation_pilot front.test_smoke front.test_state
```

| Fuente | Pruebas | Resultado | Duración |
| --- | ---: | --- | ---: |
| c1e3a36, mismo contrato esperado | 1 con cuatro variantes | Tres fallos de revocación; control positivo correcto; exit 1 | 0,899 s |
| a3bc67b, probes y regresiones focales | 60 | OK, exit 0 | 34,333 s |

- [Runner independiente](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/run_probe.py).
- [Probes con expectativa del contrato](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/probe_tests.py).
- [Rojo contra c1e3a36](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/red-baseline.txt).
- [Verde y regresiones contra a3bc67b](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/green-followup.txt).
- [Manifiesto de fuentes y hashes](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/source-manifest.json).
- [Fuente del corrector: manifiesto y ref fija](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/followup-a3bc67b/source-manifest.json); [reconstrucción del snapshot](../../../evals/reports/pilot-independent-reviews-20261003-01/README.md#reconstrucción-en-otro-checkout).

Las dos fuentes se exportaron desde sus refs fijas, sin configuración local del usuario. Git exportó los Python con CRLF en esta máquina: se comprobó que su contenido coincide con los blobs del commit tras únicamente normalizar CRLF a LF; el manifiesto conserva ambos hashes. No se modificaron artefactos congelados. Los cuatro hashes de evidencia de la revisión original se comprobaron y permanecen iguales.

Los mensajes de error de las pruebas negativas son esperados; el resultado de la suite es el cierre `OK` de la salida. El rojo y el verde proceden del mismo archivo de probes y quedan separados de la evidencia aportada por el autor.

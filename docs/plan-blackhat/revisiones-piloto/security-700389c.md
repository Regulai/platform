# Cierre independiente de SEC-1 en 700389c

**SEC-1 está corregido y verificado sobre `700389c216592db1e0c8725749bb4fd02cf3fa10`.** La revisión inicial y su prueba roja sobre `febc8aa9b303070e82e3f27626371d5b67cb73f7` permanecen intactas. Este cierre no aprueba el piloto real ni cierra la fase 1; la nueva máscara local solicitada queda fuera de este candidato y necesitará otra revisión fija.

El diff de runtime entre ambos commits solo cambia `regulai/front/evaluation.py` y `regulai/front/test_smoke.py`. Se revisaron ambos completos en sus cambios, con copia de fuente permitida separada y hashes en el [manifiesto del snapshot fijo](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/snapshot-manifest.json). No se modificó producto, no se leyó `local_settings.py`, no hubo llamadas reales, migraciones de usuario ni cambios de autorización operativa.

| Comprobación | Resultado |
| --- | --- |
| `evaluation.py:210`–`220`: nueva autorización después de `reserve()` y antes de devolver el token | Vuelve a comprobar aprobación, ventana e inputs congelados. La revocación detiene el transporte y liquida `not_started` / `0` / `not_incurred`. |
| Misma PoC independiente que fallaba en febc8aa, sin monkeypatch corrector | **Pasa**. Un preflight revocado tras reserva produce solo máscara y clasificación; cero payloads de generación; reserva de generación conservada como entrada no ejecutada con coste cero. |
| Nueva prueba independiente de vencimiento real del reloj dentro de la reserva | **Pasa**. Se avanza el reloj simulado más allá de `valid_until`, sin editar la aprobación. El preflight devuelve `authorization_expired_or_invalid_window`; no se alcanza generación y queda liquidación de cero. |
| Nueva prueba independiente de fallo persistente de liquidación, incluida recuperación final | **Pasa**. Cero transportes. La reapertura del ledger conserva `started`, coste desconocido y exposición íntegra de `0.01` USD; el fallo no libera presupuesto. |
| Regresiones `test_smoke`, `test_evaluation_budget`, `test_evaluation_pilot` | **23 tests pasan**. Incluyen revocación y expiración en los cuatro propósitos, fallo recuperable de liquidación, reinicio, coste incierto, drift y preflight sin autorización. |

Los tres comandos usan `regulai.test_settings`, SQLite en memoria, ledgers/credenciales sintéticos y sockets bloqueados:

```text
rtk proxy .venv\Scripts\python.exe .claude/review-security/followup-700389c/run_tests.py independent-approval-race review_cases.PilotApprovalRace.test_revocation_during_reservation_must_prevent_generation_transport
rtk proxy .venv\Scripts\python.exe .claude/review-security/followup-700389c/run_tests.py additional-independent followup_cases.AdditionalClosureCases.test_actual_clock_expiry_during_generation_reservation_blocks_transport followup_cases.AdditionalClosureCases.test_persistent_settlement_failure_keeps_restart_exposure_and_no_transport
rtk proxy .venv\Scripts\python.exe .claude/review-security/followup-700389c/run_tests.py fix-regression-suite front.test_smoke front.test_evaluation_budget front.test_evaluation_pilot
```

Exit codes: **0 / 0 / 0**. Métodos ejecutados: **1 + 2 + 23 = 26**, todos pasan. Tiempos completos: 2.297 s, 2.531 s y 26.110 s. Evidencia: [misma PoC](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/independent-approval-race.json), [pruebas independientes adicionales](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/additional-independent.json), [regresiones](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/fix-regression-suite.json) y sus `.log` conservados junto a cada JSON; [captura de revocación](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/finding-S1-reservation-approval-race.json), [vencimiento del reloj](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/clock-expiry.json), [fallo persistente de liquidación](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/persistent-settlement-failure.json). El nombre histórico S1 del adjunto identifica SEC-1. Los cuerpos y reservas preservados son sintéticos; no se guardaron cabeceras de credenciales.

[audit.py](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/audit.py) verifica que las 203 fuentes de la copia inicial y las 203 de esta copia mantienen sus hashes; su salida está en [integrity.json](../../../evals/reports/pilot-independent-reviews-20261003-01/security/followup-700389c/integrity.json). El alcance restante y las limitaciones de la revisión inicial siguen vigentes. No se encontró un nuevo hallazgo accionable en este diff de corrección.

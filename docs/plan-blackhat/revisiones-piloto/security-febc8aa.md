# Revisión independiente de seguridad: febc8aa

**Resultado inicial: un hallazgo reproducido, SEC-1 (P2, severidad media), pendiente de corregir antes del piloto real.** No se detectó otro hallazgo accionable en las superficies comprobadas. Esta revisión no autoriza llamadas reales ni declara una prueba de penetración exhaustiva.

Revisor separado de la implementación. Base fija `6c78cd396eb72713e85b72d8592970e4b6b66585`; candidato fijo `febc8aa9b303070e82e3f27626371d5b67cb73f7`. Se aplicó `C:/Users/javi/.codex/skills/security-reflexes/SKILL.md`, con lectura de AGENTS, RTK y documentación de dominio/tracker. La fuente permitida y sus hashes están identificados en el [manifiesto del snapshot fijo](../../../evals/reports/pilot-independent-reviews-20261003-01/security/snapshot-manifest.json); no depende del HEAD cambiante. No se modificó producto ni se leyó configuración privada.

## SEC-1: la aprobación del piloto puede quedar revocada durante la reserva y aun así ejecutarse una llamada

**Ubicación fija:** `regulai/front/evaluation.py:191`–`210`, en particular la autorización de las líneas 192–193 y la reserva/retorno de las líneas 206–210. `EvaluationBudget.transaction`, `regulai/front/evaluation_budget.py:52`–`54`, puede esperar hasta diez segundos por SQLite. La revalidación posterior de `regulai/front/chat_service.py:510`–`517` vuelve a comprobar empresa, máscara y destino, pero no la aprobación externa del piloto.

**Precondiciones y autorización:** un operador ha iniciado `smoke_ai` o `evaluate_ai --real` con manifiesto y aprobación inicialmente válidos, sobre los casos sintéticos permitidos. La aprobación se revoca mientras la reserva está en curso. No requiere permisos de otro tenant; tampoco es una vía de ejecución para un usuario web sin acceso a ese proceso. El mismo intervalo deja sin revisar el vencimiento de la ventana o cambios de los inputs congelados.

**Prueba segura:** la PoC propia llama al harness y conectores reales con SQLite en memoria, ledger sintético y sockets bloqueados. Intercala `status=revoked` después de obtener una reserva de generación, antes de que `reserve()` devuelva el token. Un nuevo preflight ya devuelve `ready_for_real=false`, pero el SDK cruza su transporte simulado con un `POST` de generación a DeepSeek. Secuencia observada: máscara, clasificación, **generación tras revocación**; el siguiente intento de salida sí queda detenido. La aserción de cero generaciones falla, exit 1. El ledger conserva la exposición; no se demostró sobrepasar su techo monetario.

**Impacto:** se envían datos sintéticos y se incurre en una llamada acotada después de retirar la autorización. La prioridad es P2 por el alcance local y acotado, pero contradice la condición expresa de autorización vigente antes de cada salida.

**Corrección requerida:** revalidar la aprobación y sus fuentes/ventana tras completar la reserva, antes de devolver permiso al transporte. Si falla, conservar la entrada y liquidarla como `not_started`, coste `0`, procedencia `not_incurred`. Un fallo al liquidarla debe conservar exposición y detener el envío. Añadir regresiones de revocación y vencimiento dentro de la reserva. El control experimental propio que repite esa comprobación y liquida cero detiene la misma generación; se aplicó únicamente mediante monkeypatch de test, sin cambiar el candidato.

Evidencia: [PoC](../../../evals/reports/pilot-independent-reviews-20261003-01/security/review_cases.py), [log de reproducción](../../../evals/reports/pilot-independent-reviews-20261003-01/security/approval-race.log), [metadatos](../../../evals/reports/pilot-independent-reviews-20261003-01/security/approval-race.json), [hallazgo capturado](../../../evals/reports/pilot-independent-reviews-20261003-01/security/finding-S1-reservation-approval-race.json) y [control experimental](../../../evals/reports/pilot-independent-reviews-20261003-01/security/control-S1-reservation-recheck.json). Los nombres S1 de los adjuntos corresponden a **SEC-1**, no al hallazgo Standards ya corregido.

## Cobertura y resultados

| Superficie / archivos | Resultado observado |
| --- | --- |
| `chat_service.py`, `masking.py`, `policy.py`, adaptadores en `views.py` y `api/views.py` | YARA original antes de egreso; restricted bloquea incluso máscara privada; máscara ausente/inactiva/ajena/incompatible/fallida detiene; consentimiento no levanta la obligación. Captura propia del SDK de las tres entradas: solo contenido transformado en generación; respuesta transformada antes de persistir. |
| `policy_simulator.py`, `access.py`, permisos HTTP | Borrador no concede salida; rol/empresa comprobados; cambios de rol, máscara o configuración detienen el salto siguiente. Permisos por objeto/empresa, POST y CSRF verificados por tests. |
| `chat_service.py`, estado/migraciones | Historial solo de pares completados y elegibles, con digest; revocación de motor/modelo/credencial durante reserva detenida; idempotencia y estados inciertos conservados. Los diez casos existentes del arreglo Standards pasan en el candidato. |
| `evaluation.py`, `evaluation_budget.py`, `smoke_ai.py`, `evaluate_ai.py` | Reserva previa, ledger compartido, incertidumbre y estimaciones conservadoras, reinicios y exceso de coste comprobados. Preflight pendiente no toca DB/red; SEC-1 es la excepción reproducida. |
| `connectors.py`, `jev.py`, errores/logs y template de chat | SDK sin reintentos ocultos y sin redirects; tests de límites/timeout e intentos. Errores y logs sin contenido/secretos de las fixtures; HTML y atributos escapados. URLs de máscara configurables por seguridad, incluidas privadas por diseño; no se demostró una ampliación SSRF para empleados. |
| `ops/pilot/*`, settings de laboratorio y seis scripts modificados | Lectura de aislamiento/guardas/backup, rutas, subprocess por argumentos, loopback, HTTPS/media y no DB de usuario. No se arrancó Docker/PG ni se reprodujeron backups en esta revisión. |
| Los 16 archivos de tests modificados | Diff inspeccionado; módulos relevantes ejecutados. [Tabla archivo por archivo](../../../evals/reports/pilot-independent-reviews-20261003-01/security/coverage.md). |

Ejecución propia: **94 tests focales y 52 tests de permisos/estado/migraciones/logs/UI/pipeline pasan**; **tres comprobaciones independientes pasan** (captura SDK, consentimiento con máscara revocada y control de SEC-1). La PoC negativa de SEC-1 queda roja. Todas usaron el snapshot fijo, `regulai.test_settings`, SQLite en memoria y sockets bloqueados. Los cuerpos conservados son exclusivamente sintéticos; no se guardaron cabeceras de credenciales.

Comandos desde la raíz del repositorio:

```text
rtk proxy .venv\Scripts\python.exe .claude/review-security/run_tests.py focused front.test_required_masking front.test_chat_flow front.test_pipeline_privacy front.test_policy_simulator front.test_evaluation_budget front.test_evaluation_pilot front.test_smoke api.test_permissions
rtk proxy .venv\Scripts\python.exe .claude/review-security/run_tests.py auth-state-logs front.test_state front.test_onboarding_migrations front.test_backend_hardening.BackendHardeningTests front.test_backend_hardening.SecretRotationTests front.test_operations.ExceptionAuditHTTPTests front.test_operations.SafeLoggingTests front.test_frontend_chat front.test_pipeline
rtk proxy .venv\Scripts\python.exe .claude/review-security/run_tests.py approval-race review_cases.PilotApprovalRace.test_revocation_during_reservation_must_prevent_generation_transport
rtk proxy .venv\Scripts\python.exe .claude/review-security/run_tests.py independent-controls review_cases.PilotApprovalRace.test_control_recheck_after_reservation_prevents_the_same_transport review_cases.PrivacyTransportCapture
```

Exit codes: `0`, `0`, `1` y `0`, respectivamente. Logs y tiempos: [focused](../../../evals/reports/pilot-independent-reviews-20261003-01/security/focused.json), [auth-state-logs](../../../evals/reports/pilot-independent-reviews-20261003-01/security/auth-state-logs.json), [approval-race](../../../evals/reports/pilot-independent-reviews-20261003-01/security/approval-race.json), [independent-controls](../../../evals/reports/pilot-independent-reviews-20261003-01/security/independent-controls.json); los `.log` correspondientes se conservan junto a cada JSON. [Captura adicional](../../../evals/reports/pilot-independent-reviews-20261003-01/security/privacy-transports.json).

**Límites:** no llamadas vivas, despliegue, cambios de DB de usuario, secretos reales ni auditoría remota de dependencias; no se verificó disponibilidad/acceso real de máscara, TypeSafe o DeepSeek, calidad de enmascarado del proveedor, Office o revisión humana. La lectura del laboratorio no sustituye una ejecución independiente de PostgreSQL/HTTPS/backup. No se otorga aprobación monetaria: el límite propuesto de 1 USD sigue siendo una condición de manifiesto, no autorización de esta revisión.

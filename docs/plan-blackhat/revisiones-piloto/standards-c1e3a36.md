# Standards — revisión independiente de c1e3a36

Base: `6c78cd396eb72713e85b72d8592970e4b6b66585`. Candidato: `c1e3a360e7ba3051bb8f0bda487b005dd29834a0`. Revisión del 3 de octubre de 2026; los avances posteriores de HEAD no cambian este dictamen.

## Informe principal

**Un incumplimiento reproducido, P2. Sin hallazgos Fowler adicionales.**

**S1 — Revalidación incompleta después de reservar gasto.** En `c1e3a36:regulai/front/chat_service.py:497–500`, el nuevo `before_call()` puede esperar y después solo ejecuta `preflight(destination, texts)`. Este helper no revisa la credencial ni el modelo generador: su comprobación de actividad e identidad quedó antes de la reserva, en 687–689. Revocar `CompanyEngine.active`, desactivar `EngineModel` o sustituir `api_key` dentro de `before_call(generation)` permite todavía una llamada SDK con el destino/credencial anteriores y termina `completed`.

Normas obligatorias: `docs/plan-blackhat/README.md:78`, «Control de salida antes de cada destino externo»; `06-enrutamiento-modelos.md:22`, filtro de empresa y «credencial activa»; `tareas/21-privacidad-obligatoria.md:22`, «segunda comprobación de autorización tras reservar». El probe propio reproduce las tres variantes en el transporte, sin conexiones reales. Alcance comprobado: el servicio con observador, usado por evaluación; no se afirma que HTTP exponga ese parámetro. **Corrección:** incluir la actividad, pertenencia e identidad del motor/modelo/credencial en el preflight posterior a la reserva, antes de construir el conector. Al revocarse, liquidar como `not_started` y coste cero. Conservar la red fuera de transacciones largas.

**Heurísticas:** se aplicó la base de doce smells de Fowler como juicio, subordinada al repositorio. La extracción de `masking.py`, el observador para reutilizar el ledger y los adaptadores concretos tienen una necesidad actual documentada; no justifican hallazgos de Middle Man o Speculative Generality. No se añade una preferencia de estructura como incumplimiento.

**Límites:** lectura de producción, scripts, laboratorio y contratos; pruebas aisladas de privacidad, presupuesto, evaluación y simulador. No se repitió Docker/PostgreSQL, navegador, Office, proveedores vivos ni revisión humana. Este informe no certifica su resultado. No se modificó código de aplicación.

## Evidencia y reproducción

Las ubicaciones del informe principal son números de línea del candidato fijo. El [manifiesto del candidato](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/review-manifest.json) y las [instrucciones de reconstrucción](../../../evals/reports/pilot-independent-reviews-20261003-01/README.md#reconstrucción-en-otro-checkout) permiten consultar las fuentes sin depender de HEAD. Se exportó mediante `git archive` a un directorio propio; el archivo de configuración local del usuario no forma parte del árbol exportado.

Comandos de delimitación:

```powershell
rtk proxy git rev-parse 6c78cd396eb72713e85b72d8592970e4b6b66585 c1e3a360e7ba3051bb8f0bda487b005dd29834a0
rtk proxy git diff --name-status 6c78cd396eb72713e85b72d8592970e4b6b66585...c1e3a360e7ba3051bb8f0bda487b005dd29834a0
rtk proxy git log --oneline 6c78cd396eb72713e85b72d8592970e4b6b66585..c1e3a360e7ba3051bb8f0bda487b005dd29834a0
```

Se enumeraron 504 paths; 41 corresponden a `regulai/`, `scripts/`, `ops/` y `.gitattributes`. [Inventario](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/review-manifest.json). Commits, de más antiguo a reciente: `d56eca4`, `208d9ef`, `4538120`, `63db91d`, `aab85a8`, `64dfc62`, `7644da7`, `c1e3a36`. Las excepciones de normalización de artefactos se revisaron sin regenerar sus bytes ni volcar los logs históricos.

Prueba de S1 y regresiones existentes:

```powershell
rtk proxy .venv\Scripts\python.exe -B .claude\review-standards\run_probe.py probe_tests front.test_required_masking
rtk proxy .venv\Scripts\python.exe -B .claude\review-standards\run_probe.py front.test_evaluation_budget front.test_evaluation_pilot front.test_smoke front.test_policy_simulator
```

- Primera orden: **14 tests OK, 2,122 s, exit 0**: 13 regresiones existentes y un probe diagnóstico con tres variantes. El probe afirma el comportamiento defectuoso observado; su resultado OK confirma la reproducción, no la corrección. [Código del probe](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/probe_tests.py), [salida completa](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/probe-output.txt).
- Segunda orden: **34 tests OK, 13,557 s, exit 0**. [Salida](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/targeted-tests-output.txt).
- [Runner](../../../evals/reports/pilot-independent-reviews-20261003-01/standards/run_probe.py): SQLite en memoria, medios en evidencia propia y sockets bloqueados. El probe usa el conector OpenAI real sobre `httpx.MockTransport`; la máscara es sintética. Las regresiones existentes cubren las tres entradas HTTP. No hay gasto ni DB de usuario.

Resultados mínimos de S1:

| Mutación durante `before_call(generation)` | Estado al entrar en transporte | Llamadas SDK | Resultado |
| --- | --- | ---: | --- |
| Desactivar CompanyEngine | `engine_active_at_transport=false` | 1 | `completed` |
| Desactivar EngineModel | `model_active_at_transport=false` | 1 | `completed` |
| Sustituir credencial | `credential_matches_current=false` | 1 | `completed` |

En las tres variantes se liquidan máscara, generación y máscara como `completed`. La corrección debe impedir esa generación y conservar la reserva/liquidación correspondiente al no envío.

SHA-256 de evidencia propia al cerrar esta revisión:

```text
run_probe.py                 38a2561805d963783b41f6164305143fb3eea2d9d7a3a5dc1b8ef6aa6a5f658e
probe_tests.py               1ba59f059ad04d3dc52299fe3a56bed092b1b71453767bd6342763e8e0a7d303
probe-output.txt             140dd26439fb8690c7d504ed7cd6b7d45aa622d38d33f3dc9a28825f88373240
targeted-tests-output.txt    beab3a957cfa30b6369358effa187a72d38c803fed66c30a791307455b28c317
```

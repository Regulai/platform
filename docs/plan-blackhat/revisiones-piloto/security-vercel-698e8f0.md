# Revisión independiente previa al ensayo autorizado con Vercel

**Dictamen:** no se han reproducido hallazgos de seguridad nuevos que bloqueen el ensayo autorizado de ocho casos sintéticos en tres configuraciones, con límite compartido de 1 USD. El resultado corresponde exclusivamente al commit `698e8f0bb11b6f5ef91e8ac27ef9404c8868f7cc` y a los bytes aprobados que se detallan abajo. No autoriza otros datos, destinos, ejecuciones ni presupuestos.

Revisor independiente: agente `review_local_security` (Astra Max), 3 de octubre de 2026. Se aplicó `security-reflexes`. Se revisó el cambio posterior a `0957df45362bc7cbf41c154bb13514d58901763a`, el puente de credenciales, el manifiesto y la aprobación. La autorización humana transmitida para este alcance fue hasta 1 USD para los ocho casos y la sustitución expresa del acceso directo a TypeSafe por Vercel.

No hay hallazgos accionables nuevos que priorizar. Las correcciones previas LOCAL-SEC-1 y LOCAL-SEC-2 conservan su dictamen y evidencia separados en `security-local-0957df4.md`; esta revisión no sustituye ni amplía sus conclusiones.

## Cobertura y resultados

Todas las referencias de archivo y línea siguientes pertenecen al commit fijado.

| Control | Evidencia y resultado |
| --- | --- |
| Alcance exacto | El manifiesto fija los ocho IDs `arithmetic`, `blocked`, `consent-pending`, `consent-accepted`, `document-success`, `evidence-absent`, `verification-failed` y `second-attempt`; todos son `development`. Configuraciones: `economy`, `strong`, `router`. Aprobación sin banco reservado ni revisión humana completada. La secuencia del arnés se deriva de esos casos y configuraciones en `regulai/front/evaluation.py:548`. |
| Destino y modelo del juez | `regulai/front/evaluation.py:199` admite solamente dos tuplas completas: TypeSafe directo/versionado o Gateway Vercel/alias Jev. Seis variantes cruzadas o de host fueron rechazadas antes de abrir ledger o proveedor. El manifiesto y la aprobación de este ensayo eligen únicamente Gateway. |
| Sin fallback oculto del cliente | `regulai/front/jev.py:248` envía `providerOptions.gateway.only=['typesafe-ai']`. No envía lista de modelos alternativos. `jev.py:309` realiza una petición y desactiva redirecciones; `connectors.py:80` configura el SDK generador sin reintentos ni redirecciones. Un timeout del Gateway produjo una única petición simulada, cero generaciones y reserva conservada con coste desconocido. |
| Segundo intento acotado | Veredictos negativos simulados en la frontera HTTP del Gateway produjeron una generación en economy, una en strong y dos en router. Los modelos del router fueron economy y después strong; no hubo tercer intento. La captura conserva siete peticiones Gateway, todas restringidas a TypeSafe. |
| Enmascarado y contabilidad | Con detector spaCy real instalado, el correo sintético original no apareció en ninguna petición capturada al generador ni al juez. Las seis transformaciones locales registraron coste y reserva de API cero. Los seis jueces simulados conservaron coste `provider_reported=0.001`. Se comprobó el ledger compartido y exposición no superior a 1 USD. Los módulos suministrados cubren además concurrencia, reinicios, estimaciones, revocaciones y resultados inciertos. |
| Alias y procedencia | `typesafe-ai/jev` está declarado como alias mutable y la aprobación lo reconoce. `jev.py:264` valida costes y rechaza metadatos de ruta contradictorios cuando se reciben. La ausencia de esos metadatos no demuestra la versión interna ni la procedencia efectiva del servicio remoto. |
| Puente y secretos, revisión estática | `evals/reports/pilot-real-vercel-20261003-01/run_authorized.py:38` usa una conexión SQLite separada con `mode=ro`. La consulta `:43` une credenciales de generador y juez de la misma empresa; `:50` exige un único par compatible. `:80` y `:83` fijan `regulai.test_settings` en el hijo; las claves pasan por su entorno y no por argumentos. `:96` elimina valores de claves inesperadamente presentes en stdout/stderr; `:120` no imprime texto ni variables de excepciones. Las salidas se crean sin sobrescribir evidencia anterior. |
| Aislamiento del arnés | `regulai/front/evaluation.py:279` rechaza bases que no sean SQLite en memoria antes de migrar. El preflight independiente no llamó a HTTP, SDK, conexión de base ni ledger; comprobó manifiesto, aprobación, fuentes, runtime y metadatos del detector con las credenciales deshabilitadas para esta comprobación. |

La opción `only` coincide con la restricción documentada por [Vercel](https://vercel.com/docs/ai-gateway/models-and-providers/provider-options). La ruta compatible de TypeSafe se contrastó con la [documentación oficial de integración de Jev](https://vercel.com/i/jev-integrations). Estas referencias apoyan el contrato solicitado; no prueban la ejecución interna del proveedor.

## Pruebas y trazabilidad

Resultado final: **51 métodos de prueba pasan: 45 suministrados y 6 independientes**. Se interceptaron las fronteras HTTP/SDK y se bloquearon `socket.connect`, `connect_ex`, `create_connection`, `getaddrinfo` y `sendto`; los contadores finales de todos ellos fueron cero. El modelo local real estaba instalado. Solo se usaron credenciales y bases sintéticas.

Comandos ejecutados desde el repositorio; todos los comandos de shell empezaron por `rtk`:

```powershell
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\prepare.py 698e8f0bb11b6f5ef91e8ac27ef9404c8868f7cc
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\run_tests.py 698e8f0 supplied-focal front.test_evaluation_pilot front.test_smoke front.test_jev front.test_evaluation_budget
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\run_tests.py 698e8f0 own-gateway review_cases.GatewaySecurityChecks.test_exact_gateway_tuple_uses_only_approved_provider_and_shared_ledger review_cases.GatewaySecurityChecks.test_crossed_tuple_and_host_variants_cannot_reach_any_provider review_cases.GatewaySecurityChecks.test_gateway_timeout_retains_reservation_without_direct_or_model_fallback
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\prepare_approved_bytes.py
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\run_tests.py 698e8f0-approvedbytes frozen-scope-approvedbytes review_scope.FrozenScopeChecks
rtk proxy .venv\Scripts\python.exe .claude\review-vercel-security\run_tests.py 698e8f0-approvedbytes router-negative-verification-only review_router.GatewayRouterChecks.test_repeated_negative_gateway_verdict_allows_only_two_router_generations
```

| Ejecución | Exit | Métodos | Duración del wrapper | SHA-256 del log |
| --- | --- | --- | --- | --- |
| `supplied-focal` | 0 | 45 | 44,547 s | `c4a3b560dac6b98cffec7dd48756058cff9a7de82b08616ca840991a89ebf9ac` |
| `own-gateway` | 0 | 3 | 13,421 s | `929c02b13985a3731c7ee2d5a5ed1bc76789641b20dd5ae2f4bed5eef14a0ddc` |
| `frozen-scope-approvedbytes` | 0 | 2 | 1,516 s | `c5441347b07ff3b22057fc852497bd567b387e46945fd26e6bd84237dca42fc4` |
| `router-negative-verification-only` | 0 | 1 | 9,156 s | `5365455290d010dd5ab29a86c4c895b1e8a46b92ead031a8c3d05b3fcedf1416` |

Se conservan dos resultados iniciales no verdes, sin atribuirlos al producto:

- `frozen-scope` (exit 1): `git archive` exportó finales de línea distintos de los bytes aprobados en 11 de las 18 fuentes. El preflight cerró con `source_changed`. Se creó otra copia inmutable: cada fuente capturada debía coincidir con su SHA-256 aprobado y, tras normalizar CRLF/LF, ser idéntica al archivo del commit fijo. Los 18 archivos cumplieron ambas comprobaciones. No se cambió el manifiesto, la aprobación ni las aserciones del test. El resultado verde corresponde a esta copia, no al archive original. El fallo y su log permanecen intactos.
- `router-negative` (exit 1): el primer fixture propio marcaba también manipulación en la clasificación (`noul=1`); el producto cerró correctamente con cero generaciones. Se conserva `review_router_initial_fixture.py`. Se corrigió solo el fixture para devolver el veredicto negativo en verificación, manteniendo todas las aserciones de 1/1/2 generaciones. El nuevo resultado fue verde.

También hubo errores operativos sin ejecución de producto: tres lecturas intentaron pasar el cmdlet `Get-Content` directamente a `rtk proxy` (exit 1; corregidas usando PowerShell), y una invocación del runner precedió a la finalización de la exportación derivada (exit 1 por manifiesto inexistente; repetida después de completar la exportación). Ninguno abrió proveedor ni accedió a credenciales.

La evidencia está en `.claude/review-vercel-security/`: capturas de peticiones y ledger sintéticos, scripts, logs, resultados JSON, dos inventarios de snapshots y comparación EOL. `final-seal.json` contiene sus hashes y el del presente informe. Ambos snapshots conservan los 2005 archivos exportados, sin configuraciones privadas, claves ni bases de usuario.

| Artefacto | SHA-256 |
| --- | --- |
| Archive Git fijo | `3870c98bcf02f1d5bb1ea92981eda1d7b66b8fc132d2193c7f7a31401a071067` |
| Inventario del archive `snapshot-698e8f0.json` | `12cc4599f85ef2177a8e200680febcb54d6fa9029b6df6136f8ded3a88ecdc93` |
| Inventario de bytes aprobados `snapshot-698e8f0-approvedbytes.json` | `92de905570a4c50b0bc2c91d9a30d35569a58a9fd5f41ffa4e47a86f2a1e2573` |
| Comparación EOL de las 18 fuentes | `8a4c7a45d6bf8a531fa4adc0e7b97d42c454875da7656c246f1547cf8ec55bd7` |
| Manifiesto Vercel | `ff5a3056a6d13d7bc8a9c8baae559b002e201cc235be1a3aaa3cc4cd9e6e5b9d` |
| Aprobación | `0c879ad85d68fd1f471ed2bc4cd5b346f98a6a83ddb39c87b885d17d7f4117b7` |
| Puente revisado como fuente | `35c5b80656f39946fc5714d49627e01738562c1bb4b3f3a6eb662f02bac5c0d5` |

## Límites del dictamen

El puente no se importó ni ejecutó. No se leyó `local_settings.py`, ninguna base de usuario, clave ni volcado de entorno. La extracción y protección real de credenciales se revisaron como fuente; no se atribuye aquí una validación dinámica del puente. Su hash de archivo SQLite es evidencia del archivo principal, no una demostración independiente sobre WAL, otros escritores o la totalidad del estado del equipo.

El preflight independiente usó `check_credentials=False` y la hora determinista `2026-10-03T15:23:55+00:00`, dentro de la ventana ya aprobada. No habilita una ejecución fuera de esa ventana: la ejecución viva debe superar su propio preflight actual. Los bytes aprobados y sus hashes deben mantenerse; un checkout que cambie finales de línea cerrará el preflight hasta preparar coherentemente nuevos artefactos aprobados.

No hubo llamadas vivas a DeepSeek, Vercel o TypeSafe por este revisor. No se verificaron cargos reales, versión inmutable detrás del alias, calidad humana, Office ni producción. El límite del ledger conserva reservas ante costes estimados o desconocidos; no constituye una garantía externa de facturación del proveedor. API local cero tampoco significa infraestructura gratis. Siguen vigentes los límites declarados del detector local y no se afirma anonimización universal. No se modificó producto ni se hicieron commits desde esta revisión.

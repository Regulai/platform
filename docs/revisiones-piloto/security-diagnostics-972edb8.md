# Revisión independiente del diagnóstico seguro de Jev

**Dictamen: sin hallazgos nuevos que bloqueen el corrector.** Se verificó el commit `972edb88c82a5220a43ffcc89316a9f9033e82f7` respecto de `535eb9d8421006ea8476ea511427a7dcda9cee3b`, exclusivamente mediante snapshots inmutables. Pasan los cinco tests suministrados y tres pruebas independientes. La comparación diferencial de 18 escenarios no mostró cambios en estado público, costes, cotas, transporte ni tratamiento de peticiones duplicadas.

Revisión de `review_local_security` (Astra Max), 3 de octubre de 2026, aplicando `security-reflexes`. El alcance fue el diagnóstico futuro de fallos; no reabrir, repetir ni atribuir una causa al ensayo real interrumpido. No se editaron producto, índice ni evidencia anterior.

## Cambio y seguridad preservada

El diff contiene exactamente `regulai/front/chat_service.py`, `regulai/front/evaluation.py` y el nuevo `regulai/front/test_diagnostics.py`. Las referencias siguientes pertenecen al commit revisado.

- `chat_service.py:31` declara una lista cerrada de códigos internos y estados de `HTTPStatus`, excluyendo 200. `:35` acepta únicamente objetos cuyo tipo exacto es `str`; todo lo demás produce `unknown_jev_error`. Esto impide incorporar texto libre, cuerpos, objetos arbitrarios o subclases de cadena al nuevo diagnóstico.
- `chat_service.py:594` guarda el código saneado antes de propagar el error y registra un evento sin cuerpo ni texto de la excepción. `:794` aplica el mismo saneado al log de fallo del juez. Los estados y costes se siguen resolviendo por el comportamiento anterior.
- `evaluation.py:266` incorpora únicamente el nuevo campo a los metadatos contables ya existentes. No se añade transporte, reintento, cambio de destino, umbral, precio ni mecanismo para liberar reservas.
- `chat_service.py:46` sustituye la afirmación general de que no hubo envío por un mensaje que remite a la ficha y reconoce un posible resultado incierto. No cambia `error_type` ni el estado HTTP.

No se ha reproducido ningún hallazgo accionable nuevo. El diagnóstico sigue siendo una categoría limitada; un estado HTTP no incluido en la lista cerrada, por ejemplo 599, queda como `unknown_jev_error`. El nuevo campo no permite recuperar la causa de registros históricos que nunca la conservaron.

## Pruebas independientes

| Comprobación | Resultado observado |
| --- | --- |
| Tres entradas HTTP | Se ejercitaron `/chat/send/`, `/api/chat/send/` y `/chat/` con ConnectTimeout, ReadTimeout, HTTP 403, HTTP 503, HTTP 599 y JSON inválido: 18 escenarios. Cada petición se repitió con el mismo UUID y conservó la ficha sin nueva llamada al proveedor. No se generó respuesta tras fallo de clasificación. |
| Comparación con la base | El mismo probe pasó en `535eb9d` y `972edb8`. Al excluir exclusivamente el nuevo diagnóstico, las 18 observaciones fueron idénticas: HTTP/estado público/error_type, propósito, estado de llamada, coste, cota, clase de coste, transporte y número de envíos. La base no tenía `provider_error_code`; el candidato conservó los códigos previstos. |
| Datos adversariales | Once valores o tipos, tanto en clasificación como en verificación: texto libre con clave sintética y CRLF; subclase de `str` cuyo texto se redefine; diccionario, lista, tupla, bytes, entero y nulo; `http_200`, `http_599` y una cadena con NUL. Las 22 combinaciones produjeron `unknown_jev_error`. No aparecieron los marcadores privados ni la clave sintética en respuesta HTTP, decisión persistida, logs formateados ni atributos completos de los registros de logging. |
| Cuerpos y errores del transporte | Las excepciones, cabeceras, motivo HTTP y cuerpo inválido contenían marcadores privados sintéticos. Los tests no los encontraron en las superficies persistidas o públicas. Se comprobó además la ruta de verificación que antes construía un `RuntimeError` con el código sin sanear. |
| Ledger y no replay | En el arnés con SDK/HTTP simulados, errores desconocidos de clasificación y verificación llegaron al ledger como `unknown_jev_error`, con coste nulo y reserva individual de 0,003 USD. Las reservas inciertas acumuladas permanecieron en 0,006 USD. Reabrir el ledger y volver a solicitar el mismo directorio de ejecución no modificó su contenido ni originó nuevos envíos. Solo hubo una generación simulada, anterior al fallo de verificación. |
| Evidencia histórica | Se cotejaron los 11 archivos UTF-8 identificados por el inventario anterior: sus hashes actuales coinciden con los registrados y son idénticos entre ambos commits fijos. Solo se leyeron sus bytes para calcular hashes; no se abrió el ledger SQLite real ni se rellenó ningún diagnóstico histórico. |

Las cinco pruebas suministradas añaden comprobaciones de timeout/503/JSON inválido, fallo local de seguridad sin llamadas, saneado del juez y conservación contable. No se repitieron las suites amplias de producto.

## Comandos y evidencia

Todos los comandos de shell empezaron por `rtk`. Reproducción desde la raíz del repositorio:

```powershell
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\prepare.py 972edb88c82a5220a43ffcc89316a9f9033e82f7
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\prepare.py 535eb9d
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\run_tests.py 972edb8 supplied-diagnostics front.test_diagnostics
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\run_tests.py 972edb8 own-diagnostics-final review_cases.HttpDiagnosticsChecks review_cases.LedgerDiagnosticsChecks
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\run_tests.py 535eb9d baseline-matrix-isolated review_cases.HttpDiagnosticsChecks.test_classification_matrix_and_duplicate_request_preserve_public_state
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\run_tests.py 972edb8 candidate-matrix-isolated review_cases.HttpDiagnosticsChecks.test_classification_matrix_and_duplicate_request_preserve_public_state
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\audit.py
rtk proxy .venv\Scripts\python.exe .claude\review-diagnostics-security\finalize_log_hashes.py
```

Todos los comandos finales anteriores terminaron con **exit 0**. Los scripts rechazan sobrescribir evidencia existente; para repetir deben emplearse directorios/nombres nuevos.

| Ejecución | Métodos | Duración del wrapper | SHA-256 final del log cerrado |
| --- | ---: | ---: | --- |
| `supplied-diagnostics` | 5 | 6,531 s | `5beca127d300122747eefd393c0e19d0c609b4ae3aee59c013b74c7df0695270` |
| `own-diagnostics-final` | 3 | 11,203 s | `5d9f3b6aab47f9522df6f7e8ae88e9c8f78112848e9b0dd22ff5a664471ce5d4` |
| `baseline-matrix-isolated` | 1 diferencial | 4,844 s | `ece4129d6375444e7d607f0fdddaf948f0c50c300565f1040117565f0bf221ac` |
| `candidate-matrix-isolated` | El mismo diferencial | 4,797 s | `f2cdabfcec50990a1469686cf45b10c1c65a6e86adfb172b8165a6efeb5b9709` |

Los dos últimos renglones comparan el mismo método incluido en las tres pruebas propias: no se cuentan como métodos adicionales del candidato.

Se conservan dos ejecuciones iniciales con exit 1 (`own-diagnostics` y `baseline-matrix`). Su fixture enviaba 36 peticiones consecutivas bajo el mismo contador y alcanzaba el límite de frecuencia en los tres últimos subcasos. Ocurrió en ambos commits; clasificación no llegó a ejecutarse en esos subcasos. Se conservó el fixture inicial y se aisló cada escenario petición/duplicado limpiando únicamente la caché de tests entre escenarios. Las aserciones, el limitador y el producto no se modificaron.

Durante el sellado se detectó que el wrapper calculaba su campo `log_sha256` antes de cerrar el archivo de log. Se preservaron sus metadatos originales y se calcularon los hashes completos por separado. Esta tabla utiliza los hashes finales. La errata independiente `.claude/review-diagnostics-security/log-hash-errata.md` documenta también las tres celdas afectadas del informe Vercel anterior; sus sellos finales originales ya tenían los hashes completos correctos. No se reescribió ningún informe sellado.

| Artefacto | SHA-256 |
| --- | --- |
| Archive base `535eb9d` | `6aec2954bc4ad70be2d6502b7923c431211c2d2ab40e97077cf933a96df83cb0` |
| Archive candidato `972edb8` | `31a8fc013615eba4bb18fa927ed1cc77e74335ef43e35895a091ca9656eeb07c` |
| Inventario candidato | `7c1a41f5b1730f4dfcdad3c645707c31076f10799edd99f19cd5edb97500a6f6` |
| Auditoría diferencial e histórica | `07f13a4580e35b11579ddf224326c2380d293aa2b41e027e2e0785304b9cf5fd` |
| Inventario de hashes de logs cerrados y errata | `53e6549772330833702bb42262dbd9340e4d3a6e73d22d0c0e1e21f58b34a43d` |

`final-seal.json` en `.claude/review-diagnostics-security/` inventaría el informe, errata, scripts, resultados, capturas sintéticas y logs. Verifica también los 4199 archivos de los dos snapshots. Los hashes de fuente son de las representaciones exportadas por Git; esta revisión no prepara ni renueva un manifiesto de ejecución viva.

## Límites

Los contadores de `socket.connect`, `connect_ex`, `create_connection`, `getaddrinfo` y `sendto` fueron cero. Se usaron bases SQLite sintéticas, un ledger temporal aislado y el detector local instalado; las fronteras HTTP/SDK estuvieron simuladas. No se ejecutó el puente, no se leyeron claves, entorno privado ni `local_settings.py`, y no se abrió ninguna base de usuario o ledger persistente de producto.

No hubo llamadas pagadas, repetición del ensayo vivo, validación de proveedor real, Office ni revisión humana. La causa de la última clasificación del ensayo anterior continúa siendo desconocida. La revisión demuestra que nuevos fallos compatibles pueden conservar un código seguro; no demuestra cuál ocurrió entonces ni permite liberar su reserva. No se hicieron cambios de producto, `git add` o commits.

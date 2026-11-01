# Revisión independiente del enmascarado local: c85d019

**Dictamen sobre el candidato fijo: dos hallazgos reproducidos, LOCAL-SEC-1 (P1) y LOCAL-SEC-2 (P2), pendientes de corregir en este commit.** Los 85 tests focales existentes pasan; las pruebas independientes muestran los dos fallos descritos a continuación. Este informe conserva el resultado original aunque una revisión posterior cierre los hallazgos.

Base `700389c216592db1e0c8725749bb4fd02cf3fa10`; candidato `c85d01963cc4e03a43162412f851e67139e602a6`. Revisor separado de la implementación; habilidad aplicada: `C:/Users/javi/.codex/skills/security-reflexes/SKILL.md`, después de leer AGENTS, RTK, dominio y tracker. Se revisó una exportación fija de Git, no el checkout que cambiaba en paralelo. No se leyó `local_settings.py`, variables de entorno ni secretos; el exportador rechaza esos nombres antes de crear el archivo. No se modificó producto ni se hicieron commits, despliegues, llamadas pagadas o cambios en bases del usuario.

## LOCAL-SEC-1 — P1: los números JSON evitan completamente la detección

**Ubicación exacta del candidato:** `regulai/front/local_masking.py:160–161`, rama `if isinstance(value, _Number): return str(value)`. El parser crea `_Number` tanto para enteros como para decimales; esta rama los serializa sin aplicar ningún detector.

**Precondición:** una empresa tiene una máscara local activa, autorizada y configurada para `both`; el usuario está autorizado a enviar a su proveedor. No requiere privilegios administrativos del usuario que envía ni modificar políticas. La entrada contiene un teléfono o tarjeta como valor numérico JSON, formato habitual en datos estructurados.

**Reproducción:** enviar `{"telefono":612345678,"tarjeta":4111111111111111}` por `/chat/send/`, `/api/chat/send/` y el POST de `/chat/`. Con spaCy y el modelo instalados reales, los tres recorridos terminan `completed` y el SDK OpenAI real llega a su transporte simulado con ambos números intactos. El mismo teléfono y tarjeta en texto plano o como cadenas JSON sí quedan enmascarados. El array `[612345678,4111111111111111]` también evita la detección. La tarjeta es el valor sintético común que pasa Luhn; no se usaron datos de una persona.

**Impacto:** D2 se omite de manera determinista según el tipo JSON: datos que el detector ya sabe reconocer salen hacia el generador mientras la ficha registra la transformación local como completada. No es una de las dos omisiones declaradas del corpus —credencial sin etiqueta y correo con «arroba»— ni una incertidumbre de NER. El control especial de tipos excluye por diseño todo el contenido numérico.

**Corrección requerida:** comprobar también los tokens numéricos, incluidas representaciones numéricas equivalentes que se admitan. Sustituir los valores detectados o rechazar el lote de forma atómica si el contrato exige conservar un tipo incompatible con la máscara. Conservar precisión y representación de los números no sensibles. Acotar cualquier normalización decimal/exponencial para que no introduzca un consumo de recursos desproporcionado. Cubrir objetos, arrays y las tres entradas HTTP en la regresión.

Evidencia: [pruebas independientes](../../../evals/reports/pilot-independent-local-20261003-01/security/review_checks.py), [log rojo](../../../evals/reports/pilot-independent-local-20261003-01/security/independent.log), [payloads sintéticos capturados](../../../evals/reports/pilot-independent-local-20261003-01/security/observations.json) y [metadatos de ejecución](../../../evals/reports/pilot-independent-local-20261003-01/security/independent-result.json). Son dos métodos con cinco subfallos: dos variantes directas y las tres entradas HTTP. No se capturaron cabeceras de credenciales.

## LOCAL-SEC-2 — P2: deshacer 0032 reactiva como HTTP una configuración local

**Ubicación exacta del candidato:** `regulai/front/migrations/0032_obfuscationconfig_backend.py:8–10`: la reversión elimina `backend` sin cerrar las filas locales antes de perder esa distinción. `regulai/front/forms.py:9` permite guardar conjuntamente `backend=local`, la URL anterior y `active=True`; el POST de edición guarda esa forma en `regulai/front/views.py:2849`.

**Precondiciones:** el administrador cambia una máscara HTTP existente a local y conserva la URL en el formulario, comportamiento permitido y normal al editar. Más adelante, un operador revierte la migración a 0031 y restaura el código base. El destino de política continúa siendo `obfuscation:<id>`; no distingue la autorización local del HTTP que existía antes. Se requiere esta operación de recuperación: no es un bypass durante la ejecución normal del candidato.

**Reproducción:** en SQLite de prueba en memoria, crear la fila HTTP, cambiarla mediante `ObfuscationConfigForm` a local, ejecutar la reversión con `MigrationExecutor` y cargar el `masking.py` exacto de la base `700389c`. La fila queda con `active=True` y `api_url=https://former-mask.example.invalid`; la política permanece intacta. El wrapper de la base acepta la fila y el transporte HTTP simulado recibe el original `ana.rollback@example.invalid` en `/api/mask`. Se conservaron tanto la fuente base utilizada como su hash.

**Impacto:** una recuperación transforma una elección vigente de procesamiento local en salida HTTP de originales sin reautorización de la empresa. Además, la cota explícita `0` introducida para local puede pasar a describir el HTTP recuperado. La prueba no demuestra cobros reales ni una elevación entre empresas.

**Corrección requerida:** antes de eliminar el campo en sentido inverso, desactivar las filas locales, conservando sus URLs y demás datos; exigir una reactivación explícita para usar HTTP. Otra solución conservadora es impedir la reversión mientras existan locales activas y documentar su resolución. El test debe conservar también los registros HTTP históricos, política y auditoría, pero incluir el estado nuevo local y no solo datos que ya existían en 0031.

Evidencia: [PoC de reversión](../../../evals/reports/pilot-independent-local-20261003-01/security/rollback_check.py), [log rojo](../../../evals/reports/pilot-independent-local-20261003-01/security/rollback.log), [captura sintética](../../../evals/reports/pilot-independent-local-20261003-01/security/rollback-observations.json), [resultado](../../../evals/reports/pilot-independent-local-20261003-01/security/rollback-result.json) y [wrapper exacto de la base](../../../evals/reports/pilot-independent-local-20261003-01/security/base-masking.py). SHA256 de este último: `2508742be605a0c6f74d5c4a5a4fca7860667b9bbdc139ca3b16bb502835f697`.

## Cobertura comprobada

| Superficie | Evidencia y resultado |
| --- | --- |
| Runtime, dependencias y red | Detector real spaCy `3.8.16`, `xx_ent_wiki_sm` `3.8.0`; 74 requisitos coinciden con las versiones instaladas. Modelo y spaCy declaran MIT. En todas las suites se bloquean `socket.connect`, `connect_ex`, `create_connection`, `getaddrinfo` y `sendto`: cero intentos. No existe fallback HTTP al fallar local. |
| D2, JSON y marcadores | P1 anterior. Los marcadores exactos no protegen datos arbitrarios entre corchetes; los valores de `id`/`source_id` siguen detectándose y el alias `S1` sobrevive. Lote demasiado grande detiene la cadena antes del siguiente HTTP. JSON malformado se detecta como texto; JSON muy profundo puede producir `RecursionError`, que el flujo HTTP trata como fallo cerrado. |
| D4, empresa y consentimiento | Tests de YARA sobre original, restricted incluso hacia destinos privados, máscara ajena/inactiva y cambios de backend/identidad: sin regresión observada. Confirmar consentimiento no elimina la obligación. Prueba propia cambia local a HTTP durante la detección real: solo queda la llamada local de API cero; no se llega a generación ni al nuevo HTTP. |
| Citas y respuesta | Prueba propia crea una cita inventada que, después de ocultar el correo, coincidiría con el marcador de la fuente. La comprobación previa conserva `quote_not_found`, impide verificación semántica posterior y no publica respuesta. Las citas válidas y aliases pasan la suite del candidato con detector y SDK reales. |
| Errores y registros | Excepción sintética con contenido sensible desde `_load_model`: respuesta, recibo y log conservan códigos sanitizados; no contienen original ni detalles de la excepción. No se crea mapa reversible de valores. |
| Costes, reserva y estado | Local se registra `transport=local`, coste/cota `0`, `configured_zero`, ámbito `api`. Los tests cubren presupuesto cero, cadenas mixtas, reserva completa, HTTP incierto, fallo antes de transporte y repetición sin reenvío. No se confunde API cero con infraestructura gratuita. |
| Simulador y configuración | Máscara local antes de Jev, auditoría previa, fallo cerrado, pertenencia a empresa, roles, cambio de backend y propuesta separada de activación; comprobados por suites focales. Inspeccionados `forms.py`, vistas, admin, modelos, bootstrap y sus cambios en los scripts de laboratorio. |
| Migración/reversión | La prueba existente conserva HTTP histórico, URLs, actividad, política y auditoría al subir/bajar. La prueba nueva revela P2 para filas cambiadas a local. Solo se migró SQLite efímero. |
| Carga acotada | Cuatro entradas sintéticas individuales: 20 KB y 80 KB de texto, 80 KB de marcadores/correos y 78 KB de números JSON. Con el modelo caliente tardan 0,110 / 0,687 / 1,125 / 0,141 s. Sin fallo ni red; no es una prueba de capacidad, inundación o carga masiva. El límite temporal de una inferencia CPU sigue siendo cooperativo, como declara el contrato. |

Las revisiones anteriores S1/S2/S3 y SEC-1 se trataron como cerradas y contexto, sin reabrirlas sin regresión. Los cambios posteriores de evaluación y UI que aún no formaban parte de este candidato están fuera de este dictamen fijo.

## Comandos, resultados e integridad

Desde la raíz del repositorio, todos los comandos shell comenzaron con `rtk`. El runner configura el snapshot y `regulai.test_settings`, comprueba SQLite `:memory:` e impide sobrescribir resultados ya emitidos. Las rutas de entrada de las pruebas son exclusivamente sintéticas.

```text
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\export_snapshot.py
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py front.test_local_masking front.test_local_masking_integration front.test_required_masking front.test_pipeline_privacy front.test_policy_simulator
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py --run-name rollback rollback_check
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py --run-name bounded-workload bounded_workload
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py --run-name supplemental supplemental_checks
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\run_review.py --run-name supplemental-v2 supplemental_checks
rtk proxy .venv\Scripts\python.exe .claude\review-local-security\audit_snapshot.py
```

| Ejecución | Exit | Resultado | Tiempo completo |
| --- | --- | --- | --- |
| Exportación | 0 | 1.319 archivos fijados | — |
| `independent` | 1 | 3 métodos: un control pasa; dos métodos reproducen P1 con 5 subfallos | 9,422 s |
| `candidate-tests` | 0 | 85 tests pasan | 29,390 s |
| `rollback` | 1 | 1 método reproduce P2 | 1,844 s |
| `bounded-workload` | 0 | 1 método, 4 cargas individuales pasan | 4,735 s |
| `supplemental` inicial | 1 | 4 controles pasan; un error de expectativa de la prueba: admitía solo transformación, aunque el rechazo atómico también es correcto | 4,625 s |
| `supplemental-v2` | 0 | 6 controles pasan; se acepta rechazo atómico y se añade prueba HTTP que confirma el cierre | 4,859 s |
| Integridad | 0 | 1.319 hashes sin cambios; 74 versiones coincidentes | — |

El fallo de expectativa inicial se conserva en su log y en `supplemental-checks-v1.py`; no se corrigió ni alteró el producto para obtener el resultado verde. Las evidencias complementarias están en [controles](../../../evals/reports/pilot-independent-local-20261003-01/security/supplemental-observations.json), [carga](../../../evals/reports/pilot-independent-local-20261003-01/security/bounded-workload-observations.json) y sus logs/resultados junto a cada archivo.

[Manifiesto del snapshot](../../../evals/reports/pilot-independent-local-20261003-01/security/snapshot-manifest.json) y [auditoría de integridad](../../../evals/reports/pilot-independent-local-20261003-01/security/integrity.json), con hashes de fuentes y evidencias. SHA256 del archivo Git exportado: `80bbd477077af0f9e03a12b9da50b487fcf8deedb7f1efd3a3eb511010ab774e`. Hash observado de los archivos de datos del modelo: `4f5b7a5c5baf29c9e940befeb1f02a3021acc22806e3c1cbcef48e2078a2477a`. El requisito fija el wheel esperado `6f3c4b853852ea9e9d2dc76cc950dddb10a7e4c42d813308caefe6c5e8be2f0a`; la metadata instalada conserva la URL, pero no su hash de descarga. Esta revisión no volvió a descargar el wheel ni vincula criptográficamente el hash observado del directorio con aquel archivo externo.

**Límites:** no auditoría remota nueva de vulnerabilidades de paquetes, proveedores vivos, llamadas monetarias, Office, revisión humana ni medición de calidad general. No se arrancaron Docker/PostgreSQL ni procesos de laboratorio. El éxito de tests concretos no garantiza detección universal; se mantienen las dos omisiones declaradas del corpus y las demás limitaciones documentadas. Este dictamen no aprueba un piloto real ni sustituye la revisión del commit que corrija P1/P2.

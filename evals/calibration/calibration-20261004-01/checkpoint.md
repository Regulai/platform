# Checkpoint — calibration-20261004-01

## Cierre vigente 2026-10-04

Campaña cerrada a nuevos pagos por `failed_or_uncertain_provider_call` en R4, P0619/router. HTTP 200 con distribución de categoría sumando 0,99, rechazada antes del umbral. Se conserva la reserva; no se reintenta ni se ejecuta ningún lote posterior. No volver a iniciar llamadas automáticamente.

Runtime final `b3fea6a63761c06ef66695fee26377d23786c347`; evidencia local/real/ledger guardada en `85ca5a9`. Configuración final `privacy-v5-legacy-policy`, umbral de manipulación omitido/None. R4 0,40 NO adoptado. `final_selection.json` SHA a33dad5bcb906f0bf26b55dfab04aa90be2f299faa4780216f157c68282d72a5 fue fijado antes del release único de A, SHA 4e8828c907eb19bccfe221f6a3ec68b3f75de23a4f9037d99b434be6c8eb085b.

Corpus completo de 4.004 casos evaluado localmente por brazo: valores sensibles 1.872→1.905/2.418, preservados 2.187/2.243 ambos. Las 33 ganancias son de una familia de desarrollo; validación y reservado empatan. Reservado 571 casos/372 grupos, 248/323 ocultados, 225/243 preservados; 120 HTTP por brazo con 114 controles aprobados, cero red y fuentes intactas. No hubo ajuste posterior. El reservado ya fue usado y no sirve como no visto en otra campaña.

Pago: base y v5 12 combinaciones cada uno y cero entregas. R4 5/12 combinaciones, una entrega «29 días» (presencia, no corrección automática completa), una llamada incierta. En conjunto, 49 HTTP (29 clasificación, 11 generación, nueve juez) y 40 máscaras locales de coste cero. Ledger reconciliado RO: comunicado 0,002794596 USD; estimado 0,00961932; exposición 0,076271376; reservas inciertas 0,006 incluidas en la exposición; remanente 1,583728624. Los 110 asientos históricos están intactos. Exposición total con conversión/margen: 0,091729495 EUR. No gastar el remanente tras esta parada.

Cinco puertas finales `gates-02` sobre b3fea6a: exit 0; 452 tests (450 OK y dos expectedFailure NER), 150 simulaciones con cero fallos de control/cero pagos, migraciones y ambas auditorías de dependencias verdes. Revisores finales Astra Max nuevos, seguridad y utilidad, verifican el commit fijo y adendas de cierre. Ningún agente cambia runtime/oráculos durante el cierre.

Limitaciones: 2.043 grupos operativos no acreditan 1.500 familias semánticamente independientes; validación/reservado tienen un caso documental y ninguno muy largo cada uno. Muestra real estratificada y confirmación remota no ejecutadas por la parada. Precisión/recobrado exhaustivos y referencias semánticas siguen incompletos. La configuración semántica base se conserva, sin ganador confirmado. Informe principal: `docs/plan-blackhat/informe-calibracion-community-20261004.md`.

Informes independientes y documentación de cierre finalizados. Seguridad reconcilia 40/40 comprobaciones; utilidad comprueba el informe principal y los límites. Las 444 fuentes de las puertas finales conservan sus hashes. Los artefactos y la documentación se guardan en commits locales, con índice de cierre `closure.json`. Sin push, despliegue, publicación, nuevos contactos, modificación de DB usuario ni participantes humanos. Archivos ajenos preservados; no hay procesos de ensayo en ejecución ni lock del piloto. La campaña no se reanuda automáticamente.

## Hito histórico 2026-10-04T08:32Z

- Runtime b3fea6a63761c06ef66695fee26377d23786c347; reservado CERRADO, manifiesto corpus9d9b0951e754cb544032e6743d736bd1dfc8696066a977652b596a61520b0e50. No leer reservado ni builder hasta final_selection y liberación A.
- Corpus4004/2043grupos operativos/1181documentos; no acreditadas1500familias independientes. Dev2813/val620/res571; val/res sólo1documental y0muy largos. Dev1201→1234/1572 ocultados,1716/1742 preservados; val423/523 y246/258 ambos.33ganancias de UNA familia,0pérdidas anotadas.
- baseline-smoke-02 y candidate-smoke-01 completados: cada uno12combinaciones/4familias,19HTTPexternos,0entregas,9bloqueos+3fallos. No incertidumbre nueva/DBusuario RO inalterada. V5 no mejora entrega en este smoke.
- Ledger acumulado: comunicado0.002561412; estimado0.00844158; conocido0.011002992; exposición0.065225712; incierto0.003histórico; restante1.594774288USD. Histórico inicial comunicado0.001461138/estimado0.00475530/conocido0.006216438/exposición0.038440878.
- R4 preregistrado08:17Z; override sólo manipulación .35/.40/.50, None conserva legacy. GREEN5tests/12HTTP/24eventos sintéticos sin red;66pruebas anteriores OK. Contrafactual v5: .40 mínimo elimina6/6bloqueos benignos y conserva3/3ataques, sin inferir entrega. Demás señales siguen.2. Agregados de entrega/reintentos U1 corregidos.
- r4-smoke-01 preparado con .40, manifest07c306ebf6e5ad258b3ad4a282cb34476e4d6f370d07d7a47fddb0fc19ed56d6, peor.308USD, offline12exit0,preflightreadytrue. Próximo activar/real centralizado. Después muestra validación estratificada6 (corto/largo,fácil/difícil) base/candidato con confirmación protegida.
- Revisores NUEVOS security_final/utility_final revisaron3940 y revisanb3fea6a; seguridad80tests independientes OK. r4_tests terminó, archivos quietos. A preparado para una liberación cuando selección fija. gates-01 sobre3940 cincoexit0/446tests/150offline; gates-02 sobreb3fea6a sesión27252 en curso.
- Próximo final: fijar configuración+SHA+selección, liberar A, reservado completo local y muestra real emparejada UNA fase sin ajuste posterior; revisores y reconciliación; informe/tareas/commits locales. Sin push/deploy ni DBusuario escrita. No agotar saldo porque sí.

## Notas históricas (no estado vigente)

Inicio 2026-10-03T23:12:23Z (4 octubre en Madrid); ventana de nuevas llamadas hasta 2026-10-04T23:12:23Z. Techo conjunto 2 EUR incluyendo exposición histórica. Sin nuevas llamadas hasta reconciliar ledger, FX, tarifas, manifiestos y pruebas.

Base observada `9d7f942`, runtime anterior `1af809f`; Git tracked limpio. Preservar MESAS_RETIRO.pdf, plantilla.pdf, plantillaInformeTecnica.pdf, docs/brainstorming-regulae-vigia13-2026-10-02.md, docs/plan-blackhat/prompt-validacion-piloto-astra-max.md. No parar procesos ajenos. No escribir DB usuario ni mostrar secretos. Todos comandos shell con rtk.

## Propiedad y contrato acordado

- A `corpus`: corpus/**, scripts/build_calibration_corpus.py y auxiliares exclusivos, tarea37. Custodia del reservado; sólo hashes/esquema antes de final.
- B `privacy`: local_masking.py, classification.py, test_calibration_privacy.py, privacy/**, tarea38. Propone cambios antes de editar runtime; no cambia servicio/política.
- C `evaluation`: evaluation.py, evaluation_budget.py, test_calibration_evaluation.py, test_calibration_budget.py, scripts/calibration_local_checks.py, evaluation/**, tarea39. Sin mutar ledger real; propone interfaz antes.
- Root: chat_service.py, verification.py, política compartida, ejecutor scripts/run_calibration_campaign.py, integración, preregistro, tarea36, informe final y nuevas revisiones independientes.

Todos los spawn aceptaron `model=gpt-6-astra`, `reasoning_effort=max`, `fork_turns=none`. Modelo root no verificable. Máximo cuatro agentes activos. Commits serializados por root con rutas explícitas; nunca git add global.

Interfaz corpus acordada: JSONL v2 por development/validation/reserved; campos compatibles históricos, familia/plantilla, prompt/history/documents, clasificación/acción/oráculo, redactions/preserve/evidence/provenance/length. API load_partition development/validation; provider_input whitelist sin metadatos; verify_integrity sin revelar reservado. Bandas preregistradas 256/2048/16384/65536 bytes; casos por encima de límites reales sólo locales.

## Estado

- Lectura inicial realizada, planes05/06/07/11/12 y tareas32–35; informes históricos son antecedentes.
- Rondas medidas: R1 normalización, R2 correo en palabras, R3 unión de spans. R1/R2 descartadas por regresión; v5 provisional. Umbrales/rúbrica intactos.
- Nuevas llamadas: 0; coste nuevo 0. Ledger leído RO: exposición histórica0.038440878 USD, incierta0.003; techo operativo conjunto1.66 USD.
- A corrige agrupación semántica previa a selección y custodia reservado. B terminó código/probes. C termina wrapper y corrige captura. Root integra ejecutor/muestras.
- Revisor independiente nuevo security activo sobre4fdbe1a; requiere comprobación final posterior a correcciones. Revisor utility aún pendiente de plaza.

## Actualización durante implementación

- Snapshot base 620 archivos: `.claude/calibration-20261004-01-baseline`, archivo ZIP SHA256 `9be15667a063754b61a4dc87d099e3fd1d16718c63f2c01e02dec0b36f8a2688`. Manifest `baseline.json`; detector base retenido en `runtime-snapshots/base/local_masking.py`.
- Nueva ejecución completa base `baseline-run-01`: 44 casos detector (37 completos, 27/32 valores ocultos, 61/66 conservados), 264 recorridos HTTP (258 controles), red externa0, integridad correcta. Resultados anteriores intactos.
- Ledger RO confirmado por C: 110 entradas, 109 completed y1 outcome_unknown; exposición0.038440878 USD, incierta0.003. Todavía ninguna nueva llamada pagada.
- Economics: ECB2026-10-02 1.1225USD/EUR; margen35%; techo operativo1.66USD, saldo inicial1.621559122. Fuentes oficiales guardadas con hashes. El usuario pidió dejar comprobaciones adicionales de tokens; se continúa implementación con límites fijados.
- R1 normalización/R2 correo con palabras mejoraron probes pero revisión descubrió fuga por puntuación Unicode en secreto etiquetado. Ambos candidatos no aceptables sin R3 unión de spans originales+normalizados. R3 verde focal; detectorv5. No cambian classification, umbrales, rúbrica ni Decimal.
- Captura causal local: «Calcula»/«Resume» se sustituyen por PERSON antes de clasificación/juez. Scope requirements ya correcto; no atribuir scores históricos al efecto sin comparación viva. Falsos positivos NER/citas permanecen.
- Root implementó `scripts/run_calibration_campaign.py`: reutiliza evaluation.run_pilot, snapshot detectorbase cargado sin sobrescribir archivos, puente credenciales RO, guard8000B/máx512, ledger único y asignación final protegida. Tres testsrunner nuevos verdes. No real hasta pruebas C y muestras A congeladas.
- Commits: B2732be1; núcleo C3cbbf19; ejecutor root147b86d; congelación/economics4fdbe1a. Nuevas ediciones root runner (adaptador IDs corpus/precios por snapshot) y C recorder/tests/wrapper pendientes de commit; A aún no commit corpus.
- Primer smoke ampliado C:2397 local,0errores,30HTTP,27 controles,red0. Sólo1544casos tienen anotaciones;1369 pasan. Los853 sinanotaciones NO se cuentan como aciertos. Tres fallos son D0728 neutral en tres HTTP por quote_not_found, rechazo seguro con pérdida de utilidad. Informe preservado, NO selección final.
- A detectó plantillas semánticas compartidas pese IDs separados: documentales locales y PII locales se agrupan y anclan a desarrollo porque ya vistos. Freeze1fb99e se preserva superseded; no se cambian oráculos ni se mueve ningún desarrollo visto al reservado. Núcleo4000 cuotas intactas; cuatro nuevos fixtures complementarios previstos. Reparto por familias cerca61/21/18; por casos será desequilibrado y se declarará. Objetivo1500familias independientes no se acredita sólo por IDs/clustering.
- Root leyó sólo los cuatro casos desarrollo smoke L0545/P0619/D0437/I0975; reservado no abierto. Esperar nuevo freeze A para medidas válidas.
- Revisor reprodujo secretos JSON escapados en recorder y respuestas reflejadas retenidas/ledger. C corrige cierre previo a SDK/parser, usa sólo credenciales ficticias. No activar pagos hasta probes verdes y fuentes quietas.

## Próximo paso

Terminar correcciones A/C y commits serializados. Medir base y candidato desarrollo con wrapper final, ejecutar smoke pagado emparejado sólo tras preflight/activación auditada, seleccionar con validación. Fijar selección antes de que A libere reservado una sola vez. Confirmación protegida. Refrescar precios en NUEVO snapshot si cambia día UTC, sin sobrescribir evidencia anterior. Cinco puertas tras último código; dos revisores nuevos sobre commit fijo final. No push/deploy ni cambios en DB usuario.

## Continuación 2026-10-04T08:03Z

Tras interrupción del runtime de agentes, no se habían iniciado nuevas llamadas. HEAD3940fdc; root conserva0pagos y ventana hasta23:12:23Z. Nuevos revisores security_final/utility_final AstraMax aceptados; el revisoranterior quedóinterrumpido paraevitarduplicación. CustodiaA pendiente reanudación. Dev2813 base/candidato y validation620 concluyeron conhashesestables/red0. Dev1201→1234/1572valoresocultos,1716/1742preservesambos; validationempate. Históricoactual40/44,31/32redactions,61/66preserve,258/264HTTP; fuenteintacta.

Baseline-smoke-01 se preserva superseded(sinactivar/pagar) trasfixJSONduplicado; baseline-smoke-02 manifest140b78da56b9fccf0307fe6612a0d9b1ce2826fad6a65bd21ef9e900bafd1fe5 preflight08:03UTC readytrue, DBROunchanged; offline12exit0. Cinco puertasgates-01encurso. Próximo: cierreprobesrevisor,activarledgerauditado+únicorealsmokebase, parearcandidate, final_selection inmutable yreleaseA, holdoutbase/candidateuna fasefinal, informeycommits.

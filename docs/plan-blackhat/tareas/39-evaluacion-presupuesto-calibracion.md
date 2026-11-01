# 39 — Evaluación y presupuesto de la campaña de calibración

**Status:** implemented and verified — corpus local completo, frontera real observada y ledger reconciliado sin borrar reservas.
**Blocked by:** comparación remota estratificada y confirmación final interrumpidas por outcome_unknown; métricas semánticas sin referencia suficiente siguen sin medir.
**Propietario:** C, evaluación/presupuesto; el orquestador centraliza toda llamada real y toda mutación del ledger compartido.
**Especificación:** [11](../11-evaluacion-reproducible.md), [12](../12-demo-y-salida.md),
[32](32-banco-adversarial-y-datos-personales.md), [33](33-limites-del-detector-adversarial.md),
[34](34-bloqueos-semanticos-en-casos-benignos.md), [35](35-frontera-numerica-del-umbral.md).

## Aceptación y decisiones

- [x] Extensión explícita de techo y ventana, con cadena de aprobación y procedencia fechada de cambio/tarifas.
  `authorization`, aprobaciones previas y `calls` permanecen intactos. El constructor nunca aumenta el techo.
- [x] Techo agregado aprobado de hasta 2 EUR; cota USD no superior a `EUR × USD/EUR ÷ (1 + margen)`.
  Registrar términos no acredita por sí mismo autenticidad de una fuente: la verificación oficial corresponde al ejecutor.
- [x] Reserva atómica y revalidación de autorización dentro del bloqueo, además de las comprobaciones anteriores y posteriores.
  Carrera de dos reservas, revocación, expiración, interrupción, objetos obsoletos y reejecución probados sin red.
- [x] Captura sintética optativa de cuerpos finales de clasificación, generación y juez, roles/rúbrica/configuración/hashes.
  No se leen cabeceras de autorización; las credenciales suministradas como valores prohibidos nunca se serializan si aparecen reflejadas.
  La captura no consume por anticipado las respuestas del juez y mantiene su límite de lectura.
- [x] La captura registra un rechazo previo al transporte como `transport_started=false`; no lo presenta como envío.
  El ejecutor conserva reservas inciertas; una ausencia de coste no se convierte en cero.
- [x] Referencias exactas y números con gramática acotada distinguen corrección retenida de utilidad entregada.
  Coincidencias `contains` solo miden presencia, nunca corrección. Los costes por correcta incluyen casos evaluables retenidos/fallidos.
- [x] `validation` conserva su identidad en el motor existente. Historial sintético completo usa los modelos y selección de historial del producto.
- [x] Corpus de desarrollo y validación medido con hashes estables; comparación local base/candidato.
- [x] Selección estratificada local y regresiones críticas por las tres entradas HTTP con frontera de transporte simulada.
- [x] Una sola apertura final local del reservado, selección fija y liberación custodiada por A; 571 casos y 120 recorridos HTTP por comparador, sin ajustes posteriores.

## Evidencia observada

La lectura **solo de lectura** del ledger al inicio de esta tarea encontró 110 entradas, 109 completadas y una incierta,
exposición conservadora `0,038440878 USD` y reserva incierta histórica `0,003 USD`. No es el saldo final de la campaña;
C no modificó ese ledger ni inició llamadas a proveedores.

Runtime integrado por root en `3cbbf19`. La batería de 66 pruebas de evaluación/piloto/presupuesto/extensión/smoke pasó
en 36,428 s, salida 0. Tras los ajustes finales de métricas y partición, 22 focales de calibración pasaron en 0,594 s,
salida 0. [Comandos y alcance](../../../evals/calibration/calibration-20261004-01/evaluation/runtime-checks.json).
No son los 404 tests históricos ni sustituyen las cinco puertas finales de integración.

El ejecutor [calibration_local_checks.py](../../../scripts/calibration_local_checks.py) bloquea red, usa SQLite en memoria,
rechaza integridad de corpus incorrecta y conserva hashes de fuentes/manifest/API/ejecutor.
Reservado exige `--split reserved --holdout-release <archivo>` y la validación de autorización del custodio en la API;
ese modo no se ha ejecutado durante el trabajo de C. El release se hashea y se comprueba de nuevo al finalizar.
Reutiliza `run_adversarial_community.run_http`; respuestas de proveedores y clasificación offline son fixtures uniformes.
Los campos sin observación suficiente permanecen `null`, con denominadores y número de familias.

La revisión independiente encontró una omisión ante credenciales reflejadas mediante escapes Unicode de JSON y en
respuestas conservadas/identificadores del ledger. La corrección comprueba valores JSON decodificados y cierra la respuesta
**antes** de propagarla al SDK o al parser, manteniendo la reserva. Solo se examina el identificador público `x-request-id`
de la respuesta, nunca cabeceras de autorización. La regresión del flujo completo usa el servicio real y transportes simulados:
no conserva la credencial ficticia en respuestas, ledger ni captura, no entrega respuesta y no libera la reserva incierta.
Tras esa corrección pasaron 27 focales en 2,806 s, salida 0; el revisor revalidará el commit final por separado.

El [smoke de desarrollo](../../../evals/calibration/calibration-20261004-01/evaluation/development-wrapper-check-01/interpretation-superseded.json)
procesó 2.397 casos locales y 30 recorridos HTTP, con cero sockets/DNS y coste externo cero. De 1.544 casos con anotaciones,
1.369 superaron todas sus comprobaciones. Los otros 853 no tienen un denominador de anotaciones y no se cuentan como éxitos.
27/30 controles HTTP pasaron; D0728/neutral conserva tres rechazos `quote_not_found`, uno por entrada HTTP.
La pasada queda **superseded para selección** porque el custodio detectó grupos de plantillas semánticas compartidas;
sirve para verificar instrumentación y no sustenta una configuración ganadora ni calidad semántica.

## Límites

La desaparición de una cadena anotada no demuestra anonimización ni eliminación completa de una entidad: puede quedar un sufijo.
El detector devuelve texto transformado, no predicciones completas de spans adjudicadas; precisión/recobrado de entidades quedan
sin medir. Las métricas locales sí cuentan desaparición de valores anotados y conservación de texto benigno.
Documentos cuyo texto de corpus sea un extracto esperado requieren la extracción real para afirmar cobertura del archivo.
La integración usa los lectores reales; no se afirma lectura completa de formatos por disponer de un texto de referencia.
La latencia informa N, mediana y p95 por rango más próximo, sin significación estadística basada en variantes correlacionadas.

## Cierre de orquestación

Se hicieron 49 llamadas externas nuevas y 40 operaciones locales de máscara con coste API cero. La última clasificación HTTP 200 tenía probabilidades sumando 0,99: se rechazó y conservó 0,003 USD inciertos; no hubo llamadas posteriores. Base y v5 completaron doce combinaciones cada uno; R4 sólo 5/12.

Exposición total incluido histórico: 0,076271376 USD, de ella 0,006 USD inciertos; comunicado 0,002794596 USD, estimado 0,00961932 USD. La [reconciliación RO y cadena](../../../evals/calibration/calibration-20261004-01/economics/final-reconciliation-01/summary.json) prueba que los 110 asientos históricos permanecen intactos. El [informe](../informe-calibracion-community-20261004.md) separa casos sin anotar, retención/entrega y costes. U1, el agregado de beneficio entregado, queda corregido; revisión independiente sobre b3fea6a y cinco puertas con 452 tests y 150 simulaciones verdes.

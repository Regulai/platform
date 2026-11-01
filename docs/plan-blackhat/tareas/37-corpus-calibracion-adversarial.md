# 37 — Corpus ampliado y custodia de referencias

**Status:** implemented — construcción y auditoría estructural verificadas; independencia semántica fuerte y referencias manuales pendientes.
**Blocked by:** adjudicación independiente para acreditar todas las familias; PINT completo no es público en la revisión disponible.
**Propietario:** agente A (corpus y custodio del reservado).
**Especificación:** [encargo de campaña](../prompt-iteracion-adversarial-2eur-20261004.md), [evaluación](../11-evaluacion-reproducible.md), [banco histórico](32-banco-adversarial-y-datos-personales.md), [límites del detector](33-limites-del-detector-adversarial.md).

## Aceptación y resultado

- [x] Núcleo de 4.000 entradas completas distintas con cuotas 1.000 legítimas, 1.000 inyección, 800 PII, 800 documentales y 400 cálculo; cuatro nuevos complementos para confirmación sin reutilizar plantillas. Se preservan los 44 históricos fuera de ese recuento.
- [x] 500 negativos difíciles; 65,7 % con etiqueta española y 63,16 % excluyendo los 103 Gretel lingüísticamente ambiguos; longitud 25/35/30/10 % con bandas fijadas antes de generar.
- [x] 1.181 documentos distintos en siete formatos; doce fixtures heredados incluyen imágenes/escaneo/páginas vacías/fórmulas con y sin caché, manteniendo su cobertura y origen por bibliotecas.
- [x] Revisión y hash de cinco fuentes primarias, licencias por componente, originales/adaptaciones conservados y descargas sin ejecución de scripts externos.
- [x] División por grupos de 1.250/421/372 familias (61,2/20,6/18,2 %); 2.813/620/571 casos. La diferencia por casos procede de dos plantillas grandes que se mantienen completas en desarrollo. Cero documentos y plantillas explícitas cruzados; deduplicación semántica universal no acreditada. El reservado sólo se inspecciona para esquema/oráculos por A antes de medir.
- [x] 2.418 spans sensibles, 2.243 spans a preservar, citas, 400 referencias GSM8K y un conteo complementario pasan la auditoría sin producto ni proveedores.
- [x] Muestras sintéticas congeladas antes de resultados; API de entrada permite únicamente campos de solicitud.
- [ ] Acreditar al menos 1.500 familias semánticamente independientes mediante revisión suficiente. Se obtienen 2.043 grupos operativos tras normalización/deduplicación y fusión conservadora de plantillas locales, con límites declarados; no se cuenta ese número como adjudicación externa.
- [ ] Resolver oráculos `manual` mediante referencia suficiente o adjudicación; no cuentan como correctos por conveniencia. PINT sólo aporta ejemplos públicos de estructura, no su banco completo.

## Evidencia y reproducción

[Método y límites](../../../evals/calibration/calibration-20261004-01/corpus/README.md),
[atribuciones](../../../evals/calibration/calibration-20261004-01/corpus/ATTRIBUTIONS.md),
[manifiesto público](../../../evals/calibration/calibration-20261004-01/corpus/manifest.json).

`scripts/build_calibration_corpus.py` no importa el producto y rechaza sobrescribir un manifiesto congelado. `scripts/validate_calibration_corpus.py` comprueba datos, hashes, separación, spans y aritmética sin red. `corpus/api.py` rechaza cargar el reservado y permite comprobar su integridad sólo por bytes. Cachés grandes y `pyarrow==23.0.1` aislado no entran en Git ni cambian dependencias del producto.

La corrección de la referencia de contar tres palabras y la selección del lote exclusivamente sintético ocurrieron en la auditoría previa, sin resultados de producto. La revisión metodológica posterior fusionó plantillas locales cuando C ya había iniciado instrumentación de desarrollo, sin consultar sus resultados. Se conservó íntegro el congelado `1fb99eb7…` en `superseded/`, todos sus casos vistos permanecieron desarrollo y sus 4.000 oráculos se comprobaron idénticos. El congelado definitivo es `9d9b0951e754cb544032e6743d736bd1dfc8696066a977652b596a61520b0e50`. La API final sólo abre reservado con liberación fechada de A y hashes de corpus, selección y candidato coincidentes. La evidencia de componentes la generan B/C y el root; no se presenta aquí como ejecutada por A.

## Apertura final

A emitió la [liberación única](../../../evals/calibration/calibration-20261004-01/corpus/reserved-release.json) el 4 de octubre a las 08:35:56 UTC, después de verificar la selección y sus hashes. Autoriza sólo la comparación local final, sin ajustes posteriores ni pagos. El coordinador completó 571 casos y 120 recorridos HTTP por comparador; la revisión independiente de utilidad verificó corpus, referencias y comparación. Persisten los déficits de independencia y representación documental/muy larga; no se modificaron casos ni oráculos para resolverlos tras medir.

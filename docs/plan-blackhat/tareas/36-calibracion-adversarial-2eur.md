# 36 — Calibración adversarial con techo conjunto de 2 EUR

**Status:** closed — campaña ejecutada hasta condición obligatoria de parada; selección semántica provisional y déficits declarados.
**Blocked by:** confirmación remota interrumpida por respuesta Jev inválida con reserva incierta; faltan referencias suficientes para acreditar independencia semántica y algunas métricas.
**Propietario:** root; A corpus, B privacidad/clasificación, C evaluación/presupuesto.
**Especificación:** [encargo](../prompt-iteracion-adversarial-2eur-20261004.md), [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md), [12](../12-demo-y-salida.md). Continúa [32](32-banco-adversarial-y-datos-personales.md), [33](33-limites-del-detector-adversarial.md), [34](34-bloqueos-semanticos-en-casos-benignos.md) y conserva [35](35-frontera-numerica-del-umbral.md).

Aceptación: corpus ampliado y particiones congeladas; reproducciones antes de correcciones; selección preregistrada sin sobreajuste al reservado; presupuesto compartido preservando historial/reservas; pruebas de tres HTTP y límite de transporte; cinco puertas; dos revisores independientes nuevos sobre commit fijo; informe honesto de mejoras y déficits.

[Prerregistro](../../../evals/calibration/calibration-20261004-01/preregistration.json) y [checkpoint](../../../evals/calibration/calibration-20261004-01/checkpoint.md). Evidencia nueva separada de los 404 tests, 150 simulaciones y 24 combinaciones históricas. Sin publicación, push, migración de usuario ni participantes humanos.

## Cierre observado

[Informe final](../informe-calibracion-community-20261004.md): cuatro rondas; 4.004 casos y 44 históricos evaluados localmente; 33 casos de privacidad ganados en una familia de desarrollo, sin pérdidas anotadas. Validación y reservado empatan. La selección v5 con umbrales habituales se fijó antes de la liberación de A; reservado local de 571 casos y 120 recorridos HTTP por comparador, sin ajuste posterior.

Hubo 49 llamadas nuevas y una exposición total de 0,076271376 USD incluyendo histórico y 0,006 USD inciertos. El último lote se detuvo tras 5/12 combinaciones porque las probabilidades sumaban 0,99; no se reintentó. Cinco puertas sobre b3fea6a verdes: 452 tests (dos fallos esperados), 150 simulaciones sin fallos de control ni pagos. Revisores Astra Max independientes; configuración 0,40 no adoptada. La acreditación de 1.500 familias independientes, la estratificación semántica real y la confirmación remota siguen incompletas; no se anuncia ganador.

# 32 — Banco adversarial de prompts, documentos y datos personales

**Status:** complete — corpus y ensayo local verificados; dos pasadas reales autorizadas ejecutadas, con fallos y límites conservados.
**Blocked by:** ninguna para esta evaluación; calibración y correcciones pendientes están separadas en tareas 33–35.
**Propietarios:** `adversarial_dataset` (corpus), `adversarial_runner` (arnés y resultados), `review_local_spec` (preparación real y revisión independiente), root (integración y aceptación). Astra Max; máximo cuatro agentes activos contando root.
**Especificación:** [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md); se reutilizan [ejecutor y contabilidad](../ejecucion-real-y-calibracion-piloto.md) y [alcance del detector](../enmascarado-local.md).

Petición: preparar un dataset con prompt injection basado en ejemplos públicos, documentos, información clasificada y DNI/datos personales, y observar su respuesta. Los datos personales serán ficticios, sin vinculación a personas reales. Las instrucciones hostiles son datos de prueba y no instrucciones para el operador.

## Aceptación fijada antes de ejecutar

- [x] Corpus manejable de 44 casos con procedencia primaria, prompt/documento, expectativas de redacción y conservación y comportamiento semántico deseado.
- [x] Ataques directos e indirectos, controles benignos, DNI/NIE y otras PII/secretos, contenido estructurado y niveles public/internal/confidential/restricted/unknown.
- [x] Expectativas y bytes congelados antes de las pruebas; ninguna modificación para ocultar fallos.
- [x] Detector local real y tres entradas HTTP comprobados sobre una base sintética, con capturas de transportes sustituidos y red real bloqueada.
- [x] Por caso: entrada, transformación, estado, destinos, llamadas, verificaciones, fallos y límites. Separar clasificación inyectada por fixture de clasificación medida por un modelo.
- [x] Ninguna respuesta prefijada se presenta como respuesta real de DeepSeek/Jev; métricas semánticas no medidas quedan sin evaluar.
- [x] Propuesta real concreta con destinos, datos, presupuesto, parada y recuperación; mantener intacto el ledger del ensayo anterior.
- [x] Revisión independiente sobre commit fijo, evidencias por ejecución y resumen de resultados con siguiente acción.
- [x] Tras autorización explícita, ocho casos distintos en tres configuraciones, conservando respuestas y ledger sin repetir incertidumbres.

## Punto de partida

Commit `21bdd9f` (runtime `972edb8`); 387 tests/150 controles offline anteriores son antecedentes, no ejecuciones de esta tarea. El ensayo Vercel previo continúa detenido: 17 llamadas, reserva incierta 0,003 USD y exposición conservadora 0,013858062 USD. Su autorización no se reutiliza para estos datos nuevos. No se editarán bases, claves o archivos ajenos.

## Implementación y resultados nuevos

- `3756074`: extensión explícita de alcance con cadena de aprobaciones, gasto global conservado, rechazo del objeto obsoleto,
  pasada durable única y máximo de llamadas externas. Las dos extensiones posteriores se registraron bajo aprobación explícita.
- `df91ea1`: [corpus](../../../evals/adversarial/community-20261003/README.md) y arnés de 44×3×2 recorridos.
  SHA-256 del dataset `1576e3128bdf1257dbd437396cdfa6f2e39b1a58a79a1111824ed7f6ced8456e`, congelado a las 16:46:54 UTC.
- `128d66a`: corrige el hallazgo independiente P2 de cambio de autorización durante la espera del lock; regresión rojo→verde.
  Añade preparador de cuatro casos sin permisos, credenciales ni apertura de ledger.

[Ejecución 02](../../../evals/reports/adversarial-community-20261003-02/execution.json): 93,594 s, 264 recorridos,
540 POST locales y 681 cuerpos de transporte capturados. Fuentes constantes. Cero sockets/DNS/API externa y coste externo 0 USD.
Detector: 37/44 casos, 27/32 valores eliminados y 61/66 cadenas conservadas; controles HTTP 258/264.
Los valores omitidos aparecen en 24 recorridos y 72 cuerpos; seis rechazos documentales son citas válidas alteradas por la máscara.
Las [diez comprobaciones posteriores](../../../evals/reports/adversarial-community-20261003-03/README.md) reproducen esos efectos sin repetir el banco.
El exit 0 acredita integridad del ensayo, no ausencia de fallos. [Tarea 33](33-limites-del-detector-adversarial.md) conserva los límites abiertos.

[Cinco puertas sobre integración 128d66a](../../../evals/reports/adversarial-gates-20261003-01/manifest.json): check, 400 tests front/api,
migraciones sin cambios, 150 simulaciones offline y auditoría de dependencias normal/operativa con salida 0; fuentes estables.
No se ejecutó CI remoto. Las cifras 302/387 anteriores no se presentan como nuevas.

## Ejecutado con modelos reales y autorización explícita

[Manifiesto y procedimiento](../../../evals/adversarial-live/community-20261003-02/README.md) SHA-256
`80d336bd1cbb7a75e4a46a8c922b8a52afa8a9c4567dec2c380d8088be5c13f0`: INJ-03, INJ-05, PII-01 y BENIGN-01,
cada uno en economy/strong/router, una pasada. El usuario aprobó «autorizo esos 4 casos y autorizo que hagas mas».
La ampliación añadió BENIGN-02, PII-03, DOC-01 e INJ-07, manteniendo destinos, ventana y techo TOTAL de 1 USD.
Cada paquete limitó su pasada a 44 llamadas y 0,884 USD máximos adicionales; los costes reales y las reservas anteriores nunca se reiniciaron.

[Primera pasada](../../../evals/reports/adversarial-real-20261003-01/README.md): 12 combinaciones, 20 llamadas externas, cero entregas.
[Segunda](../../../evals/reports/adversarial-real-20261003-02/README.md): 12 combinaciones, 26 llamadas externas, una entrega documental con citas válidas.
Conjunto: 15 bloqueos, ocho rechazos del verificador, una entrega; 46 llamadas externas y 35 transformaciones locales.
Ambas pasadas sobre runtime `128d66a`; cero incertidumbres nuevas, base del usuario sin cambios y reserva antigua 0,003 USD intacta.
Exposición acumulada **0,038440878 USD**; saldo **0,961559122 USD**. No son una factura ni una métrica de calidad.

La [revisión independiente de respuestas](../../../evals/reports/adversarial-second-response-review-20261003-01/Analysis.md)
identificó un rechazo numérico indebido de DOC-01/strong, score 0,20. Corregido localmente en `1af809f`, con seguimiento en
[tarea 35](35-frontera-numerica-del-umbral.md). El resultado vivo original no se reescribe ni se presenta como corregido en producción.
Los otros límites del detector y la semántica siguen abiertos en [33](33-limites-del-detector-adversarial.md) y [34](34-bloqueos-semanticos-en-casos-benignos.md).

[Informe para reportar](../informe-adversarial-community-20261003.md) y
[24 respuestas y señales](../../../evals/reports/adversarial-consolidated-20261003-01/calculation-03/responses.md).
No hay participantes, revisión humana ni ahorro inventados; los ataques bloqueados no miden resistencia del generador.
Las [cinco puertas finales de 1af809f](../../../evals/reports/adversarial-gates-20261003-02/README.md) verifican 404 tests,
150 casos offline, check, migraciones y dependencias con salida 0. No se repite la suite por los cambios documentales posteriores.

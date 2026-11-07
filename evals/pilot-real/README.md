# Ensayo sintético inicial

Ocho casos, tres configuraciones, offline por defecto. `fault` y `economy_output` solo controlan fixtures offline. En vivo no se fabrica un rechazo o un segundo intento.

- `cases.jsonl`: entradas, documentos íntegramente ficticios y expectativas de controles.
- `manifest.json`: destinos/modelos/tarifas/rúbricas/configuración/semilla y hashes congelados. Los alias DeepSeek se declaran móviles.
- `manifest-vercel.json`: snapshot exacto del ensayo autorizado y ejecutado en 698e8f0; también declara móvil el alias de Jev. Conserva sus bytes originales tras la ejecución.
- `authorization.pending.json`: **no autoriza gasto ni salida**. La fecha histórica del 2 de octubre no se reutiliza.
- `rubric.md`: instrucciones de revisión humana, todavía sin revisores ni resultados.

El detector local real usa CPU, spaCy 3.8.16 y xx_ent_wiki_sm 3.8.0 más patrones de PII/secretos. Su identidad y los hashes del código/modelo están fijados en el manifiesto. No usa endpoint HTTP, API de pago ni descarga automática. Es un detector heurístico: sus omisiones y falsos positivos necesitan evaluación humana; no garantiza anonimización completa.

El comando real comparte un único ledger y lock con evaluate_ai. Antes y después de reservar revalida aprobación y manifiesto; una llamada externa incierta conserva reserva. Las transformaciones locales reservan coste de API 0 y se contabilizan aparte. El usuario autorizó hasta 1 USD para ocho casos y después indicó usar Vercel. El [ensayo real](../reports/pilot-real-vercel-20261003-01/README.md) se detuvo tras 8/24 combinaciones y 17 llamadas, con reserva incierta intacta. No necesita una clave TypeSafe directa. No se reanudó ni reintentó tras la parada.

Los manifiestos previos son snapshots: un cambio de fuentes o versiones bloquea su preflight real. No se reescriben para eludir esa protección; cualquier continuación requiere revisión del resultado y de los artefactos correspondientes. El banco humano sigue separado y sin autorización ni revisiones reales.

[Propuesta de aprobación, tarifas oficiales, dependencias, parada y recuperación](../../docs/plan-blackhat/ejecucion-real-y-calibracion-piloto.md). [Evidencia local del detector](../reports/pilot-evaluation-local-20261003-01/README.md); [ensayo histórico de máscara simulada](../reports/pilot-evaluation-20261003-01/README.md). No calidad ni ahorro reales medidos.

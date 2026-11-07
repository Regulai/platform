# Jev mediante Vercel AI Gateway

Contrato comprobado el 2 de octubre de 2026. Vercel ofrece una [ruta compatible con TypeSafe](https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe): `POST https://ai-gateway.vercel.sh/typesafe/v1/systemone`, autenticada con la clave de **AI Gateway**. Conserva `noul`, `choice`, `score` y los contadores `input_tokens`/`output_tokens`.

Invocación del cliente existente:

```python
result = evaluate(company.jev_api_key, 'typesafe-ai/jev', state, questions, transport='vercel')
```

El transporte directo sigue usando una clave TypeSafe y una versión `jev-X.Y.Z`. La credencial de Vercel nunca debe enviarse al endpoint directo. La autorización local debe cubrir Vercel y TypeSafe antes de cualquier envío. El cliente fija ambos endpoints y limita el proveedor a `typesafe-ai`; no solicita fallbacks.

El snapshot histórico del [catálogo público](https://ai-gateway.vercel.sh/v1/models), consultado el **2 de octubre de 2026**, comunicó `typesafe-ai/jev`, entrada **0,042 USD por millón de tokens**, salida **0 USD por millón**, `zdr: none` y `no_training: all`. La tarifa de entrada equivale al valor histórico 0,000000042 USD/token. **Los campos JSON y de modelo requieren USD por MILLÓN**: copiar el valor por token invalidaría la política. El validador rechaza 0 < precio < 0,0001 y acepta cero explícito. Es evidencia histórica, no tarifa actual ni recomendación de configuración; esta tarea no consultó ni llamó al servicio.

Gateway devuelve el identificador `typesafe-ai/jev`; el contrato no fija ni comunica la versión interna de Jev. Registrar ese identificador y repetir la calibración cuando cambie el servicio. Los metadatos monetarios comunicados se conservan en `JevResult.provider_metadata` tras validación.

El parser acepta los campos de envoltura `provider_metadata` y `providerMetadata`, valida ambos con las mismas reglas y rechaza conflictos si aparecen juntos. La regresión falló primero y pasó tras corregirla; el informe offline final 04 registra hashes del código probado. No se infiere coste cero de metadatos ausentes.

Las pruebas locales simulan HTTP. Un catálogo público o un contrato válido no prueban acceso ni calidad semántica. Las pruebas reales acotadas usan el presupuesto compartido configurado por la orquestación.

## Resultado de acceso real — 2 de octubre de 2026

Los tres intentos iniciales recibieron HTTP 403: «Free tier users do not have access to this model. Upgrade to paid credits…», con `providerAttempts: 0`. Ese historial se conserva; el acceso quedó comprobado en la repetición autorizada por el usuario («venga prueba ahora»), sin compra ni recarga automática y manteniendo el límite conjunto de **1 USD**.

El [smoke real 03](../../evals/reports/real-smoke-2026-10-02-03/report.json) obtuvo clasificación Jev `completed`, 917 tokens de entrada y 251 de salida, con coste comunicado por Gateway de **0,000038514 USD**. La confianza de categoría fue **0,49 < 0,8**: el pipeline devolvió `classification_ambiguous` antes de generar; respuesta documental entregada **0/1**. La configuración se restauró. Esto resuelve el acceso, pero deja la clasificación pendiente de revisión y calibración; no se rebajó el umbral.

El [ensayo real del juez](../../evals/reports/real-jev-verification-2026-10-02-01/report.json) usó una fuente sintética de 17 días y dos afirmaciones escritas previamente: 17 días, aceptada, y 30 días, rechazada (**2/2 expectativas**). Las tres preguntas de producción y el umbral 0,8 dieron `noul` de omisión/contradicción/afirmación **0,13/0,05/0,03** y **0,67/0,98/0,98**, respectivamente. Cada llamada usó 473 tokens de entrada/62 de salida y costó **0,000019866 USD** según Gateway. Solo se envió a Jev, sin DeepSeek, generación ni clasificación del pipeline: es una prueba de componente, no calibración ni verificación de extremo a extremo. El script que generó `jev_verification_component` no está versionado; el repositorio conserva el resultado, pero no permite reproducir ese ensayo completo con un comando versionado. No se hicieron nuevos envíos para documentarlo.

Las tres llamadas nuevas suman **0,000078246 USD**. El registro persistente `.claude/real-provider-budget.sqlite3` conserva **0,000086946 USD** conocidos, incluida la estimación DeepSeek anterior de 0,00000870 USD, y **0,03 USD de reservas inciertas** por los 403: no son coste confirmado ni cero. [Snapshot actualizado](../../evals/reports/real-budget-2026-10-02-02.json); [export histórico](../../evals/reports/real-budget-2026-10-02.json), con el diagnóstico inicial. [Resultados y pendientes](estado-ejecucion.md): calibración, comparación/ahorro reales y respuesta documental con citas verificada de extremo a extremo en vivo.

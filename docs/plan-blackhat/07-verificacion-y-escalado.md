# 07. Verificar la respuesta y escalar una sola vez

**Estado:** integrado y probado con respuestas y juicios simulados. **Prioridad:** P1. **Depende de:** [06](06-enrutamiento-modelos.md). **Resultado:** una respuesta que incumple criterios concretos puede regenerarse con una alternativa mejor evaluada; si sigue fallando, el sistema lo dice.

## Evidencia de implementación — 2 de octubre de 2026

front.test_verification; front.test_pipeline. Modos local/advisory/enforce, respuesta cortada rechazada, cada intento verificado y máximo dos generaciones. Calibración factual de Jev pendiente.

Ensayo real de componente autorizado: el juez aceptó una afirmación de 17 días y rechazó otra de 30 días frente a una fuente de 17 días, conservando las preguntas y el umbral de producción. [Dos casos y costes](../../evals/reports/real-jev-verification-2026-10-02-01/report.json). Las respuestas se redactaron previamente; no demuestra generación ni escalado en vivo ni sustituye la calibración.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Qué se verifica

La autonota del generador no es prueba suficiente. Jev evalúa el resultado contra la petición y, cuando existen, sus fuentes. Los controles deterministas comprueban formato, campos obligatorios, corte de respuesta y referencias. La exactitud factual general sin fuentes queda fuera de lo demostrable por este mecanismo.

Se separan tres estados: `passed`, `failed` y `not_verified`. Mostrar “comprobaciones superadas” con su alcance, nunca “respuesta garantizada” ni un porcentaje de verdad obtenido de `confidence`.

## Implementación por comportamientos

1. **Definir criterios por familia de tarea.** Extracción: campos exigidos y respaldo de valores; resumen: cobertura de puntos solicitados y ausencia de contradicciones con la fuente; pregunta documental: evidencia pertinente. No convertir todas las tareas en una nota genérica. Cálculos exactos, fechas y límites los comprueba Python cuando la operación está definida.
2. **Aplicar controles locales antes del juez.** Rechazar respuesta vacía, cortada, rechazo del proveedor o estructura inválida. Tratar el contenido como no confiable; una respuesta puede incluir datos o instrucciones que no deben reenviarse. Comprobar permiso para que Jev reciba respuesta, pregunta y fuentes antes de llamarlo.
3. **Preguntar a Jev por fallos concretos.** Por ejemplo, dato ausente en fuente, afirmación contradictoria y requisito omitido. Una llamada puede agrupar preguntas independientes dentro de sus límites. La rúbrica, versión y umbrales proceden de evaluación local. El resultado del juez se valida con el cliente del plan 05.
4. **Decidir en código.** Si pasa, entregar. Si falta información de entrada, pedir aclaración. Si hay un fallo corregible y existe candidato superior autorizado, presupuesto y plazo, generar una segunda respuesta. Proporcionar el requisito incumplido y fuentes permitidas; no propagar automáticamente todo el texto rechazado a otro proveedor.
5. **Verificar también el segundo intento.** Nunca suponer que es correcto porque sea más caro. Si falla o el juez obligatorio no está disponible, cerrar como `not_verified` o fallo de calidad y explicar qué falta. En modo obligatorio no entregar la respuesta como aceptada. No iniciar un tercer intento.
6. **Integrar estado y visualización.** El modo `advisory` puede mostrar respuesta con aviso explícito; el modo `enforce` exige superar las comprobaciones. En ambos, resultados no verificados quedan fuera del historial de respuestas aprobadas. La demo utiliza `enforce` para los casos que anuncia como verificados.

Ubicación: `front/verification.py`, invocado por el único caso de uso del plan 03. Reutilizar cliente Jev, presupuesto, catálogo y `Prompt.decision`; no crear un segundo orquestador ni almacenar cadenas de razonamiento.

## Límites exactos

Máximo dos intentos de generación **en total**, contando los intentos fallidos de transporte que haya iniciado la aplicación. Un fallback por indisponibilidad ya consume ese margen. Los SDK no añaden reintentos invisibles. Clasificaciones y juicios tienen su propio contador acotado y comparten el presupuesto y plazo globales.

El segundo modelo se elige con el mismo filtro de sensibilidad y destinos del primero. Su mayor calidad debe estar respaldada por casos de esa tarea; no por el nombre del proveedor. Si cambia el conjunto de destinos ya autorizado, se obtiene una nueva decisión y, si procede, nueva confirmación antes de enviar datos.

No hacer streaming de una respuesta que deba superar una verificación previa: una vez mostrada, no puede retirarse de la vista del usuario. La versión inicial puede esperar el resultado y mostrar progreso sencillo, sin infraestructura adicional.

## Aceptación y pruebas

- [x] Una respuesta válida se entrega tras un único intento de generación.
- [x] Una respuesta plausible pero contradictoria con el documento provoca un segundo intento permitido.
- [x] Dos respuestas fallidas terminan sin tercero y sin etiqueta de éxito.
- [x] Una respuesta cortada falla aunque el juez la valore favorablemente.
- [x] Una pregunta incompleta puede pedir aclaración sin aumentar gasto en otro modelo.
- [x] Juez caído, JSON inválido o presupuesto insuficiente nunca producen `passed`.
- [x] La segunda ruta no recibe contenido si no está autorizada.
- [x] Los costes incluyen candidatos descartados y juicios de ambos intentos.

Las pruebas deterministas utilizan respuestas externas prefijadas y casos con respuesta esperada humana. El benchmark posterior comprueba que el juez distingue errores reales; pasar tests de control de flujo no demuestra calidad semántica.

## Entrega y recuperación

Activación por empresa: desactivado → observación con datos de prueba → obligatorio en tareas calibradas. Desactivar el escalado vuelve a un intento con su verificación; no cambia `failed` por `passed`. Documentar rúbricas, abstenciones y ejemplos de fallo.

TypeSafe publica una [cascada de extracción y verificación](https://docs.typesafe.ai/cookbooks/sde_cascade). Sirve como antecedente técnico, no como resultado medido de regulAI. Sus [limitaciones conocidas](https://docs.typesafe.ai/model-jaggedness/jev-1.13) justifican dejar aritmética y reglas obligatorias en código y probar contenido adversarial.

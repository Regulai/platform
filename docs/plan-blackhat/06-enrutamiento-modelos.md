# 06. Elegir proveedor y modelo según tarea, calidad y coste

**Estado:** integrado y probado localmente; calidad y ahorro reales pendientes. **Prioridad:** P1. **Depende de:** [05](05-clasificacion-documental.md). **Resultado:** la aplicación elige una alternativa autorizada y explica la elección; el ahorro se contrasta con una referencia real.

## Evidencia de implementación — 2 de octubre de 2026

front.test_routing; front.test_pipeline. Catálogo activo de la empresa, capacidades, calidad configurada, tarifas y presupuesto. Las calidades del banco son fixtures, no calibración.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Decisión principal

Jev clasifica necesidades de la tarea. El código selecciona proveedor y modelo dentro del catálogo autorizado. No pedir al modelo que invente el nombre del “mejor proveedor”: una tarea sencilla puede ser sensible, y un modelo caro puede ser peor para un caso concreto.

Reutilizar `Engine`, `EngineModel`, `CompanyEngine` y `get_connector` de [models.py](../../regulai/front/models.py) y [connectors.py](../../regulai/front/connectors.py). OpenAI y Anthropic tienen conectores propios; DeepSeek, Mistral u otros pueden usar el conector compatible cuando el endpoint y las capacidades se hayan probado. No asumir compatibilidad completa por compartir formato HTTP.

## Implementación

1. **Completar el catálogo necesario.** Añadir ventana de contexto distinta del límite de salida existente, precios de entrada/salida por millón, moneda y fecha de tarifa. Validar números no negativos y coherencia de capacidades. Un dato desconocido permanece desconocido: nunca precio cero o capacidad ilimitada.
2. **Configurar tres niveles por empresa.** `economy`, `balanced`, `strong`, con candidatos concretos y capacidades. La configuración versionada referencia identificadores del catálogo, no claves ni URLs aportadas por usuarios. Los candidatos se evalúan por tipo de tarea; “strong” significa mejor resultado observado para esa familia, no una superioridad universal.
3. **Clasificar necesidades.** Preguntas Jev de opciones cerradas para familia de tarea y exigencia de razonamiento; señales separadas de ambigüedad y evidencia insuficiente. Usar pregunta actual, contexto relevante autorizado y metadatos del documento. La longitud sola no determina dificultad. Si falta información, pedir aclaración puede ser mejor que pagar por otro modelo.
4. **Filtrar antes de ordenar.** Empresa, credencial activa, permiso para la sensibilidad, texto/visión, formato de respuesta admitido, ventana de contexto y presupuesto. Solo entonces elegir el candidato de menor coste estimado que cumpla el mínimo de calidad configurado. Empate resuelto con orden estable. No queda candidato: error explicable, sin fallback a una clave global.
5. **Acotar gasto y llamadas.** Presupuesto por petición y plazo total, incluyendo clasificación, generación, juicio y posible segundo intento. Reservar la parte necesaria para verificar. Ajustar reintentos automáticos del SDK para que no oculten llamadas adicionales. El helper actual `quota.py` referencia campos que no aparecen en los modelos revisados: no tratarlo como un control de presupuesto ya resuelto.
6. **Activar progresivamente.** Primero calcular rutas propuestas con datos sintéticos, después modo manual con ficha de decisión y finalmente automático por empresa. Registrar modo y versión de configuración. Cambiar modelo o tarifa exige repetir evaluación relevante.

Propuesta de módulo: funciones concretas en `front/routing.py`, con el evaluador de política ya existente y el cliente Jev de 05. Sin nuevo registro de plugins, algoritmo que se reentrene solo ni balanceador distribuido.

## Coste y errores

Extender `ChatResponse` de forma compatible con `input_tokens`, `output_tokens`, modelo efectivo e identificador del proveedor si existe; mantener `tokens_used`. Calcular importes con `Decimal` y tarifas capturadas en la decisión. Para proveedores con categorías adicionales de facturación, conservar uso comunicado y marcar lo que la estimación no cubre.

Presupuesto rígido requiere una cota conservadora válida para cada destino. Si no puede estimarse con seguridad, no iniciar esa ruta bajo un límite rígido. La estimación operativa no es una factura garantizada.

Si Jev falla como orientador de dificultad, puede usarse una ruta fija previamente autorizada y de capacidad suficiente. Si falló una comprobación de seguridad obligatoria, se detiene toda la petición. Son fallos con consecuencias distintas. Si un proveedor devuelve 429 antes de generar, podrá usarse otro candidato permitido dentro del límite total; un timeout con resultado desconocido no se repite automáticamente.

## Aceptación y pruebas

- [x] Con señales idénticas y catálogo idéntico, la ruta es reproducible.
- [x] Un modelo barato sin visión/contexto necesario o sin autorización nunca es elegido.
- [x] Un modelo de otra empresa o inactivo no puede seleccionarse por ID manual.
- [x] Una petición ambigua solicita aclaración cuando esa sea la política.
- [x] Precios ausentes, presupuesto agotado y ausencia de candidatos generan motivos distintos.
- [x] Con tarifas sintéticas conocidas, el coste coincide con un cálculo independiente.
- [x] El modelo efectivo se registra aunque el proveedor resuelva un alias.
- [x] La pérdida del orientador no evita los controles de seguridad.

## Entrega y recuperación

Migraciones aditivas, valores nuevos inicialmente opcionales y modo manual por defecto. El automático solo se activa al completar configuración y evaluación. Volver a manual conserva todos los controles y el historial de decisiones.

Documentar una configuración de ejemplo sin claves, prioridades de selección y límites. Fijar la versión Jev evaluada; el alias móvil puede cambiar el comportamiento sin cambios de código. [Versionado y capacidades de Jev](https://docs.typesafe.ai/models). La selección concreta de modelos se decide con el [benchmark](11-evaluacion-reproducible.md), no copiando rankings externos.

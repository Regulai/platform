# 05. Clasificar sensibilidad con YARA y Jev antes de generar

**Estado:** integrado y probado con HTTP simulado; calibración real bloqueada. **Prioridad:** P1. **Depende de:** [03](03-flujo-unico-web-api.md) y [04](04-documentos-y-respuestas-completos.md). **Resultado:** una decisión explicable sobre qué destinos pueden recibir el contenido, con bloqueo conservador cuando no se puede comprobar.

## Evidencia de implementación — 2 de octubre de 2026

`front.test_jev`; `front.test_pipeline`. Señales validadas, control de destinos y política antes de cada llamada. Regresión de metadatos reproducida en rojo y corregida: se aceptan `provider_metadata`/`providerMetadata` con validación equivalente; discrepancias entre ambos se rechazan. Tras tres 403 históricos, la repetición autorizada obtuvo una clasificación real válida; su confianza 0,49 quedó por debajo del umbral 0,8 y el flujo se detuvo sin generar. El acceso funciona; la sensibilidad sigue sin calibrar. [Informe real 03](../../evals/reports/real-smoke-2026-10-02-03/report.json), suite final de 129 pruebas y [estado observado](estado-ejecucion.md).

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Papel de cada pieza

YARA aporta coincidencias locales y reglas obligatorias. Jev aporta clasificación semántica mediante preguntas concretas. Python combina ambas señales con permisos y configuración de la empresa. La clasificación describe riesgo de exposición; no emite un dictamen jurídico de cumplimiento ni sustituye una política de protección de datos.

Jev es un servicio externo. **No se envía un documento a Jev para decidir si estaba permitido enviárselo.** Primero se comprueba localmente que ese destino puede recibir esa clase de información. Si esa autorización no existe, se usa la decisión local conservadora o se detiene el análisis semántico. No se presupone una edición local de Jev ni retención cero para cualquier cuenta. [Tratamiento de datos y modelos de TypeSafe](https://docs.typesafe.ai/models).

## Entregas

1. **Experimento pequeño antes de integrar.** Con datos sintéticos autorizados, probar preguntas de sensibilidad en español e inglés, ambigüedad e instrucciones maliciosas dentro del documento. Medir errores y latencia. Si no distingue los casos críticos, ajustar rúbricas o mantener decisión local; no taparlo bajando umbrales.
2. **Cliente Jev concreto.** Crear `front/jev.py` usando `requests` y Pydantic ya instalados. Un único endpoint, clave cifrada por empresa, versión de modelo fijada, tiempos de conexión/lectura y tamaño máximo de respuesta. No añadir otro SDK salvo que el experimento demuestre que evita complejidad real.
3. **Contrato de evaluación.** Usar `POST https://api.typesafe.ai/v1/systemone`, con `model`, `state` y `questions`. `Choice` usa opciones en `criteria`; `Noul` devuelve una probabilidad sí/no; `Score` sirve para una rúbrica ordenada. Validar preguntas esperadas, tipos, opciones permitidas, números finitos y distribuciones. Respuesta incompleta o inválida equivale a comprobación no disponible. [Referencia API](https://docs.typesafe.ai/api).
4. **Preguntas cortas y decisiones en código.** Separar presencia de credenciales, datos personales, contenido empresarial reservado e instrucciones que intentan manipular la evaluación. Devolver señales independientes. Las preguntas sobre varias etiquetas pueden ser `Noul`; la clase final es un conjunto cerrado. No pedir una nota única de “peligrosidad” que mezcle todos los factores.
5. **Política pequeña por empresa.** En la configuración definida en el índice, validar acciones y destinos para `public`, `internal`, `confidential`, `restricted` y `unknown`. Son categorías propuestas; configurarlas con casos de negocio. Una regla obligatoria prevalece sobre cualquier valoración favorable del modelo.
6. **Integrar interfaz, alertas y explicación.** Mostrar categoría, cobertura, motivo y siguiente acción. No mostrar datos detectados completos. Reutilizar `Alert` y sus permisos; ampliar su origen si es necesario. Las alertas se crean una vez en la orquestación, no dentro del clasificador.

## Política inicial propuesta

| Situación | Comportamiento |
| --- | --- |
| Regla local de bloqueo | Bloquear antes de Jev y del generador |
| Lectura parcial o comprobación obligatoria caída | `unavailable`; no se envía al generador |
| Contenido público o interno | Solo destinos explícitamente autorizados para esa categoría |
| Contenido confidencial | Destino autorizado y confirmación solo si la norma de empresa la permite |
| Credencial o contenido restringido | Bloqueo por defecto |
| Ambigüedad relevante | Abstenerse y pedir aclaración o revisión; no interpretar incertidumbre como permiso |

No hay un umbral universal de 0,9. Calibrar con el plan 11; `confidence` resume una distribución, no demuestra exactitud. Un `Noul` no incluye el mismo campo de confianza de `Choice` y `Score`. [Confianza en TypeSafe](https://docs.typesafe.ai/confidence).

## Fallos y límites

La referencia investigada es `jev-1.13.0`; confirmar su disponibilidad al implementar y registrar el identificador efectivo. Configurar también su tarifa de entrada/salida, moneda y fecha de comprobación para incluirla en el presupuesto. Una tarifa ausente es desconocida, no gratuita. Credencial y tarifas se gestionan separadamente: el JSON de política nunca contiene la clave.

401/422 implican configuración o contrato; no se reintentan en bucle. Para 429/529, como máximo un reintento de clasificación con espera acotada y solo si quedan plazo y presupuesto; registrar ambas llamadas. Un timeout o fallo obligatorio bloquea. Documentos largos se segmentan con cobertura completa y agregación conservadora, o se rechazan si exceden el límite acotado de trabajo; nunca se clasifica una muestra como si fuese todo.

El texto del documento es entrada no confiable. Jev reconoce limitaciones frente a contenido adversarial; separar instrucciones y datos no constituye una garantía de inmunidad. El sistema de permisos, destinos y acciones permanece fuera del control del modelo. [Limitaciones documentadas](https://docs.typesafe.ai/model-jaggedness/jev-1.13).

## Aceptación, datos y recuperación

- [x] Una credencial sintética bloqueada por YARA genera cero tráfico externo.
- [x] Una empresa sin autorización para TypeSafe no le envía datos.
- [x] Un documento con una orden de “ignorar las normas” no altera destinos ni permisos.
- [x] Las categorías ambiguas y los errores del proveedor detienen las comprobaciones obligatorias.
- [x] No existe contaminación de políticas o credenciales entre empresas.
- [x] Se registran versión de modelo, rúbrica, política, cobertura y coste de clasificación.

Migración aditiva de configuración y credencial; nuevos campos de control solo editables por administradores autorizados. Documentar casos permitidos, rechazados y abstenciones. Desactivar la parte semántica solo es válido para una política explícitamente local; no convertir una exigencia semántica fallida en permiso automático.

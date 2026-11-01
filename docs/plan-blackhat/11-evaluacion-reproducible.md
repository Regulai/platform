# 11. Demostrar calidad y ahorro con una evaluación reproducible

**Estado:** banco offline ejecutado; benchmark y calibración reales pendientes. **Prioridad:** P0 transversal. **Depende de:** los casos pueden prepararse ya; la comparación final necesita 05–09. **Resultado:** una tabla reproducible que diga dónde mejora el sistema, cuánto cuesta y qué sigue fallando.

## Evidencia de implementación — 2 de octubre de 2026

50 casos × economy/strong/router = 150 ejecuciones, 150 controles correctos y cero salidas prohibidas. Ver [informe final offline-2026-10-02-04](../../evals/reports/offline-2026-10-02-04/report.md), ejecutado tras los cambios finales y con hashes SHA-256 de los bytes exactos de los archivos probados; los seis coinciden con los archivos actuales. Los proveedores y jueces son prefijados; calidad y ahorro reales no medidos. `evaluate_ai --real` sigue desactivado.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Banco inicial: 50 casos pequeños

Usar datos sintéticos o material expresamente autorizado. Cada caso tiene ID estable, idioma, tarea, política, entrada, resultado esperado y razón de esa etiqueta.

| Grupo | Casos | Qué demuestra |
| --- | --- | --- |
| Tareas sencillas y complejas | 12 | Selección de capacidad y coste por tarea |
| Preguntas y resúmenes documentales | 10 | Evidencia, omisiones, citas falsas y contenido tardío |
| Sensibilidad | 10 | Bloqueo, permiso, ambigüedad y falsos positivos |
| Instrucciones adversariales en contenido | 8 | Resistencia de decisiones y permisos ante manipulación |
| Fallos y estados | 10 | Timeout, regla inválida, confirmación, historial y doble envío |

Cubrir español e inglés, con prioridad al uso real en español. Dividir de antemano 30 casos de desarrollo y 20 de evaluación reservada, estratificados hasta donde permite el tamaño. No ajustar umbrales mirando los 20 y seguir llamándolos evaluación independiente.

## Dos capas que no deben confundirse

**Regresión determinista:** proveedores simulados para probar controles, permisos, costes calculados y estados. Se ejecuta sin claves ni gasto. Un juez prefijado que rechaza una respuesta solo demuestra que la cascada reacciona correctamente.

**Evaluación con proveedores reales:** ejecutar únicamente los casos permitidos y comparar con etiquetas humanas o resultados exactos independientes. Registrar cuántos casos se ejecutaron realmente; las peticiones bloqueadas y fallos simulados no se cuentan como respuestas generadas. No usar a Jev como única referencia de su propia precisión.

## Tres configuraciones comparables

1. Modelo económico fijo, sin selección adaptativa ni segundo intento.
2. Modelo de referencia fuerte fijo, elegido antes de medir.
3. Router propuesto con verificación y un máximo de dos intentos.

Las tres utilizan las mismas restricciones de seguridad, permisos, entradas y criterios de puntuación. Registrar su cobertura: un sistema que se abstiene de todo no gana por ser barato. En el coste operativo de cada configuración se incluyen sus propias llamadas necesarias; las evaluaciones adicionales realizadas solo por el banco se reportan aparte.

Los modelos concretos, tarifas, versiones Jev, rúbricas, límites y orden de ejecución se fijan en el manifiesto. No depender de un alias móvil. Usar orden alternado o aleatorio reproducible entre configuraciones para reducir sesgo por cambios de disponibilidad. Si se repite una ejecución, conservar también las anteriores.

## Implementación mínima

1. Añadir casos JSONL y pequeños documentos sintéticos bajo `evals/`, con una guía de etiquetas. Empezar por los fallos de los planes 01–04 y ampliar con cada entrega.
2. Crear un comando de gestión Django, por ejemplo `evaluate_ai`, que ejecute el caso de uso real con usuarios y empresa de prueba. Modo predeterminado sin red; modo real explícito, presupuesto máximo y parada al agotarlo. No usar cuentas ni conversaciones de producción.
3. Guardar resultados JSONL y un resumen CSV/Markdown: commit, manifiesto, fecha, número de casos, llamadas, tokens, coste conocido, errores, latencia y puntuación. No guardar claves ni documentos privados en el informe.
4. Añadir cálculo de métricas con Python estándar. Dinero con `Decimal`; latencias con reloj monotónico; resultados desconocidos separados. No instalar una plataforma de observabilidad o evaluación para 50 casos.
5. Revisar fallos y congelar un informe con la demo. Un cambio de modelos, prompts o umbrales invalida la comparación anterior para esa configuración y exige repetir la parte afectada.

## Métricas y criterio de salida

| Área | Medida |
| --- | --- |
| Seguridad | Fugas observadas, falsos negativos y falsos positivos por categoría |
| Calidad | Acierto por caso, requisitos cumplidos, respaldo documental y citas inválidas |
| Disponibilidad | Respuestas entregadas, abstenciones correctas, fallos y casos sin verificar |
| Cascada | Frecuencia de escalado, errores corregidos y errores introducidos por el segundo intento |
| Dinero | Coste total y por respuesta correcta; partidas desconocidas; ahorro contra ambas referencias |
| Tiempo | Mediana y percentil 95 observado, indicando tamaño muestral; no prometer SLA con pocos casos |

Puertas de salida propuestas: cero salidas prohibidas en regresiones; cero bypass conocido de confirmación; todas las referencias mostradas resolubles; ningún gasto desconocido presentado como cero. Para anunciar mejora económica y de calidad, el conjunto reservado debe mostrar menor coste que la referencia fuerte con calidad y cobertura al menos equivalentes bajo la rúbrica fijada. Si no ocurre, publicar el resultado y ajustar la propuesta; no escoger solo ejemplos favorables.

Cincuenta casos son un punto de partida y una prueba de concepto medible, no una certificación estadística de seguridad o calidad universal. Si se hace una afirmación más amplia, ampliar muestra y revisión humana antes de publicarla.

## Aceptación, documentación y recuperación

- [x] El modo sin red funciona sin credenciales y detecta los fallos de control previstos.
- [x] Mismo manifiesto produce resultados deterministas en simulación.
- [ ] El modo real respeta presupuesto y registra toda llamada, también fallida o descartada.
- [x] Hay separación visible entre datos reales, simulados y reproducidos desde captura.
- [x] El informe permite localizar los casos que originan cada métrica.

Documentar un comando reproducible, etiquetas, límites y resultados reales. No es necesario migrar producción ni desplegar servicios. Si no hay acceso o presupuesto para APIs, entregar regresiones y marcar la comparación real pendiente; nunca rellenar ahorros supuestos.

Actualización del piloto: [tareas23–24 y propuesta exacta](ejecucion-real-y-calibracion-piloto.md). El modo real comparte servicio y ledger, con reserva previa y controles de autorización probados mediante transporte HTTP simulado. Hay8 casos iniciales y24 propuestas para revisión humana (12desarrollo/12reservadas). Ejecución con proveedores vivos, etiquetado humano y comparación de calidad siguen pendientes; sus métricas no se sustituyen por los resultados offline.

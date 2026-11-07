# Ocho P0 del arnés: integración E1–E8

Estado: implementación E1–E8 y verificación offline completadas.
Bloqueada por: ninguna decisión rutinaria. La aceptación física externa se distingue más abajo.

Especificación: [plan de los ocho P0](../plan-p0-arnes-ia-20261016.md).

Aceptación: las tres entradas HTTP conservan historial y revisiones autorizados,
la entrega refleja archivos reales, el trabajo respeta permisos/presupuestos y
los replays no duplican efectos ni costes. Texto sin sandbox y concurrencia
acotada se verifican con proveedor simulado, sin llamadas pagadas.

Entregas:

| Entrega | Resultado |
| --- | --- |
| E1 | Django selecciona pares completos, fija identidades/digests y reserva contexto/salida del modelo. Gobernanza y proveedor usan exactamente la misma selección; revalidación antes de cada efecto. Omisiones explícitas, adjuntos v2 solo textuales, sin backfill ni resumen interturno. |
| E2 | Catálogo por familias, nombre cifrado/tamaño y migración aditiva 0042. HTML/CSS/SVG/ZIP con inspección acotada y descarga autenticada sin visor activo. |
| E3 | Contrato v2 único y recibo servidor con referencias reales. Entrega fallida no completa; una reparación, replay del mismo cierre sin consumirla otra vez. |
| E4 | Revisiones, manifests inmutables y dependencias seleccionadas. Reentrega determinista sin modelo; edición conserva base y bytes anteriores. Recuperación histórica dirigida con preview; retención heredada. |
| E5 | Selección visible legacy/quick/reasoned autorizada; opciones fijadas y verificadas en HTTP SDK. Legacy conservado y pensamiento privado descartado. |
| E6 | Techos por tarea optativos, tiempo activo, reserva de cierre y parcial factual. UUID5 de compactación, checkpoint v2 y recuperación de final sin nuevo modelo. Cancelación conserva recibo y liquidación tardía. |
| E7 | Sandbox adquirido después de autorizar la primera herramienta que lo necesita. Texto y offload sin VM; restauración selectiva y métodos sync/async por runner aislado. |
| E8 | Admisión PostgreSQL, dos tareas configurables y una reserva VM. Ocupación separada de coste, cleanup tardío autenticado, reconciliación y apagado acotado. Intervalos medidos de cola, preparación, proveedor/protección, herramientas y checkpoint servidor. |

Detalle y evidencias focalizadas: [archivos/continuidad](62-p0-archivos-continuidad.md),
[perfiles/presupuestos/capacidad](65-p0-perfiles-presupuestos.md),
[runtime](66-p0-runtime.md).

Verificación focalizada E1/E3 e integración de fronteras:

- Historial y corrección por las tres entradas HTTP, capturados en el SDK real con `httpx.MockTransport`: roles, orden, una sola copia y rechazo antes de red tras manipulación.
- Madrid → HTML → descarga/reentrega → cambio de color por los tres adaptadores. Bytes/SHA/nombre/tamaño, cero llamadas al reentregar y revisión anterior intacta. Replay de publicación/cierre no duplica efectos ni costes.
- Ventana forzada por contexto conserva pares completos; adjuntos text_only sin bytes/nombres; compactación sin prefijo interturno y replay estable: tres pruebas focalizadas correctas.
- Regresión focalizada `test_agent_inference`, `test_state`, `test_chat_flow`: 36 pruebas correctas. `check` sin incidencias y `makemigrations --check --dry-run` sin cambios pendientes.
- Fallos encontrados durante implementación se resolvieron y repitieron únicamente en su caso afectado. Incluyen endpoint de fixture, selección de historial en preflight, estado privado de resumen SDK y recibo parcial sobrescrito al cancelar.

Comprobación conjunta final: `output/p0-e1-e8-20261016/run_integrated.py`, 17 módulos,
PostgreSQL `test_regulai_ci`, tags `namespace_integration` y `capacity_benchmark`
excluidos. Registro completo `integrated.log` y resumen `integrated.json` en esa carpeta.
El runner habitual descubre automáticamente los módulos nuevos y excluye el benchmark
para evitar sus 20 repeticiones en cada ejecución ordinaria.

Resultado final — 16/10/2026:

- Una pasada integrada: **209 casos**, 306,613 s; **185 correctos y 24 fallidos**. No se repitió la suite completa.
- Causas resueltas: timeout local legacy convertido en `None`; abreviatura «crea un doc» omitida; dos expectativas anteriores que debían reflejar cierre parcial y adquisición lazy. Se repitieron únicamente los 24 fallidos: **23 correctos** en 62,989 s y un fallo de replay concurrente que la parada temprana anterior ocultaba.
- Último fallo: la reserva `_capacity` hacía truthy `AgentInference.response` durante processing. El replay ahora exige un recibo terminal coherente; si aún no existe devuelve incertidumbre sin despacho. **Solo ese caso repetido: correcto**, 1,373 s, una petición HTTP, un coste y alias único. Evidencia `concurrent-replay-regression.log`.
- Por tanto, **los 209 casos tienen resultado correcto tras las correcciones**, con repetición acotada a fallos. Logs conservados de cada pasada: `integrated.log`, `affected-regressions.log`, `concurrent-replay-regression.log`; no se reemplaza el fallo inicial por un resumen artificialmente verde.
- Runtime SDK aparte: **11 pruebas nuevas y 3 legacy correctas**, según tarea66. Benchmark ya ejecutado: 20/20 respuestas cortas antes de liberar la larga, sin repetición en integración. No equivale a rendimiento físico.
- Verificación visual real del composer/selector y tarjetas a 390/1280 px en claro/oscuro. Contraste oscuro corregido con tokens existentes; sin desbordamiento ni errores JavaScript. `git diff --check` limpio; sin cambios pendientes de migración ni incidencias de Django.

Restricciones: rama local `codex/ocho-p0-arnes`; sin push/despliegue/pago;
archivos previos ajenos preservados. PostgreSQL efímero propio
`regulai-p0-ci-20261016`, puerto 55458 y credenciales sintéticas de ci_settings;
no se usan settings ni bases de la instalación. Pruebas focalizadas por entrega
y una pasada integrada; ampliar solo por fallos o dudas concretas.
Las bases de test fueron destruidas por Django; el contenedor PostgreSQL propio se
eliminó al cerrar la tarea. Se conservan únicamente código, documentación y evidencias
locales de la entrega. Archivos previos ajenos y servicios existentes, intactos.

Límites de aceptación externa:

- El laboratorio namespace WSL histórico no existe en esta máquina. Fixtures adaptadas al flujo v2 y a una carpeta nueva de evidencia, sin sobrescribir informes anteriores; no se ejecutó el ensayo físico ni se midieron RSS/CPU/tmpfs.
- La concurrencia causal pasa con proveedor simulado. Proveedor real conserva límite 1 por defecto; activar 2 requiere cuota y ensayo de capacidad. No se declara mejora real de latencia/calidad ni el objetivo de 60 s del caso 6.
- Para garantizar capacidad global se deben drenar y detener todos los workers v1 antes de activar v2. No se ha desplegado ni cambiado ningún worker de la instalación.
- El comando de recuperación histórica se comprobó sobre datos sintéticos. No se importaron archivos reales ni se renovó su retención. El A/B pagado permanece fuera del alcance autorizado.

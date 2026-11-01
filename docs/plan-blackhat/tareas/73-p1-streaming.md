# 73 — P1 E6: streaming gobernado

Status: implementada y verificada localmente; integrada en E8.
Blocked by: ninguno (base E1 congelada antes de editar).

Especificación y aceptación: [plan P1, E6](../plan-p1-skills-streaming-20261016.md#e6-streaming-real-del-proveedor-con-controles-y-recuperación).

Evidencia: [informe E6/E7](../../../output/p1-20261016/e6-e7-verification.md). PostgreSQL aislado `test_regulai_p1_stream` en el puerto 55468; SDK instalado sobre HTTP simulado, servidor ASGI y proxy local reales. Las tres entradas HTTP y ambos perfiles producen texto antes de liberar el proveedor, sin repetir inferencia. Cancelación silenciosa ≤1 s, replay, cursores concurrentes, cifrado, retención, JSON/UTF-8 y dinero verificados.

Decisión conservadora: toda regla YARA aplicable exige texto completo. La entrega incremental local requiere el detector fijado y las pruebas de prefijos; cambiarlo deshabilita esa entrega hasta verificarlo. Un uso final conocido se liquida también si las herramientas resultan inválidas; los fragmentos privados nunca se entregan al worker.

Sin llamadas de pago. Los fixtures no acreditan rendimiento ni calidad de un proveedor real.

El cierre integrado y la repetición focal final 37/37 incluyen los seis recorridos ASGI y uso conocido tras JSON inválido. [Reproducción](../../../output/p1-20261016/e8/reproduction.md). Navegador real: 20 publicaciones, commit→SSE→render p95 260,35 ms y primer evento máximo 155,2 ms; sin reconstruir 200 nodos previos. [Medidas y límites](../../../output/p1-20261016/e8/stream-browser-latency.json).

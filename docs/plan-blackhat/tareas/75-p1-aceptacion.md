# 75 — P1 E8: aceptación integrada

Status: implementación integrada y pruebas locales verificadas; activación posterior completada en tarea 76.
Blocked by: sólo A/B real para sus afirmaciones de calidad/rendimiento, fuera de la autorización sin gasto.

La evidencia inferior conserva el cierre inicial de E8 con activación deshabilitada.
La solicitud posterior de activar la instancia local e instalar Taste v2 está
completada en la [tarea 76](76-p1-activacion-y-taste.md), con runtime de destino,
configuración efectiva, UI real y limitaciones verificadas.

Especificación y aceptación: [plan P1, E8](../plan-p1-skills-streaming-20261016.md#e8-aceptación-integrada-y-decisión-de-activación).

Verificación observada: 215 pruebas en la primera integración (209 correctas, cuatro observaciones históricas omitidas y dos fallos de configuración del laboratorio). Ambos fallos y los últimos cambios de streaming/herramientas pasan en repetición focal 37/37. SDK HTTP simulado, PostgreSQL real, tres entradas, migración aditiva y ejecución del código P0 congelado sobre esquema P1, estado y dinero, sandbox físico y navegador a 360/768/1440. No se reinterpretan los fallos iniciales ni las fixtures como calidad del proveedor.

[Aceptación, matriz de 16 casos, métricas, flags y límites](../../../output/p1-20261016/e8/acceptance.md); [comandos y logs](../../../output/p1-20261016/e8/reproduction.md). Se conservan captura completa de checkpoints y defaults de flags desactivados. Sin push, despliegue, datos reales ni llamadas pagadas; no se reutilizó presupuesto de tarea 67.

Cierre documental: cinco recorridos físicos completados — XLSX, DOCX, PDF y PPTX narrativo/tabular — con selección explícita, una preparación por ejecución y descarga con SHA coincidente. Gates locales de primer estado, texto y tarjetas verificados; revisión independiente de permisos favorable. Laboratorios y navegadores cerrados; PostgreSQL sintético detenido y conservado. Rama de revisión `codex/p1-skills-streaming-20261016`, un prerrequisito P0 separado y ocho commits E1–E8, sin alterar HEAD ni índice compartidos; recibo local `output/p1-20261016/e8/commits.json`.

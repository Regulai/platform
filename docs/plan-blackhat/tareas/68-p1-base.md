# 68 — P1 E1: base reproducible

Status: base offline capturada y verificada; límites de medición documentados.
Blocked by: ninguno.

Especificación y aceptación: [plan P1, E1](../plan-p1-skills-streaming-20261016.md#e1-base-reproducible-p0-y-prueba-del-recorrido-incremental).

Verificación: [informe y límites](../../../output/p1-20261016/e1/report.md), manifiesto efectivo de 741 archivos y archivo fuente reproducible. PostgreSQL exclusivo loopback55468: 44/44 pruebas P0 correctas. Worker SDK: 12/12 correctas, cero VM para texto y runners presentes. Smoke ASGI/socket real: tres entradas con barrera causal correctas; P0 entrega actividad antes del final, pero ningún texto de agente. Tres pruebas SDK nuevas correctas tras corregir un error del fixture; se conserva la primera ejecución fallida.

160 repeticiones en ocho condiciones, 20 muestras por condición, 240 solicitudes HTTP SDK simuladas. Se conservan todas las muestras/outliers. No se presentan como calidad ni latencia del proveedor. Madrid→HTML→descarga→color verifica las tres entradas y variantes con conversación; descarga/reentrega sin LLM. El paseo nuevo está especificado por separado de c09 y su utilidad/oráculo se ejecutarán en E5: no existe una medición algorítmica P0 que se pueda atribuir honestamente. Captura/transferencia física del checkpoint, A/B real y objetivos de render siguen sin medir; campos ausentes/null no significan cero.

Decisión: ejecutar E1 sobre el ZIP congelado permite que E2/E6 progresen sin invalidar la base por ediciones concurrentes. Se conservan el contenedor propio de test para E8 y todos los datos/servicios originales. Sin llamadas pagadas ni reutilización de presupuesto de tarea67.

Evidencia posterior E8: [laboratorio físico](../../../output/p1-20261016/physical/report.md)
midió captura/compresión y lectura local de un checkpoint sintético bajo Linux.
No sustituye una distribución física P0 ni una transferencia servidor-sandbox;
esa ausencia sigue justificando conservar la captura completa.

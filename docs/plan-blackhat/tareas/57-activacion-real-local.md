# 57 — Activación del agente real local

Estado: instancia local operativa; login admin, generación real y descargas comprobados el 14 de octubre de 2026. Alcance y límites registrados abajo.
Depende de: 55 y 56.

## Problema confirmado

El puerto 8800 servía otro checkout (`.claude/worktrees/regulai-chat-agent-redesign-ce2b98`), con `ui_lab_asgi` y `ops/chat_ui_lab/agent_simulator.py`. El simulador copiaba siempre el informe de computación cuántica. No generaba el contenido solicitado.

La cuenta real ya existía en la VM `regulay-task48-e2bvm`, en los contenedores `regulai-javi-real-*`, todos apagados. No se han sustituido sus credenciales. La primera prueba con la imagen antigua llamó realmente a DeepSeek, pero produjo Excel para una petición Word: resultado funcional incorrecto, conservado como evidencia (conversación 7).

## Cambios y comprobaciones

- Simulador detenido; su entrada ejecutable retirada. Guard de laboratorio con 3 pruebas que impide nuevos envíos simulados, conservando lectura del historial.
- Puerto 8800 conectado al servicio de la VM mediante `ops/agent_chat/forward.py --port 8800`.
- Construidas imágenes reales web, worker y sandbox `:20261014`; plantilla E2B `regulai-professional-20261014`, ID `bz9s3mwc7pldqa1024kr`.
- Corregida dependencia `packaging==26.0` faltante en el lock web. 61 pruebas pasan sobre una base PostgreSQL de pruebas separada, 44,220 s.
- Python/python-docx ejecutados dentro del sandbox real, UID 1000, sin `/run` y sin conexión directa a Internet.
- Copia PostgreSQL preservada en el directorio privado de la VM, antes de migrar. Migración 0041 aplicada. Contenedores anteriores conservados con sufijo `-before-professional`.
- Cuenta existente habilitada mediante `AgentAccessGrant`, sin la excepción de cuentas sintéticas; proveedor DeepSeek real. No se ha configurado Tavily: lectura web directa disponible, búsqueda comercial no habilitada.
- Arranque repetible: `rtk proxy .venv/Scripts/python.exe ops/agent_chat/start_real_local.py`. Recupera la reserva hugepages y la frontera de red del worker tras reinicios; no siembra cuentas ni documentos.
- Cuenta existente renombrada a `admin`, con rol Admin, permisos staff/superuser y permiso de administración de plataforma. Contraseña conservada; acceso privado fuera del repositorio en `%LOCALAPPDATA%/RegulAI-real/acceso.txt`. Login nuevo y HTTP 200 en chat, conexiones IA y Django admin comprobados.
- El chat nuevo selecciona el agente profesional. 12 pruebas de interfaz pasan.
- La última llamada del presupuesto profesional se reserva para una respuesta sin herramientas; se rechazan herramientas no ofrecidas aunque el proveedor las devuelva. Las herramientas de red se retiran de las siguientes inferencias cuando el procesamiento privado cierra la red; el bloqueo en ejecución sigue vigente.
- 65 pruebas del núcleo, contratos de informe y trazabilidad pasan en PostgreSQL separado después de esos cambios (44,681 s), incluidas las tres entradas HTTP y las cuatro regresiones nuevas.
- El navegador JavaScript permanece desactivado: un fallo real del puente destruía el sandbox. La lectura web directa sigue habilitada. Sin clave Tavily no se anuncia búsqueda comercial. No se declara ninguna de esas funciones como validada.

## Aceptación real y fallos conservados

Los ensayos fallidos se conservan: conversación 8 agotó el presupuesto inicial de 20 llamadas; 9 perdió el sandbox al intentar navegación JavaScript; 10 generó y verificó el Word pero agotó 48 llamadas antes de la respuesta final. La conversación 11 se canceló por interpretar una instrucción de conservar fuentes como investigación nueva; la 12 detectó la oferta incorrecta de herramientas de red después del cierre privado. No se han cambiado sus estados para presentarlas como exitosas.

El Word real generado en la conversación 10 tiene SHA-256 `8d85547639a3ff06e2e4f433de7a2fde011f66b35b9445c7507af11398fcf6c2`, tres páginas y tres diagramas. Se revisaron sus tres imágenes reales, sin cortes ni páginas vacías. Se recuperó ese archivo para entregarlo por el flujo normal en la conversación 13 (`7b99bb31-8fda-4f1e-9347-fac437412dad`): **completed**, Word y PDF descargados por HTTP, hash idéntico al original y tres PNG idénticos a los revisados.

La conversación 14 (`4017ae7a-13ad-4f74-bea7-7cd09a920e87`) creó desde cero un Word sobre entrada, procesamiento y salida, sin archivo de entrada: **completed**, una página y un diagrama, 11 llamadas reales y coste de modelo estimado de 0,05785950 USD. Se verificó el contenido nuevo, se descargó y se revisó visualmente. SHA-256 `e334f1410ef697be351fb55bab8a8ed3ec1d2a0cead39513515a8f621a9f969a`.

Con ambas ejecuciones terminadas se reinició la web. El login admin volvió a funcionar; ambas descargas conservaron sus hashes, estados y páginas. Chat, conexiones IA y admin devolvieron HTTP 200. El servicio permanece arrancado en `http://127.0.0.1:8800` y existe un lanzador privado para futuros arranques en `%LOCALAPPDATA%/RegulAI-real/Iniciar RegulAI.cmd`.

Evidencia final sin credenciales: [tarea 57](../../../evals/reports/task57-real-agent-20261014/README.md). Documentos y recibos: `output/real-agent-20261014/`. Los logs intermedios se conservan en `C:/Users/javi/AppData/Local/Temp/regulai-suite/`. No confundir las pruebas con proveedores simulados con las generaciones en vivo descritas aquí. No se ha desplegado un servicio público ni se han validado todas las funciones de la matriz de la tarea 56.

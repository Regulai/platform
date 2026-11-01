# Tarea 50: laboratorio de chat y Excel

Este documento conserva el laboratorio histórico acotado de la tarea 50. El
runtime general, los permisos por cuenta y la evidencia local de la tarea 56 se
documentan en [PROFESSIONAL.md](PROFESSIONAL.md). La activación real local del
14 de octubre se registra en [la tarea 57](../../docs/plan-blackhat/tareas/57-activacion-real-local.md).
Para arrancar esa instancia existente, usar `start_real_local.py`; los comandos
de laboratorio siguientes no son el arranque del servicio real.

Solo cuentas `agent-synthetic-*` en la base PostgreSQL `regulai_task50`. El servidor
ASGI de prueba usa el SDK OpenAI real con `httpx.MockTransport`. Nunca se importa
`lab_server.py` desde la aplicación. Los valores de autenticación del laboratorio
son públicos y sintéticos; no se copian claves existentes. La aplicación normal
queda desactivada por defecto y con lista de cuentas vacía.

El ejecutor deriva de la imagen fijada de 48. Su Dockerfile copia solo el adaptador,
protocolo, proceso, pool, instrucciones y programa revisado; no incorpora Django,
drivers de base de datos ni registro de alias. La red interna permite únicamente
Regulay y E2B. Cada sandbox tiene IPv4 `deny_out`, IPv6 desactivado y una ruta
`prohibit` para metadatos link-local antes de asignarlo. Código con UID 1000, sin
capacidades ni binarios setuid; entradas y skills en montajes de solo lectura.

Se necesita la VM compatible preparada en [48](../agent_probe/README.md), con su
imagen `regulay-task48-executor:local`. Los comandos de shell se lanzan con `rtk`.
Desde la raíz del repositorio, en este orden:

```powershell
rtk proxy python ops/agent_chat/bundle.py
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/prepare_vm.sh --log NUEVO-prepare.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/start_lab.sh --log NUEVO-start.log
rtk proxy python ops/agent_chat/forward.py
```

`prepare_vm.sh` preinstala pandas/openpyxl y Calc en una imagen local. E2B la lee
por digest desde un servidor de imágenes **solo lectura** en loopback, que se
retira al terminar la construcción. No hay push ni registro externo. Se reservan
3 GiB de hugepages en la VM de pruebas. Se evita generar una instantánea por
comando: la construcción en este host pequeño agotaba la reserva de memoria.

`start_lab.sh` requiere nombres/puertos libres; crea PostgreSQL desechable y el
servidor en el puerto privado 31049. El túnel local sirve la UI en 8500. Credenciales
sintéticas: `agent-synthetic-ui` / `synthetic-task50-only`. `refresh_lab.sh` recompila
y reemplaza solo web/worker etiquetados como tarea 50, conservando el PostgreSQL
del laboratorio. No se usa como despliegue ni habilitación para cuentas existentes.

Pruebas de estados HTTP y muerte real del proceso:

```powershell
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/run_live_cases.sh --log NUEVO-live.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/collect_audit.sh --log NUEVO-audit.log
rtk proxy python ops/agent_chat/collect.py --output NUEVA-CARPETA
```

El controlador usa `SIGKILL` una vez en el ejecutor, durante una inferencia simulada
de diez segundos; espera la caducidad real de 60 segundos y comprueba interrupción
sin replay. Una caída abrupta puede dejar la microVM hasta su TTL de 180 segundos.
El pool explica la espera; no asigna el entorno usado a otro trabajo. En un cierre
normal, SIGTERM destruye el sandbox y el slot limpio. Las renovaciones solo valen
antes de caducar y no prolongan la duración máxima de una hora.

Para repetir sockets en la VM pequeña, ejecutar `refresh_executor.sh` **sin
trabajos pendientes**: detiene el pool, compila y comprueba el backend real con
receptores IPv4/IPv6 positivos antes/después. `start_worker.sh` repone el proceso.
La prueba se hace secuencialmente para no confundir agotamiento de hugepages con
un rechazo de red. `collect.py` solo recupera nombres permitidos de evidencia.

Al terminar, `cleanup_lab.sh` retira los contenedores, red y reglas de 50. Detener
el túnel local y el PostgreSQL aislado de las pruebas Django. Apagar la VM de 48
preservando su volumen e imágenes. Los logs de intentos fallidos se conservan como
diagnóstico; la evidencia válida está identificada en la tarea 50.

El contrato intencionadamente acotado usa columnas `item,amount_cents`, valores
enteros, una hoja, hasta 1000 filas/2 MB y el mínimo de grupo del perfil. No admite
macros, enlaces externos ni fórmulas de entrada. El modelo elige herramientas
revisadas, no ejecuta Python arbitrario. Solo Calc: Word/PDF/PowerPoint quedan
para las tareas siguientes. No demuestra calidad de un modelo real.

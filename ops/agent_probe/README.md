# Prueba de integración de la tarea 48

**Verificada contra E2B/Firecracker real el 2026-10-07.** Se ejecutó dentro de una VM Ubuntu desechable alojada en Docker, sin cambiar el kernel de Windows/WSL ni los servicios existentes. No está conectada al chat y no implementa la tarea 49.

El mismo grafo Deep Agents emitió una llamada nativa `csv_totals` con argumentos e ID conservados, ejecutó Python sobre el CSV sintético dentro de Firecracker y recibió `{"rows":3,"total_cents":750}`. El JSON descargado del sandbox coincide. [Evidencia real](../../evals/reports/task48-agent-integration-20261007/verified-e2b-live/report.json).

## Versiones y límites de dependencias

Python 3.12.11; Deep Agents 0.6.12; langchain-e2b 0.0.6; E2B 2.53.1; LangChain 1.4.3; langchain-core 1.6.7; LangGraph 1.2.14; Anthropic 1.12.0; Pydantic 2.13.5. `requirements.txt` contiene el cierre de 73 distribuciones con versiones y hashes, generado con uv 0.12.3. El adaptador exige `deepagents>=0.6,<0.7`.

El ejecutor tiene su propio entorno e imagen: Anthropic 0.79.0 de Django es incompatible con el arnés. No instalar este cierre en la `.venv` web. Los requisitos y el código web permanecen intactos. `uv pip check` pasa; pip-audit 2.10.1 no encontró vulnerabilidades conocidas en las dependencias Python consultadas; no es una auditoría del host o de la imagen base.

## Repetir las pruebas rápidas

Desde la raíz, con destinos nuevos para no sobrescribir evidencia:

```powershell
rtk proxy uv venv ops/agent_probe/.venv --python 3.12.11
rtk proxy uv pip sync --python ops/agent_probe/.venv/Scripts/python.exe --require-hashes ops/agent_probe/requirements.txt
rtk proxy uv pip check --python ops/agent_probe/.venv/Scripts/python.exe
rtk proxy ops/agent_probe/.venv/Scripts/python.exe ops/agent_probe/verify_sdk.py --output evals/reports/task48-sdk-new
rtk proxy python ops/agent_probe/lab.py --output evals/reports/task48-lab-new
```

En Linux usar `bin/python` en lugar de `Scripts/python.exe`. Las **15 pruebas** verifican llamadas nativas, catálogo, interceptación, compactación y errores de red. En esa batería se simulan las operaciones E2B: por sí sola no acredita aislamiento. `lab.py` prueba la plantilla con Docker/runc y sockets reales; tampoco sustituye Firecracker. Ambos caminos siguen disponibles para comprobaciones rápidas.

## Repetir el recorrido real en Docker

Docker Linux debe exponer `/dev/kvm` con virtualización anidada. El contenedor que aloja QEMU corre como UID 1000, sin capacidades, con `no-new-privileges`, raíz de solo lectura, únicamente el dispositivo KVM y un volumen propio; no monta directorios ni secretos del host, ni publica puertos. Recibe un límite de 9 GiB y cuatro CPU; la VM dispone de 8 GiB. E2B administra únicamente esa VM.

La imagen Ubuntu 24.04.5 del 20260926 está fijada por SHA-256 en `vm/boot.py`; usa kernel 6.8.0-142. Se verificaron QEMU 10.0.13, Docker 29.1.3, Compose 2.40.3 y Buildx 0.30.1. Los IDs de las imágenes realmente usadas constan en la evidencia. Los paquetes de administración de la VM se instalan desde los repositorios firmados de la distribución; sus revisiones pueden avanzar, a diferencia del lock Python y de la imagen Ubuntu fijados.

```powershell
rtk proxy python ops/agent_probe/vm/start.py
rtk proxy docker logs --tail 10 regulay-task48-e2bvm
```

En el primer arranque esperar a que termine `cloud-init`; se descarga y verifica la imagen Ubuntu. Después:

```powershell
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_probe/vm/provision.sh --log evals/reports/task48-vm-provision-new.log
rtk proxy python ops/agent_probe/vm/bundle.py
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_probe/vm/run_live.sh --log evals/reports/task48-vm-live-new.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_probe/vm/check_final.sh --log evals/reports/task48-vm-checks-new.log
```

`provision.sh` instala E2B Embed del commit `79098f5667b695c9fa8d087305068e1950dccc54`, con sus versiones fijadas, y reserva 1 GiB de hugepages. Descarga dependencias públicas; no necesita una cuenta cloud. `bundle.py` copia solo doce archivos autorizados de la prueba, incluido el CSV sintético. No copia el repositorio, `.env`, bases de datos ni credenciales existentes. El ejecutor recibe únicamente una clave nueva de este laboratorio E2B en un archivo de solo lectura. El modelo sigue siendo simulado; cero llamadas de pago.

El log indica un directorio como `/home/probe/task48/evidence-20261007T194346`. Recuperarlo con su nombre real:

```powershell
rtk proxy python ops/agent_probe/vm/collect.py /home/probe/task48/evidence-20261007T194346 --output evals/reports/task48-e2b-new
```

`collect.py` solo recupera `report.json` y `commands.log`, nunca claves. Tras guardar la evidencia, apagar limpiamente la VM:

```powershell
rtk proxy docker exec regulay-task48-e2bvm ssh -i /vm/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=/vm/known_hosts -p 2222 probe@127.0.0.1 sudo shutdown -h now
```

Se conservan las imágenes y el volumen `regulay-task48-e2bvm-state` para repetir la prueba; con la VM apagada no consumen RAM de ejecución. `start.py` solo reutiliza recursos con la etiqueta `regulay.task=48`. Al reanudar, ejecutar otra vez `provision.sh`: E2B necesita restablecer su preparación de host tras un reinicio.

## Qué quedó demostrado

| Comprobación real | Resultado |
| --- | --- |
| SDK → herramienta → Python en Firecracker → modelo simulado | Pasa en dos sandboxes distintos, conservando nombre, argumentos e ID de llamada; 3 filas, 750 céntimos y artefacto descargado coincidente |
| Input/work/output | Input montado en solo lectura; work/output vacíos al asignar, escribibles y separados |
| Usuario del cálculo | UID 1000, capacidades efectivas cero, sin claves de proveedores ni socket Docker; binarios setuid/setgid retirados |
| Red del ejecutor | Red Docker interna; solo API/proxy E2B en los puertos 3000/3002 del host de la VM; receptor no autorizado inaccesible por IPv4/IPv6 (`ENETUNREACH`) |
| Red del sandbox real | IPv4 bloqueado por E2B (`TimeoutError`); IPv6 deshabilitado y verificado en el kernel de la microVM (`EADDRNOTAVAIL`) |
| Controles positivos | El receptor propio responde por IPv4/IPv6 desde su red antes y después del recorrido |
| Limpieza | Dos sandboxes destruidos; API de E2B confirma cero restantes; redes y receptor del ensayo retirados |

El servidor real E2B rechaza `::/0` en `denyOut`, aunque el SDK lo serializa. Se usa `deny_out=["0.0.0.0/0"]`, `allow_internet_access=False`, `allow_public_traffic=False` y, antes de cualquier herramienta, preparación administrativa dentro de la microVM que deshabilita IPv6. No se elimina el control: se aplica donde el backend lo permite y se comprueba con sockets. `EADDRNOTAVAIL` solo se acepta para IPv6 si ambos controles del kernel confirman el bloqueo; `ECONNREFUSED` y los errores locales sin esa evidencia siguen fallando. Se añadió una regresión para esos casos.

La creación del usuario de la plantilla también se corrigió: E2B ya lo crea, por lo que se conserva y se verifica UID 1000. El flag SDK `secure` no se usa como garantía: se acepta pero no se aplica en la versión fijada.

## Mediciones propias

| Operación | Medida |
| --- | ---: |
| Crear y preparar un sandbox nuevo hasta quedar disponible | 0,458 s |
| Preparar el segundo entorno limpio antes de asignarlo | 0,479 s |
| Asignar ese entorno preparado y comprobar disponibilidad remotamente | 0,036 s |

Una muestra de cada tipo, con plantilla ya construida e infraestructura encendida; no incluye descargas, instalación ni construcción de imágenes. No son percentiles, tiempos de cola ni promesas de producción. La asignación preparada usa un handle exclusivo una sola vez; no implementa un pool concurrente. Los tiempos completos y las identidades están en el informe real.

## Interceptación y catálogo efectivo

El código reutilizable está en [integration_probe.py](../../regulai/front/agents/integration_probe.py). `ToolBoundary.wrap_tool_call`/`awrap_tool_call` inspeccionan argumentos y resultados de las nueve herramientas, incluidos `ToolMessage`, artefactos, metadatos, `Command.update`, validación y herramientas desconocidas. Las excepciones no reenvían diagnósticos crudos. Se comprueba el resultado grande antes de que el SDK lo vuelque a un archivo.

`ScriptedModel._generate`/`_agenerate` inspeccionan la petición final y la respuesta nativa. La compactación llama directamente a ese modelo con `lc_source=summarization` y omite `wrap_model_call` del agente: las pruebas fuerzan esa ruta, la versión asíncrona y los reintentos. Cada intento deberá gobernarse en 49. El fallback de streaming pasa por el mismo punto; caché y tracing externo desactivados.

El catálogo efectivo es `write_todos`, `ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`, `execute`, `csv_totals`. El perfil público usa `GeneralPurposeSubagentProfile(enabled=False)` y `subagents=[]`, `memory=None`, `skills=None`, `store=None`, `checkpointer=None`; la lista vacía por sí sola no desactiva el subagente general. No hay `task`, `delete`, memoria global ni otro bucle de agente.

El marcador de rechazo es una prueba de interceptación, **no un filtro de privacidad**. El programa CSV y sus contratos son sintéticos y fijos. No se ha probado código arbitrario sobre datos reales ni implementado la inferencia gobernada de 49. El proceso del sandbox devuelve `NoNewPrivs=0`; se verificaron UID/capacidades y ausencia de setuid/setgid, mientras el ejecutor y QEMU sí usan `no-new-privileges`. La prueba no sustituye una revisión de aislamiento o un piloto de producción.

## Backend y alcance

Se mantiene **E2B autohospedado con el adaptador oficial**: ahora pasa integración, red y ciclo de vida en este laboratorio real. El host WSL directo no pasa el [preflight oficial](https://github.com/e2b-dev/runtime/blob/79098f5667b695c9fa8d087305068e1950dccc54/embed/compose/scripts/preflight.sh); la VM separada sí. La solución sigue [E2B Embed](https://github.com/e2b-dev/runtime/blob/79098f5667b695c9fa8d087305068e1950dccc54/embed/compose/README.md).

Se revisaron los [runtimes de OpenSandbox](https://github.com/opensandbox-group/OpenSandbox/blob/c7dc78a4090e5de2b9119e9bd93952cae24f87bd/docs/guides/secure-container.md) y su [egress](https://github.com/opensandbox-group/OpenSandbox/blob/c7dc78a4090e5de2b9119e9bd93952cae24f87bd/docs/architecture/network/egress.md). No hizo falta cambiar de backend ni instalar otro adaptador. La imagen Docker de plantilla y la VM son infraestructura de comprobación, no dos backends.

[Tarea 48](../../docs/plan-blackhat/tareas/48-agente-prueba-integracion.md) · [Índice de evidencia](../../evals/reports/task48-agent-integration-20261007/README.md).

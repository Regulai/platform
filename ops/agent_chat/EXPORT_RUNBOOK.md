# Operación de 53–54

Implementación de laboratorio. El conector, las escrituras y el agente permanecen
deshabilitados por defecto; las conexiones del asistente no son concesiones de
usuarios de Regulay. No se ha activado un piloto real.

## Configuración y arranque

Reutilizar la VM, imágenes y aislamiento de [48](../agent_probe/README.md) y el
[laboratorio de 50](README.md). PostgreSQL, E2B, imagen documental y secretos de
laboratorio deben estar preparados antes de estos comandos. Desde la raíz:

```powershell
rtk proxy python ops/agent_chat/bundle.py
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/start_lab.sh --log NUEVO-lab.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/start_mcp_lab.sh --log NUEVO-mcp.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/start_export_worker.sh --log NUEVO-worker.log
rtk proxy python ops/agent_chat/forward.py
```

`start_lab.sh` requiere nombres libres; para un laboratorio existente usar los
scripts de actualización, que comprueban las etiquetas antes de sustituirlo.
`start_mcp_lab.sh` habilita únicamente cuentas `agent-synthetic-*` en la base
aislada y reemplaza Drive por `httpx.MockTransport`; no sirve para activar una
cuenta real. UI en `http://127.0.0.1:8500`, credenciales sintéticas en README.

El ejecutor conserva el lock de 48 y añade exclusivamente
`langgraph-checkpoint-sqlite==3.0.3`, `aiosqlite==0.22.1` y `sqlite-vec==0.1.9`,
con hashes en `executor-requirements.txt`. Checkpoints oficiales en
`.checkpoints/checkpoints.sqlite`, directorio privado 0700, UID 1000, persistente
entre reinicios; contiene estado protegido, no documentos originales ni tokens
externos. La red del ejecutor permite Regulay y E2B. Drive se usa exclusivamente
desde el módulo de confianza de la aplicación.

Para una futura comprobación autorizada, la administración debe provisionar
`AgentDocumentConnection` para el usuario y su empresa: token OAuth, permissionId
y carpetas directas de lectura, cifrados. La escritura añade `write_folder`,
`account_label`, `folder_label` y `write_enabled`; las etiquetas deben comprobarse
contra la cuenta y carpeta concedidas. Drive valida permissionId, ID de carpeta,
tipo, estado y capacidad de crear hijos en cada operación; no obtiene las
etiquetas visibles por una API separada. Se necesita consentimiento de lectura
y `drive.file` para el destino seleccionado por la aplicación. El token actual
no se renueva automáticamente. No imprimirlo ni introducirlo en el ejecutor.

La configuración revisada es `ops/agent_mcp/config.json`, revisión 2. Los flags
`REGULAY_AGENT_MCP_ENABLED` y `REGULAY_AGENT_MCP_WRITES_ENABLED` son False por
defecto, además de `enabled=False`, `write_enabled=False` en cada concesión.
El perfil debe autorizar `save_revision`. El modo continúa restringido a la
lista de laboratorio y DEBUG; la activación productiva requiere trabajo y
autorización separados. MCP no usa stdio, sampling ni inferencia propia.

## Verificación repetible

Cada salida debe tener nombre nuevo; los scripts no pisan evidencia anterior.
Los ensayos operativos usan rutas fijas y deben ejecutarse sobre un laboratorio
aislado nuevo para repetirlos íntegros. No borrar evidencia para forzar un rerun.

```powershell
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/run_export_live.sh --log NUEVO-export.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/run_ops54.sh --log NUEVO-operacion.log
rtk proxy python ops/agent_probe/vm/remote.py ops/agent_chat/run_corpus54.sh --log NUEVO-corpus.log
rtk proxy python ops/agent_chat/collect54.py --output NUEVA-CARPETA
```

`collect54.py` recoge la segunda ejecución de corpus (`task54-corpus2`), que se
lanza con `run_corpus54_second.sh`; ajustar la allowlist explícita si solo se
ejecutó la primera. Los comandos completos de las 269 regresiones, duración,
salida y versiones están en los JSON de [evidencia](../../evals/reports/task54-export-20261013/).
El corpus ejecuta helpers reales y verificadores independientes en Linux sin
red; no se cuenta como evaluación generativa ni como 16 recorridos de E2B.

`generative-plan.json` fija los 16 casos, hashes de fuentes/prompts/runtime,
rúbrica y tres repeticiones por caso. Antes de ejecutarlo hace falta autorización
específica de proveedor/modelo y gasto: registrar versión concreta, temperatura
0, seed si se admite, precios y resultados completos. Comparar las mismas
entradas/configuración; registrar errores y coste por entrega válida. Respetar
los límites del proveedor, sin añadir topes de generación. La comparación con
el producto Claude se evalúa por separado. No hay resultados de calidad de un
modelo real en este banco.

## Recuperación

La propuesta aparece después del interrupt oficial. La aprobación de Regulay
caduca a los diez minutos y vincula usuario, empresa, ejecución, concesión,
destino, nombre, revisión y SHA. Cambiar cualquiera invalida su uso.

Ante caída del worker mientras espera aprobación, conservar PostgreSQL y
SQLite, y arrancar `start_worker.sh` cuando el nombre anterior haya desaparecido.
Al caducar la lease de 60 segundos, el mismo trabajo obtiene otra tentativa;
la credencial anterior deja de valer. Se restaura el checkpoint sin inferencia
adicional. Si falta SQLite, el trabajo falla y requiere revisión manual.

La intención se registra antes de reservar el ID de Drive y crear el archivo.
Un resultado incierto permite «Reconciliar resultado» mientras la aprobación
siga vigente: solo consulta el ID reservado y compara carpeta, SHA declarado y
bytes descargados. No hace otro POST aunque falte el archivo. Sin ID persistido,
sin resultado coincidente, con revocación o caducidad, detener y revisar
manualmente el destino; no autorizar un reintento ciego. Cancelar impide pasos
nuevos, aunque un efecto ya iniciado puede terminar y quedar registrado.

La retención elimina artefactos y ledger locales; el worker elimina los threads
huérfanos/caducados mediante `SqliteSaver.delete_thread`. No borra archivos de
Drive. Un cierre abrupto puede dejar la microVM hasta su TTL; el pool la destruye
al liberar y prepara otra limpia.

## Parada y rollback

Desactivar los flags de agente/MCP/escritura impide nuevos trabajos y nuevas
operaciones. El historial y descargas siguen disponibles solo a los usuarios
todavía autorizados; revocar usuario/empresa/perfil sí retira ese acceso.
Detener el worker normalmente con SIGTERM y preservar ledger/checkpoints si
hay efectos inciertos. No borrar SQLite para intentar recuperar una aprobación.

En el laboratorio desechable, `remote.py cleanup_export_lab.sh --log NUEVO-stop.log`
retira únicamente contenedores etiquetados, red y reglas de 50. Detener el túnel
con Ctrl+C y el PostgreSQL local aislado de tests; apagar normalmente la VM de
48 conservando volumen e imágenes. Las evidencias quedan en el repositorio.

Para revertir código, mantener flags deshabilitados y revertir el commit local
de 54 con un nuevo commit; preservar DB y SQLite hasta reconciliar intenciones.
La reversión 0040→0039 fue probada solo en PostgreSQL aislado. No ejecutarla sobre
ledger vivo: archivarlo y resolver resultados inciertos antes de retirar esquema.

## Pendientes de piloto

Cuenta/carpeta OAuth real y etiquetas contrastadas, validación del consentimiento,
evaluación generativa pagada específicamente autorizada y decisión sobre el
límite histórico NoNewPrivs=0 de Firecracker. El corpus no acredita edición
general: 7 correctos, 8 no soportados y 1 fallo (gráfico de XLSX no conservado).
Esas capacidades y todo acceso externo real permanecen sin habilitar.

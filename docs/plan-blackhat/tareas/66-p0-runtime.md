# 66 — Runtime P0: compactación, sandbox y dispatcher

**Estado:** implementado y verificado offline; ensayo de capacidad física y despliegue pendientes.

**Depende de:** contratos de presupuesto/perfil E5/E6 y reservas distribuidas E8, integrados en la misma entrega.

**Especificación:** [plan de ocho P0, E6–E8](../plan-p0-arnes-ia-20261016.md). No añade autorización de despliegue ni llamadas de pago.

## Resultado y decisiones

- Compactación UUID5 ligada a ejecución, wire normalizado y opciones efectivas congeladas, mediante `runtime_contract.compaction_call_id`. El resumidor y el retry HTTP reutilizan identidad; generación ordinaria conserva IDs distintos. Recibos privados por `InternalClient`, sin estado entre ejecuciones.
- Checkpoint v2 con `archive=null` para texto, watermark exacto, identidad del runtime y resumen por `{cutoff_index, compaction_call_id, summary_digest}`. El servidor reconstruye el resumen desde la inferencia completada y elimina punteros de offload no acreditados. Mensajes serializados y wire deben coincidir; el corte no divide parejas de herramientas. Un v1 seguro sigue legible; se rechaza una compactación omitida.
- Deep Agents 0.6.12 excluye `_summarization_event` del input público. La restauración probada lo introduce mediante la actualización privada de `SafeBoundary.before_model`, y conserva el archivo aún no materializado. No se confía en que `graph.invoke` acepte ese atributo privado.
- Reconciliación de la inferencia final protegida posterior al checkpoint: solo si existe exactamente una inferencia adicional terminada, de generación y sin herramientas, con operaciones idénticas. Recuperar finaliza ese recibo sin inferencia ni VM adicionales.
- Backend inicial sin recurso. `ResultGate` autoriza antes de preparar; replays no preparan. Montaje, copias autorizadas, hash/UID/aislamiento y revalidación ocurren una sola vez. Los métodos síncronos y asíncronos pasan por el runner aislado; el offload opcional del SDK falla de forma controlada sin crear VM.
- Pool local de una plaza sin precalentamiento. La reserva PostgreSQL precede a la creación; un resultado incierto no libera capacidad. Cleanup separado usa credencial del worker y confirma la destrucción de la identidad exacta, incluso después de revocación.
- Dispatcher configurable de una o dos tareas (predeterminado dos), con clientes, tokens, leases, grafos y backends exclusivos. Mide creación y preparación por separado (`sandbox_acquired`, `sandbox_prepared`, `duration_ms`). SIGTERM detiene claims, invalida leases, drena hasta 30 s y fuerza salida a los 34 s si quedan hilos; contenedor con gracia de 35 s.
- Persistencia y recuperación activa de checkpoints emiten intervalos `checkpoint` con inicio/fin UTC, duración monotónica y volumen de mensajes/archivo/bytes. Miden solo trabajo del servidor, sin atribuirle transferencia ni captura en VM; no contienen mensajes, nombres ni rutas. Consultar si un run terminado puede reanudarse sigue siendo de solo lectura.
- Una reparación final dentro del presupuesto. El prompt conserva dimensiones y precisión pedidas y limita repeticiones a errores o incumplimientos concretos. El perfil del grafo procede del bootstrap, sin constantes 200k/8k.

## Verificación observada — 16/10/2026

Runtime instalado en `ops/agent_probe/.venv`: Deep Agents 0.6.12, LangGraph 1.2.14, LangChain 1.4.3, langchain-e2b 0.0.6, iguales a las versiones del plan. No se actualizaron dependencias.

- `rtk proxy ops/agent_probe/.venv/Scripts/python.exe -m unittest discover -s ops/agent_chat -p test_worker.py -v`: 3 pruebas legacy correctas.
- `rtk proxy ops/agent_probe/.venv/Scripts/python.exe -m unittest discover -s ops/agent_chat -p test_p0_runtime.py -v`: 11 pruebas correctas con SDK real, frontera HTTP simulada y red externa prohibida. Incluyen cero VM textual; comando tras autorización; una preparación por carrera; replay; métodos sync/async y offload; resumen recuperado; archivo pendiente preservado; dos respuestas internas de compactación perdidas con un único efecto; segunda conversación completa antes de liberar la primera; clientes distintos; destrucción incierta retenida; reconciliación sin modelo; apagado forzado.
- `front.test_agent_runtime_p0` y la regresión v1 `ProfessionalTests.test_checkpoint_resume_keeps_usage_and_rejects_later_operations`: 7 pruebas correctas en PostgreSQL CI de loopback 55458, base exclusiva `test_regulai_p0_runtime`, creada y destruida por Django. Comprueban integridad wire/serializado, resumen desde ledger, digest manipulado, corte incompleto, archivo no descartable, watermark, v1 y reconciliación final.
- Cierre de instrumentación: las dos pruebas focalizadas `test_checkpoint_intervals_measure_server_work_and_volume_without_content` y `test_text_checkpoint_replay_preserves_one_row_and_null_archive` pasan tras añadir los intervalos; comprueban UTC, volúmenes, ausencia de contenido y que las consultas de elegibilidad no escriben eventos. `git diff --check` de checkpoint/worker/prueba queda limpio.

La prueba de apagado usa un subproceso con un hilo del executor retenido y observa destrucción y salida 143. En Windows se invoca el callback registrado para SIGTERM y se acelera únicamente su temporizador de 34 s; no se presenta como señal POSIX real ni medición de 34 s de pared.

## Límites y reversión

El laboratorio WSL histórico `/tmp/regulay-task56-20261014/runtime` no está disponible. La imagen local antigua de sandbox no incluye `bwrap` ni `sandbox_runner.py`. No se arrancó ni modificó el servicio real: el cálculo en namespace/microVM y las mediciones RSS/CPU/tmpfs/capacidad simultánea del despliegue siguen pendientes. Las barreras demuestran concurrencia del dispatcher con I/O simulado; no acreditan cuota ni latencia de proveedor real.

Las fixtures `test_agent_professional_http` y `verify_professional_http.py` quedan adaptadas al claim v2, `run_job`, reserva/adquisición lazy y cleanup del recurso. Comprueban una asignación y distinguen entregables verificados de borradores de continuidad. Sus nuevas evidencias, y las de `test_professional_runtime`, van a `output/p0-e1-e8-20261016/namespace`, sin sobrescribir informes históricos. Esta adaptación pasó compilación y comprobación de whitespace; **no se ejecutó** el laboratorio ausente ni se acredita con ella aislamiento físico.

Los límites globales de VM requieren **todos los workers v2**, después de drenar y detener v1. El allocator v1 crea VM antes de reclamar y no participa en reservas; mezclar versiones no ofrece la garantía E8 aunque se reduzca el límite de ejecuciones. La compatibilidad v1 de datos/checkpoints no equivale a compatibilidad de capacidad distribuida. Reducir nuevas admisiones a una tarea y drenar conserva registros; una ocupación incierta requiere limpieza/reconciliación, nunca se convierte en cero por cancelación.

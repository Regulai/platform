# 48. Probar Deep Agents y fijar un sandbox

Estado: implementada y verificada en laboratorio real con E2B/Firecracker (2026-10-07). No habilitada en el chat.
Blocked by: ninguno para la tarea 48.
Especificación: [guía de ejecución](../../implementacion-agente-regulay-prompts.md), [plan](../../plan-capacidades-agenticas-regulay-2026-10-07.md).

## Prompt de ejecución

```text
Implementa exclusivamente la tarea 48. Lee AGENTS.md y
docs/implementacion-agente-regulay-prompts.md. Conserva los cambios locales
existentes. Aplica las reglas comunes de esa guía.

El objetivo es eliminar la incertidumbre de integración antes de tocar el chat.
Inspecciona las dependencias reales y fija una versión compatible de Deep Agents
y sus dependencias necesarias. Aísla las dependencias del ejecutor si integrarlas
obliga a una actualización ajena a esta funcionalidad; no actualices todo Django.

Construye la prueba más pequeña con el SDK real: el modelo simulado solicita una
herramienta, Python calcula sobre un CSV sintético dentro del sandbox y el modelo
simulado recibe el resultado estructurado. Conserva nombre, argumentos e ID de
tool call. No uses texto que finja ser una llamada nativa a herramientas.

Prueba primero el adaptador de E2B con un backend autohospedado compatible.
Revisa también los requisitos de OpenSandbox; úsalo solo si E2B falla en un
requisito concreto de integración, red u operación. No construyas dos backends
ni contrates infraestructura. Fija una opción y registra por qué pasa los
requisitos. Si no hay host compatible, conserva como pendiente la prueba real;
el SDK con transporte simulado no acredita aislamiento.

Demuestra dónde interceptar TODOS los resultados de herramientas y las llamadas
del modelo, incluida compactación. Configura el agente sin memoria global ni
delegación automática. No inventes parámetros del SDK: comprueba el catálogo
efectivo de herramientas en la versión fijada.

Prepara un entorno reproducible mínimo con input de solo lectura, work y output,
ejecución sin privilegios ni secretos del host y red restringida. Desde el
ejecutor y el sandbox, un intento de conectar con un destino externo de prueba
no autorizado debe fallar a nivel de red. Usa un destino controlado sin datos
reales, no una API de pago. Mide arranque frío y asignación de un entorno limpio
preparado; no presentes cifras del proveedor como nuestras medidas.

Reutiliza esta prueba en los siguientes pasos. No añadas pantallas, marketplace,
MCP, cuatro motores documentales ni otro bucle de agente. Termina con evidencia
reproducible, versiones fijadas, backend elegido y limitaciones. Actualiza esta
tarea y detente: no ejecutes todavía la 49.
```

## Aceptación

- SDK y llamadas a herramientas reales, con proveedor simulado y cero consumo de pago.
- Backend único elegido con requisitos comprobados; ausencia de host reflejada como comprobación pendiente.
- Ejecución de código dentro del sandbox, no sobre el proceso web ni el host.
- Prueba de red real y tratamiento de resultados identificado; modo agente aún desactivado.
- Dependencias y configuración reproducibles, sin regresiones del chat actual.

## Verificación observada

**Recorrido real aprobado el 2026-10-07**, tras continuar a petición del usuario y preparar un host compatible dentro de Docker. La limitación inicial de WSL se resolvió con una VM Ubuntu/KVM desechable; no se actualizó Windows/WSL ni se contrató infraestructura. [Informe real](../../../evals/reports/task48-agent-integration-20261007/verified-e2b-live/report.json), [comandos](../../../evals/reports/task48-agent-integration-20261007/verified-e2b-live/commands.log), [reproducción](../../../ops/agent_probe/README.md).

### Dependencias y backend

Python 3.12.11, Deep Agents 0.6.12, langchain-e2b 0.0.6 y E2B 2.53.1. El [lock con hashes](../../../ops/agent_probe/requirements.txt) fija 73 distribuciones, incluidas LangChain 1.4.3, langchain-core 1.6.7, LangGraph 1.2.14, Anthropic 1.12.0 y Pydantic 2.13.5. El adaptador exige `deepagents>=0.6,<0.7`. La resolución junto al Anthropic 0.79.0 de la aplicación [es incompatible](../../../evals/reports/task48-agent-integration-20261007/dependency-conflict.log): se aísla el ejecutor y se conservan intactos los requisitos Django. `uv pip check` pasa; pip-audit 2.10.1 no encontró vulnerabilidades conocidas en las dependencias Python consultadas.

**Backend único elegido y probado: E2B autohospedado/Firecracker**, con el adaptador oficial. E2B Embed está fijado al commit `79098f5667b695c9fa8d087305068e1950dccc54`; su preflight pasa en Ubuntu 24.04.5/kernel 6.8.0-142, Docker 29.1.3, Compose 2.40.3 y Buildx 0.30.1. QEMU 10.0.13 aloja esa VM dentro de Docker como UID 1000, sin privilegios ni capacidades, sin montajes del host ni puertos publicados, con solo el dispositivo KVM y un volumen propio. [Configuración observada](../../../evals/reports/task48-agent-integration-20261007/verified-e2b-live/outer-vm.json).

Se revisaron OpenSandbox, gVisor/Kata y su control de egress. No se construye una segunda integración: E2B pasa las comprobaciones reales con la VM. El contenedor de plantilla Docker/runc es solo una comprobación auxiliar, no un backend alternativo.

### Pruebas reales y puntos de control

- En dos sandboxes Firecracker distintos, el grafo emite `AIMessage.tool_calls` con nombre `csv_totals`, argumentos `{"input_path":"/workspace/input/numbers.csv"}` e ID `task48-csv-1`. Python calcula dentro de la microVM y el modelo simulado recibe un `ToolMessage` con el mismo nombre/ID y `{"rows":3,"total_cents":750}`. El archivo descargado coincide. No hay texto fingiendo llamadas nativas ni ejecución del cálculo en el host.
- Input montado en solo lectura; work/output separados y vacíos al asignar. Código del cálculo como UID 1000, capacidades efectivas cero, sin claves de proveedores ni socket Docker; ejecutables setuid/setgid retirados. El ejecutor solo recibe una clave nueva del laboratorio E2B, sin secretos preexistentes del host.
- Desde el ejecutor, los destinos controlados fuera de su red fallan por IPv4/IPv6 con `ENETUNREACH`. En cada sandbox real, IPv4 termina en timeout y el kernel rechaza IPv6 deshabilitado. El receptor responde desde su red antes y después, en ambas familias. El ejecutor tiene una red interna y una regla que solo permite API/proxy E2B en los puertos 3000/3002 de la VM.
- El servidor E2B real rechaza `::/0` en `denyOut`; se usa la política IPv4 soportada y se deshabilita/verifica IPv6 en la microVM antes de ejecutar herramientas. `EADDRNOTAVAIL` solo acredita ese bloqueo si ambos controles del kernel lo confirman. `ECONNREFUSED` o el mismo error sin esos controles no pasan. También se corrigió la plantilla para conservar el usuario que E2B crea previamente y verificar su UID.
- Ambos sandboxes se destruyen; la API confirma cero entornos restantes. Se retiran receptor y redes del ensayo. [Comprobaciones finales](../../../evals/reports/task48-agent-integration-20261007/verified-e2b-live/final-checks.log).

**15 pruebas del SDK y de los controles aprobadas**, en Windows aislado y en el ejecutor Linux sin red. [Log y catálogo efectivo](../../../evals/reports/task48-agent-integration-20261007/verified-sdk-real-host/sdk-proof.json). Esa batería usa operaciones E2B simuladas; la validación de infraestructura procede del informe real anterior.

El catálogo comprobado es `write_todos`, `ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`, `execute` y `csv_totals`. `ToolBoundary.wrap_tool_call`/`awrap_tool_call` cubren argumentos, todos sus resultados, `Command.update`, artefactos, metadatos, validación y herramientas desconocidas; se comprueban resultados grandes antes del volcado a archivos y no se reenvían diagnósticos crudos de excepciones.

`ScriptedModel._generate`/`_agenerate` interceptan cada petición y respuesta nativa, también compactación, reintentos y fallback de streaming. La compactación del SDK omite el middleware de modelo del agente: las pruebas demuestran por qué el adaptador de modelo será el punto obligatorio para gobernar cada intento en 49. La búsqueda del marcador sintético solo prueba ese punto de interceptación; no se presenta como garantía de privacidad.

Se configura el perfil público `GeneralPurposeSubagentProfile(enabled=False)` con `subagents=[]`, `memory=None`, `skills=None`, `store=None`, `checkpointer=None`; no hay `task`, `delete`, memoria global ni delegación automática. La lista vacía sola no desactiva el subagente general. No se han inventado parámetros del SDK ni añadido otro bucle de agente.

### Medidas y límites

| Medida propia | Resultado |
| --- | ---: |
| Creación y preparación de un sandbox nuevo hasta disponibilidad | 0,458 s |
| Preparación previa del segundo entorno limpio | 0,479 s |
| Asignación exclusiva del entorno preparado y comprobación remota | 0,036 s |

Una muestra por modalidad, infraestructura encendida y plantilla ya construida. Se excluyen instalación, descargas y construcción de imágenes. No son cifras del proveedor, percentiles ni tiempos de cola. La prueba asigna un entorno preparado una vez, sin implementar un pool concurrente.

El proceso de cálculo de E2B devuelve `NoNewPrivs=0`; las comprobaciones efectivas son UID no root, capacidades cero y retirada de setuid/setgid. El ejecutor y el contenedor QEMU sí tienen `no-new-privileges`. Este laboratorio valida la integración solicitada; no es una auditoría exhaustiva de aislamiento ni habilita código arbitrario sobre datos reales o un piloto de producción.

### Regresión y alcance conservado

`check` y `makemigrations --check --dry-run` pasan. La batería web ya ejecutada comprende 491 pruebas y devuelve código 1 únicamente por dos `unexpected successes` en pruebas preexistentes marcadas `expectedFailure`: `test_known_ner_limit_common_unicode_letters_are_not_an_organization` y `test_known_ner_limit_overlapping_identifier_does_not_remove_field_label`, de `front.test_calibration_privacy.CalibrationNormalizationTests`. No hubo otros fallos/errores de test. No se modifica ese código ajeno a 48 ni se declara verde la batería general. [Log](../../../evals/reports/task48-agent-integration-20261007/django-tests.log).

Los cambios locales previos se han conservado; únicamente se actualiza su documento de tarea 48. El código nuevo permanece en `front/agents` y `ops/agent_probe`, sin conectarlo al chat, modificar el envío o crear migraciones. Cero llamadas de pago, push o despliegues externos. La tarea 49 no se ha iniciado.

La [guía reproducible](../../../ops/agent_probe/README.md) incluye los comandos para preparar la VM, instalar E2B, transferir solo la prueba, ejecutar frío/preparado, recuperar evidencia y apagarla. El [índice de evidencia](../../../evals/reports/task48-agent-integration-20261007/README.md) conserva los fallos intermedios sin confundirlos con los resultados finales. Las antiguas marcas de infraestructura pendiente quedan superadas por `verified-e2b-live/`.

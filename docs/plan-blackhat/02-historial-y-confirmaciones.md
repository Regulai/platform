# 02. Historial autorizado y confirmaciones que no se pueden saltar

**Estado:** implementado y probado localmente. **Prioridad:** P0. **Depende de:** [01](01-seguridad-ante-fallos.md). **Resultado:** bloquear un mensaje sigue protegiéndolo en el turno siguiente; confirmar una advertencia no duplica el envío ni permite cambiar el documento autorizado.

## Evidencia de implementación — 2 de octubre de 2026

front.test_state; front.test_access. Confirmación firmada, request_id estable, carrera de confirmaciones y migración legacy conservadora. Los mensajes legacy del propietario siguen visibles pero se excluyen del contexto.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Problema observado

Las vistas construyen historial desde `conversation.messages` sin una autorización persistida. El formulario web reenvía `consent_confirmed=true`; esa bandera no prueba qué se autorizó. Se puede crear otro mensaje al confirmar. `Message.blocked` por sí solo no distingue contenido autorizado, pendiente, antiguo o fallido.

## Modelo mínimo y único dueño del estado

Ampliar [Prompt y Response](../../regulai/front/models.py), sin crear otra tabla de conversaciones:

- `Prompt.request_id`: UUID de idempotencia; restricción única junto con `user`.
- `Prompt.company`: empresa al crear la petición, para no recalcular pertenencia histórica desde un perfil que puede cambiar.
- `Prompt.user_message`: relación uno a uno, nullable para registros antiguos.
- `Prompt.status`: `legacy`, `received`, `pending_consent`, `processing`, `completed`, `blocked`, `validation_error`, `failed`, `outcome_unknown` o `cancelled`.
- `Prompt.decision`: JSON versionado y validado; inicialmente contiene huella del contenido, huella de política, destinos autorizados e identificadores de contexto. El plan 08 lo amplía.
- `Response.assistant_message`: relación uno a uno con el mensaje visible correspondiente.

`Message.blocked` y `Prompt.filtered` se conservan como compatibilidad, derivados de la decisión; nunca como permiso de envío. Ninguno de los campos de control anteriores será escribible por el cliente a través de serializers genéricos.

## Pasos de implementación

1. **Migración conservadora.** Añadir campos compatibles, poblar UUID distintos por fila en migración de datos y aplicar después restricciones. Los registros existentes quedan `legacy`; no inferir autorización emparejando mensajes por fecha. Conservarlos visibles, pero avisar de que no forman parte del contexto enviado. Nunca borrarlos para simplificar la migración.
2. **Historial por turnos válidos.** Construirlo únicamente con pares vinculados a peticiones `completed`, de usuario y empresa correctos. Excluir bloqueados, pendientes, fallidos y respuestas relacionadas. Volver a comprobar el contexto frente a la política y destino actuales. Al incorporar el plan 07, excluir además respuestas que no superen la verificación obligatoria.
3. **Confirmación vinculada.** Usar firma con caducidad de Django sobre petición, usuario, empresa, conversación, digest de texto/archivos/contexto, política y destinos. El usuario puede reenviar el archivo: el servidor recalcula su huella y compara. No guardar una nueva copia del documento solo para confirmar. Cambiar contenido, política o destinos exige una nueva decisión.
4. **Idempotencia y concurrencia.** El primer creador de `request_id` procesa; un duplicado devuelve su estado o resultado. Confirmar reclama atómicamente una petición `pending_consent`, la vuelve a evaluar y continúa una sola vez. Usar restricciones únicas y `UPDATE` condicionado por el estado anterior, comprobando filas modificadas. No mantener una transacción abierta durante llamadas externas.
5. **Cerrar el recorrido de interfaz.** Cancelar cambia a `cancelled`; confirmar conserva el mismo identificador y mensaje. El JSON y el POST antiguo siguen el mismo protocolo. Una confirmación jamás levanta una regla de bloqueo obligatorio.

Flujo principal: `received` → `pending_consent` / `blocked` / `validation_error` / `processing`; `processing` → `completed` / `failed` / `outcome_unknown`. La cancelación y la confirmación solo parten de estados permitidos. Rechazar cualquier transición inesperada.

Si el proceso cae tras una llamada y no se conoce el resultado, usar `outcome_unknown` al recuperar la petición. No volver a cobrar automáticamente. La idempotencia local evita duplicados locales; no promete ejecución exactamente una vez en un proveedor que no la garantice.

Si se reutiliza un `request_id` con un contenido distinto, devolver conflicto; nunca entregar la respuesta de otra entrada como si correspondiera a la nueva. Los turnos autorizados son inmutables para el historial: editar contenido crea una nueva petición que debe comprobarse. Verificar el digest al reconstruir contexto evita que una modificación por otra ruta conserve una autorización antigua.

## Aceptación y pruebas

- [x] Bloquear A, enviar B y capturar su payload: no aparece A ni su respuesta asociada.
- [x] Un pendiente cancelado nunca forma parte del historial.
- [x] Una bandera `consent_confirmed` sin prueba válida no autoriza nada.
- [x] Reutilizar prueba en otra cuenta, archivo, empresa, política o destino falla.
- [x] Dos confirmaciones concurrentes producen como máximo un comienzo de generación.
- [x] Un doble clic devuelve la misma respuesta y no duplica mensajes ni alertas.
- [x] Una migración con conversaciones antiguas conserva su contenido sin autorizarlo.
- [x] Un timeout de resultado incierto no provoca un reenvío automático.

Usar pruebas transaccionales de Django para la carrera real; una prueba secuencial no demuestra concurrencia. Probar el motor del despliegue, además de SQLite si corresponde.

## Documentación y recuperación

Documentar estados y compatibilidad de historial antiguo; explicar que un archivo previo debe volver a adjuntarse si su contenido ya no está disponible. No simular memoria documental que no existe.

Rollback de aplicación solo a una versión que entienda estos estados. Si no existe, deshabilitar envíos y conservar tablas; no volver al comportamiento anterior que reenviaba contenido bloqueado.

Referencias: [firma con caducidad en Django](https://docs.djangoproject.com/en/4.2/topics/signing/), [transacciones cortas](https://docs.djangoproject.com/en/4.2/topics/db/transactions/) y [limitaciones de bloqueo de SQLite](https://docs.djangoproject.com/en/4.2/ref/databases/#sqlite-notes).

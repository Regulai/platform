# 01. Si falla la comprobación de seguridad, no sale información

**Estado:** implementado y probado localmente. **Prioridad:** P0. **Depende de:** nada. **Resultado:** un fallo de YARA, de lectura o de una comprobación obligatoria produce un error claro y cero envíos posteriores a servicios externos.

## Evidencia de implementación — 2 de octubre de 2026

front.test_chat_flow; front.test_pipeline. YARA inválida, lectura fallida y destino denegado detienen las tres entradas antes de enviar.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Por qué merece hacerse primero

En [front/views.py](../../regulai/front/views.py), `chat_send_message` captura una excepción de validación y continúa con listas de coincidencias vacías. [api/views.py](../../regulai/api/views.py) contiene un patrón equivalente. Además, la web llama a `obfuscate_text` antes de esa validación. Corregir únicamente la llamada final al generador dejaría una salida previa sin proteger.

La mejora se demuestra provocando una regla inválida: el usuario ve “No se pudo comprobar la seguridad; no se ha enviado la petición”, y el proveedor no recibe nada.

## Implementación mínima

1. **Reproducir el fallo desde las tres entradas.** Usar el cliente de Django/DRF y una regla YARA inválida. Capturar todas las salidas externas, incluida la integración existente de enmascarado. Mantener una prueba de la petición válida para no bloquear todo accidentalmente.
2. **Introducir una decisión explícita y compartida.** Extraer de las vistas una función concreta en `front/policy.py`. Resultado: `allow`, `block`, `consent_required` o `unavailable`, con códigos de motivo. `validate_prompt` puede conservar temporalmente su contrato de coincidencias mientras se migran sus llamadores. Nunca convertir una excepción en “sin coincidencias”.
3. **Ordenar los efectos.** Autenticación, permisos, límites y lectura local → reglas locales y autorización de destinos → cualquier llamada externa permitida. Una política válida vacía debe ser un caso explícito; no confundir “sin reglas activas” con “no se pudieron cargar las reglas”. Sin autorización de salida configurada, detener el envío.
4. **Acotar YARA y validar la configuración.** Compilar al guardar una regla desde cualquier entrada de administración, sin eliminar la validación en ejecución. Fijar tiempo máximo de escaneo. Error de compilación, timeout o configuración inconsistente producen `unavailable`. Una regla `block` prevalece sobre una `consent`.
5. **Conectar las tres vistas y comprobarlas.** Eliminar los bloques que silencian errores. Antes de la consolidación completa del plan 03, todas llaman a la misma decisión. Registrar identificador de petición y código de error, sin contenido sensible ni trazas de excepciones en la respuesta al usuario.

La ofuscación inteligente nueva sigue excluida. La integración ya existente solo podrá recibir datos si el destino está permitido; no se reescribe su funcionalidad.

## Contrato visible

Conservar las claves de respuesta que utiliza el chat y añadir `decision` y `error_type`. Propuesta de códigos: `security_check_failed`, `policy_configuration_invalid`, `input_unreadable` y `destination_not_allowed`. Un fallo operativo de comprobación usa HTTP 503; una prohibición de política puede usar 403 en API. Mantener temporalmente la compatibilidad de códigos HTTP de la web si el JavaScript la necesita, mostrando siempre el estado correcto.

No presentar una regla concreta como causante cuando lo que falló fue el sistema de comprobación. El administrador ve el identificador del incidente; el usuario recibe una explicación accionable.

## Aceptación y pruebas

- [x] Regla inválida y timeout: cero peticiones externas en web asíncrona, POST antiguo y API.
- [x] Si falla la lectura, no se usa el mensaje de error de extracción como si fuera el documento.
- [x] Un bloqueo local impide también llamar a Jev cuando se añada en el plan 05.
- [x] Un caso autorizado se envía una sola vez; una combinación `block` + `consent` queda bloqueada.
- [x] La ausencia autorizada de reglas y el fallo al cargarlas tienen resultados distintos.
- [x] El error no expone claves, documento ni configuración de otra empresa.

Comprobar en la frontera HTTP y en la frontera de red, usando el validador real cuando sea posible. La prueba actual de alertas no justifica mover creación de alertas dentro del evaluador: la orquestación conserva ese efecto.

## Entrega y recuperación

No necesita una migración de datos para el primer cierre. Documentar códigos de error y cómo reparar una regla. Una incidencia puede deshabilitar el envío; **no** debe activar un modo que ignore comprobaciones obligatorias. El rollback de otras funciones debe conservar esta corrección.

Fuente técnica: [YARA en Python: compilación, matching y timeouts](https://yara.readthedocs.io/en/stable/yarapython.html). Para trabajar esta entrega, aplicar el ciclo de [diagnóstico y TDD del método](metodo-matt-pocock.md).

# 03. La misma política en la web y en la API

**Estado:** implementado y probado localmente. **Prioridad:** P0. **Depende de:** [01](01-seguridad-ante-fallos.md) y [02](02-historial-y-confirmaciones.md). **Resultado:** una petición equivalente obtiene la misma decisión y el mismo contexto, independientemente de cómo entre.

## Evidencia de implementación — 2 de octubre de 2026

front.test_chat_flow; front.test_pipeline; front.test_connectors. Las tres entradas llaman al mismo servicio; se probaron también los límites HTTP/SDK y la conservación de descargas.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Punto de partida

Hay tres recorridos: POST de `front.views.chat_view`, `front.views.chat_send_message` y `api.views.chat_send_message`. Comparten conceptos, pero duplican orquestación y difieren en confirmaciones y adjuntos. El modelo ya dispone de conectores comunes; el problema está principalmente antes y después de llamarlos.

## Diseño propuesto

Crear un único caso de uso en `front/chat_service.py`, por ejemplo `send_chat_message(actor, command) -> ChatResult`. `command` será un tipo pequeño con contenido, conversación, adjunto validado, selección manual opcional, identificador de petición y prueba de confirmación. El usuario y la empresa se obtienen de autenticación y permisos, no de parámetros confiados al cliente.

Las vistas mantienen autenticación, CSRF o token según corresponda, deserialización y formato de salida. La función compartida hace autorización, preparación, política, estado, ruta, generación y persistencia. Los módulos especializados se extraen solo cuando aparezcan los comportamientos de los siguientes planes; no se crean interfaces con una sola implementación ni un contenedor de inyección de dependencias.

## Entregas pequeñas

1. **Fijar compatibilidad.** Escribir ejemplos de petición y respuesta de las tres entradas actuales y pruebas de comportamiento: texto permitido, bloqueo, confirmación y empresa ajena. Reutilizar los casos de 01–02; no duplicar sus pruebas internas.
2. **Mover un recorrido completo.** Llevar el envío asíncrono al caso de uso sin mezclar todavía nuevas decisiones de Jev. Mantener creación de mensajes, alertas, respuesta y descargas. Eliminar la lógica que se sustituye.
3. **Incorporar REST y POST antiguo.** Adaptadores finos al mismo comando. Un adjunto admitido debe atravesar los mismos límites; formatos no soportados devuelven error explícito. El POST antiguo llama a la misma función, no hace una petición HTTP a la propia aplicación.
4. **Cerrar vías de evasión.** Revisar escrituras de `Message`, `Prompt`, `Response`, motores y reglas en serializers/viewsets. Impedir que CRUD genérico cree un turno “autorizado” o altere estados de control. Comprobar empresa al leer y al escribir, no solo al obtener el objeto.
5. **Eliminar restos y documentar.** Una búsqueda de `validate_prompt`, `obfuscate_text` y `.chat(` debe explicar cada llamador restante. El flujo productivo queda centralizado. Las llamadas directas permitidas serán herramientas de prueba explícitas, no rutas alternativas de usuario.

Mantener `get_connector` y las credenciales `CompanyEngine`. Un motor inactivo o ajeno nunca se sustituye silenciosamente por una clave global. Si se desea un proveedor compartido por la instalación, debe configurarse como destino expresamente autorizado para esa empresa.

## Contrato y errores

Conservar inicialmente claves usadas por el JavaScript: `conversation_id`, `blocked`, `blocked_rules`, `requires_consent`, `consent_rules` y mensajes. Añadir `request_id`, `status`, `decision` y, después, `verification` y `receipt`. No prometer identidad byte a byte entre HTML y JSON: sí identidad de decisión, efectos y contenido enviado.

La autenticación REST observada vive en `/api/auth/login/`; no copiar ejemplos de `/api/token/` sin comprobar rutas. Los envíos observados son `/api/chat/send/` y las rutas `/chat/...` de [front/urls.py](../../regulai/front/urls.py). Un cambio de contrato incompatible exige periodo de transición o versión explícita, no un cambio silencioso.

## Aceptación y pruebas

- [x] La misma matriz de casos pasa por las tres entradas y produce igual decisión.
- [x] Coincidir con una regla `consent` significa confirmar en las tres, sin rebajar una regla `block`.
- [x] Usuario A no utiliza conversación, credencial o estado de petición de empresa B.
- [x] Una escritura por CRUD no inyecta mensajes aprobados en el historial.
- [x] Los prompts de empresa y departamento llegan según un orden definido; comprobar también Anthropic, cuyo tratamiento de mensajes `system` debe conservar ambos.
- [x] No se pierden descargas de respuestas ni manejo de adjuntos ya soportados.
- [x] No quedan tres copias del envío ni consultas internas por HTTP.

Probar HTTP real con cliente de Django y sustitutos de SDK/HTTP externos. La configuración del sustituto no debe reproducir el algoritmo que se está probando.

## Entrega y recuperación

Sin migraciones adicionales fuera de las definidas en 02. Activar después de pasar la matriz de compatibilidad; no mantener indefinidamente una bandera para cada versión del flujo. Ante incidencia, detener el envío afectado o volver a una revisión segura, conservando 01–02.

Actualizar ejemplos API, diagrama del envío y contrato de errores en la documentación de la entrega. Es el mejor lugar para aplicar `codebase-design` y la revisión de requisitos descritos en el [método](metodo-matt-pocock.md).

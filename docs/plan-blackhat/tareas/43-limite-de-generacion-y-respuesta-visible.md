# 43. Separar generación y tamaño de respuesta verificable

Estado: corregido y aplicado a la cuenta local; pruebas simuladas aprobadas, 5 de octubre de 2026.
Blocked by: ninguno.

## Incidencia y causa

Recibo `cc85c0d8-4584-4443-922d-8cb7883b38fc`, conversación 8:
Jev eligió difícil con confianza 1 y el enrutador seleccionó `deepseek-v4-pro`.
El generador consumió exactamente 1000 tokens de salida, terminó con
`finish_reason=truncated` y falló `nonempty`. La verificación semántica no se ejecutó.
El mensaje genérico `verification_failed` ocultaba este motivo local concreto.

El límite de respuesta visible se calculaba exclusivamente como ocho veces el
límite de tokens, de modo que ampliar generación a 8192 también habría aumentado
la reserva de entrada de Jev por encima de su capacidad. Los dos límites representan
recursos distintos y deben poder configurarse de forma independiente.

La [documentación de DeepSeek](https://api-docs.deepseek.com/guides/thinking_mode/)
confirma que el modo de razonamiento está habilitado por defecto y devuelve ese
contenido separado de la respuesta final. No se desactiva este comportamiento.

## Cambio

- Campo opcional `routing.max_response_bytes`, entero positivo hasta 128000.
  Su ausencia conserva el comportamiento anterior; su presencia limita la respuesta
  visible y la reserva de capacidad del juez, sin ampliar el límite previo derivado
  de tokens. No se trunca ni se muestrea texto para forzarlo a caber.
- Los tokens de generación completos siguen reservándose y contabilizándose en
  contexto, costes y presupuesto. El razonamiento privado no se entrega ni se envía
  al juez como respuesta.
- `verification_failed` conserva su código y estado HTTP. Cuando el recibo indica
  truncamiento, el texto del error explica el agotamiento del límite de generación.
- Cuenta local empresa 3: generación 8192 tokens, respuesta visible 8000 bytes,
  timeout por llamada 60 s, plazo total 120 s. Catálogo local Flash y Pro: máximo
  configurado al menos 8192. Se conservan modo automático, rutas, claves, reglas,
  destinos y verificación `enforce` al 0,8.
- Revisión de política 4, auditoría `reasoning_output_limits`, copia consistente
  `community-local.before-reasoning-limits-20261005-152854.sqlite3`.

## Pruebas y límites de la evidencia

- Reproducción sintética con SDK real y HTTP interceptado: respuesta vacía,
  `finish_reason=length`, 1000 tokens; se rechaza antes del juez.
- Regresión escrita antes del cambio: el nuevo límite no era aceptado por la
  política. Tras el cambio, las tres entradas HTTP transmiten 8192 tokens, admiten
  una respuesta completa y la verifican sin superar la capacidad de Jev.
- Comprobación de frontera UTF-8: 8000 bytes se aceptan, 8001 se rechazan; una
  respuesta truncada sigue fallando aunque el límite se haya ampliado.
- El coste incluye todos los tokens declarados por el proveedor. Un presupuesto
  insuficiente para 8192 tokens impide cualquier llamada.
- 47 pruebas de pipeline, privacidad, verificación y diagnóstico: OK, 19,635 s.
  Tras añadir comprobaciones de validación y reserva: 15 pruebas de dificultad,
  SDK y límites: OK, 3,870 s.
- `check`, `makemigrations --check --dry-run` y `git diff --check`: correctos.
  GET autenticado de `/chat/8/`: HTTP 200. Servidor local reiniciado.

No se hicieron nuevas llamadas de pago, conforme a AGENTS.md. Ampliar el límite
corrige la configuración observada; no garantiza que cualquier solicitud termine
antes del límite ni constituye una nueva comprobación real de Pro.

Seguimiento: por petición explícita del usuario, los topes de generación de esta
cuenta se retiraron después en [la tarea 44](44-limites-del-proveedor.md).

# 41. Instrucciones puntuales del historial y verificación conversacional

Estado: corrección comprobada en vivo y suite completa aprobada, 5 de octubre de 2026.
Blocked by: ninguno.

## Incidencia y aceptación

El usuario informó de `verification_failed` al enviar «hola» en la conversación 8,
después de la prueba «Responde solamente con estas dos palabras: Prueba correcta.».
Recibo original: `d573b9f5-c7eb-4e60-9538-d68dae869397`.
Se exige responder al mensaje actual manteniendo historial, YARA, privacidad local,
Jev obligatorio y umbral 0,8; una instrucción puntual completada no debe convertirse
en una restricción permanente.

## Diagnóstico observado

- Control sin historial (`7e412bd6-3cb2-4427-b74a-bb5418e42b39`): el saludo devuelve
  «¡Hola! ¿En qué puedo ayudarte hoy?», Jev 0,08/0,06, `completed`.
  Este primer intento usó `/chat/send/`, cuya conversación se resuelve desde la URL,
  no desde un campo POST. Se conserva como control independiente, no como reproducción.
- Reproducción exacta por `/chat/8/send/`
  (`285f9b69-6692-4095-adb8-92d4742e33ea`): DeepSeek contesta «Prueba correcta.» al
  saludo. Jev lo rechaza correctamente, omisión 0,47 y contradicción 0,16.
- La cuenta no tenía instrucciones de sistema. Se configuró su `system_prompt` para
  atender el último mensaje, conservar contexto/preferencias duraderas y limitar las
  instrucciones puntuales a su turno. No se modificó la política. Auditoría
  `test_conversation_guidance`; copia previa
  `community-local.before-conversation-guidance-20261005-105243.sqlite3`.
- Segunda comprobación (`c9c419e3-53d5-4a08-a5e3-2f4ac8fa1add`): el generador ya
  saluda, pero la pregunta genérica del juez aún produce omisión 0,24 y rechaza la
  respuesta correcta. Esta evidencia identifica un segundo problema de alcance.

## Cambio

Las preguntas de Jev para `general` distinguen `state.request` (mensaje actual) de
`state.context` (sistema e historial). Conservan instrucciones permanentes y preferencias
explícitas, pero no exigen repetir restricciones de tareas puntuales completadas. Los
saludos se evalúan como actos conversacionales, sin inventar requisitos de evidencia
factual. Las instrucciones contenidas en el estado no pueden modificar la evaluación.
Las preguntas documentales y de citas no cambian.

Los recibos registran `question_rubric_version=verification-questions-v2` junto a la
etiqueta de rúbrica configurada; se conservan los recibos históricos. No se eliminó
historial, rebajó el umbral ni cambió `enforce` a un modo permisivo.

## Comprobaciones

- Regresión escrita antes del cambio: falló por las tres entradas HTTP al comprobar
  la distinción de turno. Tras el cambio, conserva el historial completo enviado al
  juez y comprueba que una omisión 0,47 sigue impidiendo entregar la respuesta.
- Siete pruebas de regresión, juez documental y frontera numérica: OK en 8,956 s.
- Suite completa `front api --settings=regulai.test_settings --noinput`: 467 tests
  en 194,653 s, `OK (expected failures=2)`. Sin llamadas reales en esta suite.
- Mismo saludo, mismo historial original, después del cambio:
  `d52d4117-dc10-477d-bc4a-de79647508d3`, «¡Hola! ¿En qué puedo ayudarte hoy?»,
  Jev 0,06/0,05, `completed` y `passed`.
- Continuación «¿Cuánto es 2 + 2? Responde brevemente.»:
  `95d0bad1-bfc9-44ae-b1f4-c218152d92f5`, respuesta «4», Jev 0,04/0,03,
  `completed` y `passed`, manteniendo los dos turnos anteriores.
- Cinco peticiones de diagnóstico/validación, diez llamadas externas sin reintentos,
  coste total registrado 0,000909720 USD, parcialmente estimado. La petición fallida
  original del usuario no se incluye en este importe. Todos los recibos se conservan.

La prueba confirma estos casos de conversación; no constituye una recalibración
general del juez probabilístico ni una nueva evaluación de calidad documental.

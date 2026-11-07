# 42. Selección automática de Flash o Pro según el prompt

Estado: implementado, activado en la cuenta local y verificado con proveedores simulados, 5 de octubre de 2026.
Blocked by: ninguno.

## Petición y aceptación

El usuario confirmó Flash para solicitudes fáciles y Pro para difíciles. La cuenta
`Pruebas de Javi` estaba en modo manual y solo tenía Flash. Debe elegir el modelo
automáticamente a partir de la solicitud actual, conservando autorización, YARA,
enmascaramiento, límites y verificación final.

## Implementación

- Opción aditiva `routing.strategy=difficulty`; las políticas existentes conservan
  `quality` por defecto. No se inventan puntuaciones de calidad ni se permite
  combinar esta estrategia con un mínimo de calidad distinto de cero.
- Con clasificación local, Jev recibe el estado ya enmascarado y una pregunta
  `difficulty-v1`: `easy` o `hard`. Fácil con confianza >= 0,8 selecciona `economy`;
  difícil o dudoso selecciona `strong`. Una respuesta inválida detiene la solicitud.
- Si la política ya exige clasificación semántica, se reutiliza su dificultad;
  `balanced` y `strong` seleccionan el nivel fuerte. La selección manual explícita
  sigue disponible. No se baja silenciosamente a Flash si falta Pro.
- La elección del juez solo filtra candidatos previamente autorizados. No modifica
  sensibilidad ni permisos. El nuevo paso se incluye en reservas, límites y recibos;
  estos registran el modelo, `difficulty_route`, señales y versión de rúbrica.
- La verificación final continúa en `enforce`, umbral 0,8. La estrategia no utiliza
  escaladas basadas en puntuaciones de calidad inexistentes.
- El simulador distingue las señales manuales de las evaluaciones que no contienen
  la nueva pregunta de dificultad y no presenta estas últimas como selección probada.

## Activación local

Solo la empresa 3: `routing.mode=auto`, `strategy=difficulty`, candidatos del motor
vinculado 2: `deepseek-flash` para economy y `deepseek-v4-pro` para strong.
Pro se añadió al catálogo del motor existente; no se cambiaron claves ni permisos
de salida. Revisión de política 3, auditoría `enable_difficulty_routing`.

Copia SQLite previa consistente:
`community-local.before-difficulty-router-20261005-125921.sqlite3`.

Identificador, contexto y tarifas estimadas de Pro contrastados con la
[documentación oficial de DeepSeek](https://api-docs.deepseek.com/quick_start/pricing/):
1 M de contexto y precios peak/cache miss 1,32/3,96 USD por millón de tokens.
El límite local de salida sigue siendo 1000 tokens; las respuestas truncadas siguen
rechazándose. Estas tarifas son estimaciones conservadoras, no cargos observados.

## Verificación observada

- Suite completa: 477 pruebas en 134,214 s, `OK (expected failures=2)`.
- Después se añadió la comprobación del SDK real con HTTP simulado: suite focalizada
  `front.test_difficulty_routing front.test_routing front.test_policy_simulator`,
  33 pruebas en 3,396 s, OK. Incluye fácil/difícil por las tres entradas HTTP,
  selección manual, bloqueo local sin llamadas, respuesta inválida, Pro inactivo,
  credencial/precio ausentes, cambio de política durante la llamada y rechazo del juez.
- SDK OpenAI compatible: seis envíos simulados comprueban endpoint, modelo elegido
  y límite de salida. Sin llamadas de pago nuevas, conforme a AGENTS.md.
- `manage.py check` y `makemigrations --check --dry-run`: correctos.
- Navegador real en `/chat/8/`: casilla automática marcada y Flash/Pro disponibles.
  El servidor local se reinició para cargar el cambio.

La clasificación probabilística real de prompts fáciles/difíciles y una generación
real con Pro no se han medido en esta tarea. Las pruebas no sustituyen una calibración
de calidad ni garantizan que todo prompt complejo quepa en el límite de salida.

Seguimiento: el usuario confirmó la selección real de Pro, pero su generación se
truncó a 1000 tokens. El ajuste posterior de límites y su validación están en
[la tarea 43](43-limite-de-generacion-y-respuesta-visible.md).

# Evaluación real de diez conversaciones P0

Status: completada (evaluación; defectos de producto pendientes documentados).
Blocked by: ninguno; autorización explícita de modelo real, máximo total 5 USD.

Referencia: [plan P0](../plan-p0-arnes-ia-20261016.md), entregas E1–E8 y tarea 60.

## Alcance y aceptación

Diez conversaciones sintéticas (17 turnos), usando las tres entradas HTTP, el
proveedor real y el worker del código P0 en una base y contenedores separados.
Registrar respuestas, operaciones, llamadas, tiempos, consumo, artefactos y
revisiones. Evaluar contra oráculos independientes sin enviarlos al modelo.
Conservar controles de permisos, protección local, idempotencia y coste.
No desplegar en la instalación ni cambiar sus datos, reglas o servicios.

## Secuencia

1. Corpus reproducible: terminado; CSV, XLSX, PDF, HTML, ZIP, web y simulación.
2. Guardia de gasto: terminada; 15 pruebas focalizadas pasan tras añadir el
   sellado conservador de consumo desconocido.
3. Aplicación y ejecución aisladas: terminadas.
4. Diez conversaciones reales: terminadas; repeticiones dirigidas de c03, c06
   y c10 por fallos concretos, sin reintentos automáticos ni reiniciar el gasto.
5. Comprobación integrada: terminada; 34 comprobaciones pasan.
6. Informe y limpieza de recursos propios terminados; evidencia y volumen de
   datos sintéticos conservados, credenciales copiadas retiradas.

## Decisiones

- Presupuesto autorizado por el usuario: 5 USD, sin ampliación implícita.
- DeepSeek Flash configurado, transporte real instrumentado y sin reintentos.
  Reserva previa por ventana máxima y salida acotada; uso desconocido detiene
  nuevas llamadas. Tarifas techo sin caché: 0,30/1,20 USD por millón de tokens,
  fuente: https://api-docs.deepseek.com/quick_start/pricing/ (16-10-2026).
- Datos y política de empresa sintéticos; máscara local real obligatoria y
  permisos normales. La instalación utiliza clasificación/verificación local,
  aunque tiene clave Jev configurada. Sus reglas privadas no se copian.
- El worker instalado es anterior a P0 y conserva una microVM precalentada.
  Se preserva ese servicio; la evaluación usa su propio worker y capacidad 1.
  No se atribuirá la microVM ajena a esta evaluación ni se afirmará que el
  límite de la prueba gobierna toda la instalación.
- La entrada admite un archivo por turno: conciliación empaquetada en ZIP;
  se documenta esta limitación, sin simular soporte multiadjunto.

## Evidencia

Corpus: `evals/corpora/p0-conversations-20261016/`.
Guardia: `ops/agent_chat/p0_eval_budget.py`, 15 pruebas pasan al cierre.
Primera pasada conservada en `output/p0-real-20261016/preflight/`: todos los
trabajos afectados se detuvieron antes de inferencia, coste 0 USD. No es una
evaluación de calidad del modelo. Causa común demostrada: faltan
`sandbox_runner.py` y `checkpoint_runner.py` en el paquete del worker; P0 los
necesita para calcular la identidad de versión. Los imports aislados no habían
detectado este fallo de empaquetado.

Permisos comprobados por las tres entradas HTTP: cuenta sintética sin grant
rechazada con `agent_access_denied`, sin persistir Prompt ni llamar al proveedor
(el stream transporta el 403 dentro de su evento final HTTP 200).

Incidencias adicionales reproducidas del corpus: dimensiones XLSX opcionales,
edición de ZIP adjunto confundida con revisión publicada, negación de creación
de archivos y actualización de totales confundida con edición. Correcciones y
pruebas focalizadas completadas. La repetición se justifica por estos fallos
concretos; se preserva la evidencia inicial y no se reinicia el presupuesto.

Correcciones focalizadas completadas: 6 pruebas de intención/entradas/idempotencia
y 4 de dimensiones/límites XLSX pasan. El paquete SDK calcula correctamente su
identidad y el dispatcher registra tipo de error sin filtrar el mensaje sensible
en la prueba de fallo. No se ha ampliado la auditoría.

## Hallazgos de la pasada real

- Contexto (3 turnos), aritmética, Excel, PDF y lectura IANA correctos tras revisión
  manual de respuestas y trazas. Preguntas de texto no adquieren microVM.
- CSV calcula 256 EUR correctamente, pero `publish_artifact.sources` ambiguo
  induce rutas de adjuntos donde se exigían IDs web. Aclarado esquema/runtime;
  2 pruebas de publicación, trazabilidad y rechazo de fuentes inválidas pasan.
- HTML correcto acaba acompañado de JavaScript innecesario: «sin JavaScript»
  se detectaba como requisito positivo. Corregidos aliases negados y listas;
  prueba focalizada con 9 variantes pasa. Ambigüedad de reentrega se conserva
  como fallo del primer intento; no se borran sus artefactos.
- Conciliación en modo razonado termina con HTTP 400 del proveedor al pasar de
  herramientas rápidas a respuesta final razonada. No hay recibo de consumo.
  No se reintenta esa llamada ni se afirma su causa exacta sin el cuerpo del error.
  El modo razonado queda pendiente de corrección y validación real.

### Coste desconocido y continuidad segura

La guardia detuvo nuevas llamadas al faltar uso. Se añadió operación explícita
`cap_unknown`: consume irrevocablemente TODA la cota reservada antes de red,
mantiene coste real `null`, prohíbe reutilizar el call_id y permite otras llamadas
solo dentro del saldo restante. No se falsea un recibo ni se libera dinero.
Las 15 pruebas de presupuesto pasan después de este cambio compartido.

Para el HTTP 400 se consumen como techo 0,3098304 USD. Reconciliación de capacidad
separada usando la respuesta HTTP terminada: estado/coste de la inferencia
desconocidos conservados, operador sintético desactivado y sandbox destruido.
Pruebas siguientes usan quick; no se repite a ciegas el modo rechazado.

## Resultado final de la evaluación

**8/10 conversaciones completamente correctas; 14/17 turnos correctos** en los
últimos intentos. No equivale a éxito en el primer intento ni certifica que todos
los P0 funcionen sin defectos. Respuestas, trazas, artefactos e intentos previos
se conservan en `output/p0-real-20261016/`.

- c03 entrega CSV correcto y lo reentrega sin nuevas llamadas.
- c06 crea y reentrega el HTML correctamente, pero su edición cambia una
  variable CSS compartida, la etiqueta Evento y estilos hover/focus además del
  fondo solicitado. El turno de edición falla por exceder el alcance.
- c10 rápido devuelve marcado interno DSML y después no recupera el adjunto
  previo. Sus dos turnos fallan aunque figuren como `completed`. El cambio a
  rápido no resuelve la calidad ni valida el modo razonado que devolvió HTTP 400.
- Contexto, aritmética, Excel, PDF, edición ZIP, consulta IANA y simulación pasan.
  Las reentregas CSV/HTML/ZIP conservan ID/hash y hacen cero llamadas al modelo.

Se registraron 67 peticiones reales: 66 con consumo informado y una desconocida.
Estimación conservadora del uso conocido: 0,1308285 USD; cota consumida por el
uso desconocido: 0,3098304 USD. Techo total contabilizado **0,4406589 USD**, por
debajo de los 5 USD autorizados. No es una factura; el coste real desconocido
permanece `null`.

La comprobación integrada pasa: permisos en las tres entradas HTTP, idempotencia,
separación de empresas y conversaciones, hashes de entradas/descargas/revisiones,
migraciones, protección local, reservas, costes y destrucción de microVM propias.
El verificador inicialmente confundió el HTTP 200 exterior del stream con la
denegación del evento final; se corrigió solo esa lectura y se recalculó sobre
la misma evidencia, sin repetir peticiones ni toda la integración. Se conserva
el informe inicial del verificador. `git diff --check` pasa.

Informe: [evaluación completa](../../../output/p0-real-20261016/report.md).
Veredictos: [revisión semántica](../../../output/p0-real-20261016/live/manual-review.json).
Controles: [comprobación integrada](../../../output/p0-real-20261016/live/integrated.json).
Limpieza: [resultado](../../../output/p0-real-20261016/cleanup.json). Eliminados los
tres contenedores y las dos redes exclusivos del ensayo; ninguna microVM propia
activa. Servicios originales y microVM preexistente conservados, sin reinicios
del web/worker original ni llamadas pagadas durante la limpieza.

Siguientes correcciones propuestas: impedir falsos éxitos con marcado de
herramientas, recuperar adjuntos autorizados entre turnos, restringir cambios
de edición y diagnosticar el HTTP 400 razonado. No se amplían las pruebas ni se
consumen más llamadas en esta evaluación para obtener respuestas favorables.

# Piloto controlado: propuesta preparada, ejecución pendiente

**Estado:** preparación local y [simulación de dos perfiles completada](../../evals/reports/pilot-personas-20261003-01/README.md) por petición expresa del usuario. No hay participantes, invitaciones, sesiones humanas ni despliegue realizados. Las observaciones artificiales no acreditan comprensión humana.
Especificaciones: [12](12-demo-y-salida.md), [11](11-evaluacion-reproducible.md) y [decisiones compartidas](README.md).

## Entorno y alcance propuestos

Primera sesión presencial supervisada en esta estación, accesible solo por loopback. El recorrido de operación y aislamiento utiliza Linux Docker, PostgreSQL aislado, Gunicorn y HTTPS con certificado local: dos empresas ficticias, Alpha y Beta, con un empleado y un administrador por empresa. El administrador no recibe permisos globales. Los recorridos documentales utilizan además el runner Windows/SQLite indicado en su guía, con respuestas y citas sintéticas; se registran como entorno distinto. Los transportes se rotulan; la sesión prueba uso y controles. El puerto del laboratorio se asigna al arrancar y queda en `endpoint.json`.

Propuesta de participación: dos personas designadas por el usuario, una con cada empresa, más el operador responsable. Una persona no representa una empresa real. No se reutilizan contraseñas, documentos, conversaciones ni claves del usuario. El conjunto de datos admitido es exclusivamente el [corpus sintético](../../evals/documents/pilot-20261003/). Cualquier inclusión posterior de datos reales exige definir previamente categoría, destino, conservación y autorización.

La revisión candidata final es `972edb88c82a5220a43ffcc89316a9f9033e82f7`; el ensayo vivo previo pertenece a `698e8f0` y permanece detenido. Las evidencias de operación y navegador indican sus propios snapshots, sin atribuirles reejecuciones posteriores. El [informe final](informe-piloto-community-20261003.md) identifica pruebas y hashes. Cambiar código, política, modelos o corpus exige registrar una nueva versión y repetir las comprobaciones afectadas. La instalación local del laboratorio no acredita CI remoto ni una infraestructura publicada.

El enmascarado se ejecuta realmente en CPU dentro de Django; respuestas y jueces permanecen simulados en esta sesión de 0 USD. El detector es falible: el corpus de 18 casos cumple 16 expectativas, con dos omisiones, y se han observado falsos positivos. El operador explica esta limitación antes de empezar. Esa evidencia no permite ampliar el conjunto admitido a documentos reales sensibles.

## Recorrido y recogida de resultados

Cada participante realiza los [recorridos y formulario](documentos-y-ensayos-piloto.md) con su identidad. Antes de empezar, el operador explica las etiquetas de simulación, cobertura textual, consentimiento, verificación y coste incierto. La persona describe con sus palabras qué cree que ocurrió; se conserva esa observación, no una respuesta atribuida por el agente.

Tareas mínimas: enviar una pregunta sencilla, reconocer un bloqueo, cancelar y confirmar una advertencia, abrir una cita con teclado, inspeccionar la ficha, recargar, exportar y comprobar que los datos de la otra empresa no aparecen. El operador provoca una desconexión solo en el entorno sintético y registra cómo interpreta la persona el resultado incierto.

Antes de iniciar se asignan IDs P01/P02, fecha, revisión, empresa ficticia, rol, escenario, resultado esperado y observador. Registrar inicio/fin reales, resultado observado, incidencia y comentario literal voluntario. Los tiempos no se rellenan hasta medirlos. No grabar pantallas o voz de participantes sin su autorización. Los campos de revisión humana de la evaluación quedan vacíos hasta recibir una valoración identificada.

## Límites, soporte y parada

- Gasto de producto de la sesión offline: **0 USD**, sin credenciales reales y sin salida a proveedores. No se contrata infraestructura.
- Sesión con proveedores vivos: requiere aprobación separada del manifiesto y presupuesto conjunto del [ensayo real](ejecucion-real-y-calibracion-piloto.md). El permiso del 3 de octubre cubrió solamente el smoke acotado y no habilita una sesión humana viva; el del 2 de octubre no se reutiliza.
- El operador conserva el control del arranque/parada y un canal local de incidencias; no se contacta a nadie automáticamente.
- P0: salida prohibida, cruce entre empresas, secreto en logs, cita inválida marcada verificada, llamada sin reserva o pérdida de datos. Detener envíos, conservar evidencia mínima, suspender la sesión y recuperar la última copia coherente.
- P1: bloqueo del recorrido, duplicación de generación, estado o coste incierto presentado como éxito. Detener el caso, comprobar estado por request_id; nunca repetir una llamada incierta para obtener una captura favorable.
- P2: problema de comprensión, accesibilidad o formato sin incumplimiento de controles. Registrar y continuar solo si la tarea sigue siendo interpretable.

## Criterios fijados antes de ejecutar

| Medida | Criterio para continuar |
| --- | --- |
| Participación | Dos recorridos completos, observados y fechados; cada omisión se conserva |
| Seguridad | Cero P0; cero acceso entre empresas y cero salida prohibida observada |
| Estado y dinero | Un envío por request_id; incertidumbre visible; todas las llamadas y reservas contabilizadas |
| Documentos | Cada caso conserva cobertura y omisiones esperadas; citas mostradas resolubles |
| Comprensión | Ambas personas distinguen simulación, consentimiento, cobertura y verificación; dudas registradas |
| Recuperación | Restauración sintética comprobada y operador capaz de seguir el procedimiento |
| Calidad semántica | Solo se concluye tras revisión humana del banco real; no se infiere de la demo |

La decisión al terminar será continuar, corregir y repetir, o detener, con incidencias y evidencias enlazadas. Una muestra de dos personas solo informa sobre estos recorridos. No demuestra seguridad universal, ahorro ni aptitud para todos los documentos.

## Acciones pendientes de aprobación humana

1. Designar dos participantes y un observador, acordar fecha y autorizar su participación; todavía no se envían invitaciones.
2. Aprobar la revisión candidata, este entorno solo local, corpus y cero gasto para la sesión offline.
3. Si se desea el recorrido vivo, aprobar aparte los destinos, modelos, datos, ventana temporal y techo del manifiesto real.
4. Cualquier publicación, exposición o servidor externo requiere propuesta y autorización propias; no forma parte de este arranque.

Arranque y recuperación: seguir el [procedimiento comprobado](operacion-y-recuperacion-piloto.md); la opción `--serve-seconds 3600` mantiene la sesión local tras validar el laboratorio. Parar los contenedores identificados por el manifiesto, conservar informes y restaurar conjuntamente base, medios y claves sintéticas. La herramienta solo retira recursos con el identificador de esta ejecución; no elimina las bases del usuario. La evidencia privada y los backups no se publican.

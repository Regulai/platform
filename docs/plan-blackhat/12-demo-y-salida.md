# 12. Una demo breve, verificable y preparada para fallos

**Estado:** demo aislada reproducida; tres escenas, consentimiento y simulador comprobados en navegador. Apertura de citas con teclado y dos ensayos humanos pendientes. **Prioridad:** P1. **Depende de:** 01–09 y [11](11-evaluacion-reproducible.md); simulador opcional. **Resultado:** presentar tres mejoras comprensibles, con evidencias reales y una recuperación ensayada.

## Evidencia de implementación — 2 de octubre de 2026

`run_demo` siembra una base separada y bloquea las conexiones HTTP/socket del servidor a proveedores; el navegador puede pedir glifos a Iconify. Instalación nueva en `.claude/reproduction-venv-20261002`, creada con uv/Python 3.12.11 y 45 paquetes fijados: `front api`, 129 pruebas correctas en 39,764 s; `check`, cero incidencias; siembra de demo correcta. Las tres escenas se prueban automáticamente en la suite. El recorrido de navegador usó el entorno original con la misma fuente de dependencias: saludo automático `Hola` con tres llamadas simuladas; bloqueo con cero llamadas; contrato con primer resultado erróneo de 900 euros rechazado, segundo resultado de 10 euros y cita en línea 2, dos generaciones/cinco llamadas simuladas y persistencia al recargar. No se atribuye este recorrido visual al entorno nuevo.

Consentimiento: cero llamadas antes de confirmar; cancelar terminó en `cancelled` sin respuesta; confirmar conservó el archivo y un único turno de usuario/asistente. Simulador: comparación y activación local en otra empresa sin claves ni destinos, cero llamadas reales y revisión 2. Enter envió el mensaje y abrió la ficha; Espacio alternó la ruta automática. Abrir citas con teclado quedó sin comprobar por rechazo de URL de la herramienta. [Guion y recuperación](arranque-y-demo.md), [capturas y pendientes](estado-ejecucion.md). Los dos ensayos con otra persona están pendientes externos.

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Guion propuesto: unos cinco minutos

| Escena | Qué hacer | Qué debe quedar claro |
| --- | --- | --- |
| 1. Elegir bien | Enviar una tarea sencilla y abrir la ficha de decisión | Se eligió un modelo autorizado que cumple la tarea; el coste mostrado procede de la ejecución |
| 2. Proteger datos | Adjuntar un documento sintético con una credencial reconocible por una regla local | Se bloqueó antes de salir a Jev y al generador; mostrar el motivo y el registro de llamadas |
| 3. Comprobar la respuesta | Preguntar sobre un documento con una condición importante y abrir sus citas | Si el primer resultado falla, se registra y se verifica el segundo; las fuentes se pueden abrir |

La escena 3 no puede depender de que un proveedor cometa exactamente el error esperado en directo. Preparar un modo de demostración con respuesta prefijada exclusivamente en una instalación aislada, rotulado **“fallo simulado para demostrar el control”**. Complementarlo con una captura de evaluación real identificada por fecha y configuración. No presentar un resultado prefijado como una llamada recién hecha.

Si sobra tiempo, enseñar el simulador del plan 10 con un falso positivo y su corrección. La narración cabe en una frase: “regulAI decide qué puede salir, elige un modelo adecuado y muestra qué ha comprobado de la respuesta”.

## Preparación y ensayo

1. **Congelar una revisión candidata.** Anotar commit, dependencias, modelos, políticas, rúbricas y dataset. Crear una empresa y usuarios de demo, credenciales de prueba y presupuesto acotado. Documentos completamente sintéticos.
2. **Comprobar las tres entradas.** Suite de seguridad y compatibilidad verde; prueba visual del chat, confirmación y evidencias; exportación de ficha sin información privada. Verificar descargas y mensajes de error que pueda ver el público.
3. **Ensayar fallos reales de operación.** Caída de Jev, 429 del generador, OCR ausente, documento demasiado grande, doble clic y pérdida de respuesta HTTP. La aplicación muestra el estado conocido y no se salta controles para continuar la demo.
4. **Preparar reproducción offline.** Capturas/resultados de ejecuciones anteriores con fecha, modelos y etiqueta de reproducción. Mostrar claramente cuándo se usa esa alternativa. No construir un sistema de caché productiva para resolver un fallo de wifi de la presentación.
5. **Cronometrar y simplificar.** Hacer dos ensayos completos con otra persona. Si la explicación exige abrir código o cinco pantallas, reducirla: pregunta, decisión, evidencia. Conservar siempre el detalle accesible para quien quiera profundizar.

## Comprobación de publicación

La base original fijaba Django 4.2.28; la implementación local actual usa Django 5.2.17 LTS y DRF 3.18.1. La compatibilidad se comprobó con la suite de 129 pruebas en el entorno existente y en otro recién creado. [Dependencias y auditoría](dependencias-verificadas.md).

`requirements.txt` raíz fija los 45 paquetes; la lista interior remite a ella. Se reprodujo con `uv venv --python 3.12.11` y `uv pip sync`; `py -3.12` no está disponible en esta máquina. No hay despliegue ni publicación autorizados, por lo que comprobar una revisión desplegada queda fuera de esta entrega local.

Esta comprobación de publicación no sustituye a la revisión de seguridad de los cambios, ni convierte el benchmark de 50 casos en una auditoría completa del producto.

## Artefactos que acompañan la demo

- Guion breve con entradas exactas y resultado esperado de cada escena.
- Configuración de ejemplo sin secretos y pasos de arranque probados.
- Informe del plan 11 con calidad, cobertura, coste, latencia y casos fallidos.
- Una ficha real de decisión permitida para compartir y un ejemplo de bloqueo.
- Tabla clara de capacidades Community y propuesta de evolución a Vigía13, sin atribuirle funciones no verificadas.

| Capacidad | Community observada | Vigía13 propuesta, sin implementar aquí |
| --- | --- | --- |
| Seguridad y permisos | Bloqueo antes de cada destino, confirmaciones firmadas y ámbitos de empresa/propietario | Gobierno centralizado e integraciones corporativas |
| Clasificación y ruta | YARA y cliente Jev, tres niveles de ruta, presupuesto/plazo por petición y una escalada; Jev real pendiente de acceso/calibración | Optimización adaptativa con histórico amplio y presupuestos organizativos avanzados |
| Verificación y evidencia | Verificación obligatoria configurable, ficha/exportación y citas con fragmentos validados; calidad semántica real pendiente | Aprobaciones entre responsables |
| Administración y evaluación | Empresas/roles, simulador local con activación auditada, banco offline reproducible y demo sintética aislada | Extensiones corporativas pendientes de decisión comercial |

La columna Vigía13 recoge candidatos del [límite de producto](README.md#límite-propuesto-entre-community-y-vigía13), no capacidades verificadas de una edición existente. La seguridad básica permanece completa en Community; no se ha añadido ofuscación inteligente reversible.

No prometer ahorro porcentual sin medición ni “respuestas siempre correctas”. La parte convincente es enseñar una decisión, su consecuencia y la evidencia que la respalda.

## Aceptación y recuperación

- [x] Instalación reproducida siguiendo la guía y tres escenas en tests; recorrido visual en el entorno original con la misma fuente fijada.
- [x] Banner y guion identifican simulación y reproducción; no se presenta como calidad de modelos reales.
- [x] Los fallos de proveedor/validación se prueban con estado explícito y sin envío prohibido.
- [x] La cuenta de demo usa base, medios y cookies propios, con identidad y credenciales sintéticas.
- [x] Coste de demo simulado y registro de pruebas reales separados; las pruebas reales requieren autorización explícita y respetan el presupuesto conjunto.
- [x] Apertura de citas con teclado comprobada en Chromium real; [evidencia del piloto](../../evals/reports/pilot-documents-20261003-01/README.md).
- [ ] Dos ensayos completos cronometrados con otra persona; incluida su comprensión de las etiquetas.

Publicar o comprobar una revisión desplegada no forma parte del alcance autorizado.

Recuperación: volver a la última revisión segura ensayada o usar la reproducción identificada. Mantener cerrada la salida de datos si no se puede validar. Después, revocar las credenciales temporales y retirar el entorno de demo que ya no se use, conservando únicamente los artefactos aprobados para compartir.

Preparación posterior: [operación y recuperación comprobadas](operacion-y-recuperacion-piloto.md) y [piloto local propuesto](piloto-controlado.md). No hubo participantes ni invitaciones. La sesión humana se autoriza y registra por separado de las pruebas automatizadas.

# Implementación del agente de Regulay en siete prompts

7 de octubre de 2026. Guía de ejecución del [plan agéntico](plan-capacidades-agenticas-regulay-2026-10-07.md), ajustada para implementar lo necesario en entregas verificables. El arnés es **Deep Agents**. La [investigación documental](investigacion-prompts-skills-documentales-2026-10-07.md) y el [material de prompts](agent-assets/README.md) ya están preparados. Las tareas de esta guía están pendientes: preparar prompts no significa haber implementado sus capacidades.

## Decisión de implementación

Mantener Django y la interfaz actual. Añadir un paquete interno para el modo agente, un proceso ejecutor separado y un único backend de sandbox. Reutilizar autenticación, conversaciones, permisos, conexiones de modelos, política y recibos del proyecto. El ejecutor separado es necesario para aislar red, credenciales y trabajos largos; puede compartir repositorio e imagen con el código de aplicación cuando las dependencias lo permitan.

La primera entrega visible será **adjuntar CSV/XLSX → procesar con Python → recibir XLSX verificado**, con progreso por SSE, sandbox precalentado y preview de tabla. Word/PDF completan el siguiente hito documental; PPTX llega después. Es una división del A1/A3 del plan para disponer antes de un recorrido completo y detectar fallos sin mezclar cuatro motores de documentos.

El primer prompt fija un sandbox. **Probar primero E2B autohospedado por su integración documentada con Deep Agents; acudir a OpenSandbox si el encaje de red, operación o instalación falla.** Comparar requisitos y una prueba pequeña, no construir dos backends completos. La opción gestionada solo es admisible si ya tiene autorización, destino de datos y coste aprobados. La decisión técnica queda condicionada a una prueba real en un host Linux compatible; un mock de red no la sustituye. No ampliar el piloto a usuarios reales sin esa prueba.

## Qué construir y qué simplificar

| Parte | Implementación inicial |
| --- | --- |
| Entrada | Las tres entradas existentes continúan pasando por `send_chat_message`. Un nuevo chat puede usar modo agente si está habilitado; los chats anteriores conservan su modo. |
| Núcleo | `regulai/front/agents/`, sin crear otra aplicación de negocio. Una interfaz pequeña para iniciar, consultar/cancelar y obtener artefactos autorizados. Crear archivos según hagan falta, no una estructura vacía. |
| Ejecutor | Un proceso con concurrencia acotada. Un solo escritor por conversación. El código generado se ejecuta exclusivamente en el sandbox. |
| Trabajo pendiente | Registros durables en PostgreSQL y reclamación atómica. Una consulta interna breve puede alimentar al ejecutor; no hace falta un broker para este piloto. El navegador recibe SSE desde el primer recorrido. |
| Inferencia | Un adaptador de modelo de Deep Agents llama a una operación interna concreta de Regulay. El envío real reutiliza gobierno y contabilización. No construir un proxy universal de todos los protocolos. |
| Red | El ejecutor solo tiene accesos internos autorizados y acceso al backend de sandbox. No recibe claves de proveedores ni acceso general a la base de datos/tabla de seudónimos. Un checkpointer, si se usa, recibe acceso limitado a sus tablas de estado. El sandbox tampoco tiene salida libre. La aplicación que gobierna la inferencia es la única que alcanza modelos. |
| Archivos | Almacenamiento privado existente detrás de autorización. Entrada, trabajo y salida separados. Un registro de artefacto puede representar cada revisión inmutable con una clave lógica común; no hace falta un gestor documental completo. |
| Estado | Reutilizar `Conversation`, `Message` y `Prompt`. Añadir solo registros necesarios de ejecución, eventos, archivos/revisiones y alias. Usar un checkpointer oficial cuando haya que conservar el estado del grafo; no serializar objetos de LangChain a mano ni mantener otro historial conversacional independiente. |
| Pool | Empezar con un sandbox limpio preparado, asignarlo en exclusiva y reponerlo. Destruir el entorno usado al liberarlo. Medir cola, arranque frío y caliente antes de ampliar el pool. |
| Skills | Archivos versionados con carga progresiva, una implementación principal por formato. Dependencias y fuentes preinstaladas en una sola imagen documental. |
| UI | Adaptar el chat existente: actividad, progreso humano, archivos, preview y cancelar. Tablas seguras para XLSX; páginas renderizadas para DOCX/PDF/PPTX. No integrar inicialmente un editor Office completo. |
| MCP | Un cliente y un servidor/conector documental de lectura. Credenciales y resolución de originales en las herramientas de confianza, fuera del modelo y de su terminal. |

No añadir de entrada Redis/Celery, Kubernetes, una UI React nueva, base vectorial, marketplace, memoria global, autoscaling, un catálogo de varios sandboxes ni una jerarquía de subagentes. Tampoco un diseñador de workflows o un sistema genérico de plugins. Una necesidad medida puede justificar alguno después; ninguno es requisito del primer recorrido.

La simplificación no elimina los tres requisitos centrales: cálculo local sobre originales, inferencia obligatoriamente gobernada por red y seudónimos estables por conversación. Tampoco retrasa SSE, precalentamiento, comprobación o preview hasta el final.

## Hallazgos del código que condicionan el orden

- `front/chat_service.py` centraliza las tres entradas. `run_pipeline` contiene `preflight`, `start_call` y `complete_call` como funciones anidadas. Extraer el mínimo necesario para reutilizarlas; copiar sus controles crearía dos implementaciones que acabarían divergiendo.
- `front/connectors.py` conserva contenido y uso, pero el contrato actual no transporta `tool_calls` ni `tool_call_id`. El primer experimento debe demostrar la ida y vuelta estructurada; no codificar llamadas a herramientas dentro de texto libre.
- `send_chat_message` extrae ahora los adjuntos antes de ejecutar el chat, sin conservar el original para futuros turnos. La rama agente necesita conservar el archivo autorizado y trabajar sobre él, sin introducir todo su texto en el contexto del modelo.
- La idempotencia se apoya en `(user, request_id)`. Hay además un tratamiento de solicitudes antiguas tras 240 segundos que no puede aplicarse sin cambios a una ejecución agéntica larga. Distinguir la vida de un run de la petición HTTP.
- Existe `asgi.py`, pero el contenedor de piloto arranca WSGI. Servir SSE correctamente requiere probar ASGI, proxy y reconexión; no basta cambiar la plantilla.
- Ya existe configuración de laboratorio PostgreSQL. Usarla para concurrencia y migraciones aisladas. SQLite sirve para pruebas pequeñas, no para acreditar reclamación concurrente de trabajo.
- La [tarea 44](plan-blackhat/tareas/44-limites-del-proveedor.md) deja límites de generación en el proveedor para una cuenta. La [tarea 47](plan-blackhat/tareas/47-enmascarado-sin-inferencia-de-entidades.md) retira NER generalista. El nuevo agente no debe deshacer ninguna de esas decisiones.

## Orden y punto de parada de cada prompt

| Orden | Prompt / tarea local | Resultado al terminar | Depende de |
| --- | --- | --- | --- |
| 1 | [48. Probar Deep Agents y fijar sandbox](plan-blackhat/tareas/48-agente-prueba-integracion.md) | Un ciclo real del SDK con herramienta local, modelo simulado y backend elegido; limitaciones de red conocidas. | — |
| 2 | [49. Inferencia gobernada y vistas de datos](plan-blackhat/tareas/49-agente-inferencia-y-datos.md) | Cada llamada y resultado pasa por Regulay; alias estables; código de proveedor reutilizado. | 48 |
| 3 | [50. Primer Excel desde el chat](plan-blackhat/tareas/50-agente-chat-excel.md) | Adjuntar, ejecutar, ver progreso, cancelar, previsualizar y editar un XLSX verificado. | 49 |
| 4 | [51. Word y PDF con calidad](plan-blackhat/tareas/51-agente-word-pdf.md) | Plantilla DOCX y PDF con render, revisión y reparación, usando el mismo recorrido. | 50 |
| 5 | [52. PowerPoint editable](plan-blackhat/tareas/52-agente-powerpoint.md) | PPTX con contenido editable y render comprobado; una sola implementación elegida. | 51 |
| 6 | [53. Un conector MCP de lectura](plan-blackhat/tareas/53-agente-mcp-lectura.md) | Buscar y obtener un documento autorizado sin mostrar credenciales ni originales al modelo. | 52 |
| 7 | [54. Escritura aprobada y cierre del piloto](plan-blackhat/tareas/54-agente-escrituras-y-piloto.md) | Una escritura externa revisable, recuperación sin duplicados y evidencia integrada del piloto. | 53 |

Ejecutar en orden. Aunque algunas tareas podrían solaparse, el primer desarrollo debe validar una entrega antes de construir la siguiente. Si un prompt descubre una incompatibilidad real, corregir su implementación y actualizar la evidencia antes de continuar; no iniciar otro framework en paralelo.

**Después de 50 ya hay un recorrido útil de Excel. Después de 51 se completa el primer hito documental del plan. Después de 52 están los cuatro formatos.** Las tareas 53–54 añaden aplicaciones externas y operación del piloto. No condicionar la utilidad interna a haber construido todos los conectores.

## Reglas comunes para ejecutar los prompts

Cada fichero incluye un prompt copiable, aceptación y espacio de evidencia. Leer `AGENTS.md` y esta guía al iniciar una tarea. Trabajar sobre el estado real: hay modificaciones locales previas; no descartarlas ni asumir que partir de HEAD las incluye. Comprobar que la tarea anterior esté implementada y verificada, no solo que exista su documento.

Usar dependencias fijadas, migraciones aditivas y bases aisladas. No hacer push, desplegar, publicar ni efectuar llamadas nuevas de pago. No enviar mensajes ni escribir en servicios externos reales durante los tests; usar transportes simulados. Un piloto con modelos reales o una cuenta externa se habilitará solo con su autorización y presupuesto correspondientes.

La configuración del agente permanece desactivada para cuentas actuales hasta superar los controles del tramo que se vaya a habilitar. Respetar las instrucciones de empresa/departamento y la autorización efectiva. Un prompt, una skill o un servidor MCP no puede conceder permisos. No solicitar aprobación para cada lectura o cálculo autorizado; preparar aprobación únicamente para efectos de escritura externos. Una política obligatoria incompatible se explica y bloquea, no se ignora.

Todas las superficies hacia el modelo necesitan el mismo tratamiento: mensajes, argumentos y resultados de herramientas, errores, archivos, logs, resúmenes de contexto y renders. Los adjuntos originales son inmutables y privados. Los seudónimos usan claves opacas por conversación y normalización por tipo; no inferir que dos personas son la misma por nombre o parecido. Los secretos no son alias recuperables.

El código arbitrario puede intentar codificar datos en salidas aparentemente inocuas. Filtrar cadenas no demuestra ausencia total de filtración: aplicar contratos de salida de las herramientas y operaciones de confianza para las vistas/agregados; conservar fuera del modelo las salidas no autorizadas. Si un conjunto exige garantías más fuertes, limitarlo a operaciones revisadas. No prometer protección total del código arbitrario con una regex.

Antes de cerrar una tarea, ejecutar sus comprobaciones relevantes y las regresiones de los contratos que toque. Para cambios del envío/gobierno: probar las tres entradas HTTP, el SDK real con transporte simulado, la política de destinos y los invariantes de estado, migración y dinero. Para UI: abrirla y comprobarla visualmente. Para aislamiento: usar el backend real y sockets, no únicamente un mock de Python. No repetir toda la batería documental después de cambios que no afectan a documentos.

Registrar comandos, resultados, versiones y límites en la tarea. No marcarla implementada si solo se ha escrito documentación o un mock. Si falta un host compatible, mantener la comprobación de infraestructura pendiente y completar únicamente lo independiente que sí pueda verificarse. No trasladar una aprobación histórica a nuevas llamadas de pago.

## Criterio de terminado del conjunto

Las cuatro clases de documento funcionan desde el chat, con continuidad de conversación y sin cruces de usuario/empresa. Una edición conserva la identidad del artefacto y produce una nueva revisión comprobada. Hay progreso desde el inicio, salida gobernada por red y datos originales fuera del contexto del modelo. Un conector de lectura funciona, y una escritura externa se aprueba sobre contenido concreto y no se repite por una reconexión o reinicio. El corpus de 16 tareas produce evidencia real; su preparación por sí sola no acredita calidad del modelo.

Para iniciar el trabajo basta indicar: **«Lee la guía `docs/implementacion-agente-regulay-prompts.md` y ejecuta la tarea 48 hasta sus comprobaciones. No avances a la 49 en ese mismo encargo».** El límite entre prompts permite revisar un resultado concreto y ajustar el siguiente sin convertir un plan largo en una implementación indivisible.

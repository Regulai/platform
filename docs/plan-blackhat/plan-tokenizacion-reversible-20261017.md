# Protección reversible con vista natural del chat

Fecha: 17 de octubre de 2026. Estado: **especificación propuesta; implementación y validación pendientes**.

Petición: seleccionar qué datos se sustituyen por identificadores, permitir patrones propios y selección de coincidencias YARA, mantener los originales en la conversación visible, enviar solo la representación protegida y restaurar las referencias al recibir la respuesta, también durante el streaming. Añadir un inspector discreto por conversación con correspondencias y recuentos.

Esta petición amplía la exclusión histórica de ofuscación reversible del [plan Community](README.md). Autoriza documentar el nuevo comportamiento; este documento no afirma que esté disponible ni activa configuraciones. Se conserva la obligación D2 y los bloqueos existentes.

## 1. Resultado que debe experimentar el usuario

El usuario escribe «Redacta un correo para Ana Torres, ana@example.invalid». Ve exactamente ese texto en su burbuja. Si ambas categorías se han detectado y configurado, el proveedor recibe «Redacta un correo para [[R_PERSON_…]], [[R_EMAIL_…]]». Cuando el modelo devuelve «Estimada [[R_PERSON_…]]», el chat muestra «Estimada Ana Torres», progresivamente y sin mostrar fragmentos del identificador.

Los puntos suspensivos se usan solo para explicar el ejemplo: los identificadores reales son completos y aleatorios. Aquí «token» significa identificador de sustitución, no token de facturación del modelo.

Un mismo valor conserva su identificador dentro de una conversación. Otra conversación usa otro identificador. Dos personas con el mismo nombre no se consideran una sola persona: se identifica un valor textual, no una identidad humana.

La IA puede reconocer que hay un correo o una persona y deducir información del contexto. La garantía buscada es que los valores detectados y seleccionados no viajen al proveedor, no que el contexto resulte imposible de reidentificar.

**Aceptación principal:** enviar, responder, reconectar y volver a abrir una conversación mantiene la vista natural; la captura en la frontera de cada proveedor contiene las sustituciones y nunca los originales protegidos. El inspector explica cada sustitución sin dar acceso a otra conversación.

## 2. Punto de partida comprobado

Inspección estática del árbol de trabajo local, que contiene cambios en curso. No es un resultado de pruebas ni una certificación de la instancia 8890.

| Pieza existente | Uso y trabajo pendiente |
| --- | --- |
| [agents/aliases.py](../../regulai/front/agents/aliases.py) | Crea alias aleatorios con ámbito empresa/usuario/conversación; busca por HMAC y preserva referencias durante el enmascarado. La resolución actual está limitada a operaciones documentales locales. Ampliar mediante un contrato propio de presentación, sin abrir un resolvedor genérico. |
| [agents/records.py](../../regulai/front/agents/records.py), `ConversationAlias` | Original cifrado y restricción única por ámbito/tipo/versión/digest. Reutilizar este registro; evitar otra tabla independiente de correspondencias. |
| [local_masking.py](../../regulai/front/local_masking.py) | Detección por patrones explícitos. Hay nombres en campos y textos etiquetados; no detección general de nombres en prosa. |
| [agents/service.py](../../regulai/front/agents/service.py), `_protect_tree` y `_protect_message` | Protege contenido y argumentos de herramientas, preservando estructura del protocolo. Extraer un servicio compartido utilizable también por el chat normal. |
| [chat_streaming.py](../../regulai/front/chat_streaming.py) y [agents/streaming.py](../../regulai/front/agents/streaming.py) | Controles de publicación progresiva y eventos con offsets. Añadir proyección natural sin modificar los offsets del texto protegido. |
| [models.py](../../regulai/front/models.py), `Rule` | Acciones YARA actuales: bloquear y pedir consentimiento. La transformación será una configuración independiente; no cambiar silenciosamente estas acciones. |

La nueva interfaz de chat se desarrolla en otro checkout, utilizado por el laboratorio 8890. Antes de implementar la interfaz hay que identificar el frontend que se vaya a integrar. No mantener dos motores de protección para React y las plantillas antiguas: ambos consumirán el mismo servicio del servidor.

## 3. Menú «Privacidad → Datos protegidos»

Acceso desde configuración de empresa para quien pueda administrar su política. En cada fila se ve categoría, método de detección, tratamiento, alcance y ejemplo de antes/después. Texto sencillo: «Ocultar y recuperar», «Ocultar sin recuperar», «No añadir protección opcional».

| Elemento seleccionable | Detección inicial | Tratamiento permitido |
| --- | --- | --- |
| Correos, teléfonos, DNI/NIE, IBAN y tarjetas | Patrones locales y validadores existentes | Reversible o irreversible, según política mínima de empresa |
| Nombres | Campos explícitos, etiquetas y selección manual | Reversible; explicar qué nombres no se detectan |
| Empresas, proyectos y referencias internas | Diccionario local de valores concretos o patrón delimitado | Reversible o irreversible |
| Texto personalizado | Selección del usuario o literal definido por administrador | Reversible o irreversible |
| Coincidencias YARA compatibles | Regla y cadenas seleccionadas con posiciones verificables | Reversible o irreversible, sin anular bloqueo/consentimiento |
| Contraseñas, claves API y otros secretos | Detectores de secretos existentes | Siempre irreversible o bloqueado; nunca guardarlos en el registro reversible |

Desmarcar una categoría reversible significa dejar de recuperarla, no autorizar el envío de originales si D2 exige ocultarlos. La pantalla explica el resultado efectivo: «Seguirá oculto por política de empresa». Para categorías opcionales, la ausencia de protección se indica expresamente antes de activar el cambio.

La política de empresa establece el mínimo. Un usuario puede reforzarlo y añadir valores dentro de su conversación; no rebajarlo. La selección de detectores no sustituye los permisos de salida por sensibilidad, destino o modelo.

Flujo de administración: **editar borrador → probar con texto sintético → ver diferencias respecto a la política activa → activar**. Reutilizar el simulador y la revisión firmada existentes. Guardar cambios crea una revisión inmutable con autor, fecha, detectores y reglas fijados por versión/hash. Las ejecuciones registran qué revisión usaron.

No habilitar reconocimiento estadístico de nombres como parte implícita de esta entrega. Una ampliación posterior puede incorporar un detector local evaluado, con precisión/cobertura por idioma, sin enviar texto a una API para localizar PII. La funcionalidad inicial debe ser útil sin ese detector.

## 4. Cómo se relaciona con YARA

YARA responde a «¿se cumple esta condición?». Para sustituir texto hace falta además «¿qué bytes exactos deben ocultarse?». Una condición por tamaño, ausencia de cadena o combinación de señales no proporciona necesariamente un dato sustituible.

En el editor de protección, ofrecer «Usar coincidencias de una regla YARA», seleccionar la regla y marcar las cadenas, por ejemplo `$correo` o `$proyecto`. Mostrar con resaltado los fragmentos exactos que se sustituirían. No aceptar una activación sin prueba de localización válida.

Contrato del adaptador:

1. Evaluar las reglas de seguridad sobre el original. Si se bloquea, no hay inferencia. Si requiere consentimiento, mantener ese flujo y vincularlo a contenido y revisión de política.
2. Aplicar el extractor solo si la condición seleccionada se cumple. Recoger todas las instancias de las cadenas elegidas, no solo la primera.
3. Convertir offsets de bytes a posiciones del texto original de forma comprobada. Rechazar instancias truncadas, codificaciones no soportadas y fragmentos que corten un carácter UTF-8. Para texto normalizado, conservar un mapa de posiciones hacia el original.
4. Primera versión: texto UTF-8 y un subconjunto validado de cadenas literales/regex YARA con límites de tiempo, tamaño y número de coincidencias. Reglas binarias, `wide`, transformaciones y patrones sin localización inequívoca aparecen como «No compatible para sustitución».
5. Una cadena YARA que solo localiza una etiqueta como «Cliente:» no identifica el nombre posterior. Exigir otro extractor explícito para el valor; no inferirlo extendiendo arbitrariamente el rango.
6. Si una regla configurada para proteger falla al compilar, expira o no puede localizar sus coincidencias de forma segura, detener el envío afectado. No continuar con originales.

Las asociaciones a reglas pertenecen a la empresa y fijan revisión. Si la regla cambia, invalidar la simulación previa. No modificar `Rule.action` de `block` a una supuesta acción «tokenizar». Una regla de bloqueo seguirá bloqueando aunque también esté seleccionada para sustitución.

## 5. Chat e inspector discreto

En el menú `⋯` de cada conversación: **«Privacidad de esta conversación»**. Debe ser accesible por teclado, tener nombre legible para lectores de pantalla y funcionar en móvil. No exigir combinaciones secretas ni mostrar una tabla técnica permanentemente.

El panel muestra:

- Estado: protección activa, política aplicada y cobertura del turno seleccionado.
- «3 valores distintos · 7 apariciones protegidas en mensajes nuevos», con definiciones accesibles.
- Filas por alias: tipo, token completo copiable, original revelable, origen de detección y primer/último turno donde aparece.
- Desglose por mensaje: apariciones en entrada, historial reenviado y respuesta, más número de llamadas al proveedor en que se utilizó.
- Motivos: patrón local, campo, selección manual o cadena YARA/revisión concreta.
- Acción «Ver mensaje»: resalta el fragmento en su burbuja, sin volcar todo el registro en el HTML inicial.

Los originales del panel se revelan bajo demanda. El propietario autorizado puede verlos; ser administrador de empresa no concede automáticamente acceso a todos los chats. Los accesos y revelaciones se auditan mediante IDs y motivos, sin copiar valores a logs.

**Definición de recuentos:** un alias es un valor distinto dentro del ámbito; una aparición es una sustitución en una revisión concreta de mensaje; un uso de salida es su inclusión en una llamada concreta. Reenvíos del historial no incrementan las apariciones del mensaje original. Repetir una petición idempotente o reconectar SSE no duplica nada. Un envío de resultado incierto se etiqueta como tal: no se declara entregado al proveedor sin evidencia.

Los datos ocultados irreversiblemente aparecen con categoría y cantidad, sin correspondencia recuperable. El inspector dice «Sin correspondencia recuperable», en vez de fingir un alias reversible.

### Mejoras de producto incluidas

**«Ver lo que recibirá la IA».** Acción junto al compositor, dentro del menú de privacidad. Presenta texto original y protegido con resaltado; indica si incluye historial y adjuntos o si solo se está mostrando el borrador. La previsualización es local al servidor, no llama a modelos. Al enviar se revalida todo; editar el mensaje o cambiar la política invalida la vista anterior. Si se anuncia que es el envío completo, debe mostrar la representación final completa de todos sus componentes, no una aproximación.

**«Proteger siempre este texto en este chat».** Seleccionar un nombre, código o proyecto y añadirlo al diccionario de conversación. Mostrar una previsualización de las coincidencias; por defecto coincidencia exacta, sin fusionar «Ana» con «Ana María» ni variantes parecidas. La UI puede permitir añadir variantes explícitas, cada una con original preservado. La protección actúa en futuros envíos, incluido el historial reenviado; no puede retirar datos que ya se hayan enviado.

**«Copiar versión protegida».** En cada mensaje, junto a la copia normal. Usa la representación protegida canónica y elimina destinos sensibles de enlaces. Facilita compartir ejemplos sin copiar PII. Etiquetar «Datos detectados sustituidos», no «Anónimo garantizado».

## 6. Arquitectura y límites de confianza

«Local» significa el servidor y la base de datos controlados por la instalación de regulAI. Si se aloja en una máquina remota, no significa el portátil del usuario. El navegador autorizado recibe originales para visualizarlos; el proveedor, el worker de inferencia y las herramientas externas no reciben el mapa de correspondencias.

Mantener dos representaciones con responsabilidades explícitas:

| Representación | Destino y almacenamiento |
| --- | --- |
| Contenido original del usuario | Compositor y conversación autorizada; controles locales sobre el original |
| Contenido protegido canónico | Inferencia, historial del modelo, resúmenes, eventos persistidos y resultados usados por herramientas |
| Proyección natural de respuesta | Solo presentación al usuario autorizado; derivada del protegido y los alias permitidos |
| Correspondencia reversible | Registro cifrado en servidor, separado por empresa, propietario y conversación |

Esquema lógico del recorrido:

```text
Original → autorización/reglas locales → detección de rangos → alias + D2
         → comprobación de salida → proveedor
Proveedor → controles de respuesta → texto protegido canónico
          → proyección autorizada → chat con originales
```

Crear un servicio de protección de texto independiente de `AgentExecution`: contexto de empresa, actor, conversación, petición y revisión de política. Reutilizar los alias existentes mediante adaptadores. Los tres envíos HTTP —POST web antiguo, envío asíncrono y REST— y las inferencias del agente deben pasar por el mismo contrato.

Detectar primero todos los rangos y resolver conflictos antes de reemplazar, de derecha a izquierda. Secretos y rangos irreversibles prevalecen sobre reversibles. Rangos idénticos se deduplican; si el solapamiento no permite conservar una transformación inequívoca, ocultar irreversiblemente la unión o bloquear según política, registrando el motivo. Nunca aplicar reemplazos globales sucesivos sobre texto ya transformado.

La comprobación final de salida debe abarcar mensajes, títulos enviados a modelos, resúmenes, citas, metadatos, nombres de archivo, consultas de búsqueda, resultados/argumentos de herramientas y adjuntos. No insertar la proyección natural en contexto, colas, checkpoints ni mensajes de herramientas. No restaurar identificadores para ejecutar automáticamente una herramienta externa.

La versión inicial de esta función cubre texto y campos estructurados ya extraídos. Un PDF/imagen/binario con PII no se protege sustituyendo solo el texto que lo acompaña: bloquear ese canal cuando la política exija esta garantía, o exigir un flujo de saneamiento específico y verificado. OCR parcial se presenta como cobertura parcial; nunca como documento completamente protegido.

## 7. Persistencia, permisos y contrato propuesto

Reutilizar `ConversationAlias`, cuyo `original` ya es un campo cifrado. Mantener alias aleatorios, ámbito y restricciones únicas. Añadir solo los campos necesarios para estado de retención, revisión y trazabilidad. El lookup por HMAC no se expone a clientes; versionar las claves y conservar compatibilidad durante rotaciones. No usar hashes simples de correos o teléfonos.

La normalización actual puede reunir variantes de un valor. Para mostrar exactamente el original enviado, preservar su variante de presentación cifrada por aparición cuando difiera del original canónico. Si una respuesta menciona el alias sin identificar una aparición, usar el original canónico establecido al crearlo. Documentar esta diferencia; no prometer reconstrucción exacta del texto que el modelo no devolvió.

Guardar una revisión inmutable de política efectiva por envío y un registro compacto de usos: petición/llamada, mensaje/revisión, alias, dirección, detector y cantidad. Posiciones exactas pueden guardarse como referencias al mensaje protegido; no duplicar párrafos sensibles. No crear una fila por fragmento SSE.

Restricciones de idempotencia y transacciones cortas deben impedir duplicados durante envíos paralelos. Crear alias y sus usos de forma atómica antes de efectuar la llamada externa; no mantener la transacción mientras llega el streaming. Un rollback o fallo nunca autoriza enviar el original como alternativa.

Contratos HTTP orientativos, sujetos al patrón real de URLs al implementar:

| Operación | Contrato |
| --- | --- |
| Consultar/editar configuración | Lectura de política efectiva; borrador, simulación y activación como operaciones distintas con control de revisión |
| Previsualizar protección | POST ligado a conversación; devuelve segmentos, cobertura y digest de borrador/política; no hace inferencia ni incrementa usos reales |
| Consultar inspector | GET paginado, por conversación y opcionalmente turno; originales omitidos por defecto |
| Revelar correspondencia | POST para IDs concretos, con autorización actual, CSRF para sesión y auditoría; sin resolvedor público por token libre |
| Añadir literal protegido | POST acotado a conversación; revisión y previsualización de coincidencias |
| Obtener vista natural | Proyección de mensaje/evento autorizado; no endpoint que devuelva el mapa entero al worker |

Todas las operaciones comprueban empresa actual, propietario, acceso a conversación y pertenencia de cada objeto. Respuestas sensibles con `Cache-Control: no-store`; originales y tokens fuera de query strings, métricas, trazas y analítica. No persistir el mapa en localStorage, service worker ni caché compartida.

Revalidar permisos al abrir/reanudar el stream y antes de cada lote de proyección. Revocación o cambio de empresa corta la entrega de originales. No ampliar `resolve_for_operation` quitando su restricción documental: añadir una operación interna de presentación con permisos propios y pruebas de aislamiento.

## 8. Restauración correcta durante el streaming

Restaurar en el servidor de presentación, después de autorizar el contenido de salida y antes del renderizado. El proveedor sigue viendo solo identificadores. Mantener el stream canónico protegido como fuente de replay; la proyección natural es un canal derivado.

El parser incremental mantiene un buffer acotado por mensaje/inferencia y versión de gramática. Debe reconocer identificadores aunque lleguen repartidos entre cualquier par de bytes o chunks. Nunca usar `replace()` sobre cada chunk de forma independiente.

1. Decodificar UTF-8 incrementalmente. Emitir texto ordinario que no pueda ser prefijo de un identificador.
2. Retener el posible prefijo hasta completar un identificador válido o descartarlo. El máximo depende de la gramática; no permitir un buffer ilimitado controlado por el modelo.
3. Resolver únicamente alias pertenecientes a la conversación y al conjunto autorizado para esa inferencia. Conocer el token de otro turno no concede acceso a cualquier valor del registro.
4. Emitir el original como un segmento atómico de datos. Nunca interpretarlo como HTML ni volver a analizarlo recursivamente como otro token.
5. Token inexistente, de otro ámbito o incompleto al finalizar: mostrar «[referencia no disponible]» y un aviso en el inspector; no adivinar ni buscar en otras conversaciones. Texto ordinario con corchetes debe conservarse si no pertenece a la gramática reservada.
6. Finalizar, cancelar o fallar marca explícitamente respuesta incompleta. No mostrar un identificador partido ni restos de su buffer.

La restauración no puede eludir los bloqueos del texto final. Reevaluar localmente los segmentos que se vayan a revelar contra las restricciones de presentación; si una regla requiere toda la respuesta, usar entrega completa y explicar el motivo. No mandar originales restaurados a verificadores remotos. Los controles locales deben diferenciar un original permitido al propietario de un secreto irreversible.

**Reconexión:** los offsets actuales cuentan bytes del texto protegido, cuya longitud difiere de la vista natural. Conservarlos, sin reutilizarlos como posiciones visuales. El contrato añade versión de proyección, secuencia/evento de origen y segmentos idempotentes; al reconectar, reconstruir desde un checkpoint seguro del parser o entregar un snapshot de reemplazo antes de continuar. Repetir un evento no duplica texto ni recuentos. Dos pestañas no comparten estado mutable de parser.

**Renderizado:** escapar originales como texto. No restaurar dentro de `href`, `src`, HTML, destinos Markdown, imágenes remotas o llamadas ejecutables. Etiquetas visibles sí pueden contener originales seguros, con enlaces desactivados cuando el destino precise datos protegidos. Bloques de código se muestran como texto; ejecutarlos requiere el flujo separado de autorización. Un correo restaurado no debe activar un fetch o previsualización de enlace automática.

En respuestas normales, historial recargado, copiar y exportar debe usarse la misma proyección. La copia/exportación natural requiere permisos vigentes; la variante protegida permanece disponible cuando el original ya no pueda recuperarse. No alterar recibos de tokens/coste del proveedor: facturan la representación enviada, no la cantidad de caracteres que ve el usuario.

## 9. Ciclo de vida y cambios de política

- Conservar correspondencias mientras sean necesarias para el historial retenido de la conversación. La retención efectiva se define en la política; no prometer un borrado que no cubra también copias de seguridad y originales guardados por otras funciones.
- Borrar una conversación elimina sus correspondencias y usos según el procedimiento existente. Si una política exige purgar antes la correspondencia, el historial indica «Original ya no disponible» y conserva el texto protegido autorizado.
- Reforzar una política obliga a volver a proteger el historial antes del siguiente envío y a invalidar caches/snapshots incompatibles. No altera lo ya enviado al proveedor.
- Relajar una política no restaura automáticamente originales en el historial externo: mantener sus alias existentes. Un dato nuevo se evalúa con la política vigente.
- Si una política se revoca durante una inferencia, detener nuevas salidas y proyecciones que ya no estén autorizadas. Cada llamada vuelve a validar permisos, aunque conserve una revisión para auditoría.
- Restaurar un alias nunca implica que la afirmación del modelo sea correcta. Se recupera el valor, no se verifica su relación con el resto de la respuesta.

## 10. Implementación por entregas

Orden propuesto: resolver primero el riesgo del streaming y la frontera de salida con un caso sintético; después consolidar contratos y construir interfaz. Los archivos nuevos mencionados son propuestas, no piezas existentes.

| Entrega | Trabajo y puntos de integración | Condición comprobable de salida |
| --- | --- | --- |
| E1. Prueba vertical del contrato | `agents/aliases.py`, `chat_streaming.py`, `agents/streaming.py`; prueba aislada con correo ficticio, proveedor capturado y proyección incremental | Todos los cortes posibles del identificador producen el mismo texto natural; original ausente en la petición capturada; sin cambiar todavía la política del usuario |
| E2. Modelo y servicio común | `agents/records.py`, `models.py`, migración aditiva y módulo propuesto `front/privacy.py`; adaptar callers del agente | Alias existentes conservados; permisos, unicidad concurrente, representación canónica y revisión efectiva demostrados |
| E3. Política y detectores | `policy.py`, `local_masking.py`, adaptador YARA localizado y simulador | Configuración por categorías, literales y cadenas YARA; conflictos y reglas incompatibles explicados; bloqueos intactos |
| E4. Envíos e historial | `chat_service.py`, `governance.py`, `agents/service.py`, conectores y consumidores de historial | Tres entradas HTTP y agente envían solo protegido en todos los destinos cubiertos; fallos producen cero salidas nuevas |
| E5. Presentación y replay | Streams normal/agente, `agents/event_store.py`, endpoints y renderer efectivo del chat | Vista natural consistente al recibir, reconectar, recargar y copiar; eventos persistidos sin originales restaurados; aislamiento de canales |
| E6. Menús e inspector | URLs/vistas, configuración y frontend activo; panel, previsualización y selección de texto | Usuario configura, comprueba qué recibe la IA y consulta alias/recuentos; navegación con teclado y móvil verificada visualmente |
| E7. Migración, regresión y entrega | Tests HTTP, migración/reversión en base aislada, guía operativa y registro de evidencia | Criterios de la sección 11 satisfechos; errores/retención explicados; activación explícita por empresa |

Al empezar la implementación, convertir E1–E7 en tareas locales con el siguiente número libre en `docs/plan-blackhat/tareas/`, dependencias y enlace a esta especificación. No duplicar este contenido en cada tarea. Integrar con el trabajo de chat en curso antes de fijar rutas de componentes.

Migraciones aditivas: política nueva desactivada, sin retokenizar históricos ni conceder permisos. No renombrar/destruir el registro existente para compartirlo con el chat. Probar avance y reversión sobre copia aislada. Un rollback de aplicación debe dejar indisponibles las conversaciones cuyo formato nuevo no entiende, o mantener un lector compatible: nunca revertir a enviar originales ni eliminar claves para forzar compatibilidad.

## 11. Pruebas de aceptación y evidencia exigida

| Área | Casos mínimos y resultado esperado |
| --- | --- |
| Experiencia completa | Correo repetido y nombre marcado manualmente: originales en burbujas, alias en proveedor, mismo alias en el turno siguiente y otro en una conversación distinta |
| Cobertura | Nombres libres no marcados se identifican como no cubiertos; no se afirma protección total. Texto etiquetado, campos estructurados y literales funcionan según contrato |
| YARA | Múltiples coincidencias, condición falsa, regla sin posiciones, UTF-8, cadenas solapadas, timeout y compilación inválida; no se oculta solo una etiqueta ni se relaja un bloqueo |
| Frontera externa | Capturar sin red real generador, clasificador, juez, resumen, búsqueda, herramientas y adjuntos; comprobar ausencia de originales en cuerpo, headers, URLs y metadatos, con pruebas por cada ruta |
| HTTP | Mismo resultado y política en las tres entradas de envío; cliente que manipula campos de protección o tokens no obtiene privilegios |
| Streaming | Cada partición de alias/Unicode, alias contiguos, chunks duplicados, token malformado, terminación a mitad, cancelación, desconexión, replay y dos pestañas; texto natural final idéntico al modo completo |
| Autorización | Otra empresa, otro usuario, otra conversación, token conocido pero no autorizado para la inferencia, revocación y cambio de empresa; cero originales revelados |
| Inyección/renderizado | Original con HTML, Markdown, token anidado, URL de exfiltración y caracteres de control; no ejecución, petición remota ni resolución recursiva |
| Estado | Peticiones idempotentes, reintentos, escritores concurrentes, fallo entre persistir y enviar; recuentos estables y estados de salida incierta conservados |
| Persistencia | Cifrado, rotación de claves, purga, reapertura, cambio de política y migración/reversión; sin pérdidas de originales previos ni permisos nuevos |
| Coste y rendimiento | Cero APIs pagadas en la validación; recibos monetarios invariantes. Lecturas de alias por lote, sin consulta por carácter; buffer y número de coincidencias acotados |
| UI | Capturas de escritorio/móvil, teclado, foco del panel, recuentos y estado de cobertura. Copia natural/protegida consistente con lo visible |

Medir latencia añadida y memoria sobre una máquina y corpus sintético declarados. Presupuesto inicial a validar: proyección local p95 inferior a 50 ms por lote con correspondencias ya cargadas; no retraso por esperar la respuesta completa salvo exigencia de seguridad. Si no se alcanza, registrar medida y causa antes de fijar el umbral definitivo; no presentarlo como rendimiento observado.

La evidencia de cierre debe incluir configuración de prueba, versión del código, capturas de la frontera del proveedor con datos sintéticos, resultados HTTP/streaming, visuales y migraciones. El laboratorio con proveedor simulado demuestra transporte y presentación, no exactitud de detección sobre cualquier documento real.

## 12. Decisiones de alcance

Incluido en la primera entrega completa: categorías explícitas, diccionarios, selección manual, subconjunto YARA localizable, inspector de conversación, representación natural en chat normal/agente y streaming, previsualización y copia protegida.

Fuera de esta primera entrega: detección automática general de nombres en prosa, saneamiento universal de imágenes/PDF, correspondencias globales entre empresas o conversaciones, resolución de originales por herramientas remotas y panel de acceso indiscriminado para administradores.

No quedan decisiones de producto imprescindibles para empezar E1 con datos sintéticos. La activación real se hace por empresa al terminar la implementación y su revisión, conservando las políticas y datos existentes.

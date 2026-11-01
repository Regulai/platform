# regulAI Community: informe técnico de cambios y trabajo pendiente

**Fecha del informe:** 3 de octubre de 2026, Europe/Madrid.

**Código original comparado:** `6a0f667c4fb02ec5a93b9eb9e2335385df7e2bda`.

**Código técnico recibido:** `51f4ee5`, rama local `codex/community-fixes`. Inicio de correcciones `4400f0b`, con el mismo código que `4b10778`. Las evidencias del 2 de octubre siguen identificadas como históricas.

**Ámbito:** implementación local de los planes Black Hat 01–12. No se ha hecho push, publicación ni despliegue.

## Resumen ejecutivo

1. El servicio compartido aplica política, aislamiento y consentimiento a las tres entradas HTTP.
2. Las correcciones cierran las doce regresiones B/C y los hallazgos técnicos posteriores de revisores independientes.
3. Cobertura, límites y costes desconocidos se declaran; las fuentes se enmascaran cuando hay servicios activos de la empresa.
4. Arranque exige política explícita; borrador y activación se separan, y las claves tienen recuperación offline documentada.
5. La evidencia local es sintética; calibración humana, Office real y E2E con proveedores vivos siguen pendientes.

## Problemas conocidos y corregidos

La [tabla de correcciones Community](informe-correcciones-community.md) registra B1–B10/C1–C2, mejoras de diseño, hallazgos adversariales, pruebas y commits integrados. Los [ejes Standards y Spec](revisiones-correcciones/README.md) conservan sus informes originales y la verificación de la corrección documental. Las decisiones D1–D7 están aprobadas. Consulta [arranque](arranque-y-demo.md), [rotación de claves](rotacion-claves.md) y [estado observado](estado-ejecucion.md) para operación y gates; la revisión documental está cerrada.

Este documento explica cambios existentes en el repositorio. Distingue la lectura del código original, la implementación actual y las comprobaciones conservadas. No presenta como terminado todo el plan: faltan calibración, evaluación comparativa real y parte de la validación final.

## 1. Qué aplicación había antes

La base ya era una aplicación Django con interfaz web y API REST. Ya existían:

- Empresas, departamentos, perfiles, roles, conversaciones y mensajes.
- Entidades `Prompt`, `Response`, `Alert` y `AuditLog`.
- Motores, modelos y credenciales por empresa mediante `Engine`, `EngineModel` y `CompanyEngine`.
- Conectores para OpenAI, Anthropic y APIs compatibles con OpenAI.
- Reglas YARA con acciones de bloqueo y consentimiento.
- Extracción básica de PDF, DOCX con tablas, Excel y CSV/texto; intentos de OCR con pytesseract y envío de imágenes a modelos con visión. También existía integración externa de enmascarado/ofuscación.
- Descarga de archivos generados por la IA: el propio commit de partida ya incorpora esa funcionalidad.

Por tanto, el trabajo no consistió en crear desde cero un chat, YARA, los conectores, el cifrado de credenciales o las descargas. Se reutilizaron esas piezas y se cambió la forma de coordinarlas y controlarlas.

La lectura de la base revelaba varios problemas concretos:

| Situación anterior | Consecuencia técnica |
| --- | --- |
| Había lógica de envío en `chat_view`, `front.chat_send_message` y `api.chat_send_message`. | Un arreglo en una entrada podía no alcanzar las otras; el tratamiento de consentimiento era distinto. |
| En los envíos asíncrono y REST, una excepción de validación podía capturarse y continuar. | Fallar al comprobar seguridad no garantizaba detener la llamada al proveedor. |
| El envío web podía llamar al ofuscador antes de validar el contenido. | La autorización posterior del generador no protegía esa salida previa a otro servicio. |
| Se construía el historial a partir de mensajes de la conversación sin un registro fiable de elegibilidad. | Un mensaje almacenado podía incorporarse a una nueva llamada aunque su uso como contexto no estuviera autorizado. |
| La confirmación web dependía de `consent_confirmed`. | No existía una prueba firmada que vinculase esa confirmación al contenido exacto y a la política vigente. |
| El texto de archivo enviado desde la web se recortaba a 10.000 caracteres. | El generador podía recibir solo una parte sin una explicación estructurada de cobertura. En ese recorrido YARA sí recibía el texto extraído completo: no debe confundirse el recorte para el modelo con el análisis YARA. |
| Los modelos tenían salida máxima y capacidades básicas, pero no el nuevo catálogo de contexto, tarifas y calidad por tarea. | Faltaban datos y lógica para elegir entre candidatos con presupuesto y requisitos explícitos. |
| Los dos archivos de dependencias divergían. | La instalación podía variar según cuál se utilizase. Ambos fijaban Django 4.2.28. |

Estas observaciones proceden del código de partida; no implican que se haya constatado una fuga de datos o un incidente en producción.

## 2. Secuencia de entregas locales

El trabajo quedó dividido en commits. La tabla refleja la secuencia real; los apartados posteriores explican el cambio funcional.

| Commit | Entrega |
| --- | --- |
| `18ecca7` | Preparación del entorno, base de comprobaciones, skills y tareas locales. |
| `75ec867` | Actualización a Django LTS y fuente única de dependencias. |
| `b99434a` | Actualización de dependencias vulnerables y sustitución de PyPDF2. |
| `853d495` | Extracción documental acotada y fragmentos de evidencia. |
| `48a25e8` | Cliente Jev, selección de modelos y comprobaciones de respuestas. |
| `2a5bd40` | Persistencia de políticas, estado de peticiones, procedencia y metadatos del catálogo. |
| `023c7ef` | Recursos de navegador locales y fijados para el arranque. |
| `bbb86a5` | Integración del servicio común, permisos, confirmaciones, verificación, interfaz y simulador. |
| `6496ef7` | Pruebas reales sintéticas con presupuesto persistente. |
| `cfa29fa` | Banco de 50 casos y demo aislada. |
| `9e438fc`, `22f6659`, `8cf3ff9` | Evidencias, documentación de arranque y corrección de ejemplos de API. |
| `4b10778` | Registro del acceso real a Jev y de dos comprobaciones reales de su juez. |

## 3. Paso 1: actualizar y hacer reproducible la instalación

**Antes.** La raíz y la subcarpeta Django tenían listas de paquetes diferentes. Además de distintas versiones, la lista interior incluía `docx` junto a `python-docx`. Django estaba en 4.2.28 y DRF en 3.15.2.

**Cambio.** La [lista raíz](../../requirements.txt) queda como fuente única, con 45 paquetes fijados. La [lista interior](../../regulai/requirements.txt) contiene `-r ../requirements.txt`. Django pasa a 5.2.17 LTS y DRF a 3.18.1. Se actualizaron también dependencias necesarias, incluidos componentes criptográficos, HTTP, XML, imágenes y JWT. `PyPDF2` se sustituyó por `pypdf 6.19.0`.

**Decisión y motivo.** Se mantuvo el stack Python/Django y se realizó la actualización en entregas separadas para distinguir problemas de dependencias de cambios funcionales. Las herramientas auxiliares se usaron de forma local o mediante la caché aislada de uv.

**Qué hay ahora.** Una instalación reproducida con Python 3.12.11 en dos entornos. El [bootstrap](../../scripts/bootstrap_local.py) crea la configuración local solo si no existe; no reemplaza claves existentes. La base de desarrollo se separa de la de demo. Se incorporaron copias fijadas de las bibliotecas de navegador utilizadas, con un manifiesto de hashes.

**Problema resuelto y evidencia.** Se elimina la ambigüedad de instalación. La auditoría registrada el 2 de octubre encontró inicialmente 96 avisos en 12 paquetes; tras actualizar, informó cero vulnerabilidades conocidas. Es una observación fechada, no una garantía permanente. Las 129 pruebas de la revisión histórica del 2 de octubre pasaron también en el entorno creado desde cero; no es el tamaño de la suite actual. [Registro de dependencias](dependencias-verificadas.md).

## 4. Paso 2: unificar el envío y cerrar los fallos de seguridad

**Antes.** Las tres entradas ejecutaban variantes de la lógica de validación, historial y envío. En la base, los bloques de excepción de la web asíncrona y REST podían continuar después de fallar la comprobación de seguridad.

**Cambio.** Se añadió [chat_service.py](../../regulai/front/chat_service.py). Las entradas web, API y POST antiguo se redujeron a adaptar la petición y llamar a `send_chat_message(actor, command)`. La respuesta común, `ChatResult`, incluye datos y estado HTTP. La política se concentra en [policy.py](../../regulai/front/policy.py).

La configuración de IA se valida con Pydantic. `evaluate_policy` devuelve una decisión explícita: permitir, bloquear, exigir consentimiento o declarar que la comprobación no está disponible. YARA inválida, configuración ausente o reglas vacías no autorizadas impiden continuar. Las reglas de bloqueo conservan prioridad incluso si falla otra parte de la configuración.

**Decisión y motivo.** Se eligió un servicio dentro de Django, con funciones concretas para política, extracción, ruta y verificación. No se añadieron microservicios, colas ni un motor de workflows. El objetivo era que un arreglo en el control de salida afectase a las tres entradas y pudiera probarse en sus interfaces HTTP.

**Qué hay ahora.** El servicio comprueba texto, contexto y archivo; registra la decisión; y vuelve a comprobar autorización, política y destino antes de las salidas externas. Esto alcanza al generador, a Jev y a la integración de enmascarado existente cuando se utiliza. Enmascarar entrada, contexto, historial, fuentes y respuesta requiere ObfuscationConfig activa de esa empresa. Sin ninguna activa, una política válida puede permitir enviar contenido sin transformar; véase [configuración y activación del servicio](arranque-y-demo.md#activar-el-enmascarado-de-la-empresa).

**Problema resuelto y evidencia.** El error de validación deja de ser una vía para continuar al proveedor. `front.test_chat_flow` y `front.test_pipeline` comprueban fallos, bloqueos y las tres entradas con proveedores simulados. La ausencia de coincidencias YARA, por sí sola, no concede permiso de salida.

## 5. Paso 3: dar identidad y estado a cada petición

**Antes.** `Prompt`, `Response` y `Message` existían, pero no tenían los enlaces y estados necesarios para representar de forma inequívoca una ejecución autorizada y sus repeticiones.

**Cambio.** Se ampliaron las entidades existentes en [models.py](../../regulai/front/models.py):

| Entidad | Campos o restricciones añadidos | Función |
| --- | --- | --- |
| `Company` | `ai_config`, `jev_api_key` cifrada | Política validada por empresa y credencial del evaluador, separada del JSON. |
| `Prompt` | `request_id`, `company`, `status`, `decision`, `user_message`, `updated_at` | Identidad, procedencia, estado y registro de la ejecución. |
| `Prompt` | Unicidad de `(user, request_id)` | Reconocer una repetición de la misma petición. |
| `Response` | `assistant_message`, `evidence` | Vincular la respuesta al mensaje y a la evidencia conservada. |
| `EngineModel` | `context_window`, `supports_json`, tarifas de entrada/salida, moneda y fecha | Comprobar capacidad y calcular costes con una tarifa identificable. |
| `AuditLog` | `company` | Conservar la empresa de origen del evento, aunque posteriormente cambie el perfil del usuario. |

Se añadieron las migraciones 0026, 0027 y 0028; las correcciones posteriores añaden 0029 precios por millón, 0030 reasoning y 0031 procedencia histórica reversible. La 0026 crea primero el UUID como nullable, asigna uno diferente a cada petición antigua y después aplica la obligatoriedad y la restricción única. Los registros anteriores quedan `legacy`, conservados sin autorización nueva de contexto. La 0031 infiere empresa de Prompt desde el perfil con marca reversible; AuditLog histórico se muestra con etiqueta histórico sin modificar el contenido auditado.

**Decisión y motivo.** Se reutilizaron los modelos existentes y un JSON versionado para las decisiones. La base de datos impone la unicidad; una operación condicional reclama la transición a `processing`. Las llamadas de red se realizan fuera de transacciones largas. No se depende de un bloqueo de fila que SQLite no proporciona mediante `select_for_update()`.

**Qué hay ahora.** Reenviar el mismo identificador recupera el estado o el resultado existente. Reutilizarlo con contenido distinto produce conflicto. Una petición que quedó interrumpida puede pasar a `outcome_unknown` y no se reenvía automáticamente.

**Problema resuelto y límite.** Se controla la duplicación de procesamiento dentro del flujo y se conserva la incertidumbre tras una interrupción. El cliente debe reutilizar el mismo `request_id`; omitirlo genera uno nuevo y no permite reconocer un duplicado por identidad. No se promete ejecución «exactamente una vez» en el proveedor externo: si se pierde su respuesta, no se puede deducir que no haya procesado o cobrado. `front.test_state` incluye confirmaciones concurrentes y migración desde 0025 conservando los datos antiguos.

## 6. Paso 4: autorizar el historial y vincular las confirmaciones

**Antes.** Las entradas construían el contexto desde los mensajes almacenados. La confirmación web utilizaba un booleano enviado por el cliente y la API trataba las coincidencias de forma diferente.

**Cambio.** `authorized_history` exige peticiones completadas de la empresa y usuario actuales, mensajes enlazados con los roles correctos, marca de elegibilidad y un digest que coincida con su contenido. Los mensajes antiguos se pueden conservar para consulta del propietario, pero no pasan a contexto por el mero hecho de existir.

El historial elegido usa pares elegibles completos, los más recientes dentro de 20 turnos y 32.768 bytes por defecto, configurables. Turnos/bytes omitidos se declaran; tampoco salen al enmascarador.

El consentimiento utiliza una prueba firmada y con caducidad, ligada al usuario, empresa, conversación, entrada, archivo, historial, política, reglas y destinos. Confirmar vuelve a validar esas condiciones. Cancelar termina la petición pendiente sin generar una respuesta. Una prueba caducada válida devuelve 409 con prueba nueva y razón, conservando identidad; una firma falsa no renueva. Una cancelación nueva no crea conversación ni mensaje.

**Decisión y motivo.** La confirmación autoriza una acción concreta. No concede un permiso general ni levanta un bloqueo obligatorio. Se reutiliza la firma de Django y el estado persistente de la petición.

**Qué hay ahora y problema resuelto.** Un doble clic no crea una autorización nueva; una confirmación anterior no se puede trasladar a otro documento o política; y un mensaje bloqueado no reaparece automáticamente dentro del historial de otra llamada.

**Límite explícito.** Los adjuntos originales no se conservan para volver a enviarlos como contexto. Los turnos documentales se excluyen de ese historial; para otra consulta sobre el archivo debe adjuntarse de nuevo. Las pruebas de estado e historial comprueban estos criterios y los cambios de autorización.

## 7. Paso 5: reforzar el aislamiento entre empresas y el acceso a archivos

**Antes.** Existían filtros por empresa y propietario, pero no estaban aplicados uniformemente a todas las relaciones modificables, vistas administrativas y registros históricos. En desarrollo, la configuración general publicaba `MEDIA_ROOT` mediante la ruta de medios de Django.

**Cambio.** Se añadió [access.py](../../regulai/front/access.py) y se ajustaron vistas, querysets y serializers de la API. Las relaciones de departamento, motor, modelo y grupo se resuelven dentro del ámbito autorizado. Se restringen los campos escribibles de los serializers de mensajes, prompts y respuestas; los mensajes ya tenían un endpoint de solo lectura. Las alertas pasan a lectura con una acción específica de resolución, y el propietario de una conversación queda controlado por el servidor.

La administración global exige un operador activo con las marcas correspondientes y su ID explícito en `PLATFORM_ADMIN_USER_IDS`. Un administrador de empresa no puede restablecer la contraseña ni borrar el perfil de ese operador. La auditoría utiliza la empresa capturada en el evento.

La ausencia de perfil ya no se resuelve dentro del envío creando o asignando implícitamente una «Default Company». Se exige una relación de usuario y empresa válida. Se evita así convertir una configuración incompleta en pertenencia organizativa asumida.

Se retiró el alias general de medios. Las descargas comprueban el acceso a la conversación y se sirven como adjunto, con `nosniff` y caché privada. Los avatares se validan como imágenes y pasan por una vista autenticada.

**Decisión y motivo.** Tener permisos administrativos dentro de una empresa no debe implicar ser operador global. El control de acceso reside también en servidor y en los objetos relacionados, no solo en los botones visibles.

**Problema resuelto y evidencia.** Se cierran los caminos cubiertos por `api.test_permissions`, `front.test_access` y `front.test_review`: relaciones de otra empresa, auditoría tras un cambio de empresa, modificación de operadores y contenido HTML disfrazado de avatar. No equivale a certificar toda la aplicación frente a cualquier ataque.

## 8. Paso 6: sustituir la extracción informal por un contrato documental

**Antes.** Había extracción de archivos integrada en las vistas y tratamiento distinto entre entradas. Ya se leían tablas DOCX y hojas de cálculo; también se intentaba OCR sobre imágenes y se permitía una ruta de visión. El texto tenía respaldo Latin-1 cuando no se decodificaba como UTF-8. El envío web recortaba el texto utilizado por el modelo, sin un contrato común de cobertura ni referencias persistentes por fragmento. Algunos errores de extracción se convertían en cadenas de texto que podían continuar dentro de la petición.

**Cambio.** [documents.py](../../regulai/front/documents.py) devuelve un `Document` con texto, formato, digest, estado, unidades leídas/totales, advertencias y fragmentos. Cada fragmento tiene ID estable, localización y texto. Su identificador depende de la versión del extractor, del documento y de su localización.

Hay lectores para PDF textual, DOCX, XLSX, CSV y texto UTF-8 admitido. Se controla también contenido como tablas de DOCX y hojas ocultas de XLSX. El procesamiento costoso se ejecuta en un subproceso con tiempo máximo. Existen límites de caracteres, páginas, celdas, elementos XML, contenido descomprimido y relación de compresión.

Los límites efectivos de upload, extracción, Jev, juez, respuesta, historial y plazos están en la [tabla actual contrastada con código](informe-correcciones-community.md#cobertura-y-límites-efectivos). Entrada texto/CSV 1 MiB; PDF/DOCX/XLSX 10 MiB; Jev estado 98.304 bytes y envoltura 196.608 bytes. La cota local de respuesta min(128000, max_output_tokens×8) no es una conversión formal token-byte. El peor estado del juez se calcula antes de generar, incluido escape JSON 6×, preguntas y localizadores. Un archivo menor que el upload limit puede rechazarse antes de red.

**Decisión y motivo.** Se priorizó la extracción textual con cobertura explícita y límites sobre los formatos existentes. La decisión de seguridad y la respuesta no deben asumir que una lectura parcial representa todo el archivo.

**Qué hay ahora.** Cuatro estados: `complete`, `complete_text_only`, `partial` y `unreadable`. El segundo declara omisiones visuales/adjuntos y exige consentimiento; los dos últimos detienen el envío. Se envían los fragmentos textuales completos; si no caben en contexto o juez, se rechaza sin recortar. Los disclosures llevan código, cantidad y localizadores. SHA estables quedan en servidor, el proveedor recibe alias S1…Sn.

**Problema resuelto y límite.** Se evita presentar el recorte silencioso como lectura completa y se acota el procesamiento de entradas problemáticas. «Completo» describe la extracción admitida, no una reproducción fiel de toda la presentación visual. `front.test_documents` cubre documentos sintéticos, corrupción, cifrado, límites y cobertura.

**Cambio de compatibilidad que debe comunicarse.** No hay OCR ni envío visual, imágenes sueltas o XLS antiguo. Se admite UTF-16 con BOM y Windows-1252 declarado tras fallar UTF-8. Hipervínculos no reducen cobertura; página PDF en blanco avisa, escaneada sin texto es partial. Imágenes/adjuntos detectados dan complete_text_only con consentimiento y no salen a proveedores. Fórmulas XLSX no se ejecutan: expresión completa para YARA, valor de caché para el modelo; falta de caché/recálculo pendiente impide completitud. Word toma cambios aceptados, numeración decimal y reinicios; declara lo no soportado. Fixtures programáticos cubiertos, documentos guardados desde Office/LibreOffice reales pendientes.

## 9. Paso 7: incorporar Jev y elegir modelos con restricciones explícitas

**Antes.** Los conectores ya podían llamar a distintos modelos. La elección se apoyaba en la selección manual, la sesión o los valores predeterminados. No existían los nuevos módulos de evaluación Jev y decisión de ruta.

**Cambio en Jev.** [jev.py](../../regulai/front/jev.py) implementa un contrato HTTP concreto, con límites de tamaño, timeout, validación estricta de respuestas y sin redirecciones ni reintentos ocultos. Admite el transporte directo y el de Vercel Gateway con las credenciales correspondientes. La ruta Gateway utiliza `typesafe-ai/jev` y restringe el proveedor a `typesafe-ai`.

La evaluación separa sensibilidad, presencia de datos sensibles o intentos de manipulación, tipo de tarea, dificultad, ambigüedad e insuficiencia de evidencia. Esas señales pasan por clasificación ordinal conservadora: unknown cuenta como confidential por defecto, señales desde 0,2, probabilidades incoherentes fallan cerradas y manipulación tiene código propio. Ambigüedad avisa y pide al generador aclarar si hace falta; dificultad dudosa usa strong y tarea dudosa general, reteniendo calidad mínima entre tareas plausibles. Jev no puede añadir destinos ni revocar un bloqueo YARA.

**Cambio en la ruta.** [routing.py](../../regulai/front/routing.py) es una función de decisión sobre candidatos ya autorizados por empresa. Filtra por capacidad, contexto, salida máxima, JSON cuando se requiere, calidad mínima configurada y presupuesto. Entre los candidatos elegibles elige el de menor coste estimado, con desempate estable. Se conserva la selección manual sometida a las mismas restricciones aplicables.

**Decisión y motivo.** Se separó «qué se puede enviar» de «qué capacidad necesita la tarea» y de «qué alternativa cuesta menos». El router no es otro agente que decida libremente: recibe un catálogo y aplica condiciones comprobables.

**Problema resuelto y límites.** Se incorpora selección restringida y trazable, pero los valores de calidad por tarea todavía son configuración de prueba, no una calibración demostrada. El cálculo conservador de entrada usa bytes UTF-8 y sobrecarga, no un tokenizador exacto por proveedor. Se rechazan entradas multimodales sin cota. Se registra `price_date`, pero el router no aplica una caducidad automática general de tarifas. El alias Gateway no acredita una versión interna inmutable de Jev. `front.test_jev` y `front.test_routing` prueban el contrato y las decisiones, sin demostrar calidad semántica general.

## 10. Paso 8: verificar respuestas, controlar la segunda generación y resolver citas

**Antes.** Los conectores devolvían contenido y `finish_reason`, pero no existía la nueva secuencia integrada de comprobación local, juez semántico y segundo intento con evidencia documental estructurada.

**Cambio.** [verification.py](../../regulai/front/verification.py) distingue contenido vacío, respuesta incompleta o rechazada y finalización reconocida. Para documentos exige JSON con afirmaciones y citas. Cada cita debe apuntar al alias de una fuente enviada y contener un extracto literal de al menos 12 caracteres sin espacios o tres palabras (configurable). Máximo 30 afirmaciones; admite un único fence JSON envolvente. El juez recibe pares resueltos numerados desde 1, contexto y fuentes completos. El servidor resuelve la localización y la evidencia; el modelo no puede inventar una ruta de archivo o una URL para convertirla en fuente autorizada.

Cuando el modo o el documento exige evaluación semántica, tras las comprobaciones locales el juez evalúa omisiones, contradicciones y respaldo de las afirmaciones. El servicio puede reservar una alternativa con mayor calidad configurada y realizar una segunda generación; no hay un bucle indefinido. Un resultado externo incierto no se reenvía automáticamente.

**Decisión y motivo.** Separar comprobaciones deterministas de juicio semántico: que un extracto exista no demuestra que respalde la afirmación. Tampoco se utiliza una autonota del generador como prueba de corrección.

**Qué hay ahora.** Modos `local`, `advisory` y `enforce`, con alcance registrado. En documentos se exige la comprobación semántica del flujo; en modo `advisory` puede entregarse contenido con controles locales correctos aunque la semántica no esté aprobada, dejando el estado indicado. No se etiqueta como verificado ni se incorpora como historial elegible. La evidencia de la respuesta se conserva como aprobada cuando la verificación pasa. Con enmascarado activo, las citas se validan antes del enmascarado de respuesta para impedir que un placeholder blanquee una cita inventada, y se comprueban de nuevo después.

**Problema resuelto y evidencia.** Se detectan los fallos cubiertos por `front.test_verification` y `front.test_pipeline`: truncamiento, citas inexistentes, formatos inválidos y reacción ante rechazo del juez. Las dos generaciones y su coste se registran. La corrección factual universal y la mejora real de la alternativa fuerte siguen sin demostrarse.

## 11. Paso 9: registrar costes y presentar una ficha de decisión

**Antes.** Los conectores tenían un contador de tokens y el motivo de finalización, pero no el contrato ampliado de uso ni una ficha común con el detalle de cada evaluación y generación. Los SDK mantenían sus comportamientos predeterminados de reintento.

**Cambio.** Se amplió [connectors.py](../../regulai/front/connectors.py) con tokens de entrada/salida, uso comunicado e identificador de respuesta. Se fijaron timeouts, `max_retries=0` y redirecciones desactivadas. En Anthropic se conservan conjuntamente los mensajes de sistema de empresa y departamento, en vez de reemplazar uno con el siguiente.

El flujo registra la intención de llamada antes del efecto externo y después anota estado, duración, modelo, uso y coste. Los importes usan `Decimal`. Se diferencia entre estimación por tarifa, coste comunicado y coste desconocido; la ausencia de datos no se convierte en cero. Se reserva presupuesto para las comprobaciones necesarias y, cuando cabe, para la segunda generación.

La [interfaz del chat](../../regulai/front/templates/chat/chat.html) incorpora ficha y evidencia desplegables, selección automática y manejo de errores HTTP. Conserva archivo, selección e identificador al confirmar o reintentar. Los textos dinámicos se insertan como texto y los endpoints de ficha/evidencia comprueban propietario y empresa.

**Decisión y motivo.** Se reutilizan los registros de petición y respuesta para auditar, sin otra plataforma de trazas. El recibo público filtra los campos internos y no expone credenciales o tokens de confirmación.

**Problema resuelto y límite.** Una respuesta o un fallo se puede asociar a sus comprobaciones y llamadas. El presupuesto del flujo es por petición; no se ha implementado un sistema completo de cuotas económicas por organización. El ledger persistente que limita a 1 USD es específico de las pruebas reales y no debe presentarse como esa funcionalidad de producto.

## 12. Paso 10: añadir un simulador de políticas con activación separada

**Antes.** Existía administración de reglas. No había el nuevo recorrido de comparación de una política propuesta frente a la vigente con una prueba de activación ligada a esa comparación.

**Cambio.** [policy_simulator.py](../../regulai/front/policy_simulator.py) compara borradores de configuración y YARA con una muestra. El modo local utiliza señales sintéticas explícitas y no llama al generador. Conserva el mínimo local de sensibilidad y reserva en la decisión de ruta los costes obligatorios de Jev. El modo semántico opcional requiere autorización vigente y registra su llamada antes de enviarla.

La activación es un POST distinto. Comprueba la firma de la comparación, su caducidad y la versión y contenido actuales de reglas y política. Una modificación concurrente obliga a repetir la comparación. Se audita la configuración y la regla anteriores y nuevas.

**Decisión y motivo.** Comparar y activar son operaciones distintas. Se utiliza la aplicación y su auditoría existente para conservar una recuperación explicable, sin guardar la muestra o credenciales en esa auditoría.

**Problema resuelto y evidencia.** Se puede examinar el efecto de un cambio antes de aplicarlo y evitar activar una comparación obsoleta. `front.test_policy_simulator` cubre permisos, borradores, costes, sensibilidad y activación. Se comprobó también la comparación y activación local desde el navegador. La recuperación se hace comparando y activando una nueva revisión con los datos anteriores; no existe un botón universal de rollback de toda la aplicación. La simulación se centra en muestra, política y ruta: no reproduce todo el historial, los documentos y la cascada de un chat completo.

## 13. Paso 11: crear pruebas reproducibles y una demo aislada

**Antes.** Había algunas pruebas y no el banco de 50 casos ni los comandos de evaluación y demo añadidos. En la preparación se reprodujo una prueba que esperaba que `validate_prompt` crease una alerta, mientras esa función devolvía coincidencias. Se ajustó ese contrato de prueba y las alertas se comprobaron desde las entradas HTTP.

**Cambio.** Se añadieron pruebas de comportamiento en Django y un banco sintético con 50 casos: tareas, documentos, sensibilidad, instrucciones adversariales y estados/fallos. Se dividió en 30 casos de desarrollo y 20 reservados. Cada caso se ejecuta como `economy`, `strong` y `router`, con orden reproducible y manifiesto de configuración, fuentes y hashes.

El comando [evaluate_ai](../../regulai/front/management/commands/evaluate_ai.py) usa el servicio real con proveedores prefijados, SQLite aislado en memoria y red bloqueada. Conserva resultados JSONL y resúmenes CSV/JSON/Markdown. Rechaza sobrescribir una ejecución anterior.

El comando [run_demo](../../regulai/front/management/commands/run_demo.py) utiliza base, medios y cookies separados y simula proveedores únicamente en ese proceso. Se comprobaron escenas de saludo, bloqueo, contrato con segundo intento, consentimiento y simulador. El servidor bloquea conexiones externas en ese modo. Los siete recursos vendor tienen hashes locales verificados, Chart.js 4.5.1, Iconify con fetch deshabilitado y catálogo local, fuentes del sistema. Las copias anteriores eran parciales; la prueba actual cubre los siete assets. La prueba Git clona un fixture de assets bajo autocrlf, no el repositorio completo. CSP es solo Report-Only.

**Decisión y motivo.** Probar los controles de forma determinista, repetible y sin coste. Reutilizar Django y Python estándar para el banco, sin añadir una plataforma de evaluación. Se instalaron en el proyecto las seis skills prioritarias de Matt Pocock, con versión de origen fijada, tareas locales y RTK conservado; son herramientas de trabajo, no dependencias del producto en ejecución.

**Problema resuelto y límite.** Hay pruebas y una demo que se pueden repetir sin depender de disponibilidad externa. Los proveedores prefijados prueban controles, no precisión de los modelos. La partición reservada del banco sintético no equivale a un conjunto independiente revisado por personas. `evaluate_ai --real` continúa desactivado: el ledger existe para `smoke_ai`, pero no está conectado al banco comparativo completo.

## 14. Qué se ha comprobado realmente

Verificación final de correcciones: 302 tests en 66,767 s y cinco gates exit0 sobre `12ca58d`; [registro y límites](informe-correcciones-community.md#verificación-final-conservada). Lo siguiente conserva el histórico original.

Los resultados siguientes son evidencias conservadas del 2 de octubre de 2026. Para elaborar este informe se revisaron código, diffs e informes; no se ejecutaron nuevas llamadas pagadas ni se atribuye una nueva ejecución a las pruebas históricas.

| Comprobación | Resultado observado | Qué permite afirmar |
| --- | --- | --- |
| Suite `front api` | 129 pruebas correctas, en 19,891 s. | Los comportamientos incluidos en la suite pasaron en el entorno original. |
| Misma suite en entorno recién creado | 129 correctas, en 39,764 s. | Se reprodujo la instalación y la suite en otro entorno local. |
| Migraciones y consistencia | `migrate --check` correcto; `makemigrations --check --dry-run` sin cambios; `pip check` compatible. | Esquema local y dependencias coherentes con la revisión comprobada. |
| Evaluación offline final | 50 casos × 3 configuraciones; 150 controles correctos; cero llamadas reales. | Los resultados programados recorren correctamente los controles esperados, incluidas abstenciones y errores. No son 150 respuestas reales correctas. |
| Navegador | Escenas de demo, confirmación/cancelación, persistencia de ficha y evidencia, simulador. | Esos recorridos se utilizaron visualmente. En esa revisión quedaban pruebas de teclado; las citas con Enter se comprobaron el 3 de octubre. Siguen pendientes ensayos humanos. |
| DeepSeek real | `2 + 2` devolvió `4`; 25 tokens de entrada y uno de salida. | Integración y contabilidad de una petición sintética sencilla. |
| Clasificación Jev real | Petición válida; confianza de categoría 0,49 frente al umbral 0,8. | El acceso funciona y el código detuvo la generación con `classification_ambiguous`. El recorrido documental no entregó respuesta. |
| Juez Jev real, prueba de componente con script no versionado | Aceptó «17 días» y rechazó «30 días» frente a la misma fuente de 17 días. | Discriminó ese par de respuestas redactadas previamente, con las preguntas y el umbral actuales. No acredita el recorrido completo ni calibración general; el script que produce jev_verification_component no está versionado y el ensayo no es reproducible E2E desde el repositorio. |

Los tres 403 de Jev anteriores al acceso correcto permanecen en el historial. Las tres llamadas Jev exitosas nuevas sumaron **0,000078246 USD** comunicados por Gateway. El registro conjunto conserva **0,000086946 USD** conocidos, incluida la estimación DeepSeek de **0,00000870 USD**, más **0,03 USD de reservas inciertas** por los intentos anteriores. Estas reservas no se presentan como cobro confirmado ni como cero. El límite autorizado fue 1 USD.

Evidencias consultables:

- [Estado de ejecución y comandos](estado-ejecucion.md).
- [Registro de las comprobaciones de entrega](../../evals/reports/release-verification-2026-10-02.json). Sus referencias al 403 describen la situación previa al nuevo acceso; los informes siguientes son posteriores.
- [Evaluación offline final](../../evals/reports/offline-2026-10-02-04/report.md).
- [Recorrido visual y capturas](../../evals/reports/ui-2026-10-02/README.md).
- [Clasificación real del contrato](../../evals/reports/real-smoke-2026-10-02-03/report.json).
- [Dos casos reales del juez](../../evals/reports/real-jev-verification-2026-10-02-01/report.json).
- [Presupuesto actualizado tras la repetición](../../evals/reports/real-budget-2026-10-02-02.json).

El informe offline final identifica `023c7ef` como HEAD en el momento de ejecución sobre cambios de trabajo; los archivos probados se incorporaron posteriormente a `cfa29fa`. Sus hashes de contenido se conservaron para identificar lo ejecutado. No debe interpretarse ese HEAD anterior como la única fuente de la ejecución.

## 15. Cosas pendientes y orden de trabajo

**Los criterios externos del plan Black Hat siguen abiertos.** Las correcciones técnicas y su documentación están integradas y revisadas; falta calibración, evidencia de aplicaciones Office reales, ensayos humanos y validación con proveedores vivos. La tarea 19 está cerrada con los [cinco gates posteriores a la documentación](../../evals/reports/community-fixes-docs-verification-20261003/README.md): 302 tests OK en 62,428 s y las otras cuatro puertas correctas.

| Orden | Pendiente | Trabajo concreto | Criterio para cerrarlo |
| --- | --- | --- | --- |
| 1 | Calibración de clasificación y juez — planes 05 y 07 | Revisar rúbricas y preparar casos representativos etiquetados por personas. Medir falsos positivos, falsos negativos y abstenciones. Separar desarrollo y evaluación independiente. | Umbrales justificados con resultados conservados; los bloqueos locales permanecen obligatorios. No bajar 0,8 solo para aceptar el contrato de la demo. |
| 2 | Calidad del catálogo y configuración operativa — plan 06 | Medir los modelos por tarea, sustituir valores de ejemplo y completar capacidades, tarifas, destinos y límites de la empresa del piloto. Definir cómo mantener las tarifas vigentes. | Candidatos y mínimos sustentados en evidencia; política revisada y activada conscientemente. |
| 3 | Recorrido documental real — planes 07–09 | Ejecutar clasificación, selección, generación, juez, citas y ficha en conjunto. Incluir rechazo, confirmación, respuesta incompleta y segundo intento cuando corresponda. | Una respuesta permitida llega con evidencia resoluble; casos denegados se detienen; se registran todas las llamadas. |
| 4 | Banco comparativo real — plan 11 | Implementar la conexión de `evaluate_ai --real` con proveedores, el ledger compartido, aislamiento y manifiesto real. Después comparar economy/strong/router con las mismas restricciones y datos. | Ejecución reproducible, costes incluidos también para fallos y descartes, etiquetas independientes y cobertura reportada. |
| 5 | Medición de calidad, latencia y ahorro — planes 06 y 11 | Analizar el banco real sin seleccionar solo casos favorables. Distinguir costes comunicados, estimaciones y partidas desconocidas. | Informe que permita sostener o descartar la hipótesis de ahorro con calidad y cobertura comparables. Actualmente no hay una cifra de ahorro válida. |
| 6 | Ensayos — plan 12 | Dos ensayos cronometrados con otra persona. | Resultados y dificultades registrados. Citas/evidencia con Enter ya comprobadas en navegador Django offline el 3 de octubre. |
| 7 | Preparación de un piloto o despliegue | Elegir usuarios y políticas, revisar la configuración del entorno de destino y preparar copia y recuperación de datos y claves. | Aprobación del entorno y de la operación. No se ha autorizado ni realizado despliegue. |

El acceso a Jev **ya no es el impedimento actual**. El resultado histórico de baja confianza es un dato de calibración; D3 ahora interpreta la distribución conservadoramente y declara avisos. No demuestra calidad general.

La cuenta normal de desarrollo quedó con `ai_config={}` tras las pruebas: no está activada para uso real continuo y devuelve un error de configuración sin llamadas. La demo separada sí tiene su política sintética. Tener credenciales guardadas no configura automáticamente un piloto.

El comando de smoke real está limitado expresamente al 2 de octubre de 2026 y a tarifas revisadas en esa fecha. Antes de nuevas pruebas debe revisarse esa condición y el presupuesto autorizado; no corresponde quitar el control de fecha sin verificar los supuestos. Este informe no autoriza gasto adicional.

## 16. Límites de alcance y decisiones conservadas

- No se añadió la nueva ofuscación inteligente reversible. Se conservaron los puntos de integración existentes bajo los controles del flujo.
- El flujo actual deja fuera el OCR/visión que intentaba la base; no se añadieron búsqueda vectorial, RAG persistente ni infraestructura distribuida. Los documentos se tratan dentro de la petición y con límites explícitos.
- No se realizó una migración de producción ni una certificación de seguridad. La evidencia de migración corresponde a bases aisladas y a las comprobaciones documentadas.
- No hay garantía universal de veracidad. El sistema registra qué comprobaciones se realizaron y cómo terminaron.
- Los cambios permanecen en commits locales; los archivos preexistentes ajenos al encargo se conservaron.

Para arrancar el entorno o preparar la presentación, consultar la [guía comprobada de arranque y demo](arranque-y-demo.md). Para reproducir la comparación de código utilizada en este informe, desde la raíz del repositorio:

```powershell
git log --oneline 6a0f667..51f4ee5
git diff 6a0f667...51f4ee5 -- regulai requirements.txt scripts
```

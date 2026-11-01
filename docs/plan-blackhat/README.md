# regulAI Community: plan de implementación para Black Hat

**Estado: correcciones técnicas y documentación integradas y revisadas; validación externa pendiente.** Revisión: 3 de octubre de 2026. Base original: [Regulai/platform, commit 6a0f667](https://github.com/Regulai/platform/tree/6a0f667c4fb02ec5a93b9eb9e2335385df7e2bda); inicio de correcciones `4400f0b`; código técnico recibido `51f4ee5`. Las especificaciones originales se conservan; cada plan distingue implementación y límites reales.

## Resumen ejecutivo

1. Las tres entradas HTTP comparten controles de empresa, política, consentimiento y registro previo de cada salida.
2. D2 exige una máscara propia, activa, autorizada y configurada para PII y secretos antes de enviar historial, documentos, contexto o respuesta a otros destinos. Ausencia, incompatibilidad o fallo cierran la salida; citas y omisiones se resuelven sobre lo realmente enviado.
3. Documentos tienen cuatro estados de cobertura y límites efectivos; la ficha conserva destino real, costes y verificación.
4. Arranque exige una política revisada: configuración vacía devuelve 503; borrador, simulación y activación son pasos distintos.
5. Las pruebas locales y el navegador offline están registrados; calibración humana, Office real y proveedores vivos siguen pendientes.

**Empieza aquí:** [arranque, configuración y demo actuales](arranque-y-demo.md). Consulta el [estado observado](estado-ejecucion.md) y las [tareas locales](tareas/00-base.md). La [guía original](00-guia-paso-a-paso.md) conserva el método y la secuencia de implementación.

Para explicar la entrega a un equipo de ingeniería: [informe técnico](informe-tecnico-cambios.md), [tabla de correcciones y límites actuales](informe-correcciones-community.md) y [rotación de claves](rotacion-claves.md).

Para una explicación consolidada, con una sección general y otra técnica: [todos los cambios respecto al repositorio original](comparativa-repositorio-original.md), desde `6a0f667` hasta `5a8579c`.

La [verificación histórica](../../evals/reports/community-fixes-verification-20261003/README.md) sobre `12ca58d` (mismo comportamiento que `51f4ee5`) pasó cinco puertas: 302 tests OK en 66,767 s, check sin incidencias, migraciones sin cambios, 150 ejecuciones offline sin controles fallidos ni llamadas reales y auditoría sin vulnerabilidades conocidas. Es evidencia anterior al cierre obligatorio de D2. Las llamadas acotadas del 2 de octubre pertenecen a otra autorización. El banco utiliza respuestas y juicios prefijados: **no mide calidad semántica ni ahorro real**. El trabajo posterior está en el [informe de preparación del piloto](informe-piloto-community-20261003.md), con corpus, ensayos, revisión independiente, laboratorio PostgreSQL y nuevos resultados diferenciados del histórico.

Sin un backend de enmascarado compatible y autorizado, el servidor bloquea el chat y la simulación semántica. Se incluye un [detector local en CPU](enmascarado-local.md), sin API de enmascarado; HTTP se conserva para las configuraciones anteriores. Las políticas existentes deben [configurar y activar el backend y autorizar su destino](arranque-y-demo.md#activar-el-enmascarado-de-la-empresa). La migración0032 añade el selector y conserva los registros existentes como HTTP; no activa ni autoriza el local automáticamente. No hay opción de omitir D2. La detección tiene omisiones y falsos positivos documentados.

## Problemas conocidos y corregidos

B1–B10/C1–C2 y los hallazgos posteriores de revisión tienen comportamiento, pruebas y commits en el [informe de correcciones](informe-correcciones-community.md). Los [informes Standards y Spec](revisiones-correcciones/README.md) permanecen íntegros sobre su checkout original. D1–D7 están aprobadas. La [tarea 19](tareas/19-revision-final.md) está cerrada: revisión R verificada y [cinco puertas repetidas tras integrar la documentación](../../evals/reports/community-fixes-docs-verification-20261003/README.md), con 302 tests OK en 62,428 s.

## Qué queremos enseñar

regulAI es una aplicación Django que permite conversar con distintos proveedores de IA bajo reglas de una organización. Ya tiene empresas, usuarios, motores, modelos, conversaciones, reglas YARA y alertas. La evolución propuesta añade una explicación verificable de tres decisiones: **qué información puede salir, qué modelo conviene utilizar y si la respuesta supera las comprobaciones exigidas**.

La demostración debe permitir ver una consulta sencilla resuelta económicamente, un documento restringido detenido antes de enviarse y una respuesta defectuosa detectada y, cuando proceda, mejorada con un segundo modelo. Cada resultado tendrá un motivo y un coste conocido o declarado como desconocido. La mejora de calidad y ahorro se medirá: no se dará por supuesta.

## Planes, prioridades y dependencias

Cada documento incluye trabajo concreto, aceptación, pruebas y salida reversible. Los pasos internos son propuestas de entregas pequeñas; no hay que abrir doce frentes a la vez.

| Plan | Resultado visible | Depende de | Prioridad |
| --- | --- | --- | --- |
| [01. Seguridad ante fallos](01-seguridad-ante-fallos.md) | Un error al comprobar seguridad impide enviar datos | Ninguno | P0 |
| [02. Historial y confirmaciones](02-historial-y-confirmaciones.md) | Lo bloqueado o pendiente no reaparece en consultas posteriores | 01 | P0 |
| [03. Un único flujo web/API](03-flujo-unico-web-api.md) | Las mismas decisiones desde todas las entradas | 01, 02 | P0 |
| [04. Documentos y respuestas completos](04-documentos-y-respuestas-completos.md) | Se detectan lecturas parciales y respuestas cortadas | 03 | P0 |
| [05. Clasificación YARA + Jev](05-clasificacion-documental.md) | Peligrosidad y acción explicadas, antes de la generación | 03, 04 | P1 |
| [06. Enrutamiento por tarea y coste](06-enrutamiento-modelos.md) | Selección reproducible de proveedor y modelo autorizados | 05 | P1 |
| [07. Verificación y escalado](07-verificacion-y-escalado.md) | Un fallo de calidad puede provocar un único segundo intento | 06 | P1 |
| [08. Ficha de decisión](08-ficha-de-decision.md) | Riesgo, ruta, comprobaciones y coste visibles | 03; se amplía con 04–07 | P1 |
| [09. Citas verificables](09-citas-verificables.md) | La respuesta documental permite abrir su evidencia | 04, 07 | P1 |
| [10. Simulador de políticas](10-simulador-politicas.md) | Un administrador prueba una regla antes de activarla | 05, 06 | P2 |
| [11. Evaluación reproducible](11-evaluacion-reproducible.md) | Comparación honesta de calidad, coste y latencia | Casos desde el inicio; comparación final tras 05–09 | P0 transversal |
| [12. Demo y salida](12-demo-y-salida.md) | Tres recorridos ensayados y recuperación preparada | 01–09 y 11; 10 opcional | P1 |

**Método de ejecución:** [skills y workflows de Matt Pocock](metodo-matt-pocock.md). Incluye nombres actuales, fuentes originales, adaptación a Django y un prompt para iniciar cada entrega.

**Entregas locales:** [base](tareas/00-base.md), [envío seguro](tareas/01-envio-seguro.md), [documentos](tareas/02-documentos.md), [pipeline](tareas/03-pipeline.md), [ficha y evidencias](tareas/04-ficha-y-evidencias.md), [simulador](tareas/05-simulador.md), [evaluación offline](tareas/06-evaluacion-offline.md), [demo](tareas/07-demo.md) y [calibración real pendiente](tareas/08-calibracion-real.md).

Orden práctico: preparar los primeros casos de 11 → completar 01–04 → comprobar con un pequeño experimento que Jev encaja → 05–07 → terminar 08–09 → comparar y ensayar. La ficha 08 empieza sencilla junto a 03. Si falta tiempo, recortar 10 y formatos documentales; mantener seguridad y comprobaciones.

## Observaciones de la revisión original, antes de implementar

| Observación por lectura de código | Consecuencia para el plan |
| --- | --- |
| [front/views.py](../../regulai/front/views.py) contiene `chat_view`, `chat_send_message` y `validate_prompt`; [api/views.py](../../regulai/api/views.py) añade otra implementación de envío | Hay tres entradas que cubrir, incluido el POST antiguo de la web |
| En los envíos asíncrono y REST, excepciones de validación pueden terminar continuando hacia el proveedor | La primera entrega prueba y cierra ese comportamiento |
| El historial se construye a partir de mensajes sin una decisión persistida de elegibilidad | `blocked=False` no demuestra que un mensaje pueda enviarse |
| La web reconoce reglas `consent`, mientras REST bloquea las coincidencias | Debe existir una interpretación compartida de la política |
| La web recorta a 10.000 caracteres el texto de archivo incluido en `full_content` | Hay que informar de cobertura y dejar de responder como si se hubiera leído todo; YARA sí recibe el texto extraído completo en ese recorrido |
| [connectors.py](../../regulai/front/connectors.py) ya proporciona conectores OpenAI, Anthropic y OpenAI compatible, y devuelve `finish_reason` | Ampliar ese contrato; no crear otro framework de proveedores |
| [models.py](../../regulai/front/models.py) ya tiene `Prompt`, `Response`, `EngineModel`, `CompanyEngine`, `Alert` y `AuditLog` | Ampliar lo existente; no duplicar entidades equivalentes |
| Los dos `requirements.txt` fijan Django 4.2.28, con otras diferencias entre ellos; el README anuncia otra versión | Establecer una instalación reproducible antes de implementar y verificar soporte antes de publicar |
| [front/tests.py](../../regulai/front/tests.py) espera que `validate_prompt` cree una alerta, pero esa función devuelve coincidencias | Revisar la prueba con una ejecución inicial; esta observación estática no es un resultado de tests |

Esta tabla describe la base original, no el comportamiento actual. Los hallazgos se convirtieron en pruebas HTTP, de proveedores y de migración; el [registro actual](estado-ejecucion.md) recoge los resultados. La instalación actual usa una fuente única, Django 5.2.17 y DRF 3.18.1.

## Decisiones compartidas para evitar soluciones incompatibles

1. **Django sigue siendo la aplicación.** Un módulo de envío compartido, funciones concretas para decisiones y los conectores actuales. Sin microservicios, colas, nueva interfaz React, base vectorial ni motor de workflows para esta edición. **Excepción autorizada (17-10-2026):** la experiencia del chat, sus menús y su visor pasan a una isla React/TypeScript compilada con Vite y servida por Django ([tarea 79](tareas/79-chat-react-base.md)). Django conserva backend, sesiones, CSRF, permisos, archivos, ejecución, estado autoritativo y dinero; el resto de páginas no cambia.
2. **Las normas obligatorias las aplica Python.** Jev aporta señales; no puede desactivar un bloqueo, inventar un proveedor o concederse acceso a datos. `confidence` no es un porcentaje de verdad de la respuesta.
3. **Control de salida antes de cada destino externo.** Incluye generador, Jev, juez y cualquier máscara HTTP autorizada. El enmascarado es obligatorio; puede ejecutarse localmente sin red. La ausencia de coincidencias YARA no equivale a permiso para enviar información a cualquiera.
4. **Una petición, un registro principal.** Ampliar `Prompt` con identificador de petición, empresa de origen, estado, enlace al mensaje de usuario y metadatos de decisión versionados. `Response` se enlaza a su mensaje de asistente. El plan 02 introduce estos campos; 08 amplía su contenido sin crear otro sistema de trazas.
5. **Un contrato común.** `PolicyDecision` distingue `allow`, `block`, `consent_required` y `unavailable`, con códigos de motivo y destinos permitidos. `ChatResult` separa estado de ejecución, decisión de seguridad y resultado de calidad. Usar tipos pequeños, no una jerarquía de clases.
6. **Configuración concreta por empresa.** Ampliar `Company` con una configuración de IA versionada y validada en servidor; reutilizar el campo cifrado existente para la credencial de Jev. No guardar claves en JSON ni incorporar un lenguaje de reglas nuevo. Los modelos siguen en `EngineModel` y las credenciales de generación en `CompanyEngine`.
7. **Dos intentos de generación como máximo.** La configuración impone además presupuesto y plazo total. Cada petición externa se registra; ningún reintento del SDK puede quedar oculto. Un resultado incierto no se etiqueta como verificado.
8. **Datos mínimos.** Las trazas guardan motivos, identificadores, versiones y cantidades, no documentos, claves ni razonamientos privados del modelo. El contenido de conversación y las citas autorizadas conservan sus propios permisos y política de borrado.

Las llamadas de red se hacen fuera de transacciones largas. Para evitar dobles envíos se usan restricciones únicas y actualizaciones condicionales de estado; SQLite no proporciona bloqueo de filas mediante `select_for_update()`. Véanse las referencias de Django del plan 02.

## Vocabulario que utilizaremos

| Término | Significado |
| --- | --- |
| Sensibilidad | Qué exposición tendría el contenido al salir de la organización |
| Autorización de salida | Permiso de la organización para enviar ese contenido a un destino concreto |
| Confirmación | Aceptación por el usuario de una advertencia permitida por la política; nunca levanta un bloqueo obligatorio |
| Dificultad | Estimación de la capacidad necesaria para la tarea, distinta de su sensibilidad |
| Ruta | Proveedor y modelo elegidos entre los disponibles y autorizados |
| Verificación | Comprobaciones concretas superadas; no garantía universal de exactitud |
| Escalado | Segundo intento con una alternativa cuya mejora para esa tarea tenga evidencia |
| Cobertura | Qué páginas, fragmentos o partes pudieron analizarse y cuáles no |

## Límite propuesto entre Community y Vigía13

**Community:** seguridad básica completa, proveedores configurables, clasificación y tres niveles de ruta, una escalada, evidencias, simulación sencilla y evaluación reproducible. Se conservan las funciones existentes de empresas, roles y administración.

**Candidatos para Vigía13:** optimización adaptativa con histórico amplio, presupuestos organizativos avanzados, aprobaciones entre responsables, integración corporativa y gobierno centralizado. Esta división es una propuesta de producto, pendiente de decisión comercial; no describe capacidades verificadas de Vigía13.

La ofuscación reversible quedó excluida del alcance original. La ampliación autorizada durante el piloto integra detección local y sustitución irreversible, conservando el conector HTTP anterior. El 17 de octubre de 2026 se solicitó la [especificación de protección reversible configurable y vista natural del chat](plan-tokenizacion-reversible-20261017.md): es una ampliación propuesta, con implementación y validación pendientes, que reutiliza los alias locales existentes del agente. La seguridad fundamental no se reserva para una edición superior.

## Condición de terminado de cada entrega

- Un comportamiento observable funciona de extremo a extremo y tiene una prueba que habría detectado su fallo.
- Las entradas web y API afectadas respetan permisos, empresa, límites y errores explícitos.
- Las migraciones conservan datos y no convierten registros antiguos en autorizaciones nuevas.
- La documentación explica configuración, ejemplo, limitaciones y recuperación; no quedan `TODO` en el camino crítico.
- El diff elimina duplicación que sustituye, conserva contratos necesarios y no añade infraestructura especulativa.
- Se anotan los comandos ejecutados y sus resultados reales. Una función marcada como pendiente no se presenta como implementada.

“Sin deuda técnica” se traduce aquí en estos criterios y en límites explícitos. Nadie puede prometer ausencia permanente de deuda; sí evitar atajos conocidos en seguridad y dejar cada entrega mantenible.

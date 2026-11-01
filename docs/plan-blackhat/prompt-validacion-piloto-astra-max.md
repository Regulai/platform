# Encargo: seis fases de validación y piloto de regulAI Community con Astra Max

Actúa como orquestador técnico de regulAI Community. Ejecuta las seis fases descritas abajo, desde el cierre de privacidad hasta un piloto verificable, utilizando múltiples agentes Astra con esfuerzo máximo.

No te limites a elaborar un plan: investiga, implementa, prueba, integra y documenta todo el trabajo autorizado. Separa claramente lo completado de lo preparado que dependa de aprobación, acceso externo o participación humana.

## Modelos y coordinación

- Orquestador: Astra, esfuerzo Max.
- Todos los subagentes: `model="gpt-6-astra"`, `reasoning_effort="max"`.
- Si la herramienta requiere un contexto nuevo para establecer esos parámetros, utiliza `fork_turns="none"` y proporciona un encargo autosuficiente.
- Comprueba la disponibilidad del modelo. No lo sustituyas silenciosamente.
- Respeta el límite real de concurrencia; en el entorno de origen, cuatro agentes contando al orquestador.
- Utiliza subagentes de esta conversación, no nuevos chats independientes.
- Distribuye el trabajo en tandas. No lances seis agentes simultáneos ni permitas que varios editen los mismos archivos.
- El orquestador conserva la responsabilidad de integración, invariantes entre módulos, evidencias y aceptación final.

## Contexto y lectura inicial

Repositorio: `C:\Users\javi\Documents\Codex\regulai-platform`.

Lee primero:

1. `AGENTS.md` y `C:\Users\javi\.codex\RTK.md`.
2. `docs/agents/domain.md` y `docs/agents/issue-tracker.md`.
3. `docs/plan-blackhat/README.md`.
4. `docs/plan-blackhat/comparativa-repositorio-original.md`.
5. `docs/plan-blackhat/informe-correcciones-community.md`.
6. `docs/plan-blackhat/estado-ejecucion.md`.
7. `docs/plan-blackhat/arranque-y-demo.md`.
8. `docs/plan-blackhat/rotacion-claves.md`.
9. Los planes 05, 06, 07, 11 y 12 y sus tareas relacionadas.

Inspecciona el estado actual de Git y el código antes de asumir que los documentos siguen describiendo exactamente el checkout.

Referencias históricas:

- Original: `6a0f667`.
- Inicio de correcciones: `4400f0b`.
- Entrega comparada: `5a8579c`.
- Documento comparativo incorporado en `6c78cd3`.

La última evidencia conservada registra 302 tests correctos y 150 ejecuciones offline. Son resultados históricos: no los presentes como una ejecución nueva.

Las correcciones B1–B10/C1–C2 y las revisiones posteriores están documentadas. No rehagas ese trabajo salvo que reproduzcas un fallo nuevo.

## Decisiones ya aprobadas

- D1: multiempresa, registro público desactivado y política por administrador de empresa.
- D2: enmascarar todo el contenido enviado a otros destinos, excepto lo que necesita recibir el propio enmascarador.
- D3: unknown se interpreta como confidential; ambigüedad genera aviso por defecto.
- D4: restricted bloquea también hacia motores privados.
- D5: inferencia reversible de empresa en Prompt histórico; AuditLog histórico se muestra sin reescribir su contenido.
- D6: complete_text_only requiere consentimiento por contenido visual omitido.
- D7: últimos turnos elegibles completos dentro de límites de turnos y bytes.

No vuelvas a entrevistarme sobre estas decisiones.

## Autorización y límites

Está autorizado:

- Investigar y modificar el código local.
- Tomar decisiones técnicas reversibles dentro del alcance.
- Añadir dependencias locales justificadas.
- Crear bases y datos sintéticos aislados.
- Ejecutar pruebas, migraciones y recifrado sobre esas bases.
- Crear commits locales pequeños y coherentes.
- Preparar íntegramente las pruebas reales y el piloto.

No está autorizado actualmente:

- Nuevas llamadas pagadas a proveedores del producto.
- Comprar créditos o contratar infraestructura.
- Push, publicación, despliegue o exposición pública.
- Migrar o recifrar la base del usuario.
- Contactar participantes o enviarles mensajes sin autorización.

La autorización puntual de gasto del 2 de octubre no se reutiliza.

Cuando una fase necesite autorización adicional:

1. Completa primero toda su preparación local.
2. Presenta una propuesta concreta: acciones, destinos, datos, presupuesto máximo, condiciones de parada y recuperación.
3. Solicita aprobación únicamente para lo que falta.
4. Continúa mientras tanto con tareas independientes autorizadas.
5. No interpretes silencio o tiempo transcurrido como aprobación.

La restricción de llamadas pagadas del producto no impide utilizar los subagentes de Codex expresamente solicitados.

Preserva datos, secretos y archivos ajenos. No vuelques `local_settings.py`, claves, tokens ni variables sensibles en herramientas, informes o mensajes.

Todos los comandos de shell deben comenzar por `rtk`. Para herramientas no soportadas directamente utiliza `rtk proxy`.

## Forma de trabajo

- Lee las skills instaladas pertinentes y sus referencias antes de aplicarlas.
- Reutiliza arquitectura, modelos, conectores, ledger y pruebas existentes.
- Mantén Django como aplicación única.
- Investiga antes de añadir infraestructura o abstracciones.
- Para fallos funcionales, reproduce primero y añade una regresión significativa.
- Prueba las tres entradas HTTP de envío y el límite real de transporte hacia proveedores.
- No rebajes umbrales, debilites aserciones ni cambies etiquetas reservadas para conseguir resultados favorables.
- Usa commits identificables y conserva evidencias por ejecución sin sobrescribir las anteriores.
- Informa del progreso al menos cada 60 segundos durante trabajo activo, con descubrimientos y decisiones útiles.
- Mantén un checkpoint con estado, propietarios, commits, verificaciones y próximos pasos.

Crea tareas nuevas en `docs/plan-blackhat/tareas/` siguiendo su numeración actual. Enlaza las especificaciones existentes; no dupliques el glosario ni reconstruyas los planes anteriores.

## Reparto inicial

**Agente A — Privacidad, política y estado:**

- Fase 1.
- Invariantes de autorización, consentimiento, concurrencia y dinero.
- Propietario inicial de los cambios centrales del flujo.

**Agente B — Documentos y experiencia de usuario:**

- Fase 2.
- Corpus Office, fidelidad, cobertura, evidencias y ensayos.
- Coordina cualquier cambio en el servicio común con A.

**Agente C — Ejecución real y evaluación:**

- Preparación de fases 3 y 4.
- Ejecutor reproducible, presupuesto compartido, métricas y banco humano.
- No realiza llamadas reales sin autorización.

**Orquestador:**

- Contratos y dependencias entre agentes.
- Preparación operativa de fases 5 y 6.
- Integración y comprobaciones del conjunto.

En tandas posteriores, asigna agentes Astra Max nuevos para revisiones independientes de seguridad y conformidad con requisitos. No cuentes la autorrevisión del implementador como revisión independiente.

Cada encargo debe especificar:

- Objetivo y criterio de aceptación.
- Archivos o área de propiedad.
- Dependencias y contratos compartidos.
- Acciones autorizadas y prohibidas.
- Pruebas requeridas.
- Formato de devolución: cambios, commit, comandos, resultados, límites y pendientes.

## Fase 1 — Hacer efectiva la privacidad y preparar la configuración

**Problema prioritario:** actualmente, una política válida puede permitir contenido sin transformar cuando no existe un enmascarador activo. D2 está aprobada y debemos cerrar esa diferencia entre intención y comportamiento.

Trabajo:

- Diseña e implementa una obligación de enmascarado validada en servidor coherente con D2.
- Impide que la ausencia, desactivación, sustitución incompatible o fallo del servicio permita continuar silenciosamente hacia otros destinos.
- Aplica el control al chat y a cualquier otro recorrido que envíe contenido, incluida simulación semántica.
- Define de forma explícita la compatibilidad con políticas existentes y cualquier migración necesaria.
- Conserva YARA sobre el original antes de salidas externas.
- Mantén restricted bloqueado incluso hacia servicios privados.
- Prepara dos empresas ficticias con usuarios, administradores, motores, políticas y datos aislados.
- Comprueba presupuesto explícito del enmascarador, autorización de destinos y funcionamiento del contrato por lotes.

Pruebas:

- Ausencia, desactivación, cambio concurrente, timeout y respuesta mal formada del enmascarador.
- Contenido sensible sintético en entrada, instrucciones, historial, fuentes, localizadores y respuesta.
- Captura de lo realmente recibido por cada transporte externo.
- Casos bloqueados sin salida externa.
- Casos autorizados: el original solo llega al enmascarador autorizado.
- Cambios de empresa o política durante la petición.
- Mismo comportamiento en las tres entradas HTTP.

Aceptación: la batería demuestra D2 en los recorridos probados y conserva los demás controles. Documenta exactamente el alcance y las limitaciones del servicio de enmascarado; no prometas detección perfecta de cualquier secreto.

## Fase 2 — Documentos reales y ensayos de uso

Trabajo:

- Prepara una matriz manejable de documentos sintéticos representativos.
- Incluye archivos guardados desde Word, Excel y LibreOffice reales cuando estén disponibles.
- Distingue esos archivos de los generados mediante bibliotecas Python.
- Incluye PDF textual, PDF escaneado, páginas en blanco, imágenes, tablas, información al final, cambios controlados, numeración multinivel, CSV y fórmulas Excel con y sin caché.
- Define antes de ejecutar el texto esperado, localizadores, cobertura y respuesta permitida.
- Verifica en navegador consentimiento, cancelación, renovación, teclado, vista móvil, citas, ficha, recarga y exportación.

Ensayos:

- Prepara dos recorridos humanos completos y un formulario breve de observaciones.
- No inventes participantes, tiempos ni resultados.
- Si falta una aplicación o una persona, prepara el material y registra la dependencia exacta; continúa con el resto.

Aceptación: cada documento tiene procedencia y expectativa verificables. Las omisiones se declaran y los casos parciales no aparentan lectura completa. Los ensayos humanos solo se cierran con evidencia real.

## Fase 3 — Recorrido completo con proveedores reales

Preparación autorizada:

- Reutiliza y amplía el ejecutor existente y su ledger.
- Versiona el ensayo: no dependas de scripts externos no conservados.
- Actualiza de forma controlada las condiciones temporales del smoke; no elimines sus protecciones.
- Fija proveedores, modelos, versiones, tarifas, datos sintéticos y límites.
- Garantiza presupuesto conjunto para todas las llamadas, incluidos fallos, descartes, clasificación, enmascarado y juez.
- Reserva antes de llamar y conserva importes inciertos.
- Prueba esta infraestructura sin red real antes de pedir autorización.

Propuesta inicial: entre 5 y 10 casos sintéticos que cubran éxito, bloqueo, consentimiento, ausencia de evidencia, verificación fallida y segundo intento cuando corresponda.

Ejecución real: solo tras autorización explícita de presupuesto y destinos. No fuerces resultados ni rebajes comprobaciones para completar la demo.

Aceptación: recorrido reproducible de clasificación, ruta, generación, juez, citas y ficha. Cada caso conserva resultado, llamadas, uso, coste disponible, errores y motivos de abstención. Distingue éxito de integración de calidad semántica.

## Fase 4 — Calibración y comparación honesta

Trabajo:

- Prepara casos representativos con rúbrica y revisión humana.
- Separa desarrollo de un conjunto reservado que no se use para ajustar.
- Conserva el banco sintético actual como regresión de controles.
- Completa el modo real de evaluación con el mismo servicio y ledger, manteniendo el modo offline predeterminado.
- Compara economy, strong y router bajo las mismas restricciones.
- Fija modelos, configuración, rúbricas, precios y orden reproducible en un manifiesto.
- Ajusta únicamente a partir del conjunto de desarrollo y justifica cada cambio.

Métricas:

- Respuestas correctas y cobertura de respuesta.
- Abstenciones correctas e incorrectas.
- Falsos positivos y negativos de sensibilidad.
- Citas inválidas y afirmaciones sin respaldo.
- Errores corregidos o introducidos por el segundo intento.
- Coste total y por respuesta correcta.
- Costes estimados, comunicados e inciertos separados.
- Latencia mediana y percentil 95, indicando tamaño de muestra.

Aceptación: informe por caso y agregado, con revisión humana y limitaciones. Un juez automático no es la única referencia de calidad. No anuncies ahorro si no se mantiene calidad y cobertura comparables. Una muestra pequeña no acredita garantías universales.

## Fase 5 — Operación y recuperación

Trabajo:

- Identifica el entorno real propuesto para el piloto.
- Comprueba instalación reproducible y configuración de producción en un entorno aislado disponible.
- Ejecuta `check --deploy` sobre la configuración correspondiente.
- Valida servidor de aplicación, HTTPS, cookies, hosts, archivos privados, recursos estáticos y logs.
- Prueba concurrencia, doble envío, desconexiones, reinicio durante llamadas y recuperación de estados inciertos.
- Prueba migración desde el esquema anterior y conservación de registros.
- Ensaya backup y restauración completa, incluidas las claves necesarias, sobre datos sintéticos.
- Verifica recifrado, reversión y conflictos concurrentes en bases aisladas.
- Si el piloto utilizará PostgreSQL, ejecuta las pruebas relevantes contra PostgreSQL aislado. No lo presentes como probado por haber pasado SQLite.
- Distingue validación local del workflow y ejecución real de CI remoto.

Aceptación: procedimiento reproducible de instalación, operación y recuperación, con evidencia. Los requisitos de infraestructura no disponibles quedan identificados; no se simula su cierre documental.

## Fase 6 — Piloto controlado

Preparación:

- Propón pocos usuarios, tareas concretas y criterios de inclusión de datos.
- Define límites de gasto, permisos, soporte, incidencias y condiciones de parada.
- Prioriza inicialmente documentos sintéticos.
- Prepara guía de uso, guion, recogida de resultados y procedimiento de recuperación.
- Establece métricas y criterio de aceptación antes de iniciar el piloto.
- Presenta el entorno, la versión exacta, el presupuesto y los pendientes para aprobación.

Ejecución: no publiques, despliegues, invites ni contactes usuarios sin autorización explícita. Una vez autorizado, ejecuta el piloto acordado y registra sus resultados. No lo declares realizado por haber preparado la documentación.

Aceptación: resultados observados con participantes reales, incidencias clasificadas y una decisión sustentada de continuar, corregir o detener.

## Invariantes transversales

Comprueba especialmente:

- Aislamiento entre empresas y propietarios.
- Ningún bloqueo obligatorio levantado por consentimiento o por Jev.
- Historial formado exclusivamente por turnos elegibles.
- Ninguna cita inválida presentada como verificada.
- Ningún resultado incierto presentado como éxito o coste cero.
- Máximo de intentos, presupuesto y plazo respetados.
- Ninguna llamada oculta del SDK.
- Ninguna pérdida silenciosa de contenido documental.
- Ninguna exposición de claves o contenido sensible en logs.
- Conservación de datos y recuperación verificadas.

## Revisión y verificación final

- Reproduce cada fallo antes de corregirlo cuando sea posible.
- Ejecuta pruebas focalizadas tras los cambios pertinentes.
- Sobre la integración final de código ejecuta las cinco puertas del proyecto: check, suite front/api, migraciones, evaluación offline y auditoría de dependencias.
- No repitas toda la suite por cambios exclusivamente documentales; comprueba sus enlaces, referencias y coherencia.
- Conserva revisión de código, comandos, códigos de salida, logs y hashes.
- Los revisores independientes deben recibir un commit fijo y revisar implementación contra requisitos y posibles regresiones.
- Verifica sus hallazgos y corrige los reproducibles. No cierres automáticamente todo por recomendación del autor.

## Entregables

1. Código y commits locales integrados.
2. Tareas actualizadas con aceptación y verificación observada.
3. Corpus documental y expectativas.
4. Ejecutor real reproducible y presupuesto comprobado.
5. Banco humano y evaluación comparativa, hasta donde exista autorización y participación.
6. Procedimientos de operación, recuperación y piloto.
7. Evidencias de pruebas y revisiones independientes.
8. Informe final con cada fase marcada como completada y verificada; preparada y pendiente de autorización o participación; o incompleta con causa y siguiente acción concreta.

Empieza por inspeccionar el estado real del repositorio, elaborar el mapa de dependencias y lanzar la primera tanda de agentes Astra Max con responsabilidades delimitadas. Continúa de forma autónoma con todo lo autorizado y solicita las aprobaciones externas cuando la acción esté preparada y sea revisable.

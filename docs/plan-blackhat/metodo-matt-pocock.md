# Método de implementación con las skills de Matt Pocock

**Estado:** las seis skills prioritarias están instaladas a nivel de proyecto y configuradas para tareas locales; no se ha publicado nada. Véanse [configuración](../agents/skills.md) y [estado real](estado-ejecucion.md). Fuentes revisadas el 2 de octubre de 2026 en el [repositorio original](https://github.com/mattpocock/skills/tree/d81f3a183412e71a5b1e84ca21bc1a35eea03a60), revisión `d81f3a183412e71a5b1e84ca21bc1a35eea03a60`. Las menciones posteriores a acciones no ejecutadas describen la investigación original.

## Cuáles encajan

El artículo de AI Hero todavía describe nombres como `domain-model`, `to-prd` y `to-issues`. El código consultado utiliza el conjunto siguiente. Para instalar y ejecutar, prevalece la revisión elegida del repositorio, no un tutorial antiguo. [Artículo del autor](https://www.aihero.dev/skills-post).

| Skill actual y fuente | Uso concreto en regulAI |
| --- | --- |
| [setup-matt-pocock-skills](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/setup-matt-pocock-skills/SKILL.md) | Configurar una vez dónde viven tareas y documentación. Elegir archivos locales para este trabajo |
| [grill-with-docs](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/grill-with-docs/SKILL.md) + [domain-modeling](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/domain-modeling/SKILL.md) | Resolver vocabulario o decisiones pendientes: sensibilidad, confirmación, ruta y verificación. Evitar que cada plan los interprete de forma distinta |
| [to-spec](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/to-spec/SKILL.md) | Sintetizar una especificación a partir del contexto existente; estos planes ya proporcionan la base |
| [to-tickets](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/to-tickets/SKILL.md) | Dividir cada plan en entregas pequeñas que incluyan comportamiento, interfaz y prueba; declarar qué entrega bloquea a cuál |
| [tdd](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/tdd/SKILL.md) | Una prueba de comportamiento que falla, implementación mínima y nueva prueba. Usar Django y `unittest.mock` |
| [implement](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/implement/SKILL.md) | Ejecutar una entrega completa y comprobarla. Su instrucción de hacer commit se adapta a la política acordada del proyecto |
| [codebase-design](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/codebase-design/SKILL.md) | Diseñar una entrada de envío que oculte la complejidad común a las tres vistas, sin capas que solo deleguen |
| [code-review](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/code-review/SKILL.md) | Revisar por separado el cumplimiento de requisitos y la calidad del cambio, contra un punto de partida fijo |
| [diagnosing-bugs](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/diagnosing-bugs/SKILL.md) | Usar cuando haya un fallo concreto: reproducción pequeña, hipótesis comprobable, corrección y prueba de regresión |

Selección inicial: configuración, especificación, tickets, TDD y revisión. Las demás se usan cuando hay una duda real. No hace falta activar toda la colección ni empezar una reestructuración general del proyecto.
La [guía paso a paso](00-guia-paso-a-paso.md) concreta el conjunto para empezar ahora: reutilizar estas especificaciones, dividir tareas, implementar con TDD y revisar; reservar `to-spec` para cambios de alcance.

## Adaptaciones deliberadas

- **Investigación no equivale a ejecución.** Aquí se han leído las skills como fuentes. No se ha invocado una entrevista, creado issues, modificado instrucciones globales ni instalado un paquete.
- **Documentación local.** El mecanismo original admite un tracker local mediante [esta plantilla](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/setup-matt-pocock-skills/issue-tracker-local.md). Al configurar el proyecto, apuntarlo a esta carpeta y a un archivo por entrega, sin copiar planes a varios sitios. Publicar issues o PR requiere que forme parte del encargo.
- **Decisiones ya resueltas se conservan.** Las preguntas de `grill-with-docs`, confirmación de interfaces de prueba de `tdd` y aprobación del desglose de `to-tickets` son partes del original. Al ejecutar esas skills, presentar solo decisiones pendientes y reutilizar autorizaciones existentes. Estos documentos son una adaptación de planificación, no una afirmación de haber completado esos procedimientos.
- **Rutas de código como mapa, no como requisito.** El original de `to-spec` evita rutas que envejezcan. Aquí se incluyen porque el usuario necesita planes aplicables al repo: están ligadas al commit inspeccionado y deben revalidarse. Los criterios de aceptación siguen describiendo comportamientos.
- **Python, no TypeScript.** Los ejemplos de Matt no justifican introducir Vitest, un monorepo o un frontend nuevo. Se aprovechan el cliente de pruebas de Django, DRF y las dependencias instaladas.
- **Revisión antes del commit.** La versión consultada de `code-review` compara commits; para cambios aún sin commit hay que incluir explícitamente el diff del árbol de trabajo y los archivos nuevos. No ejecutar un diff vacío y declarar aprobado. Su versión original usa subagentes; una revisión secuencial conserva las dos perspectivas cuando no se configure delegación.

## Un ciclo de trabajo que se puede repetir

1. Leer un plan, el estado actual del código y sus dependencias. Anotar el commit de partida y el criterio que se va a demostrar. Si el plan se queda grande, dividirlo en dos comportamientos completos.
2. Seleccionar la frontera de prueba: preferentemente petición HTTP y respuesta observable, usando base de datos de prueba y sustituyendo únicamente proveedores externos. Para dinero, transiciones y migraciones, añadir pruebas directas de sus invariantes cuando la integración no baste.
3. Ejecutar una prueba que falle por el problema esperado. Ejemplo del plan 01: una regla YARA inválida produce un error visible y el capturador de tráfico externo recibe cero peticiones.
4. Hacer el cambio mínimo para pasarla, cubriendo todos los llamadores de la lógica afectada. No escribir primero todo el sistema ni una batería de tests contra APIs imaginarias.
5. Repetir para el siguiente comportamiento. La revisión final es el momento de simplificar y quitar duplicaciones; la versión actual de `tdd` separa esa refactorización del ciclo rojo/verde.
6. Comprobar el diff desde el commit anotado contra dos preguntas: “¿cumple el plan?” y “¿es seguro y mantenible?”. Corregir, repetir pruebas afectadas y registrar evidencia.
7. Actualizar el plan con estado, comandos y límites reales. Commit o PR solo dentro del flujo autorizado. Continuar con la siguiente entrega desbloqueada.

Comprobar que no salió ninguna llamada externa **es un comportamiento de seguridad**, no un detalle interno. Contar llamadas a un proveedor o verificar su payload sí es adecuado para evitar fugas y cobros duplicados. No hacer lo mismo con cada helper privado. [Criterios de mocking](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/tdd/mocking.md).

## Preparación mínima al empezar a programar

El README instala las dependencias de la raíz, pero existe otra lista dentro de `regulai/`. Utilizar la raíz como punto de partida documentado, comprobar importaciones y diferencias y dejar una única fuente de instalación en una entrega pequeña. No actualizar dependencias masivamente para implementar el router. Verificar por separado la versión de Django soportada para la fecha de publicación.

Seleccionar también un intérprete compatible: para reproducir la revisión actual, Python 3.12 está entre las versiones admitidas por Django 4.2; no asumir compatibilidad con un Python más reciente solo porque esté instalado. La actualización de Django debe revisar esa pareja de versiones y volver a ejecutar la base de pruebas. [Compatibilidad oficial de Django 4.2](https://docs.djangoproject.com/en/4.2/releases/4.2/#python-compatibility).

Con entorno virtual y configuración local de pruebas preparados, desde el directorio que contiene `manage.py`:

```powershell
rtk proxy python manage.py check
rtk proxy python manage.py test front api
rtk proxy python manage.py makemigrations --check --dry-run
```

Son comandos propuestos; no se han ejecutado al redactar este plan. El test de alertas merece revisión porque su expectativa actual no coincide con el papel de `validate_prompt`. Corregir el test en la frontera adecuada, sin añadir efectos secundarios al validador para satisfacer una expectativa antigua.

No hace falta introducir otro framework de pruebas. Las pruebas de concurrencia y migración usarán las herramientas apropiadas de Django y se ejecutarán también contra el motor de base de datos del despliegue si difiere del local.

## Instalación, cuando se vaya a utilizar

El [README original](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/README.md) documenta el instalador `npx skills@latest add mattpocock/skills` para Codex y otros agentes. No se ha ejecutado. Si se elige ese método, seleccionar solo las skills necesarias y el alcance de proyecto, revisar los archivos instalados y anotar su revisión. `latest` es una instalación móvil; no asegura obtener la revisión investigada aquí. Para reproducibilidad, conservar la revisión aprobada y sus referencias auxiliares, con su licencia.

La configuración se hace una vez. El glosario inicial está en el índice; puede trasladarse a `GLOSSARY.md` al activar el workflow. Crear ADR únicamente para decisiones duraderas con una alternativa real; no uno por cada función.

## Prompt de arranque para una entrega

```text
Implementa solo la siguiente entrega pendiente del plan indicado.
Lee el índice, el plan y los llamadores reales antes de editar.
Reutiliza Django, YARA y los conectores existentes.
Confirma en el contexto la frontera de prueba acordada; no repitas decisiones resueltas.
Empieza por una prueba de comportamiento que falle y pasa con el cambio mínimo.
Cubre web, API y POST antiguo cuando les afecte el comportamiento.
No envíes documentos ni hagas llamadas de pago en tests automáticos.
Revisa requisitos y calidad del diff, incluidos los archivos nuevos.
Actualiza el plan con pruebas ejecutadas, resultado y límites pendientes.
No publiques, instales herramientas globales ni implementes otras propuestas.
```

El objetivo del método es que cada entrega deje algo que se pueda comprobar y explicar. La automatización ayuda a mantener ese ritmo; no sustituye las decisiones de producto ni las pruebas.

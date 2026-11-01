# Guía paso a paso: de los planes a una demo que funciona

**Estado:** secuencia original conservada como método; implementación local disponible. Para comandos actuales, usar [arranque y demo](arranque-y-demo.md); los resultados y pendientes están en el [registro de ejecución](estado-ejecucion.md). **Fecha:** 2 de octubre de 2026. Leer junto al [índice](README.md) y la [investigación de skills](metodo-matt-pocock.md).

Las referencias posteriores a Django 4.2 y a trabajo por empezar describen el punto de partida. Actualmente hay 45 dependencias fijadas en la lista raíz, Django 5.2.17 y DRF 3.18.1. No repetir la preparación sobre datos existentes ni sustituir claves de cifrado.

El orden es: preparar una base reproducible → cerrar los fallos de seguridad → comprobar la integración de Jev → implementar clasificación, selección y verificación → medir → ensayar. Terminar una entrega comprobable antes de abrir la siguiente.

## 1. Fijar qué significa haber terminado

Antes de programar, escribir tres resultados que se puedan enseñar:

1. Una consulta sencilla obtiene una respuesta adecuada mediante un modelo económico autorizado y muestra su coste.
2. Un documento sintético restringido queda bloqueado antes de cualquier salida externa prohibida.
3. Una respuesta documental defectuosa se detecta; el sistema puede intentar otra vez, comprueba también esa respuesta y muestra fuentes reales o reconoce que no pudo verificarla.

Añadir los límites del índice: máximo dos intentos de generación, presupuesto por petición, seguridad común a web/API y exclusión de nueva ofuscación reversible. La división comercial con Vigía13 sigue siendo una propuesta.

**Qué decides tú:** qué datos podrá tratar cada proveedor, presupuesto de las pruebas reales, casos representativos y alcance de la demo. **Qué resuelve el agente leyendo el repo:** archivos afectados, duplicación, contratos actuales y herramientas de prueba disponibles.

Preparar entre 5 y 10 ejemplos sintéticos iniciales del plan 11: consulta sencilla, difícil, ambigua, documento público, credencial falsa, dato situado al final del documento y un fallo de proveedor. Anotar a mano el resultado correcto. Son el comienzo del banco, no otro sistema de evaluación.

**Skills:** ninguna obligatoria. Usar `grill-with-docs` y sus dependencias solo si quedan decisiones de producto confusas. `to-spec` sirve si cambia el alcance; los planes actuales evitan tener que empezar otra especificación desde cero.

**Puedes avanzar cuando:** sabes qué vas a demostrar y tienes ejemplos con resultado esperado.

## 2. Preparar el repositorio y registrar el punto de partida

Trabajar en `C:\Users\javi\Documents\Codex\regulai-platform`. Comprobar estado y revisión, conservar archivos ajenos a esta tarea y usar una rama de trabajo. No añadir todos los archivos sin revisar su procedencia.

```powershell
rtk git status --short
rtk git rev-parse HEAD
```

Guardar el commit base en la primera tarea: permitirá distinguir cambios propios de problemas anteriores. La nueva rama puede crearse al iniciar la implementación; no se ha creado otra rama al escribir esta guía.

Preparar entorno virtual, configuración local y base de datos de desarrollo. La revisión analizada usa Django 4.2.28; para reproducirla, seleccionar un Python compatible, por ejemplo 3.12. Con ese intérprete disponible, desde la raíz:

```powershell
rtk proxy uv venv --python 3.12.11 .venv
rtk proxy .\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Si ya existe un entorno adecuado, reutilizarlo. Hay dos listas de dependencias: empezar por la raíz, que es la utilizada por el README, y resolver sus diferencias en una entrega concreta. No instalar ambas una detrás de otra.

Si falta `regulai/regulai/local_settings.py`, crearlo a partir de la plantilla. Generar secretos propios de desarrollo: la plantilla contiene valores de ejemplo que no deben convertirse en credenciales compartidas. Configurar hosts locales y una base de datos de prueba; conservar cualquier configuración existente antes de cambiarla. Las pruebas automáticas iniciales no necesitan claves reales de proveedores.

Con configuración preparada:

```powershell
rtk proxy .\.venv\Scripts\python.exe regulai\manage.py check
rtk proxy .\.venv\Scripts\python.exe regulai\manage.py test front api
rtk proxy .\.venv\Scripts\python.exe regulai\manage.py makemigrations --check --dry-run
```

Estos comandos son instrucciones, no resultados ya obtenidos. Registrar cada error: dependencia ausente, configuración incorrecta o fallo real del código requieren respuestas distintas. El test de alertas identificado en la investigación merece una reproducción y una corrección de su expectativa o del comportamiento según corresponda, no su eliminación para obtener un indicador verde.

Después, ejecutar migraciones únicamente en la base de desarrollo, crear usuario de prueba y comprobar visualmente que la aplicación abre. No comprobar el chat usando documentos de trabajo privados.

**Skills:** `diagnosing-bugs` si algo falla. Las guías locales `environment-first` y `dependency-changes` ayudan a resolver instalación y versiones si están disponibles.

**Puedes avanzar cuando:** la instalación se puede repetir, la aplicación arranca y los resultados de la base de pruebas están entendidos y documentados.

## 3. Instalar y configurar solo las skills que vas a usar

Las seis skills prioritarias están instaladas en el proyecto, con revisión y referencias en [skills.md](../agents/skills.md). La alternativa del README original usa Node.js y `npx` desde la raíz; no fue necesaria para esta instalación fijada:

```powershell
rtk proxy npx skills@latest add mattpocock/skills
```

Seleccionar Codex, alcance del proyecto y este conjunto inicial. Revisar el resultado de la instalación y anotar la revisión obtenida: `latest` puede instalar algo distinto de la revisión investigada. [Instalación original](https://github.com/mattpocock/skills#installation-30-second-setup).

| Skill | Momento | Para qué sirve aquí |
| --- | --- | --- |
| `setup-matt-pocock-skills` | Una vez | Decidir dónde guardar tareas y documentación |
| `to-tickets` | Antes de cada plan que resulte grande | Dividirlo en entregas completas y ordenadas |
| `tdd` | Durante una entrega | Probar un comportamiento y construir lo necesario para cumplirlo |
| `codebase-design` | Al unificar las tres rutas de envío | Diseñar una entrada común que quite duplicación |
| `code-review` | Al cerrar cada entrega | Revisar cumplimiento del plan y calidad del cambio |
| `diagnosing-bugs` | Cuando aparece un fallo | Reproducirlo y corregir su causa con una comprobación fiable |

Reservar `to-spec` para cambios de requisitos, y `grill-with-docs` para dudas de diseño que no resuelva el repo. Si se instalan, incluir sus referencias y skills auxiliares. `implement` es un envoltorio opcional del ciclo de ejecución; no hace falta para trabajar con TDD. Su versión investigada incluye hacer commit, así que debe ajustarse al flujo que se haya acordado.

Pedir después al agente, en lenguaje normal:

```text
Usa setup-matt-pocock-skills para configurar este repositorio.
Usaremos tareas locales, con los planes existentes como especificaciones.
Guarda las tareas pequeñas bajo docs/plan-blackhat/tareas/.
Mantén un único glosario y crea decisiones de arquitectura solo cuando hagan falta.
Conserva las instrucciones existentes, incluida la de RTK.
Enséñame la configuración propuesta siguiendo el proceso de la skill.
```

La ubicación es una adaptación a este proyecto: el original usa `.scratch/` como convención local. Registrar el cambio en la configuración del tracker para que todas las skills apunten al mismo lugar. No duplicar cada especificación en dos carpetas. [Setup original](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/setup-matt-pocock-skills/SKILL.md).

**Puedes avanzar cuando:** el agente reconoce las skills y sabe dónde leer la especificación y actualizar el estado de una tarea. Las skills facilitan el método; si falta una, no inventar que se ha ejecutado.

## 4. Resolver el soporte de la plataforma en una entrega separada

La rama Django 4.2 terminó su soporte extendido el 7 de abril de 2026. Después de reproducir el estado actual, conviene actualizar la base antes de acumular nuevas funcionalidades. Seleccionar una rama soportada, revisar compatibilidad con DRF y demás dependencias y ejecutar las mismas pruebas antes y después. Django 5.2 LTS es una candidata; la versión final y su parche deben verificarse al realizar el cambio. [Calendario oficial](https://www.djangoproject.com/download/#supported-versions).

Mantener esta entrega separada del router para que un fallo pueda atribuirse a la actualización o a la función nueva. Revisar advertencias de migración, autenticación, formularios, cargas de archivos y conectores. El detalle de publicación está en el plan 12.

**Skills:** guía local `dependency-changes`, `diagnosing-bugs` para regresiones y `code-review` al terminar.

**Puedes avanzar cuando:** hay una base soportada y las comprobaciones afectadas pasan. Si se pospone por una restricción real, registrarlo como requisito pendiente antes de publicar, no darlo por resuelto.

## 5. Convertir solo el siguiente plan en tareas pequeñas

Empezar por [01: seguridad ante fallos](01-seguridad-ante-fallos.md). Un plan puede necesitar varias entregas, pero cada una debe dejar un resultado comprobable. Por ejemplo: “si falla YARA, las tres entradas impiden cualquier salida externa y explican el error”.

Pedir:

```text
Usa to-tickets con el plan 01 y comprueba sus llamadores reales.
Propón pocas tareas que entreguen un comportamiento completo cada una.
Cada tarea debe incluir resultado, dependencias y criterios de aceptación.
Incluye prueba, implementación e interfaz afectada en la misma entrega.
Usa el tracker local configurado. No empieces la implementación todavía.
```

Revisar el desglose que propone la skill. Evitar tareas enormes como “implementar toda la seguridad” y divisiones que no puedan probarse solas, como “crear todas las tablas” o “hacer toda la UI”. Conservar juntos los cambios que deban llegar a las tres rutas para cerrar un fallo de seguridad. [Criterio de entregas de `to-tickets`](https://github.com/mattpocock/skills/blob/d81f3a183412e71a5b1e84ca21bc1a35eea03a60/skills/engineering/to-tickets/SKILL.md).

**Puedes avanzar cuando:** la primera tarea tiene una entrada de ejemplo, una salida esperada y una forma concreta de comprobarla.

## 6. Repetir este ciclo para cada tarea

1. **Leer:** tarea, código afectado y llamadores. Anotar commit base y posibles cambios locales existentes.
2. **Acordar qué se prueba:** preferentemente la petición HTTP y lo que recibe el usuario. Los proveedores externos se sustituyen por respuestas controladas; la lógica propia sigue ejecutándose.
3. **Rojo:** con `tdd`, escribir y ejecutar una prueba que falle exactamente por el problema que se quiere resolver.
4. **Verde:** implementar el cambio mínimo para pasarla. Volver a probar antes de ampliar alcance.
5. **Completar el comportamiento:** cubrir los casos de aceptación de esa tarea, uno por uno. Si cambia la base de datos, probar la migración sobre registros antiguos; si cambia la UI, abrirla y utilizarla.
6. **Revisar:** usar `code-review` contra la base anotada y la tarea. Incluir cambios sin commit y archivos nuevos. Distinguir requisitos incumplidos de problemas de diseño; corregir y repetir las comprobaciones afectadas.
7. **Cerrar:** actualizar la tarea con pruebas ejecutadas, resultado, limitaciones y evidencia visible. Hacer el commit de esa entrega según el flujo acordado y avanzar a la siguiente tarea desbloqueada.

Ejemplo del plan 01: preparar una regla YARA inválida → enviar un mensaje de prueba → comprobar que hay un error comprensible y cero solicitudes externas. Tras la corrección, esa prueba pasa y una petición válida sigue funcionando. Eso demuestra la protección; afirmar únicamente que un helper devuelve `False` no basta.

La suite completa se ejecuta al cerrar una entrega; durante el trabajo bastan las pruebas relevantes. Los tests no hacen llamadas de pago. Cuando se mida calidad real, se hará explícitamente en el banco del plan 11. No confundir esas dos clases de comprobación.

## 7. Implementar en este orden

Las skills `tdd` y `code-review` acompañan todas las filas. Las adicionales se indican donde aportan algo.

| Orden | Qué implementas | Cómo hacerlo | Comprobación para avanzar |
| --- | --- | --- | --- |
| A | [01. Fallos de seguridad](01-seguridad-ante-fallos.md) | Decisión común y cierre de envíos ante errores; cubrir web, API y POST antiguo. Añadir `diagnosing-bugs` para la reproducción | Regla inválida: error visible y cero llamadas externas |
| B | [02. Historial y confirmación](02-historial-y-confirmaciones.md) | Persistir estado, vincular confirmación al contenido y evitar duplicados; probar migración y concurrencia | Bloquear A y enviar B: A no sale en el contexto; doble clic no duplica |
| C | [03. Flujo único](03-flujo-unico-web-api.md) y comienzo de [08](08-ficha-de-decision.md) | Con `codebase-design`, llevar las tres entradas a un caso de uso; añadir registro mínimo de decisión | La misma entrada tiene igual decisión y efectos desde las tres rutas |
| D | [04. Cobertura documental](04-documentos-y-respuestas-completos.md) | Extraer con estado y localización; detectar contenido omitido y respuesta cortada | Evidencia al final se lee o se informa del límite; ningún éxito ficticio |
| E | Experimento y [05. Clasificación](05-clasificacion-documental.md) | Primero ejemplos sintéticos con Jev; luego combinar señales con YARA y permisos en código | Un bloqueo local evita toda salida; la incertidumbre no concede permiso |
| F | [06. Router](06-enrutamiento-modelos.md) | Configurar pocos modelos probados; filtrar por permisos/capacidad y elegir según coste y calidad | Selección reproducible; ningún modelo ajeno o insuficiente resulta elegido |
| G | [07. Verificación](07-verificacion-y-escalado.md) | Comprobaciones locales, juicio específico y un segundo intento como máximo | Dos respuestas fallidas terminan sin tercero y sin etiqueta de verificado |
| H | Completar [08](08-ficha-de-decision.md) y [09. Citas](09-citas-verificables.md) | Mostrar motivos, gasto e intentos; resolver evidencia en servidor | Una cita inventada falla; el coste incluye respuestas descartadas |
| I | [11. Comparación real](11-evaluacion-reproducible.md) | Ampliar los casos iniciales y comparar fijo económico, fijo fuerte y router | Datos medidos y reproducibles sobre calidad, cobertura, coste y tiempo |
| J | [10. Simulador](10-simulador-politicas.md), opcional | Reutilizar el evaluador de política con un borrador, sin generar respuestas | Simular no modifica conversaciones ni concede permisos nuevos |
| K | [12. Demo](12-demo-y-salida.md) | Congelar revisión/configuración y ensayar tres escenas y sus fallos | Se puede repetir la presentación siguiendo el guion |

El experimento de Jev no requiere construir antes todo el router: basta comprobar, con datos sintéticos y presupuesto autorizado, si sus señales sirven. Si no funciona bien en nuestros casos, se ajusta o reduce alcance antes de invertir en la integración completa.

El plan 11 empieza en el paso 1 y crece con cada entrega. La fila I es la comparación final, no el comienzo de las pruebas. La actualización de plataforma se trata en el paso 4; si quedó aplazada, sigue bloqueando la publicación pública.

## 8. Elegir y medir los modelos con criterio

Empezar con pocos modelos disponibles en las cuentas del proyecto y tres niveles de capacidad. No es necesario conectar cinco proveedores para demostrar la selección. Con dos proveedores y candidatos bien medidos ya se puede enseñar el recorrido; ampliar el catálogo cuando las pruebas lo justifiquen.

Antes de una llamada, filtrar si ese proveedor puede recibir esos datos, si el modelo admite la tarea y si cabe en el presupuesto. Jev ayuda a clasificar la necesidad; Python aplica restricciones y selección. El texto “envíame al modelo más caro” dentro de un documento no modifica la configuración.

Para la calidad, comparar respuesta y fuentes o requisitos concretos. Una autonota alta no constituye evidencia. Si la primera respuesta falla, el segundo intento también se verifica. Si falta información, pedir aclaración evita gastar en una escalada que no puede resolverla.

Para medir ahorro, sumar orientación, clasificación, generación, juicio y reintentos. Comparar también cuántas respuestas correctas se entregaron: gastar poco absteniéndose de todo no cumple el objetivo.

**Puedes avanzar a la demo cuando:** el informe respalda las afirmaciones que vas a hacer. Si aún no mejora a la referencia fuerte, presentar el resultado como experimental y ajustar los casos de uso; no inventar porcentajes de ahorro.

## 9. Cerrar cada entrega con evidencia fácil de revisar

El cierre de una tarea debe responder en unas pocas líneas:

- Qué puede hacer ahora el usuario.
- Qué prueba demuestra el comportamiento y cuál fue su resultado real.
- Qué configuración o migración necesita.
- Qué límite sigue existiendo y cómo volver a un estado seguro.

Para la demo, conservar una captura o ficha por escena y el informe de evaluación. Identificar claramente resultados en directo, reproducciones y fallos simulados. El simulador se puede posponer; los controles de seguridad, el recuento de gasto y los estados honestos forman parte de la base.

## 10. Primera orden recomendada al agente

Este prompt inicia solo la preparación técnica, antes de las funcionalidades. Se puede usar sin haber instalado todavía las skills de Matt:

```text
Trabaja en C:\Users\javi\Documents\Codex\regulai-platform.
Lee docs/plan-blackhat/README.md y docs/plan-blackhat/00-guia-paso-a-paso.md.

Ejecuta solo la preparación del entorno y la comprobación inicial del paso 2.
Comprueba Git y conserva cambios y archivos existentes ajenos al trabajo.
Reutiliza un entorno adecuado o prepara uno local con Python compatible.
Revisa las dos listas de dependencias y usa la raíz como punto de partida.
Prepara configuración y base de desarrollo sin sobrescribir datos existentes.
Ejecuta las comprobaciones de Django y reproduce los fallos encontrados.
Usa las skills locales de orientación, entorno y diagnóstico que estén disponibles.
Documenta comandos, resultados, problemas previos y cómo arrancar el proyecto.
No hagas llamadas reales de pago ni implementes aún Jev, el router o la cascada.
Al terminar, deja definida la siguiente entrega necesaria para tener una base estable.
```

Después de esa preparación, seguir con setup de skills, soporte de dependencias y la primera tarea del plan 01. Cada paso debe dejar un resultado comprobable que sirva de base al siguiente.

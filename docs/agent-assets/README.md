# Material del agente de Regulay

Preparado el 7 de octubre de 2026 para el [plan de Deep Agents](../plan-capacidades-agenticas-regulay-2026-10-07.md). La tarea 50 promueve el sistema y el procedimiento Excel a [front/agents/runtime](../../regulai/front/agents/runtime/NOTICE.md), fuente única que carga el ejecutor. El chat normal conserva su prompt. La rama agente permanece desactivada por defecto y solo admite cuentas sintéticas explícitas de desarrollo.

La [guía de implementación en siete prompts](../implementacion-agente-regulay-prompts.md) indica cuándo integrar cada formato. Los archivos promovidos de `prompts/` son enlaces de documentación; las secciones futuras Word/PDF/PPTX siguen sin cargarse.

## Contenido y procedencia

- [Prompt de sistema](prompts/system.md): texto original de Regulay, basado en los requisitos de este proyecto. No es una transcripción del prompt de Claude Desktop/Cowork.
- [Instrucciones documentales](prompts/documents.md): complemento original que se carga para trabajos con DOCX, XLSX, PPTX o PDF.
- [Fuentes de Claude y candidatos documentales](sources.json): referencias oficiales, revisiones de repositorios y tratamiento de cada material. Referenciar un prompt no significa haber copiado su texto ni tener permiso para redistribuirlo.
- [Skill PDF pública de OpenAI](upstream/openai-pdf/SKILL.md): copia de referencia sin modificaciones, con su [licencia Apache 2.0](upstream/openai-pdf/LICENSE.txt). No se activa automáticamente. Procedencia y hashes en `sources.json`.
- [Investigación y selección](../investigacion-prompts-skills-documentales-2026-10-07.md): hallazgos, Reddit, límites de calidad y pruebas pendientes.

La copia PDF contiene las instrucciones de instalación y rutas de su entorno original. Antes de habilitarla hay que adaptar esos puntos a la imagen preinstalada, a las carpetas de Regulay y al control de salidas. El agente de producción no descargará paquetes durante una conversación. Una instrucción de inspeccionar imágenes tampoco autoriza enviar documentos originales al modelo.

## Integración prevista con Deep Agents

1. Cargar `front/agents/runtime/system.md` como instrucciones de producto en el `system_prompt` del agente. La tarea 50 ensambla además las instrucciones documentales comunes y una única skill Excel. Comprobar el prompt efectivo junto con las instrucciones que añade la versión fijada de Deep Agents; no asumir que este archivo sustituye todos sus componentes.
2. Adjuntar, desde el servidor, un bloque de contexto fiable con fecha y zona horaria, capacidades habilitadas, referencias opacas a los recursos autorizados, rutas y perfil de modelo. Los textos del usuario, los documentos y las respuestas MCP siguen siendo contenido no fiable en sus mensajes correspondientes: nunca se interpolan como instrucciones del sistema.
3. Registrar las herramientas reales con sus esquemas. El prompt no crea herramientas: solo puede nombrar operaciones presentes en ese registro. El catálogo efectivo y sus permisos se calculan por empresa, usuario y ejecución.
4. Cargar `front/agents/runtime/documents.md` y la skill Excel para el recorrido de 50. Las otras alternativas permanecen como referencia para tareas posteriores; no concatenarlas.
5. Montar `/workspace/input/` y `/skills/` como solo lectura; permitir candidatos en `/workspace/work/` y `/workspace/output/`. La publicación de una revisión corresponde al servicio de artefactos, después de validar el archivo. Estas rutas son el contrato propuesto y deben existir antes de activar el prompt.

El gateway, las políticas de red, la autorización, el filtro de resultados, el registro de seudónimos, el aislamiento y la comprobación independiente se implementan fuera del texto. Estas instrucciones no constituyen sus pruebas de cumplimiento.

## Activación y verificación pendientes

La evidencia del recorrido Excel y sus límites está en la [tarea 50](../plan-blackhat/tareas/50-agente-chat-excel.md). El corpus de los otros formatos sigue pendiente. No se ha evaluado calidad con un modelo de pago ni habilitado usuarios reales. Los avisos del material promovido permanecen junto al runtime.

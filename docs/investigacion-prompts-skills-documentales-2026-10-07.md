# Prompts de Claude Desktop y skills documentales para Regulay

Investigación del 7 de octubre de 2026. Complementa el [plan de capacidades agénticas](plan-capacidades-agenticas-regulay-2026-10-07.md). Deep Agents sigue siendo el arnés elegido.

## Decisión propuesta y material incorporado

Hay material público útil, pero no un paquete cuya publicación permita afirmar «copiamos todo Claude Desktop y obtenemos la misma calidad». Separar tres cosas: el comportamiento escrito en prompts, las skills con sus scripts y los motores que producen/verifican archivos.

La selección para el piloto es:

| Necesidad | Primera candidata | Licencia consultada | Alcance de la recomendación |
| --- | --- | --- | --- |
| DOCX con plantilla corporativa | BrandDocs, `brand-docx` | MIT, con NOTICE de implementación propia | Mejor ajuste encontrado al requisito de conservar una plantilla; requiere evaluación con nuestras plantillas. |
| XLSX | Python/openpyxl + recálculo de LibreOffice; BrandDocs `brand-xlsx` para rellenar plantillas | BrandDocs MIT; inventariar también las dependencias de la imagen | Mantener cálculo local sobre datos y comprobar fórmulas. OfficeCLI es una alternativa a evaluar para edición general. |
| PPTX | OfficeCLI `officecli-pptx`; BrandDocs si se parte de una plantilla | Apache 2.0 / MIT | Edición de elementos y archivos reales. `dom-to-pptx` queda como alternativa para creación visual desde HTML. |
| PDF | Skill pública `pdf` de OpenAI, adaptada a Regulay | Apache 2.0 en esa carpeta | Base pequeña y reutilizable para creación, extracción y revisión por render; necesita motor y validadores. |

Se han añadido un [prompt de sistema original](agent-assets/prompts/system.md), un [complemento documental original](agent-assets/prompts/documents.md), un [manifiesto de fuentes y revisiones](agent-assets/sources.json) y una [copia de referencia de la skill PDF](agent-assets/upstream/openai-pdf/SKILL.md), conservando su licencia. La [guía de integración](agent-assets/README.md) indica cómo conectarlos a Deep Agents. **Aún no están activos en el chat**: no existe aquí un runtime Deep Agents implementado al que conectarlos.

El prompt original recoge los requisitos de Regulay: código sobre datos locales, seudónimos estables, herramientas autorizadas, progreso humano, reparación, verificación y aprobación de escrituras externas. No se ha etiquetado como un prompt auténtico de Anthropic. Las otras candidatas se han investigado, no instalado.

## Qué publica realmente Anthropic

**Prompt base del chat.** Anthropic publica versiones fechadas de sus prompts de comportamiento. La [página oficial](https://platform.claude.com/docs/en/release-notes/system-prompts/overview) describe la publicación para web y móvil y aclara que las actualizaciones no se aplican automáticamente a la API. El [bloque de Opus 5.5 consultado](https://platform.claude.com/docs/en/release-notes/system-prompts/claude-opus-5-5), fechado el 22 de septiembre de 2026, también menciona la interfaz desktop. Por tanto, sí hay texto oficial relevante para el chat de Desktop; no sería correcto afirmar que no tiene relación alguna con él.

**Desktop, Chat, Code y Cowork son alcances distintos.** La [ayuda de instalación de Desktop](https://support.claude.com/en/articles/10065433-install-claude-desktop) distingue esas experiencias y describe el uso de una máquina virtual para Cowork. La publicación del bloque de comportamiento no demuestra que incluya todo el prompt efectivo, definiciones de herramientas, contexto de sesión, rutas, permisos y skills del modo Cowork.

**Resultado de la búsqueda.** No he localizado una publicación oficial del prompt completo de Desktop/Cowork acompañada de una licencia de reutilización para integrarlo íntegro en otro producto. Tampoco he encontrado una licencia permisiva específica para copiar íntegramente los prompts base consultados. Se han incorporado sus referencias al manifiesto y se ha escrito un prompt propio para Regulay; no se han importado transcripciones de terceros como si fueran oficiales. Esto es un resultado de la búsqueda, no una afirmación de que nunca pueda existir otro material o un permiso particular.

**Herramientas.** Una documentación pública de Bash, lectura, edición o búsqueda permite conocer sus contratos, pero no entrega necesariamente su implementación. Conservar Deep Agents y construir los adaptadores de Regulay. El [SDK público de Claude](https://github.com/anthropics/claude-agent-sdk-python) no es una razón para sustituir el arnés elegido ni para asumir que toda la aplicación que ejecuta está cubierta por la licencia de su wrapper.

**Skills documentales originales.** El [README de Anthropic](https://github.com/anthropics/skills/blob/main/README.md) distingue explícitamente las skills abiertas de `docx`, `xlsx`, `pptx` y `pdf`, que publica como source-available. Sus licencias remiten a los acuerdos de servicio y restringen copia, derivados y distribución. La [licencia de DOCX](https://github.com/anthropics/skills/blob/main/skills/docx/LICENSE.txt) lo deja explícito; las otras tres se revisaron también en el plan. No se incluyen esos archivos en Regulay.

La [constitución de Claude](https://www.anthropic.com/constitution) sí anuncia CC0, pero es otro documento: no es el prompt de Desktop ni un conjunto de herramientas. No se ha usado como sustituto para afirmar que el prompt completo está abierto.

## Candidatas examinadas

### BrandDocs: la opción más ajustada a plantillas

Repositorio: [ferdinandobons/brand-docs](https://github.com/ferdinandobons/brand-docs). Se revisaron README, LICENSE, NOTICE, skill DOCX, dependencias y pruebas de fidelidad XLSX, revisión visual y corpus. El [NOTICE](https://github.com/ferdinandobons/brand-docs/blob/main/NOTICE) declara código original MIT y ausencia de helpers propietarios; eso es una declaración del mantenedor, no una auditoría independiente de toda su procedencia.

Incluye tres skills y un motor compartido: extraer un perfil de marca desde un archivo, verificarlo y generar a partir de su estructura. Usa python-docx, python-pptx, openpyxl, lxml y Pillow. La parte determinista puede trabajar sin modelo; el enriquecimiento con modelo es opcional. No basta copiar un único `SKILL.md`: las carpetas de skills dependen del motor común. [README y estructura](https://github.com/ferdinandobons/brand-docs/blob/main/README.md).

Hay evidencia técnica concreta: el [test de fidelidad XLSX](https://github.com/ferdinandobons/brand-docs/blob/main/tests/test_xlsx_complex_fidelity.py) comprueba que rellenar una región no borre sus fórmulas, conserva un fixture sintético con varias hojas y compara generaciones deterministas. Esto valida un contrato del código, no calidad general equivalente a Claude.

Límites que afectan a Regulay:

- El README declara versión alpha. El perfil sirve para plantillas; no sustituye toda la edición libre de Word o Excel.
- Su revisión visual puede degradarse si faltan conversores. Para una entrega que exija render, Regulay debe exigir la modalidad estricta y comprobar evidencias, sin aceptar silenciosamente una revisión solo estructural.
- Las [pruebas visuales](https://github.com/ferdinandobons/brand-docs/blob/main/tests/test_visual_qa.py) usan imágenes sintéticas y mocks en buena parte; el caso con render real depende de binarios. La existencia de tests no prueba que se haya renderizado nuestro documento.
- La conservación de una fórmula no equivale a su recálculo correcto. Mantener recálculo y contraste independientes.
- Los perfiles pueden contener muestras de texto y datos de la plantilla. Deben filtrarse antes de entrar en el contexto del modelo y aislarse por empresa. La mejora persistente del perfil no debe convertirse en memoria personal entre chats.

**Decisión:** evaluar primero `brand-docx` y después `brand-xlsx`/`brand-pptx` con plantillas autorizadas. Fijar el paquete entero, restringir las vistas al modelo y mantener la publicación de artefactos en Regulay.

### OfficeCLI: motor y skills para edición general

Repositorio: [iOfficeAI/OfficeCLI](https://github.com/iOfficeAI/OfficeCLI). Licencia [Apache 2.0](https://github.com/iOfficeAI/OfficeCLI/blob/main/LICENSE), con [avisos de componentes](https://github.com/iOfficeAI/OfficeCLI/blob/main/THIRD-PARTY-NOTICES.txt). Se revisaron las skills general, DOCX, XLSX y PPTX, el proyecto .NET, el evaluador de fórmulas y el workflow de compilación.

Ofrece lectura estructurada, operaciones sobre elementos, validación OOXML y previsualización. Las skills documentan edición incremental, referencias estables cuando existen y guardado antes de usar otro programa. Su motor tiene código real para evaluar fórmulas; no se limita a escribir instrucciones en Markdown. [Skill general](https://github.com/iOfficeAI/OfficeCLI/blob/main/SKILL.md), [evaluador](https://github.com/iOfficeAI/OfficeCLI/blob/main/src/officecli/Core/Formula/FormulaEvaluator.cs).

Límites:

- El evaluador distingue resultados, errores y fórmulas no evaluadas. No asumir cobertura completa de Excel; contrastar las funciones del corpus.
- La vista HTML propia no demuestra idéntica paginación, fuentes o gráficos en Office. PNG necesita navegador headless y algunas salidas requieren plugins; el eslogan de binario sin dependencias no describe todos los recorridos de render.
- En el árbol público inspeccionado no encontré una suite de tests de documentos. El [workflow de build](https://github.com/iOfficeAI/OfficeCLI/blob/main/.github/workflows/build.yml) acredita un proceso de compilación, no un benchmark de fidelidad que hayamos ejecutado.
- Las instrucciones de instalación automática y los servicios de vista previa se deben adaptar a la imagen y a la autenticación de Regulay. No exponer un puerto de preview directamente a otros usuarios.
- Un proceso residente debe guardar/cerrar antes del hash, render o publicación; de lo contrario puede verificarse una versión anterior del archivo.

**Decisión:** candidata principal para PPTX editable y candidata secundaria para edición DOCX/XLSX. Probar sus comandos como herramientas locales del sandbox, sin incorporar otra capa de agente ni permitir que sus lecturas vuelquen los datos originales al modelo.

### PDF de OpenAI: base abierta, pequeña y portable

La [skill pública PDF](https://github.com/openai/skills/tree/main/skills/.curated/pdf) tiene su propio `LICENSE.txt` Apache 2.0. Indica generación con ReportLab, extracción con pdfplumber/pypdf y revisión de páginas renderizadas. El procedimiento encaja con la verificación que necesita Regulay y no exige un proveedor de modelos concreto.

Su alcance es una guía: en la carpeta inspeccionada no hay un motor de procesamiento ni una batería de pruebas documentales. No cubre por sí sola OCR avanzado, redacción segura, PDF/A, accesibilidad o formularios complejos. Es buena base para una skill propia con esas capacidades añadidas según demanda, no una sustitución demostrada de toda la skill de Anthropic.

Se conserva en `agent-assets/upstream/openai-pdf/` la copia exacta del texto y la licencia, desde una revisión fijada. Antes de activarla, adaptar rutas, instalación y revisión visual a la política de datos de Regulay. No confundir esta publicación con skills internas de otras aplicaciones ni copiar sus paquetes privados por analogía.

### dom-to-pptx: alternativa visual que merece una prueba

Repositorio [atharva9167j/dom-to-pptx](https://github.com/atharva9167j/dom-to-pptx), [licencia MIT](https://github.com/atharva9167j/dom-to-pptx/blob/master/LICENSE). Hay [skill instalable](https://github.com/atharva9167j/dom-to-pptx/blob/master/packages/dom-to-pptx-skills/skills/dom-to-pptx-skill/SKILL.md), exportador headless y tests de tablas, texto, fuentes y otros componentes en el árbol revisado.

La propuesta es generar HTML y convertirlo en elementos editables de PowerPoint. Es una opción interesante para presentaciones nuevas. No es lo mismo que preservar un PPTX existente. La correspondencia CSS/OOXML requiere pruebas: ni el calificativo «pixel-perfect» ni una captura del HTML prueban el resultado exportado. Su skill también fomenta imágenes externas y estéticas específicas; en Regulay prevalecen la plantilla del usuario, los recursos autorizados y la ausencia de salidas de red no gobernadas.

**Decisión:** comparación acotada con OfficeCLI en tres tareas de PPTX. No incorporarlo además como motor obligatorio del primer piloto.

### GenOffice: alternativa amplia con mayor integración

Repositorio [genspark-ai/genoffice](https://github.com/genspark-ai/genoffice), [Apache 2.0](https://github.com/genspark-ai/genoffice/blob/main/LICENSE). Su [CLI](https://github.com/genspark-ai/genoffice/blob/main/packages/cli/README.md) y [skill](https://github.com/genspark-ai/genoffice/blob/main/skills/genoffice/SKILL.md) cubren DOCX/XLSX/PPTX/PDF, operaciones estructuradas, render y comprobaciones.

La distribución descrita enlaza la CLI con la aplicación y su runtime Electron. Algunas operaciones locales se separan de funciones de búsqueda, imagen y medios que pueden llamar a proveedores. El ajuste a un sandbox Linux sin interfaz y a la pasarela de Regulay requiere comprobar qué componentes bastan y deshabilitar las rutas externas. No se ha medido su tamaño, arranque ni fidelidad en esta investigación.

**Decisión:** reserva para una prueba posterior si interesa también su editor. No sustituir Deep Agents ni importar toda la suite solo para obtener cuatro skills.

### Univer y catálogos: precauciones concretas

[dream-num/skills](https://github.com/dream-num/skills) publica skills bajo Apache 2.0, pero su [skill Pro](https://github.com/dream-num/skills/blob/main/skills/univer-pro-integrate/SKILL.md) sitúa importación/exportación Office y otras funciones en componentes con licencia. La licencia del texto de una skill no prueba que todo el recorrido XLSX sea gratuito. No lo seleccionaría como primera solución de archivos independientes sin resolver ese punto.

[tfriedel/claude-office-skills](https://github.com/tfriedel/claude-office-skills/blob/main/README.md) afirma empaquetar las mismas skills de Claude y remite al repositorio oficial. No es una implementación independiente cuya aparición resuelva la licencia de Anthropic. Los catálogos y forks que enlazan o copian sus cuatro skills se han tratado como vías de descubrimiento, no como nuevas alternativas abiertas.

## Qué aportó Reddit

Reddit sirvió para encontrar proyectos y problemas de uso. Sus votos, autopromoción y testimonios no se han convertido en medidas de calidad. En particular, varias publicaciones de BrandDocs repiten el mismo texto del autor: no son evaluaciones independientes.

| Hilo consultado | Hallazgo útil | Qué no demuestra |
| --- | --- | --- |
| [Supuesto prompt completo de Cowork](https://www.reddit.com/r/ClaudeAI/comments/1qchck5/share_claude_cowork_system_prompt_anyone_else/) | Existe interés y circulan transcripciones más amplias que el bloque oficial. | Autenticidad, integridad, actualidad o permiso de reutilización. |
| [Diferencias entre prompts publicados y supuestos prompts completos](https://www.reddit.com/r/ClaudeAI/comments/1kgrdac/) | La comunidad distingue comportamiento base e instrucciones de herramientas. | Que cualquier extracción de un chat sea el prompt real. |
| [BrandDocs y plantillas corporativas](https://www.reddit.com/r/ClaudeCowork/comments/1u026bo/claude_skill_to_generate_onbrand_word_documents/) | Descubrimiento del repositorio; conservación de plantillas como problema concreto. | Igualdad o superioridad a Claude en un corpus controlado. |
| [Experiencia con OfficeCLI](https://www.reddit.com/r/LocalLLM/comments/1v3cdlr/officecli_review_word_excel_powerpoint/) | Interés por edición estructurada y ciclo de previsualizar/corregir; comprobar empaquetado Linux. | Ahorros de memoria o calidad general; es un testimonio aislado. |
| [Skill dom-to-pptx](https://www.reddit.com/r/AgentSkills/comments/1tf29bo/built_ai_agent_skills_for_generating_clean/) | Descubrimiento de skill y motor editables. | Fidelidad perfecta; es una presentación del propio proyecto. |
| [Agente que crea y edita PPTX con vista previa](https://www.reddit.com/r/AI_Agents/comments/1mv94xe/) | La previsualización HTML y la representación del archivo exportado son problemas distintos. | Que no existan soluciones posteriores ni que una biblioteca concreta los haya resuelto. |

Las conclusiones técnicas anteriores se apoyan en los repositorios y documentos primarios enlazados, no en esos testimonios.

## Cómo decidir si alcanzan la calidad que queremos

No he ejecutado las candidatas ni una comparación con Claude en esta investigación. No hay base para afirmar «igual de buenas». Se ha comprobado disponibilidad de código, alcance, licencias declaradas, dependencias y algunos contratos de prueba; no toda su cadena de procedencia o compatibilidad.

Preparar 16 tareas, cuatro por formato, con tres repeticiones cada una. Usar el mismo modelo, entradas y configuración al comparar skills dentro de Deep Agents. Separar esa comparación de una prueba contra el producto Claude, que incorpora su propio modelo, runtime e instrucciones. No atribuir toda diferencia del producto a su skill.

| Formato | Cuatro casos mínimos |
| --- | --- |
| DOCX | Informe con plantilla; tabla que cruza páginas; cambio de título conservando estilos; edición con comentarios o control de cambios. |
| XLSX | CSV con identificadores y fechas; fórmulas entre hojas y nulos; relleno que atraviesa celdas de fórmula; gráfico y vista de impresión. |
| PPTX | Plantilla con maestros; creación de deck nuevo; cambio localizado sin alterar otras diapositivas; gráfico/tabla editables y texto largo. |
| PDF | Informe español con fuentes; formulario; extracción de escaneo con OCR; eliminación verificable de información. |

Medir contenido correcto, conservación de estructura, fórmulas recalculadas, editabilidad, calidad visual, cambios no solicitados, reparación, latencia y coste por entrega válida. Para privacidad, incluir datos sintéticos reconocibles y verificar que no aparezcan en llamadas al modelo, logs, errores o renders enviados. No ocultar fallos como simples advertencias.

El verificador debe leer los bytes finales desde otro proceso y asociar el resultado a su hash. Los renders reales permanecen locales; la visión remota recibe solo vistas protegidas autorizadas. Una entrega incompleta no cuenta como éxito porque su ZIP abra o porque una fórmula exista.

Los ensayos locales con fixtures y transportes simulados pueden comenzar sin consumo de APIs. La comparación real con modelos necesita presupuesto y autorización específicos; no se ha realizado ninguna llamada de pago. «Gratuito» aquí describe la disponibilidad/licencia del material seleccionado, no el coste de inferencia, máquinas o mantenimiento.

## Cambios necesarios antes de activar cualquier skill

Fijar versión y dependencias; conservar licencias y avisos; preinstalar sus herramientas en la imagen; adaptar rutas y catálogo a Deep Agents; sustituir lecturas completas por vistas permitidas; impedir descargas e inferencia directa; exigir recálculo y render según formato; guardar revisiones de artefactos y publicar solo después de verificar. Estas son las adaptaciones del producto, no garantías que se obtengan copiando un `SKILL.md`.

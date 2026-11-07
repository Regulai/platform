# Detector integrado de enmascarado local

## Comportamiento actual: patrones explícitos (5 de octubre de 2026)

Por petición del usuario, `regulai-local-v6-patterns` elimina NER de spaCy del backend local. La predicción de persona/lugar/organización no demuestra que haya datos privados: en el prompt real de planificación sustituía «Tengo», «A» y «A. Dispongo», alterando las dependencias. Ahora conserva la prosa, los nombres en texto libre, las letras de tareas y las tablas. Solo transforma coincidencias de patrones explícitos: correos, identificadores, teléfonos, cuentas, tarjetas, secretos y campos de nombre etiquetados. YARA continúa evaluando el original y aplicando las acciones de cada regla.

Se aplica a todas las transformaciones del backend local (entrada, historial, documentos y salida), sin cambiar el backend HTTP. No carga ni exige spaCy o sus modelos. Los paquetes fijados de la instalación anterior permanecen en requirements para no mezclar esta corrección con una limpieza de dependencias. `detector_metadata()` identifica la versión y el hash de los patrones activos; los manifiestos anteriores de evaluación quedan obsoletos, no se reescriben sus resultados. Los límites de lote, atomicidad, fallo cerrado, JSON y coste API cero se conservan.

Esto reduce deliberadamente la detección: los nombres, lugares y organizaciones en prosa libre ya no se ocultan por inferencia estadística. No se presenta como anonimización completa. La [tarea 47](tareas/47-enmascarado-sin-inferencia-de-entidades.md) registra la reproducción exacta y las pruebas posteriores. El resto de este documento conserva la historia de la implementación anterior y sus mediciones, que no representan esta versión.

## Implementación anterior (histórico)

Ampliación solicitada el 3 de octubre de 2026 durante la preparación del piloto. El conector anterior exigía un servicio HTTP compatible con PasteGuard: la aplicación no incluía ese detector. La implementación nueva ejecuta la detección y sustitución dentro del proceso Django, en CPU y sin llamadas a DeepSeek, Jev ni otro servicio para enmascarar. No se modificó ninguna base del usuario.

## Elección y dependencias

Se reutiliza el contrato de lotes del flujo y se añade un backend explícito `local`, conservando `http` para las configuraciones anteriores. No hay servicio nuevo, GPU ni descarga automática durante una petición. Se exige instalar `requirements.txt`, que fija spaCy 3.8.16 y el modelo `xx_ent_wiki_sm` 3.8.0 mediante URL de release y SHA256. La instalación observada añadió29 paquetes y conservó todas las versiones anteriores; `uv pip check` pasó. La auditoría preliminar no encontró vulnerabilidades conocidas en dependencias auditables; el modelo no está en PyPI y no tiene cobertura de esa consulta, por lo que se comprueba su artefacto/versionado por separado. Las cinco puertas finales registrarán la auditoría integrada.

NER aporta detección de nombres, lugares y organizaciones. Las reglas propias añaden correos habituales, DNI/NIE/NIF españoles, teléfonos, cuentas con formato admitido, tarjetas que pasan Luhn, claves con prefijos conocidos, bloques PEM, JWT y credenciales etiquetadas. Un framework de anonimización más amplio no resultó necesario para esta primera integración: sustituir intervalos no requiere sus módulos de cifrado ni modificar las dependencias criptográficas existentes.

Referencias verificadas: [spaCy, paquetes de modelos](https://spacy.io/usage/models), [metadatos oficiales del modelo](https://raw.githubusercontent.com/explosion/spacy-models/master/meta/xx_ent_wiki_sm-3.8.0.json) y [release fijada](https://github.com/explosion/spacy-models/releases/tag/xx_ent_wiki_sm-3.8.0). spaCy y el modelo declaran licencia MIT. El modelo atribuye sus datos a WikiNER, de Joel Nothman, Nicky Ringland, Will Radford, Tara Murphy y James R Curran, bajo CC BY4.0; [fuente de datos y atribución](https://figshare.com/articles/Learning_multilingual_named_entity_recognition_from_Wikipedia/5462500). No se extrapolan sus métricas publicadas al piloto.

## Contrato y límites

- Solo idiomas declarados español/inglés o campo vacío con el mismo modelo multilingüe; no se realiza detección automática del idioma. Un idioma distinto se rechaza; no hay fallback silencioso.
- Lote completo de hasta512000 bytes y4096 segmentos. El exceso se rechaza, sin cortar contenido. El plazo incluye espera por el detector; si se excede no se devuelve un lote parcial ni se permite continuar al transporte. La llamada CPU en curso termina antes de comprobar su plazo, no se mata un hilo a mitad de inferencia.
- Modelo ausente, incompatible, cambiado o error de detección: fallo cerrado. `detector_metadata()` conserva versión, hash del wheel y hash observado de todos los archivos de datos instalados. Los manifiestos de evaluación vinculan esa identidad.
- Un candado serializa el uso del modelo cargado. No se guardan diccionarios reversibles de personas o secretos ni se restauran datos al generar la respuesta. Los marcadores fijos se mantienen entre las sucesivas transformaciones.
- JSON válido conserva estructura, claves duplicadas y precisión de números no sensibles. Los números detectados como sensibles se sustituyen por una cadena marcador, también si usan notación exponencial; mantener su tipo numérico impediría ocultarlos correctamente. Se protegen las claves del protocolo documental y la gramática corta de aliases; datos arbitrarios bajo esos campos se siguen detectando. La verificación normal de citas permanece obligatoria.
- La transformación local tiene **coste incremental de API0**, registrado como `configured_zero` y `transport=local`. Esto no significa que CPU, memoria o alojamiento sean gratuitos. Las salidas HTTP conservan su propio presupuesto e incertidumbre.

La migración0032 conserva los registros existentes como HTTP, sus URLs y actividad; no habilita enmascarado local automáticamente en empresas existentes. Las altas por la interfaz proponen local, requieren `both` y una cota explícita0 cuando la cadena sea solo local. Administradores de empresa controlan la activación. Se conserva YARA sobre el original, el bloqueo restricted y la revalidación de empresa, política, consentimiento y backend antes de cada salida.

## Evidencia y omisiones observadas

[Corpus de18 casos](../../evals/privacy/local-mask-v1/cases.json) fijado antes del primer ensayo. [Primer resultado](../../evals/reports/pilot-local-detector-benchmark-20261003-01/results.json):15 expectativas cumplidas, dos omisiones y un falso positivo sobre el nombre del campo «Tarjeta». Se corrigió ese falso positivo conservando la detección del número; no se cambiaron casos ni expectativas. [Segundo resultado](../../evals/reports/pilot-local-detector-benchmark-20261003-02/results.json):16 expectativas cumplidas, dos omisiones, ninguna pérdida de contenido exigido; cero conexiones/DNS, API0 y revisión humana pendiente.

Las dos omisiones permanecen: un secreto arbitrario sin prefijo/etiqueta y un correo escrito con «arroba»/«punto». También pueden faltar nombres ambiguos, variantes lingüísticas, direcciones, formatos no contemplados o datos codificados. Se usa detección probabilística y por patrones: **no garantiza anonimización ni eliminación de cualquier secreto**. El banco mide desaparición de valores sintéticos exactos y preservación de contenido esperado; no equivale a recall por entidad, representatividad empresarial ni evaluación humana. No es permiso para usar datos reales de alto riesgo.

La preparación inicial mantiene documentos sintéticos. El usuario puede revisar el contenido y las reglas antes de autorizar proveedores. La existencia del detector resuelve la dependencia de un endpoint de máscara; no concede presupuesto para DeepSeek/Jev ni valida su calidad semántica.

Además de las dos omisiones, se han observado falsos positivos contextuales sobre «Único» y la clave JSON inglesa `card`. Se conservan en los informes de evaluación y [seguridad independiente](revisiones-piloto/security-local-0957df4.md). No se añadieron excepciones basadas en esas palabras para favorecer las pruebas.

La revisión independiente reprodujo una omisión de teléfonos y tarjetas escritos como números JSON en las tres entradas HTTP. La versión `regulai-local-v2` la corrige en `be29b6f`, con [rojo](../../evals/reports/pilot-local-detector-20261003-01/numeric-red.json) y [32 pruebas locales/de integración correctas](../../evals/reports/pilot-local-detector-20261003-01/numeric-green.json). La [medición posterior](../../evals/reports/pilot-local-detector-benchmark-20261003-03/results.json) conserva los mismos 18 casos: 16 expectativas cumplidas y las dos omisiones declaradas, sin cambiar etiquetas. No se suman las suites parciales ni se transforma esta medición en una garantía.

## Reproducción aislada

El [replay del ensayo vivo](../../evals/reports/pilot-real-diagnosis-20261003-01/README.md) reprodujo además falsos positivos sobre «Cuál», «Cita» y «Contrato» en entradas de desarrollo. Esas palabras comunes recibieron marcadores; no se demuestra que causaran el rechazo semántico del juez ni el error externo. Se conservan las transformaciones exactas y no se ajustó el detector para hacer pasar la demo.

```text
rtk proxy uv pip install --python .venv/Scripts/python.exe -r requirements.txt
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_local_masking front.test_local_masking_integration --settings=regulai.test_settings
rtk proxy .venv/Scripts/python.exe scripts/evaluate_local_mask.py --output evals/reports/local-detector-nueva-ejecucion
```

Usar una carpeta nueva. El código de salida del medidor confirma que pudo ejecutarse; las omisiones siempre permanecen en `results.json` y no se convierten en éxitos por excluir casos difíciles. La [tarea28](tareas/28-enmascarado-local-integrado.md) conserva la integración, migración y navegador; las revisiones independientes posteriores deben recibir un commit fijo que incluya este backend.

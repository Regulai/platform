# Calibración local de privacidad

Corrección provisional `regulai-local-v5`: DNI/NIE con separadores y representaciones Unicode, correo Unicode y correo expresado con palabras tras una etiqueta explícita. La vista normalizada conserva offsets originales y sus coincidencias se unen a las originales. No se cambian API, clasificación, umbrales, Decimal, NER, verificador, políticas, destinos ni dependencias.

Base observada `9d7f9424a70143614c9d673e64ebed9723ff3439`; runtime final SHA256 `5d6eaa792de291c96b0d2c94c8e1697136f42594e4ef8d9344106255f2e965b6`. Python 3.12.11, spaCy 3.8.16 y xx_ent_wiki_sm 3.8.0. Corpus propio: 33 casos de desarrollo y 44 regresiones conocidas, expectativas fijadas antes de la primera medición; hash `6249deac7f9061674e90031b22e27f2d2cde82de98a2286d040e3c651b654f07`. No se ha leído el conjunto reservado. El contraste con el corpus ampliado está pendiente de su congelación.

## Candidatos y resultados

| Ejecución local | Desarrollo: casos completos | Valores ocultados / 20 | Texto preservado / 32 | Históricos: casos completos | Valores ocultados / 32 | Texto preservado / 66 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [Base v2](baseline-01/summary.json) | 18/33 | 9 | 28 | 37/44 | 27 | 61 |
| [R1 v3](r1-candidate-01/summary.json), normalización y DNI | 25/33 | 16 | 28 | 39/44 | 30 | 61 |
| [R2 v4](r2-candidate-01/summary.json), correo en palabras | 28/33 | 19 | 28 | 40/44 | 31 | 61 |
| [R3 v5](r3-candidate-01/summary.json), unión con coincidencias originales | 28/33 | 19 | 28 | 40/44 | 31 | 61 |

Las rondas se preregistraron por el coordinador en `../hypotheses.jsonl`. v3/v4 se descartan como candidatos finales: la revisión posterior encontró una regresión de secretos con puntuación Unicode, fuera de los 33 casos iniciales. `password=abcd，efgh.` se ocultaba completo en v2; al convertirse la coma a ASCII sólo en la vista de búsqueda, v3/v4 dejaban visible `efgh`. Se añadieron cuatro variantes nuevas sólo a desarrollo, sin cambiar expectativas anteriores. La [regresión roja](extent-red-01/stderr.log) observa los cuatro escapes; v5 mantiene las coincidencias originales y pasa esas cuatro variantes.

[Diferencias completas](r3-candidate-01/comparison.json): 10 casos propios y 3 históricos mejoran frente a base; cero empeorados dentro de esas anotaciones. DNI/NIE propios: 3→8/8; correo: 1→6/6. Las entidades restantes conservan resultado: persona 2/2, teléfono 1/1, cuenta 1/1, secreto etiquetado 1/1 y cadena opaca sin etiqueta 0/1. En histórico mejoran tres representaciones de DNI y un correo; el secreto opaco sigue omitido. Los cambios de entidades/máscaras aparecen por caso en `comparison.json`.

Estas cifras miden desaparición exacta de valores anotados y conservación de cadenas. **No son precisión/recobrado exhaustivos por span ni prueba de anonimato**: eliminar una parte de un secreto también hace desaparecer su cadena completa; por eso las pruebas nuevas comprueban sus sufijos expresamente. No se calculan intervalos ni significación sobre variantes relacionadas. Los resultados de v3/v4 no se presentan como seguros porque su tabla inicial no detectara la regresión posterior.

## Causas reproducidas y límites

1. La gramática original exigía DNI contiguo y no normalizaba letras de ancho completo/invisibles. v5 admite separadores horizontales, punto y guion acotados, NFKC por carácter, dígitos Unicode decimales, guiones U+2010–2015/U+2212 y omite U+200B/C/D, U+2060 y U+FEFF sólo en la vista de búsqueda. No modifica los bytes de texto benigno por normalización ni cambia localizadores globalmente.
2. El correo con palabras requiere una etiqueta `correo`, `email`, `e-mail` o `contacto`, hasta dos calificativos acotados, dos puntos y dirección de 1–4 tokens locales con `arroba/at` y 1–4 separadores de dominio `punto/dot`. No cubre toda descripción libre, toda codificación, toda lengua ni una dirección arbitrariamente larga. Los tests preservan usos corrientes de arroba, punto, at y dot.
3. [Captura base nueva](transport-base-02/transport.json): 11 pares por tres entradas HTTP, 99 cuerpos efectivos de clasificador, generación y juez. `Calcula` se transforma en `[[REGULAI_PERSON]]` tanto en BENIGN-01 exacto como en la operación independiente 23×4+6. `Resume` se transforma con/sin PII y con/sin negación. PII-03 sin negación conserva el DNI separado en base. Esto demuestra corrupción contextual por NER, no la causa de puntuaciones reales históricas que no conservaron su entrada efectiva.
4. [Captura final](transport-final-01/transport.json) añade respuestas de fixture recibidas. Los cuerpos se observan en `requests.adapters.HTTPAdapter.send` y `httpx.MockTransport`, con serialización real de requests/SDK. No se capturan cabeceras ni credenciales. Las respuestas y señales son prefijadas; **no miden Jev/DeepSeek ni éxito semántico del ataque**. El juez recibe ámbito `requirements` y respuesta 88/98 intacta; no se reproduce un supuesto RAG universal.
5. [Diagnóstico NER actual](ner-diagnosis-01/diagnosis.json): `Calcula`, `Resume`, términos comunes y un DNI Unicode unido a `Plazo` producen entidades falsas. Los controles Ana/María López muestran por qué retirar entidades de una sola palabra sería inseguro. No se ha añadido una lista de excepciones con palabras del banco.
6. La misma [nueva ejecución local](ner-diagnosis-01/diagnosis.json) toma dos respuestas sintéticas históricas: las citas INJ-05 y DOC-03 pasan antes de enmascarar y fallan después con `quote_not_found`, al transformarse FI-017/Cláusula por cambio de contexto. Sigue siendo una pérdida de utilidad con cierre seguro, no una cita inválida entregada. No se altera la verificación literal ni se restaura contenido original.
7. Las cadenas opacas sin etiqueta siguen sin detectarse universalmente. Los falsos positivos NER y de referencias/citas permanecen abiertos. Dos pruebas `expectedFailure` conservan explícitamente los límites preexistentes (solapamiento DNI/Plazo y ABC de ancho completo); no son pruebas aprobadas ni se eliminan de las métricas.

## Verificación nueva

- [Normalización roja](normalization-red-01/stderr.log): 2 tests, 9 subfallos en base; la envoltura inicial tuvo además un error de salida de consola cp1252 después de guardar resultado/log íntegro. Siete subfallos pertenecían a H1; los dos de NER permanecen declarados como límites.
- [Correo rojo](email-red-01/stderr.log): 3 tests, 6 subfallos; controles benignos pasan antes del cambio.
- [R3 focal e integración](r3-tests-01/execution.json): 87 tests, 22,781 s, exit 0; 85 aprobados y 2 fallos esperados NER. Incluye máscara local/configuración/migración, clasificación y fronteras Decimal; SQLite en memoria, ajustes privados sustituidos antes de importar Django, transportes externos simulados.
- Tras añadir únicamente las respuestas de fixture a la captura: [9 tests propios](transport-final-01/execution.json), 8,206 s, exit 0; 7 aprobados y los mismos 2 fallos esperados. Runtime sin cambios respecto al gate de 87.
- `rtk git diff --check`: exit 0. No llamadas pagadas, ninguna operación contra la base del usuario, ningún push/despliegue/publicación. Las cinco puertas de integración final corresponden al coordinador.

Los scripts rechazan directorios de salida existentes. Ejemplos para repetir en carpetas nuevas:

```powershell
rtk proxy .venv/Scripts/python.exe evals/calibration/calibration-20261004-01/privacy/probe.py --output evals/calibration/calibration-20261004-01/privacy/probe-new
rtk proxy .venv/Scripts/python.exe evals/calibration/calibration-20261004-01/privacy/run_tests.py --output evals/calibration/calibration-20261004-01/privacy/tests-new --capture front.test_calibration_privacy front.test_local_masking front.test_local_masking_integration front.test_classification front.test_semantic_threshold_boundary
rtk proxy .venv/Scripts/python.exe evals/calibration/calibration-20261004-01/privacy/diagnose_ner.py --output evals/calibration/calibration-20261004-01/privacy/ner-new
```

`transport-base-01` se conserva como intento incompleto del arnés: la limitación de frecuencia del cliente de pruebas detuvo las tres últimas solicitudes. `transport-base-02` vacía la caché sintética entre ejemplos y completa las 33 solicitudes. Ningún error del arnés se cuenta como degradación del proveedor o del producto. Las fuentes históricas nunca se reescriben.

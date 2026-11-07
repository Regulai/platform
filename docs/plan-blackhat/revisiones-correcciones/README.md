# Revisiones independientes de las correcciones

Los informes se conservan íntegros, sin fusionar ni reordenar los hallazgos entre ejes. Cada revisor Spec es un SOL GPT6.1 HIGH nuevo, distinto del implementador; Standards es otro revisor independiente. Aplicaron la skill `code-review` sobre la base fija `4400f0b` y el checkout inmutable `9549e74`. Las líneas y enlaces de esos informes corresponden a ese checkout, anterior a las correcciones posteriores. El [manifiesto](manifest.json) conserva sus hashes.

## Eje Standards

[Informe original](standards.md). Su hallazgo sobre pérdida de límites del historial se reprodujo en exportación y carga HTTP y quedó corregido en `f778336`. Las dos aserciones también fallan en `4400f0b`; la prueba se ajustó en `865e8cb` para que un campo ausente falle como aserción de comportamiento, no como error de preparación.

## Eje Spec

| Carril | Informe original | Seguimiento posterior a la reproducción |
| --- | --- | --- |
| P | [Pipeline](spec-P.md) | `a02f483`, `f8b5ba3`, `95dfb77`: destinos obligatorios e identidad de máscaras antes de generar; suelo unknown compartido con simulador. Cuatro regresiones, diez aserciones rojas y cero errores en la revisión anterior; integradas en verde. |
| D | [Documentos](spec-D.md) | `f92d5a1`, `520fa3a`, `5701a10`, `4cd129f`, `90000c6`: imágenes PDF inline, filas Word borradas, CSV irregular y reinicio decimal. Doce regresiones, veintidós aserciones rojas y cero errores; integradas en verde. |
| V | [Verificación y conectores](spec-V.md) | Sin defecto técnico nuevo. Unidades de precio en [snapshot Jev](../jev-gateway.md), corregidas en `cacae92` y contrastadas en revisión R independiente. |
| C | [Clasificación](spec-C.md) | `d4e1313`, `9840bd6`: calidad mínima también para una única tarea plausible e instrucción de aclaración para todos los avisos de ambigüedad. Tres probes independientes rojos, después verdes. |
| S | [Seguridad](spec-S.md) | `e7311bf`: alternar enmascarado exige POST/CSRF, probado con GET405, POST sin token403, POST válido302 y empresa ajena404. [Procedimiento de rotación](../rotacion-claves.md) añadido en `cacae92` y contrastado en revisión R independiente. |
| F | [Interfaz](spec-F.md) | Pérdida de límites duplicada con Standards, resuelta en `f778336`. Identificación del motor real en ficha, exportación y restauración corregida en `c373c87`; tres entradas HTTP/JavaScript Node y captura adicional. |
| O | [Onboarding y datos](spec-O.md) | Exposición del departamento de otra empresa reproducida y corregida en `51f4ee5`: cinco pruebas sobre ambos listados, filtros, datos legítimos y relaciones inconsistentes. Los controles adicionales de 2.005 filas y política inicial pasan. |
| Q | [Operación y CI](spec-Q.md) | Código de salida corregido en `21c291e`: copia development90/52 fallos, cero reserved, exit1 y cinco informes preservados; banco normal150/0 fallos exit0. |

Las pruebas usaron bases aisladas y transportes sintéticos. No hubo llamadas reales a proveedores/Jev, publicación ni ejecución de CI remoto.

## Revisión documental R

Dos SOL nuevos revisaron por separado el diff documental `51f4ee5..b6a24fb`. Los originales se conservan en otro [manifiesto](manifest-R.json), sin alterar los nueve informes técnicos anteriores.

- [Standards R](standards-R.md): un P2 por prometer enmascarado sin declarar que requiere servicios activos. ASTRA reprodujo el envío sin máscara mediante HTTP aislado (1 test OK en 0,745 s); `52bdc8d` corrige afirmaciones y explica configuración, activación, permisos y coste.
- [Spec R](spec-R.md): sin hallazgos accionables; requisitos y evidencia contrastados.
- [Verificación independiente de la corrección](standards-R-followup.md), sobre `52bdc8d`: P2 resuelto, sin nuevos defectos específicos. [Manifiesto separado](manifest-R-followup.json). D2 aprobada permanece literalmente intacta.

Después de integrar R, ASTRA repitió las [cinco puertas](../../../evals/reports/community-fixes-docs-verification-20261003/README.md): 302 tests OK en 62,428 s, check correcto, migraciones sin cambios, 150 controles offline correctos/cero llamadas reales y auditoría sin vulnerabilidades conocidas. El cierre posterior solo añade estado y evidencia.

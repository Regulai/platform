# 19: Revisión adversarial y evidencia final

**Status:** done
**Blocked by:** none

## Entrega y aceptación

SOL nuevos por carril, reproducir hallazgos, todas las puertas y documentación final; pendientes honestos.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada

Revisión independiente en dos ejes: Standards sobre todo el cambio técnico y un SOL nuevo Spec por carril. Terminados Standards y Spec P/D/V/C/S/F/O/Q; sus hallazgos técnicos están resueltos. R documental también revisada y su corrección verificada. Los hallazgos P/D/C se han reproducido antes de modificar el código. El defecto de filtrado de límites del historial señalado por Standards está corregido en `f778336`, con rojo HTTP/export y verde independiente.

Correcciones P integradas en `a02f483`, `f8b5ba3` y `95dfb77`: preflight de destinos obligatorios antes de generar, identidad de máscaras y suelo unknown compartido con el simulador. Las cuatro pruebas nuevas dieron diez AssertionError y cero errores sobre `f778336`; las cinco puertas de integración resultan correctas: **279 tests OK en 46.899 s**, check sin incidencias, migraciones sin cambios, 150 controles offline correctos/cero llamadas reales y pip-audit sin vulnerabilidades conocidas.

La [comprobación visual offline](../../../evals/reports/ui-community-fixes-20261003/README.md) cubre consentimiento por una imagen, cita y evidencia abiertas con teclado, ficha tras recarga, ancho móvil y bloqueo sin llamadas. Usa documento generado con Python y proveedores simulados; no sustituye los ejemplos guardados con Word/Excel/LibreOffice ni ensayos humanos todavía pendientes.

## Resultado técnico y cierre

Último gate técnico O `51f4ee5`: 302 tests OK en 65,158 s, sin expected failures ni omitidas; check sin incidencias, migraciones No changes detected, 150 offline/0 controles fallidos/0 llamadas reales y pip-audit No known vulnerabilities found. Cinco puertas exit0. F `c373c87`, Q `21c291e`, O `51f4ee5` cierran sus hallazgos adversariales; S `e7311bf` cierra GET mutante. Los [nueve originales y manifiesto](../revisiones-correcciones/README.md) se preservan íntegros.

R actualiza [informe y tabla de correcciones](../informe-correcciones-community.md), [arranque](../arranque-y-demo.md), unidades USD/millón y [rotación](../rotacion-claves.md). Revisión documental y cinco puertas cerradas. Siguen abiertos los pendientes externos de Office/LibreOffice, personas, calibración, proveedores vivos, PostgreSQL y CI remoto.


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).


Entrega documental R integrada: `cacae92` documenta contratos/límites efectivos, arranque, unidades USD/millón y rotación de claves; `f65da23` actualiza estado, tareas e índices de evidencia. Comprobación inicial R: 22 documentos, 234 enlaces relativos existentes, 77 commits resueltos, doce nombres exactos de regresión, módulos citados existentes, nueve hashes de informes originales contra blobs Git y cinco logs finales contra gates.json; git diff --check sin incidencias.


Revisión R: Spec sin hallazgos; Standards reprodujo que una política válida puede completar el envío sin ObfuscationConfig activa. ASTRA repitió la prueba HTTP (1 OK en 0,745 s). `52bdc8d` condiciona la transformación a servicios activos y detalla configuración/activación, permiso de destino, cota bajo presupuesto y contrato JSON. D2 humana se conserva; no se añadió una obligación global al código. El [revisor confirmó su resolución](../revisiones-correcciones/standards-R-followup.md), sin nuevos defectos específicos.

Puertas posteriores a integrar R sobre `52bdc8d`: **302 tests OK en 62,428 s**, sin expectedFailure ni omisiones; check sin incidencias, migraciones sin cambios, 150 offline/0 fallos/0 llamadas reales y pip-audit sin vulnerabilidades conocidas. [Logs, comandos, hashes y banco conservados](../../../evals/reports/community-fixes-docs-verification-20261003/README.md). Se cierra el encargo técnico y documental; los pendientes externos conservan su alcance propio.

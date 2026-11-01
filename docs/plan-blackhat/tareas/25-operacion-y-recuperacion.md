# 25: Operación y recuperación en laboratorio aislado

**Status:** done (laboratorio local sintético)
**Blocked by:** ninguno para este alcance; entorno público y CI remoto no ejecutados.
**Specification:** [12](../12-demo-y-salida.md), [rotación](../rotacion-claves.md).

## Aceptación

- [x] Instalación reproducible, check --deploy, Gunicorn/HTTPS/cookies/hosts/estáticos/archivos privados y logs.
- [x] Dos empresas aisladas; concurrencia, interrupción y recuperación de incertidumbre.
- [x] Pruebas relevantes PostgreSQL, migraciones históricas, recifrado/conflicto real y restauración de base/medios/claves.
- [x] Evidencia de ejecución y límites respecto a CI remoto o infraestructura publicada.

## Verificación observada

**Cierre actual:** [operación 10 y resumen local](../../../evals/reports/pilot-operations-20261003-summary-local/README.md), detector CPU real y correctores JSON/rollback: 117 tests PostgreSQL en 17,185 s, una omisión específica de SQLite y recuperación completa; exit 0. Diez ejecuciones preservadas, hashes de logs correctos y cero coincidencias de claves/marcadores. Los párrafos siguientes conservan los snapshots anteriores.

Ejecuciones 06, 07 y 08 con código 0. [Resultado 08](../../../evals/reports/pilot-operations-20261003-08/result.json): 84 pruebas PostgreSQL en 12,128 s, una omisión específica de SQLite; escritor concurrente PostgreSQL comprobado aparte. Restauración y reversión exactas de 27 tablas, dos archivos y claves; recifrado y lectura con clave nueva sola correctos. Reinicio real durante llamada deja incertidumbre sin reenvío ni coste 0. El arranque opcional supervisado de un segundo pertenece a 07, sin participantes.

[Verificación final de logs](../../../evals/reports/pilot-operations-20261003-summary-final/verification.json): ocho ejecuciones preservadas, hashes de comandos correctos y cero coincidencias de claves sintéticas o marcador sensible en logs. Recursos Docker propios retirados; consultas posteriores por etiqueta e identidad sin contenedores, redes, volúmenes ni imagen temporal. Backups privados sintéticos retenidos. Los intentos 01–05 y el resumen anterior conservan sus fallos y resultados parciales. [Última revisión](../../../evals/reports/pilot-operations-20261003-summary-final/README.md) y [procedimiento y límites](../operacion-y-recuperacion-piloto.md).

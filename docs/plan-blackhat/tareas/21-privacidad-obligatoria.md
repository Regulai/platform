# 21. Privacidad obligatoria

Status: done
Blocked by: ninguno

Spec: [clasificación](../05-clasificacion-documental.md), [enrutamiento](../06-enrutamiento-modelos.md), [verificación](../07-verificacion-y-escalado.md), decisión D2 aprobada y [privacidad previa](18-pipeline-privacidad.md).

## Aceptación

- Chat y simulación semántica rechazan la ausencia, desactivación o sustitución de la máscara autorizada.
- El original solo llega al enmascarador autorizado después de YARA; los demás destinos reciben los segmentos devueltos por la máscara.
- Empresa, usuario, consentimiento, política y configuración de máscara se revalidan en cada salida.
- Lotes inválidos, fallos y resultados inciertos detienen el recorrido y conservan sus reservas de coste.
- Las tres entradas HTTP y el transporte real simulado tienen regresiones significativas.

## Verificación observada

Ampliación posterior solicitada: [tarea 28](28-enmascarado-local-integrado.md), detector CPU real y migración 0032. El [cierre final](../informe-piloto-community-20261003.md) incluye revisiones independientes, 387 tests y 117 PostgreSQL. La evidencia inicial de abajo acredita su snapshot HTTP; no se atribuye eficacia NER a esas 134 pruebas.

[Evidencia propia](../../../evals/reports/pilot-privacy-20261003-01/README.md): rojo inicial de ausencia/inactividad en chat y simulación (3 tests, 5 fallos, exit 1) y rojo adicional de revocación de privilegios durante la máscara semántica (1 test, 1 fallo, exit 1). Después de los cambios finales: **134 tests OK en 40,985 s**, incluidos 13 tests nuevos; check sin incidencias, migraciones sin cambios y diff sin errores, todos exit 0. Proveedores sintéticos; SDK OpenAI real sobre `httpx.MockTransport` en las tres entradas. PostgreSQL y el ensayo operativo se verifican en la tarea del coordinador.

La máscara es obligatoria, propia, activa, autorizada y configurada para datos personales y secretos; no existe opción de omitirla. El conjunto completo de máscaras se revalida antes de cada destino. Lotes inválidos no se marcan completados. La caché inversa usuario/perfil no puede conservar permisos revocados en la simulación semántica.

Se añadió el observador interno de llamadas acordado con evaluación: reserva antes de red, segunda comprobación de autorización tras reservar y liquidación de metadatos/costes también en fallos e incertidumbre. Cota original conservada y procedencia de coste explícita. Sin migración, sin cambio de históricos y sin llamadas pagadas. La eficacia semántica del detector vivo queda fuera de estas pruebas. Resultados anteriores de 302 tests y 150 ejecuciones offline siguen siendo históricos.

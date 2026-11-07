# 28. Enmascarado local integrado

Status: done
Blocked by: ninguno

Spec: [enmascarado local](../enmascarado-local.md), [privacidad obligatoria](21-privacidad-obligatoria.md), [clasificación](../05-clasificacion-documental.md), [enrutamiento](../06-enrutamiento-modelos.md) y [verificación](../07-verificacion-y-escalado.md).

## Aceptación

- Backend explícito `local`/`http`; la migración conserva como HTTP las configuraciones históricas y sus URL. Las nuevas altas de interfaz proponen local sin crear ni activar registros globales.
- El detector local procesa el lote completo dentro de Django, sin red ni descarga automática; ausencia de modelo, fallo, tiempo agotado o cardinalidad inválida cierran el flujo.
- YARA sigue evaluando originales antes de transformar. Empresa, usuario, política, consentimiento y backend autorizado se revalidan antes de los destinos y después de reservar presupuesto.
- Las transformaciones locales conservan `provider=obfuscation:<id>` y `model=null`, con `transport=local`, `cost_scope=api` y coste/cota cero antes del observador. HTTP conserva `transport=http` y sus costes desconocidos.
- Una cadena solo local exige `masking.max_call_cost=0` explícito. Las cadenas mixtas suman cero local y la cota configurada para cada paso HTTP.
- Las tres entradas HTTP, simulación semántica, citas JSON, reversión de migración y configuración por empresa tienen pruebas significativas con transportes externos sintéticos.

## Verificación observada

[Evidencia de integración](../../../evals/reports/pilot-local-masking-integration-20261003-01/README.md): contrato rojo inicial de tres tests (dos fallos y un error, exit 1), seguido de verde. El detector real reveló un alias de cita `S1` transformado; el rojo `unknown_citation` se preserva y la corrección se hizo en el módulo del detector.

Gate focal final: **137 tests OK en 47,006 s**, exit 0; incluye 24 pruebas nuevas de integración/configuración/contrato/migración, las tres entradas HTTP con SDK OpenAI real sobre `httpx.MockTransport`, simulación y comprobación documental. Cota mixta exacta de 0,06 admitida y 0,059 rechazada antes de transformar; ausencia real del paquete de modelo y cambios de backend cierran sin salida. Migración 0031 → 0032 → 0031 conserva configuración HTTP, política y AuditLog. `check`, `makemigrations --check --dry-run` y `git diff --check`: exit 0.

Interfaz comprobada en Chromium, escritorio y móvil: alta local sin URL, error HTTP sin URL, edición HTTP conservada, teclado y nombres de 200 caracteres. El desbordamiento grande del aviso se corrigió y se conservan capturas antes/después. Tres tests de configuración se repitieron después del ajuste visual: OK, exit 0. El tema oscuro forzado por CSS hereda problemas de contraste y no equivale a un modo de producto soportado; persiste un margen horizontal de 3 px en la maqueta base. No se afirma una auditoría de accesibilidad completa.

Código integrado por el coordinador en `3e4d9d2` y ajuste visual en `da836e3`. El ensayo PostgreSQL/HTTPS, el benchmark del detector y la contabilidad de evaluación tienen evidencia propia del coordinador/agente C. Esta tarea no migra la base del usuario ni activa su política, y no realizó llamadas pagadas. La detección sigue siendo falible; la integración no prueba ausencia universal de datos sensibles.

## Anexo: reversión sin reautorizar un destino HTTP anterior

La revisión independiente encontró una transición que no cubría el gate inicial: cambiar una máscara HTTP a local conservaba la URL y `active=True`; al eliminar `backend` durante 0032 → 0031, el código anterior interpretaba esa fila como una máscara HTTP autorizada. Se reprodujo con la implementación congelada de `700389c` y un transporte HTTP sintético que capturó el original.

La reversión de 0032 ahora desactiva las filas locales antes de eliminar el campo. Conserva URL, nombre, empresa, idioma, fechas, política y AuditLog; las máscaras que siguen siendo HTTP conservan exactamente su estado. Un nuevo avance a 0032 no reactiva las antiguas filas locales.

Para un downgrade, detener primero los procesos de la aplicación y ejecutar la reversión con la **versión corregida de la migración 0032**, mientras el campo aún existe. Después pueden arrancar los procesos del código anterior. Las filas locales quedan inactivas deliberadamente: el código anterior no soporta ese backend. Mantenerlas así, o revisar y autorizar expresamente el envío HTTP a su destino antes de activarlas. Al volver a una versión con detector local, seleccionar y autorizar explícitamente el backend local antes de reactivar. No reutilizar la URL conservada como prueba de autorización ni reescribir históricos de auditoría.

[Evidencia nueva de rollback](../../../evals/reports/pilot-local-masking-rollback-20261003-01/README.md): regresión permanente roja antes del cambio (1 test, 1 fallo, exit 1); probe con código anterior rojo (1 fallo, exit 1) y verde (0 fallos, exit 0), con cero llamadas para la exmáscara local y un control HTTP autorizado conservado. Gate de migración/configuración: **9 tests OK en 2,322 s**, exit 0, incluyendo varias empresas, locales con/sin URL, estados activos/inactivos, reversión repetida y nuevo avance. Las evidencias iniciales y las del revisor no se modificaron. No se aplicó ningún downgrade a bases de usuario.

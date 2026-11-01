# 47. Conservar el texto sin inferir personas y lugares

Estado: implementado y verificado localmente.
Bloqueado por: ninguno. Continúa el diagnóstico de 45 y la configuración de 46.

## Solicitud y decisión

El usuario pide impedir que el enmascarador altere palabras corrientes y variables de tareas; esperaba reglas YARA. Se elimina la detección estadística NER del backend local completo, en vez de añadir excepciones para «Tengo» o «A». YARA sigue aplicando las reglas configuradas. Se conservan los patrones explícitos de datos y secretos, incluido el valor de campos como `Nombre:`; los nombres, lugares y organizaciones en prosa libre quedan intactos. El backend HTTP conserva su contrato.

La identidad pasa a `regulai-local-v6-patterns`, con hash de patrones. No se carga ni exige modelo. No se cambian dependencias instaladas, configuración de la cuenta, datos de conversación ni recibos históricos. Los resultados históricos de privacidad son de la versión anterior y no acreditan cobertura de esta versión.

## Aceptación y evidencia observada

- Antes del cambio, el nuevo test con el prompt exacto y una respuesta con tabla falla: «Tengo» se convierte en `[[REGULAI_PERSON]]` y se alteran las referencias.
- Después, el prompt original leído de `7fb0e19d-fca5-4cad-a242-dfdcc04209f1` (397 bytes UTF-8) sale idéntico del detector real.
- La regresión cubre el detector real, el enrutador Jev simulado, el SDK OpenAI real con transporte sintético y las tres entradas HTTP: seis envíos conservan el prompt, la respuesta y el historial; Pro sigue seleccionado para difícil y no aparece la verificación final de texto.
- 84 pruebas de enmascarado local, integración, enrutamiento, barrera obligatoria y conexiones pasan en 18,785 s. Incluyen YARA, aislamiento de empresa, fallos cerrados, JSON, costes y migraciones reversibles sobre SQLite aislada.
- `manage.py check`: sin incidencias. `makemigrations --check --dry-run`: sin cambios.
- 16 pruebas adicionales de `front.test_smoke` pasan en 22,192 s: se conserva la invalidación de manifiestos antiguos y los controles de presupuesto/estado. `git diff --check`: sin errores.
- Servidor de desarrollo reiniciado con el cambio en `127.0.0.1:8765`, tras comprobar que no había peticiones en proceso; GET del chat responde y redirige a login sin sesión.
- Cero llamadas nuevas de pago; esta prueba no afirma calidad semántica del proveedor.

Comando de pruebas: `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_local_masking front.test_local_masking_integration front.test_difficulty_routing front.test_required_masking front.test_ai_connections --settings=regulai.test_settings`.

# 05: Revisar una política antes de activarla

**Status:** completed
**Blocked by:** none
**Specification:** [plan 10](../10-simulador-politicas.md).

- [x] Comparación current/proposed con YARA temporal y señales sintéticas explícitas.
- [x] Borrador permisivo no autoriza Jev; una llamada opcional bajo política vigente, presupuesto y auditoría.
- [x] Sin conversación/mensaje/respuesta/alerta ni generador; activación separada con guardas y rollback de configuración y fuentes YARA.
- [x] Las señales no rebajan el mínimo local y la ruta reserva clasificación/jueces obligatorios.
- [x] Comparación y activación local comprobadas desde navegador, con cero llamadas reales y revisión 2.

Rojo observado al faltar llamada semántica y al ignorar umbral distinto del borrador; verde tras corregir. `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_policy_simulator --settings=regulai.test_settings`: 14 correctas tras las regresiones finales de sensibilidad, reserva y recuperación YARA. No hubo llamadas reales; se simuló el límite HTTP.

Usar modo local en el ensayo. [Ejemplo validado y recuperación](../arranque-y-demo.md). AuditLog restringido a la empresa conserva las fuentes YARA anterior/nueva y sus identidades/digests, sin muestra ni credenciales, para reconstruir el borrador de recuperación.

Se usó una empresa separada sin claves ni destinos. La comparación interna/restringida mostró sus respectivos bloqueos y semántica no evaluada; la activación separada mostró éxito. Comprobación SQLite: revisión anterior 1 y nueva 2 guardadas para recuperación, cero intentos semánticos y cero `Prompt`. [Captura de activación](../../../evals/reports/ui-2026-10-02/simulator-activated.jpg).

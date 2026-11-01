# 01: Un envío seguro desde las tres entradas

**Status:** done
**Blocked by:** 00
**Planes:** 01, 02, 03; ficha mínima de 08.

Entrega por ciclos: fallo cerrado local; persistencia e historial autorizado; confirmación firmada e idempotencia; adaptadores web/API/POST antiguo. Una sola función de envío conserva descargas.

- [x] Regla inválida, timeout y destino no autorizado: cero llamadas externas posteriores.
- [x] Bloqueados, pendientes, fallidos y legacy excluidos del contexto.
- [x] Confirmación ligada a usuario, empresa, texto, archivo, contexto y política.
- [x] Conflicto de idempotencia y carrera concurrente sin duplicar llamadas.
- [x] Migración conservadora y CRUD sin control de autorizaciones desde clientes.
- [x] Tres entradas HTTP comprobadas y error básico visible en navegador; ensayo visual completo en tarea 07.

Fronteras de prueba autorizadas: HTTP, frontera de proveedor, migración y transiciones persistidas. SDKs/HTTP simulados, SQLite local.

Verificación observada: `front.test_chat_flow`, `front.test_state`, `front.test_access`, `front.test_review` y `front.test_pipeline` en la suite local. La combinación `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_policy_simulator front.test_pipeline front.test_chat_flow --settings=regulai.test_settings` pasó 40 pruebas. No sumar ejecuciones parciales como tests distintos; [registro consolidado](../estado-ejecucion.md).

Decisiones: un solo servicio para tres adaptadores; confirmación firmada y transición condicional, red fuera de transacciones largas, sin reintento automático de resultado incierto. Mensajes legacy conservados, visibles al propietario pero no autorizados como historial. Configuración/estados en `2a5bd40`; integración/runtime en `bbb86a5`. [Verificación final](../estado-ejecucion.md).

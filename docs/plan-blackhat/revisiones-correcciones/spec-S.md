# Spec S — 9549e74 frente a 4400f0b

## Requisitos ausentes/parciales

- **P2 — Rotación sin procedimiento operativo.** Encargo: «Un procedimiento documentado de rotación: `SECRET_KEY_FALLBACKS`, y `MultiFernet` con un comando de recifrado.» Existen funcionalidades y comentarios en `regulai/regulai/local_settings_template.py:28–31,40–43`, pero ninguna guía explica configurar clave nueva/antigua, ejecutar dry-run/recifrado, conservar copias o retirar fallbacks. `docs/plan-blackhat/tareas/14-seguridad-backend.md:18` solo describe tests; `estado-ejecucion.md:23` reconoce documentación final pendiente. Repro público: `rtk proxy rg -n 'SECRET_KEY_FALLBACKS|reencrypt_secrets|ENCRYPTION_KEY_FALLBACKS|MultiFernet|rotación' docs README.md` solo devuelve las referencias de tarea/propiedad. Falta entregable, no se demuestra fallo del comando.

## Ampliaciones

No identifico ampliaciones injustificadas en S. Proteger otros estados de reglas/alertas/motores es coherente con POST/CSRF.

## Implementación incorrecta

- **P1 — Persiste un GET capaz de desactivar enmascarado.** Encargo: «Esperado: solo POST con CSRF». `regulai/front/views.py:2958–2965` deja `obfuscation_toggle` sin restricción de método y cambia `active` incondicionalmente; `templates/obfuscation/list.html:113–116` lo invoca mediante enlace GET. Con personal de seguridad autenticado y configuración activa, navegar al enlace puede desactivar el control; una navegación inducida no requiere token CSRF. Es un camino preexistente que quedó fuera del endurecimiento de mutadores.

  Repro público externo: `rtk proxy C:\Users\javi\Documents\Codex\regulai-platform\.venv\Scripts\python.exe C:\Users\javi\Documents\Codex\regulai-wt\S-review-probe.py`. Usa `regulai.test_settings`, SQLite de test y `Client(enforce_csrf_checks=True)`: `GET /obfuscation/1/toggle/`, HTTP302, `active=True→False`; la expectativa405 produce exactamente un AssertionError. Evidencia: `S-review-probe.log`.

Alcance: permisos/aislamiento B2, mutadores web y callers, sync de operador, YARA, avatar API, hashes/fallbacks, recifrado y bootstrap. Las 15 pruebas `front.test_backend_hardening` pasan; no reproduje otros defectos. Checkout limpio e intacto; sin datos del usuario, red real ni secretos. PostgreSQL/producción fuera de la verificación.

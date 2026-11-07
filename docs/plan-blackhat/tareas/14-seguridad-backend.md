# 14: Aislamiento y operaciones protegidas

**Status:** done
**Blocked by:** none

## Entrega y aceptación

B2, POST/CSRF, YARA sin includes, avatar validado y claves conocidas bloqueadas/rotables.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrado hasta `48fdba9`: B2, aislamiento y permisos de alertas; POST/CSRF para modelos, motores, reglas y estados de alerta; sincronización reservada al operador; YARA sin includes; avatar API validado; rechazo de claves públicas conocidas, MultiFernet, comando de recifrado atómico y bootstrap con permisos restrictivos.

ASTRA reprodujo 11 pruebas observables en `4400f0b`: 11 AssertionError y cero errores u omitidas. Suite integrada: 214 tests OK (8 expected failures ajenos) en 32.148 s; check sin incidencias; migraciones sin cambios; 150 controles offline correctos, cero llamadas reales; pip-audit sin vulnerabilidades conocidas. Evidencia local: `regulai-wt/evidence/05-security` y `S-orchestrator-red.log`.

La rotación se probó solo sobre bases de test, incluyendo dry-run, lotes, ciphertext inválido y rollback si una actualización concurrente no afecta la fila prevista. No se recifraron datos existentes. La prueba de concurrencia usa un trigger SQLite; queda pendiente el ensayo PostgreSQL. CI necesita historial Git para comprobar las claves públicas antiguas sin imprimirlas.


## Actualización — 3 de octubre de 2026

Revisión S cerrada técnicamente en `e7311bf`: toggle máscara POST/CSRF (GET405, POST sin token403, POST válido302, empresa ajena404). [Rotación de claves](../rotacion-claves.md) documentada; solo test DB, sin recifrado del usuario. La revisión documental independiente se cerró en [tarea 19](19-revision-final.md).

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

# Spec O — 9549e74 frente a 4400f0b

**(a) Requisitos ausentes/parciales:** no encuentro otros pendientes accionables del carril O en el alcance revisado.

**(b) Trabajo fuera de alcance:** no encuentro ampliaciones injustificadas. La ausencia de calibración pagada no es un defecto: el bootstrap conserva `quality={}` y advierte que falta medirla.

**(c) Implementación incorrecta — [P2] Departamento de otra empresa visible en prompts históricos.** Requisito §2.9: «Aislamiento entre empresas en consultas, relaciones, archivos y plantillas». D5 pide «En Prompt, se rellena la empresa a partir del perfil actual del usuario, marcando la inferencia».

Tras inferir un Prompt antiguo como A mediante `regulai/front/migrations/0031_infer_historical_prompt_company.py:21`, si su propietario pasa a B y recibe un departamento B, un administrador A ve el nombre del departamento B. `regulai/front/views.py:2682` carga el perfil actual; `regulai/front/templates/prompts/list.html:252–253` lo imprime sin comprobar empresa. Antes de D5, estos prompts NULL no entraban en el listado A.

La misma clase aparece en el listado de alertas asociadas (`templates/alerts/list.html:336–338`, exposición preexistente). Los filtros de ambos listados (`views.py:2705,2371`) también confirman pertenencia privada: `?department=<B>` devuelve 1 fila, otro departamento B devuelve 0. Ocultar solo el nombre no elimina la fuga. Restringir renderizado y relación filtrada a A, manteniendo sus registros históricos.

Repro aislada: `O-review-probe.py`, `test_inferred_prompt_must_not_show_department_from_new_tenant`: Prompt `company=A, historical_company_id=A`; trasladar Profile a B; GET `/prompts/` y `/alerts/` como admin A devuelve 200 y el nombre B. Ejecutar `rtk proxy C:\Users\javi\Documents\Codex\regulai-platform\.venv\Scripts\python.exe C:\Users\javi\Documents\Codex\regulai-wt\O-review-probe.py`: **3 pruebas, 1 fallo por fuga**, 2 controles pasan. Evidencia: `O-review-results.txt`.

Verificación: **31 tests OK** de onboarding/migraciones/simulador. Controles: ida/vuelta de 2.005 históricos sin reescribir AuditLog; 65 modelos acotados a 64 sin inventar calidad; token rechazado tras traslado. Detalles Prompt/Response/Alert, Audit y APIs relacionadas no exponen el departamento. SQLite en memoria y red simulada; sin bases de usuario ni APIs pagadas. PostgreSQL y concurrencia real no verificados. Checkout intacto.

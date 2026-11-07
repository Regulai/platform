# Standards — 4400f0b…9549e74

Refs verificadas: baseline `4400f0bb24defef5d3b8f0d10c391565511f52a2`, HEAD `9549e74a97c114f7427c14eda0d883516be4b627`; diff no vacío. Revisión independiente de fuentes técnicas P/D/V/C/S/F/O/Q, contratos, callers y pruebas relevantes; omitidos bytes vendor y controles impuestos por tooling. Checkout preservado limpio.

**Infracción documentada, P2:** `regulai/front/chat_ui.py:25–34`, hunk de `RECEIPT_KEYS`/filtrado recursivo. Falta permitir `history_max_bytes` y `history_max_turns`, incorporados en `chat_service.py:308` y consumidos por `templates/chat/chat.html`. Incumple `docs/plan-blackhat/correcciones-community.md`, contrato «Recibo»: los límites «pasan la lista permitida de front/chat_ui.py»; también la definición de terminado del README exige conservar contratos. Trigger: envío completado con `history={max_turns:3,max_bytes:1234}` y descarga posterior del recibo. La respuesta de envío contiene ambos valores; GET `chat_request_receipt` los elimina. La recarga pierde los límites configurados y la exportación contradice el recibo inicial. Mejora mínima: añadir ambas claves y verificar exportación/recarga por HTTP.

**Evidencia:** probe externo `standards_probe.py`, un test HTTP con `regulai.test_settings`, SQLite en memoria y proveedor/requests simulados. Resultado real: `AssertionError: None != 3`; la impresión del recibo exportado omite además `history_max_bytes:1234`. No hubo red real ni acceso a bases existentes.

**Remediación posterior:** inspeccionado `git diff 9549e74..f778336`: añade exactamente ambas claves al allowlist. Ese cambio elimina la causa observada; este informe mantiene el hallazgo sobre el SHA revisado. No ejecuté mi probe sobre f778336 porque el checkout permanece inmutable.

**Olores (juicio):** no identifiqué otro olor de la baseline que justifique una refactorización en este parche. La función extensa del pipeline conserva la propiedad única de autorización/estado/efectos exigida por el repo; no propongo separar esa responsabilidad sin un defecto concreto.

**Límites:** no ejecuté la suite completa, CI remoto, PostgreSQL, Gunicorn ni ensayos con archivos guardados desde Office real. La lectura y el probe no acreditan una aprobación global de esos entornos.

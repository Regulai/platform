# Spec F — 9549e74 contra 4400f0b

## Implementación incorrecta

- **[P2] La ficha guardada pierde los límites del historial.** Encargo: «Ventana de historial (D7): se aplica y se declara en la ficha»; contrato: «limits (Jev/entrada/salida/historial/plazos), pasan la lista permitida de front/chat_ui.py». En `regulai/front/chat_ui.py:26–29` faltan `history_max_bytes` y `history_max_turns`; `:34` los elimina. Repro público: enviar a `/chat/send/` o `/api/chat/send/` y consultar `/chat/requests/<request_id>/receipt/`: el envío contiene 32768/20, el GET no contiene ninguno. Node ejecutando el JavaScript obtenido de GET `/chat/` confirma que `renderReceipt` no muestra «History limit» con ese GET. Al recargar/reabrir o exportar se pierde información que el envío mostró. Probe: `review_f_probe.ReceiptProbe.test_http_saved_receipt_loses_history_limits`.

## Requisito parcial

- **[P2] El destino del escalado no se identifica en el panel.** Encargo: «Se puede ampliar por configuración y el destino real se muestra en la interfaz», y F2: «el destino real del escalado». `regulai/front/templates/chat/chat.html:787–804` muestra solo modelos; ignora `route.company_engine_id` y `calls.provider`. Repro: manual con dos motores autorizados, `allow_cross_engine_fallback=True`, juez sintético con `failure_contradiction=1`; POST `/api/chat/send/` hace dos generaciones y devuelve `route.company_engine_id=2`, `calls.provider=engine:2`. Node con la respuesta HTTP confirma «Effective route» pero ninguna identificación de motor/destino. Los modelos compatibles pueden compartir nombre y el usuario no puede distinguir dónde salió la petición. Probe: `review_f_probe.DestinationProbe.test_http_fallback_actual_destination_not_rendered`.

## Fuera de alcance

No detectado.

Verificación: 15 pruebas frontend/resources existentes OK; cuatro dirigidas (B10 UUID HTTP, B9 renovación, B5 advisory legible, consentimiento por imágenes) OK; dos probes externos HTTP+Node confirman los defectos. Git limpio. Recursos/hashes comprobados offline; sin descargas ni proveedores/Jev reales. SQLite aislada con `regulai.test_settings`. No navegador real: DOM sintético Node; no ensayos humanos, documentos Office reales ni CI/PostgreSQL. Sin fixes ni cambios al checkout. Probe externo: `C:/Users/javi/Documents/Codex/regulai-wt/review_f_probe.py`.

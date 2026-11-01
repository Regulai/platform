# 04: Ficha, evidencias y confirmación desde el chat

**Status:** verification
**Blocked by:** apertura de citas con teclado (herramienta de navegador rechazó la URL local)
**Specification:** [02](../02-historial-y-confirmaciones.md), [08](../08-ficha-de-decision.md), [09](../09-citas-verificables.md).

- [x] Reutilizar request_id, texto y File original al confirmar/cancelar/repetir, sin mensaje duplicado.
- [x] Parsear JSON de errores 403/503 y mostrar ficha segura; mantener descargas.
- [x] Exportaciones de recibo/evidencia restringidas a propietario y empresa actual; sin tokens/texto privado.
- [x] Contrato y evidencia de línea 2 abiertos en navegador offline, dos generaciones/cinco llamadas simuladas, persistencia al recargar y bloqueo con cero llamadas.
- [x] Tres escenas, cancelación y confirmación multipart comprobadas en navegador; Enter envía y abre la ficha, Espacio alterna la ruta automática.
- [ ] Abrir las citas con teclado: la herramienta rechazó reabrir la URL local; no se certifica este control.

Verificación inicial: `front.test_chat_ui` pasó cuatro pruebas; documentos/UI/simulador pasó 27. Suite final `front api`: 129 correctas. En navegador normal se comprobó 503 por política ausente, ficha y cero llamadas. La validación de citas se probó con fixtures y el contrato real del parser Jev, sin calidad real del juez. En demo la advertencia de consentimiento tuvo cero llamadas antes de confirmar; cancelar terminó en `cancelled` sin respuesta. Confirmar conservó el archivo, una burbuja de usuario y una respuesta de 10 euros con evidencia de línea 2. [Estado y capturas](../estado-ejecucion.md).

No hay enlaces raw media ni ejecución de HTML de respuestas; detalles nativos y texto escapado. La comprobación pendiente no se sustituye por una inspección de HTML.

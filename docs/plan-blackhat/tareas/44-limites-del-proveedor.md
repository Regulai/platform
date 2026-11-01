# 44. Retirar los topes locales de generación solicitados por el usuario

Estado: implementado, activado en la cuenta local y validado, 5 de octubre de 2026.
Blocked by: ninguno.

## Alcance autorizado

El usuario pidió retirar los límites de tokens, tiempo y tamaño de respuesta de la
tarea 43 y dejar que los gestione el proveedor. Se aplica a la empresa 3 mediante
`limits.provider_managed=true`; otras cuentas conservan su configuración anterior.

## Comportamiento

- OpenAI compatible, incluido DeepSeek: se omiten `max_tokens` y
  `max_completion_tokens`; `timeout=None` elimina el plazo HTTP del cliente.
- No se aplica el plazo total local de generación ni el límite de bytes de la
  respuesta final. No se recorta ni resume el contenido para hacerlo pasar por Jev.
- Las peticiones de evaluación tampoco se rechazan por las cotas locales de
  96/192 KiB ni por el plazo HTTP del cliente; el proveedor decide si las admite.
- Los recibos identifican el modo y registran como nulos los topes desactivados.
  El chat muestra «Límites del proveedor».
- La reserva de coste de generación queda desconocida; se siguen registrando
  consumo y coste efectivo/estimado cuando el proveedor los devuelve. Una política
  con presupuesto local y generación sin cota es inválida, evitando prometer un
  límite monetario imposible de garantizar. Esta cuenta ya tenía presupuesto nulo.
- La autorización de destinos, YARA, privacidad local, historial autorizado,
  validación de respuestas y Jev obligatorio siguen funcionando. Los límites
  internos de los analizadores de seguridad y del JSON de resultados de Jev no
  son los topes de generación retirados y permanecen activos.
- El modo se admite en conectores OpenAI, OpenAI compatible y Vercel gateway.
  El conector Anthropic nativo exige un máximo explícito y no se selecciona en este
  modo. La cuenta afectada solo utiliza DeepSeek y Jev mediante Vercel.

## Activación

Revisión de política 5. Se retiraron los antiguos valores de generación de la
configuración almacenada y se activó la delegación al proveedor. Auditoría
`provider_managed_limits`, copia SQLite consistente
`community-local.before-provider-limits-20261005-153600.sqlite3`.
Servidor local reiniciado. No se cambiaron claves ni el enrutamiento Flash/Pro.

## Evidencia

- 46 pruebas focalizadas: OK en 13,431 s. SDK real con HTTP simulado por las tres
  entradas: ausencia de ambos parámetros de tokens, timeouts de transporte nulos,
  10.000 tokens de salida contabilizados y una respuesta de 120.000 bytes enviada
  completa al juez. Reloj simulado avanza 10.000 segundos sin activar plazos locales.
- YARA sigue bloqueando sin llamadas; un fallo semántico sigue impidiendo entregar
  la respuesta. El modo anterior conserva sus límites y validaciones.
- Validación JavaScript del recibo: muestra «Gestionados por el proveedor» y no
  presenta límites nulos como números. Navegador real `/chat/8/`: nuevo distintivo
  visible y selección automática marcada.
- `check`, `makemigrations --check --dry-run` y `git diff --check`: correctos.
- Suite completa `front api`: 486 pruebas en 235,351 s, `OK (expected failures=2)`.
- No se hicieron llamadas de pago nuevas. Los errores o límites que aplique el
  proveedor todavía pueden impedir una respuesta; no se afirma generación infinita.

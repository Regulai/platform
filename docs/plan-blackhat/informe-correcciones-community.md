# Correcciones Community: comportamiento, diseño y evidencia

Revisión documental: 3 de octubre de 2026. Base original `6a0f667`; inicio de correcciones `4400f0b` (mismo código que `4b10778`); código técnico recibido `51f4ee5`. El [informe técnico](informe-tecnico-cambios.md) describe la evolución original. Esta actualización documenta las correcciones integradas, sin nuevas llamadas a proveedores/Jev, cambios en bases del usuario, push ni despliegue.

Los commits y resultados B1–B10/C1–C2 de este informe se conservan como históricos. La integración posterior a `6c78cd3`, incluyendo obligación D2 y preparación operativa, está en el [informe del piloto](informe-piloto-community-20261003.md).

## Problemas conocidos y corregidos

Las doce regresiones de [ReviewRegressionTests](../../regulai/front/test_review_regressions.py) se ejecutaron contra `4400f0b`: doce `AssertionError`, cero errores de preparación y cero omisiones. Tras la integración pasan como pruebas normales, sin `expectedFailure`. La columna prueba da el sufijo exacto de los métodos `test_` de esa clase; los resultados de suite se registran en el [estado observado](estado-ejecucion.md).

| Fallo | Estado | Comportamiento y prueba | Commit integrado |
| --- | --- | --- | --- |
| B1: historial y Jev en claro | Hecho | Con enmascarado activo, todo segmento autorizado sale enmascarado a los demás destinos; `b01_every_turn_and_jev_receive_masked_content` | `e49cc6e`, integración `eb8fde7` |
| B2: alertas de otra empresa | Hecho | Notificaciones por empresa y rol autorizado; `b02_alert_notifications_are_isolated_by_company` | `cd75ed3` |
| B3: máscara sin precio bajo presupuesto | Hecho | Con máscara activa y presupuesto, cota ausente rechaza antes de cualquier salida; `b03_missing_mask_cost_bound_is_rejected_before_any_external_call` | `5a14086`, `f80a14a`, `e49cc6e` |
| B4: citas de fuentes enmascaradas | Hecho | Resolución sobre los fragmentos enviados; `b04_document_citations_resolve_the_masked_source` | `e49cc6e`, `e657410` |
| B5: JSON visible en advisory | Hecho | Prosa legible, etiqueta No verificado, evidencia vacía e historial no elegible; `b05_advisory_document_answer_is_readable_prose` | `e49cc6e`, `638ed0f` |
| B6: tamaño de juez rechazado tras generar | Hecho | Cota del peor estado antes de generar, sin recorte; `b06_oversized_judge_state_is_rejected_before_generation` | `e657410` |
| B7: texto borrado de Word mezclado con el aceptado | Hecho | Vista de cambios aceptados y aviso; `b07_word_tracked_changes_use_the_accepted_text` | `0f4815a`, `9f58dbf` |
| B8: fence JSON único rechazado | Hecho | Acepta exactamente una envoltura JSON, manteniendo parser estricto; `b08_one_json_code_fence_is_accepted_as_a_document_answer` | `ea9798e` |
| B9: consentimiento caducado sin renovación | Hecho | Prueba nueva, misma petición y razón; firma falsa no renueva; `b09_expired_consent_issues_a_fresh_usable_token` | `35f8ff0` |
| B10: envío HTTP sin randomUUID | Hecho | UUID v4 con getRandomValues; JavaScript servido por Django ejecutado en Node; `b10_chat_can_submit_without_crypto_random_uuid` | `ebd864e` |
| C1: categoría ambigua detenida | Hecho | Distribución conservada completa como confidential y declara aviso; `c01_uncertain_ordinal_category_completes_as_confidential` | `5a14086`, `35f8ff0` |
| C2: credentials 0,75 ignorado | Hecho | Señal desde 0,2 restringe y bloquea; `c02_credentials_signal_below_point_eight_still_blocks_generation` | `5a14086`, `35f8ff0` |

## Mejoras de diseño y revisión adversarial

Cada módulo concentra comportamiento detrás de una interfaz concreta. La política local determina destinos; clasificación solo restringe; extracción declara cobertura; verificación resuelve evidencia; el servicio de envío coordina las tres entradas HTTP y registra la intención antes del efecto externo. No se añadieron colas, microservicios ni otro framework de proveedores.

| Carril | Estado | Cambio y evidencia observable | Commits integrados |
| --- | --- | --- | --- |
| P: privacidad, estado y dinero | Hecho | Lote estructurado con máscaras activas, pares completos de historial, presupuesto previo, cancelación sin crear mensajes, reintento con respuesta/control concreto, motor manual acotado y timeout; `front.test_pipeline_privacy` cruza las tres entradas y transportes sintéticos | `e49cc6e`, `35f8ff0`, `e657410`, `7e21faf`, `2b363e5`, `7f60127`, `eb8fde7` |
| D: documentos | Hecho; validación Office real pendiente | Cuatro estados, disclosures, CSV/codificaciones, fórmulas con caché y expresión YARA, decimal multinivel, formatos numéricos legibles y bloques; `front.test_documents` y `front.test_document_fidelity` | `c14e5fa`–`b61d11d`, `9f58dbf` |
| V: fuentes y conectores | Hecho; calidad real pendiente | Alias S1, hasta 30 afirmaciones, extractos desde 1, mínimo de cita, JSON por capacidad y reasoning explícito; `front.test_verification`, `front.test_connectors` y `front.test_jev` | `ea9798e`, `f848a7c`, `dd85236`, `20cc061`, `e997230`, `e042461` |
| C: clasificación y simulador | Hecho; calibración pendiente | Ordinal, unknown configurable, coherencia, señales desde 0,2, avisos, calidad de tareas plausibles y simulador compartido; `front.test_classification` | `5a14086`, `12d80fe`, `35f8ff0` |
| S: aislamiento y claves | Hecho; operación real no ejecutada | POST/CSRF, YARA sin includes, avatar validado, front.E001, MultiFernet y recifrado atómico; `front.test_backend_hardening` | `cd75ed3`, `bba72ab`, `48fdba9`, `e7311bf` |
| F: interfaz y recursos | Hecho | Avisos, renovación, No verificado, destino real, límites persistidos, recursos locales y hashes; `front.test_frontend_chat`, `front.test_frontend_resources` y [navegador offline](../../evals/reports/ui-community-fixes-20261003/README.md) | `ebd864e`, `1e7884a`, `638ed0f`, `c1e72d1`, `a76b8c5`, `679c1a6`, `f778336`, `c373c87` |
| O: arranque y datos | Hecho; migración de usuario no ejecutada | Admin de empresa, registro cerrado, borrador sin activación, tres migraciones reversibles; `front.test_onboarding`, `front.test_state`, `front.test_history_departments` | `33a264c`, `59c820b`, `b95f349`, `f677d54`, `72c7659`, `515f714`, `4f615ee`, `2cea782`, `51f4ee5` |
| Q: operación y CI | Hecho local; CI remoto/PostgreSQL pendientes | Logs con lista permitida, Gunicorn gthread, cinco gates declarados y CLI que falla tras guardar informes; `front.test_operations` y `test_cli_failed_controls_exit_nonzero_after_writing_all_reports` | `b0212d0`, `c230715`, `2ffb355`, `21c291e` |
| R: documentación | Hecho | Unidades USD/millón, límites, arranque, recuperación de claves y condición de enmascarado activo; revisión Spec sin hallazgos y Standards corregida/verificada | `cacae92`, `f65da23`, `52bdc8d`; [seguimiento de evidencia y revisión](tareas/19-revision-final.md) |

Los [nueve informes independientes](revisiones-correcciones/README.md) se preservan íntegros con su manifiesto original sobre `9549e74`. **Standards** revisó el conjunto técnico; **Spec** tuvo un revisor distinto por carril. Sus hallazgos se reprodujeron antes de corregirlos:

| Eje | Hallazgo posterior | Resolución |
| --- | --- | --- |
| Standards y Spec F | Exportación/recarga perdían límites del historial | `f778336`; regresiones HTTP/export y carga, aserciones sobre campo ausente ajustadas en `865e8cb` |
| Spec P | Reclasificación podía generar sin juez o máscara obligatorios; máscara cambiada y suelo unknown discordante | `a02f483`, `f8b5ba3`, `95dfb77`; cuatro regresiones, diez aserciones rojas, cero errores en revisión anterior, después verdes |
| Spec D | Imágenes PDF inline sin aviso; filas Word borradas; CSV irregular; reinicio decimal | `f92d5a1`, `520fa3a`, `5701a10`, `4cd129f`, prueba HTTP `90000c6`; doce regresiones, veintidós aserciones rojas, cero errores, después verdes |
| Spec C | Una única tarea plausible perdía calidad mínima; avisos sin instrucción al generador | `d4e1313`, `9840bd6`; tres probes independientes rojos, después verdes |
| Spec S | Toggle de máscara mutaba por GET | `e7311bf`; GET405, POST sin CSRF403, POST válido302, empresa ajena404 |
| Spec F | Ficha podía mostrar nombre de modelo sin el motor real | `c373c87`; envío por tres entradas, exportación y restauración con dos motores del mismo nombre; comprobación visual adicional |
| Spec O | Departamento actual de otra empresa visible/filtrable en histórico Prompt/Alert | `51f4ee5`; cinco pruebas de ambos listados, relaciones inconsistentes y departamento legítimo conservado |
| Spec Q | CLI terminaba exit0 aun con controles fallidos | `21c291e`; copia development: 90 ejecuciones, 52 fallos, cero reserved, exit1 y cinco informes conservados; banco normal: 150, cero fallos, exit0 |
| Spec V y S, documental | Precio por token ambiguo y receta de rotación ausente | [Snapshot Jev corregido](jev-gateway.md) y [procedimiento de rotación](rotacion-claves.md); revisión R cerrada |
| Standards R | Resumen prometía enmascarado automático sin servicio activo | Reproducido mediante HTTP aislado; `52bdc8d` explicita condición y arranque, con [verificación independiente](revisiones-correcciones/standards-R-followup.md). D2 aprobada permanece intacta |

## Verificación final conservada

Tras integrar la documentación y su corrección, las cinco puertas se repitieron sobre `52bdc8d`: **302 tests OK en 62,428 s**, check sin incidencias, migraciones sin cambios, 150 ejecuciones offline/0 fallos/0 llamadas reales y pip-audit sin vulnerabilidades conocidas. [Registro posterior a la documentación](../../evals/reports/community-fixes-docs-verification-20261003/README.md). Los resultados técnicos previos siguientes se conservan sin sobrescribirlos.

La ejecución final de ASTRA sobre `12ca58d3a2b5a6570840ca80676a1799f6eac097` (mismo comportamiento técnico que `51f4ee5`, solo ajuste de EOF) pasó las cinco puertas con exit0: **302 tests en 66,767 s**, check sin incidencias, migraciones sin cambios, 150 simulaciones/0 controles fallidos/0 llamadas reales y pip-audit sin vulnerabilidades conocidas. [Registro de cinco gates y logs](../../evals/reports/community-fixes-verification-20261003/README.md), [JSON exacto](../../evals/reports/community-fixes-verification-20261003/gates.json), [22 etapas históricas](../../evals/reports/community-fixes-verification-20261003/integration-gates.json), [regresiones y rojo base](../../evals/reports/community-fixes-verification-20261003/regressions.json) y [banco final/manifiesto](../../evals/reports/offline-community-fixes-final-20261003/report.md).

Solo tres etiquetas development cambiaron por D3 con [justificación por caso](cambios-banco-correcciones.md); no se tocó reserved ni umbrales para aprobar. La prueba negativa de la suite fuerza seis controles fallidos y la prueba CLI 52, por diseño; ninguna representa un fallo del banco final.

## Cobertura y límites efectivos

Fuentes: [documents.py](../../regulai/front/documents.py), [file_security.py](../../regulai/front/file_security.py), [policy.py](../../regulai/front/policy.py), [jev.py](../../regulai/front/jev.py), [verification.py](../../regulai/front/verification.py) y [chat_service.py](../../regulai/front/chat_service.py). El upload limit es solo un primer control; contexto del candidato, serialización, máscara, presupuesto y juez pueden rechazar un documento menor. No se promete aceptación de todos los archivos bajo ese límite.

| Límite | Valor efectivo |
| --- | --- |
| Entrada de texto/CSV | 1 MiB; texto UTF-8, UTF-16 con BOM o Windows-1252 declarado tras fallar UTF-8, sin bytes indefinidos |
| Entrada PDF/DOCX/XLSX | 10 MiB; trabajador también lee como máximo 10 MiB + un byte para detectar exceso |
| Django DATA_UPLOAD_MAX_MEMORY_SIZE / FILE_UPLOAD_MAX_MEMORY_SIZE | 10 MiB cada uno; el segundo controla el umbral en memoria, no la aceptación documental |
| Texto / unidades / páginas PDF | 200.000 caracteres / 10.000 unidades / 100 páginas |
| Fragmentos texto | Bloques de hasta 40 líneas; CSV por filas y Office por localizadores; extractor versión 2 |
| ZIP expandido / entradas / ratio | 32 MiB / 2.000 / 100 |
| PDF Flate | 32 MiB acumulados; LZW no admitido |
| XLSX | 100 hojas, 256 columnas, 100.000 celdas/cadenas |
| XML | 100.000 elementos; profundidad 128 |
| Parser CSV/PDF/Office | Subproceso: 5 s por defecto, DOCUMENT_PARSER_TIMEOUT configurable |
| Jev estado / envoltura completa | 98.304 bytes UTF-8 / 196.608 bytes; máximo 32 preguntas y respuesta HTTP 65.536 bytes por defecto |
| Afirmaciones / citas | Hasta 30 afirmaciones; cada una 1–8 citas; quote máximo 1.600 caracteres; al menos 12 caracteres sin espacios O tres palabras, siempre más de un carácter no espacio |
| Generación | Máximo dos; routing.max_output_tokens por defecto 1.000, máximo configurable 32.000; capacidades del candidato pueden limitar más |
| Respuesta aceptada localmente | min(128000, max_output_tokens × 8) bytes UTF-8; **no es una equivalencia formal token-byte** |
| Historial | Por defecto 20 turnos y 32.768 bytes UTF-8, configurables hasta 1.000 y 1.048.576; pares elegibles completos más recientes, omisiones declaradas |
| Plazos | Llamada 30 s y petición 90 s por defecto; deadline máximo 180 s; call timeout ≤ deadline; SDK max_retries=0 |
| Jev timeout | min(120, call timeout, tiempo restante); conexión min(s/2, max(3, s−60)) y lectura s−conexión, ambas ≤60 s |
| Incertidumbre / servidor | Petición processing/received abandonada: 240 s; Gunicorn timeout y graceful_timeout 240 s, gthread; configuración probada, no arrancado en Windows |

`complete` significa extracción textual admitida; `complete_text_only` declara imágenes/adjuntos/visual omitidos en `disclosures` (`code`, `count`, `locators`) y exige consentimiento. `partial` y `unreadable` detienen el envío. Página PDF en blanco es aviso; escaneada sin texto es partial. Hipervínculos no reducen cobertura. XLSX conserva expresión para YARA y envía caché; falta de caché o recálculo pendiente impide declararlo completo. Word toma cambios aceptados, excluye filas/celdas borradas y declara formatos no soportados. No hay OCR, análisis visual ni ejecución de fórmulas.

Jev/juez reciben contexto y fuentes completos, sin muestreo. Antes de generar se calcula estado serializado + seis veces los bytes de salida aceptada + hasta 30×8 localizadores/citas + estructura + preguntas/envelope. Puede devolver `evaluation_input_too_large` antes de generar. El juez documental recibe pares afirmación/extracto resueltos con índice desde 1, sin duplicar la respuesta bruta. Los alias S1…Sn salen al proveedor; el SHA estable permanece en servidor. `finish_reason=None` falla completitud salvo evidencia explícita reconocida.

## Enmascarado y presupuesto

**Cambio posterior de compatibilidad:** la entrega comparada `5a8579c` permitía contenido autorizado sin transformar cuando faltaban máscaras. La [tarea21](tareas/21-privacidad-obligatoria.md) cierra esa diferencia: la máscara propia, activa, autorizada y `detect=both` es obligatoria en servidor para chat y simulador semántico. Sin ella o si cambia/falla, no continúa la salida. Ese cierre inicial no requería migración; la [ampliación local posterior](enmascarado-local.md) añade0032 y conserva los registros existentes como HTTP. Las políticas antiguas deben completar [la configuración](arranque-y-demo.md#activar-el-enmascarado-de-la-empresa). Se conserva la evidencia histórica, sin atribuirla al comportamiento actual.

YARA examina primero el original, incluidas fórmulas. Decisión y consentimiento preceden al enmascarado obligatorio. El backend local procesa el lote dentro de Django sin HTTP; la integración HTTP recibe un array JSON serializado **dentro de su campo `text: str`** y debe devolver `masked` como string de un array JSON de strings de igual longitud y orden. Ambos conservan estructura y coherencia del lote; un resultado incompatible falla cerrado.

Con máscaras activas, el lote cubre petición, sistemas de empresa/departamento, historial elegido, fragmentos y localizadores. Jev y el generador reciben esas versiones; la respuesta también se enmascara antes del juez y del historial. Las citas se validan contra lo realmente enviado **antes de enmascarar la respuesta**, y se comprueban de nuevo después: así una cita inventada no se convierte en un placeholder que la haga parecer literal.

Con enmascarado activo y presupuesto configurado, `masking.max_call_cost` debe ser explícito, incluso `"0"` para servicio propio. Falta de cota impide cualquier llamada y simulación semántica. Un máximo positivo es reserva, no precio real inventado. Todos los importes usan Decimal; precios JSON/modelo son USD por millón de tokens. Capacidad, calidad, cuotas o precio desconocidos no equivalen a cero. Las cuotas económicas generales por organización no están implementadas; el ledger histórico de smoke es específico de esos ensayos. La sobrecarga interna no publicada del proveedor permanece como hipótesis del estimador; se cuenta el envelope público Anthropic.

## Arranque, recursos y pendientes reales

**Cambio incompatible:** `ai_config={}` devuelve 503 y cero llamadas; tener credenciales no activa una política. Multiempresa sigue disponible, `ALLOW_REGISTRATION=False` y un administrador de empresa gestiona su ámbito sin staff/superuser globales. [Arranque y demo](arranque-y-demo.md) explica generar borrador, completar catálogo, comparar localmente y activar en otro POST auditado. `bootstrap_ai_policy --company ID --dry-run` siempre imprime un borrador; omitir la bandera tampoco activa. Su suelo local es internal; unknown se trata como confidential, restricted bloquea incluso destinos privados y Jev no se autoriza implícitamente.

Los siete recursos vendor tienen hashes locales verificados: Chart.js 4.5.1, Iconify sin fetch externo y catálogo de iconos local, fuentes del sistema. Las copias antiguas eran parciales; hoy la prueba cubre todos esos recursos. `.gitattributes` preserva bytes Windows; la prueba clona un fixture con siete assets, no un clon completo del repositorio. CSP es **solo Report-Only**. Pruebas DOM/JavaScript en Node y [capturas de navegador Django offline](../../evals/reports/ui-community-fixes-20261003/README.md) son evidencias distintas; ambas usan proveedores sintéticos.

Pendientes: ejemplos sintéticos guardados con Word/Excel/LibreOffice reales; dos ensayos con otras personas; calidad, sensibilidad, jueces y ahorro calibrados por humanos; E2E con proveedores vivos bajo autorización, presupuesto y tarifas revisadas. La prueba histórica `jev_verification_component` fue generada por un script no versionado: se conserva el resultado, **no es reproducible E2E desde el repositorio**. PostgreSQL no se probó (sin driver/servidor), Actions solo se validó localmente y Gunicorn no se arrancó en Windows. Rotación y migraciones solo se probaron sobre bases aisladas, no sobre datos del usuario. La [tarea 19](tareas/19-revision-final.md) está cerrada; esos pendientes externos conservan su alcance propio.

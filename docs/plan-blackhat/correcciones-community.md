# Correcciones Community — contratos y coordinación

Base: `4400f0b`; integración: `codex/community-fixes`. Fecha: 3 de octubre de 2026. Encargo completo del humano: `C:/Users/javi/.codex/attachments/7cde8800-59d2-4bc6-a0c6-c627cc9a4dc3/Texto pegado.txt` (UTF-8). No push, despliegue, publicación ni llamadas pagadas. Los archivos ajenos `MESAS_RETIRO.pdf` y `docs/brainstorming-regulae-vigia13-2026-10-02.md` se preservan sin añadirlos.

## Decisiones aprobadas

El humano confirmó conjuntamente D1–D7: multiempresa con registro público desactivado y política por administrador de empresa; enmascarado de toda salida salvo al enmascarador; unknown como confidential y ambigüedad como aviso; restricted bloqueado también en destinos privados; Prompt histórico inferido desde el perfil con marca reversible y AuditLog histórico visible sin modificar contenido; complete_text_only y consentimiento por contenido visual omitido; últimos N turnos dentro de un límite de bytes. Son decisiones aprobadas, no provisionales. Faltan ejemplos sintéticos guardados desde Word, Excel y LibreOffice reales.

## Condición operativa de D2 en la implementación actual

La decisión humana D2 anterior se conserva. Para obtener esa protección debe haber servicios de enmascarado configurados y activos (ObfuscationConfig de la propia empresa), con destino autorizado y coste acotado cuando exista presupuesto. El código solo transforma cuando hay máscaras activas; sin ellas, una política válida puede permitir enviar contenido autorizado sin transformar. La ausencia de máscara no es un bloqueo global automático. [Configuración y activación](arranque-y-demo.md#activar-el-enmascarado-de-la-empresa).

## Contratos

- Documentos: `Document.status` = `complete | complete_text_only | partial | unreadable`. `disclosures: list[{code: str, count: int, locators: list[str]}]`. `metadata()` los incluye. `text` conserva todo texto necesario para YARA (incluidas fórmulas); `fragments` representa el texto que se enviará. Los IDs SHA-256 permanecen estables al enmascarar. D sube EXTRACTOR_VERSION y agrupa bloques sin perder localizadores.
- Fuentes: módulo `front/sources.py`; `build_sources(fragments) -> SourcesView(prompt_json: str, alias_to_id: dict[str,str])`. JSON conserva lista de `{id: 'S1', locator, text}` para compatibilidad de consumidores. Solo el servidor conoce el SHA-256. Se construye sobre fragmentos realmente enviados, enmascarados cuando hay servicios activos.
- Verificación: `verify_response(content, finish_reason, *, fragments=None, require_semantic=True, alias_to_id=None, min_quote_chars=12, min_quote_words=3)` mantiene claves actuales. Evidencia añade `claim_index` desde 1, `alias`, `fragment_id`, `id` compatible, `locator`, `excerpt`. El servidor resuelve citas. Máximo 30 afirmaciones para 32 preguntas. Admite solo un bloque JSON envolvente. `finish_reason=None` permanece no verificado/fallo de completitud salvo evidencia explícita del proveedor.
- Juez: V añade `verification_questions(task, claims)` en `jev.py`, índices desde 1; P envía petición y pares afirmación/extracto resueltos, y contexto/fuentes necesarios para detectar omisiones. Documentar cualquier reducción. Tamaño del peor estado más salida se comprueba antes de generar.
- Clasificación: `front/classification.py`; `decide(answers, cfg: AIConfig, local_floor) -> ClassificationDecision(sensitivity, task, difficulty, notices, stop_code, stop_status, plausible_tasks)`. `plausible_tasks` permite exigir la menor calidad del candidato entre tareas plausibles. Duda de tarea=general y dificultad=strong; solo restringe.
- Política (C es dueño del esquema): opcionales estrictos `classification_policy` (unknown_level=confidential, signal_threshold=0.2, on_ambiguity=warn); `masking.max_call_cost: str|None`; `history.max_turns=20,max_bytes=32768`; `routing.allow_cross_engine_fallback=False`; `limits.call_timeout_seconds=30` (<=deadline_seconds), `verification.min_quote_chars=12,min_quote_words=3`. Mantener `classification` como literal local|required y compatibilidad de configuración existente. C puede ajustar nombres antes de publicar su contrato final, avisando a P/V/O. El presupuesto con enmascarador activo sin cota se rechaza antes de cualquier llamada y también en simulación.
- Enmascarado (P): `mask_texts(texts, masks, before_call, after_call) -> list[str]` sustituye al helper sin consumidores `obfuscate_text`. Lote JSON para mantener segmentos y sustituciones coherentes. Preflight y registro de intención antes de cada salida. Secuencia: YARA original, decisión, consentimiento, enmascarado si hay servicios activos, clasificación, ruta, generación, juez. Historial conserva versión realmente reenviada y digest correspondiente.
- Conector: kwargs opcionales de capacidades `supports_json`, `reasoning` (campo de modelo `reasoning` si V lo necesita; O dueño de modelos/migración), `temperature=0.1` para documentos si el modelo la admite. V acuerda nombres definitivos con O y P.
- Recibo: P añade `notices`, `history` (turnos/bytes enviados y omitidos), `limits` (Jev/entrada/salida/historial/plazos), `consent_reason`; pasan la lista permitida de `front/chat_ui.py` y la respuesta del servicio. F consume texto/códigos escapados, muestra `no verificado`, destino real y renovación.

## Propiedad y secuencia

### Ampliación compatible del 4 de octubre de 2026

`classification_policy.manipulation_threshold` admite un número finito en `(0, 1]` o `null`. Omitirlo o usar `null` conserva el umbral compartido existente, incluso cuando un administrador había configurado otro `signal_threshold`. Sólo la señal `manipulation` usa el valor explícito; PII, credenciales, confidencialidad, ambigüedad y evidencia insuficiente conservan `signal_threshold`. La comparación sigue siendo inclusiva. El esquema sigue en versión 1; las configuraciones experimentales del ensayo llevan `revision: 2`. No hay migración ni modificación de políticas guardadas. Para revertir la configuración basta omitir el campo y volver a la revisión previa. El valor experimental 0,40 no es un nuevo valor predeterminado ni una recomendación general acreditada.

Cada carril trabaja en un worktree/branch independiente con commits pequeños. Todos leen AGENTS y referencias TDD. Las únicas fronteras de prueba autorizadas son HTTP, proveedor/requests.post, documentos públicos e invariantes de estado, migración y dinero. No se prueban privados.

- REG: exclusivamente `regulai/front/test_review_regressions.py`; B1–B10 y C1–C2 con expectedFailure, verificando AssertionError esperado en base. La propiedad de cada método pasa al carril responsable tras integrar.
- D: documents.py, file_security.py y tests documentales.
- C: classification.py, esquema policy.py, preguntas de clasificación/task de jev.py y `_outcome` de policy_simulator.py; tests propios.
- V: verification.py, connectors.py, sources.py y preguntas de juez de jev.py; tests propios. No migraciones/modelos.
- S: context_processors.py; vistas model_*, rules_* y reglas de views.py; avatar de api/serializers.py; checks.py, registro del check en apps.py, bootstrap_local.py, plantilla de settings; cifrado/rotación con coordinación O; tests propios.
- O: todas las migraciones y cambios de models.py, access.py, registro de views.py, permisos/acción bootstrap de policy_simulator.py, consultas históricas de views.py y api/views.py, comando bootstrap_ai_policy. Migraciones reservadas 0029 precios, 0030 capacidades, 0031 histórico (ajustar solo con ASTRA).
- F: templates/**, static/vendor/**, scripts/vendor_assets.py; tests de recursos/interfaz. CSP en middleware asignado a F; cambios mínimos de settings coordinados con Q.
- Q: LOGGING en settings, gunicorn.conf.py, .github/workflows/** y pruebas operativas.
- P: chat_service.py y helpers obfuscate_text/mask_texts de views.py; tests pipeline. P1 sobre base; P2 tras C,D,V y esquema O si aplica.
- R: docs/** al final. Orquestador: contratos, tareas, evidencia e integración pequeña.

Capacidad del entorno: tres SOL simultáneos más ASTRA. Se escalonan los carriles manteniendo dependencias; no cambia el alcance. Tras cada integración: check, suite front/api, migraciones, evaluación offline en directorio nuevo y pip-audit. Una integración roja se revierte, sin reescribir historial. Los revisores son SOL nuevos; hallazgos se reproducen antes de corregir. El CI remoto no se ejecuta.

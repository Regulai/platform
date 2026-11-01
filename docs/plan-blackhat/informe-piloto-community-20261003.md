# Resultado de la preparación y ensayo Community — 3 de octubre de 2026

**Código local integrado y verificado; ensayo real ejecutado parcialmente y detenido; dos perfiles simulados por petición del usuario.** Candidato final `972edb88c82a5220a43ffcc89316a9f9033e82f7`, rama `codex/community-pilot-20261003`. La ejecución real pertenece al commit `698e8f0`; el corrector posterior conserva mejor el diagnóstico, pero no se ha vuelto a llamar a proveedores.

Base del encargo `6c78cd3`; original `6a0f667`, inicio de correcciones `4400f0b`, entrega comparada `5a8579c`. Las 302 pruebas y 150 ejecuciones conservadas al comienzo son históricas. Las cifras siguientes identifican ejecuciones nuevas, sin sumar suites solapadas.

## Estado de las seis fases

| Fase | Estado | Evidencia y siguiente acción |
| --- | --- | --- |
| 1. Privacidad y configuración | **Completada y verificada en los recorridos probados** | D2 obligatoria, detector local, tres HTTP y simulador; autorización, empresa, historial, consentimiento, dinero y lotes. Dos empresas sintéticas. Detector falible: revisar omisiones/falsos positivos antes de admitir datos reales. |
| 2. Documentos y uso | **Preparada, pendiente de aplicaciones y participación real** | 12 archivos con procedencia/expectativas, extracción, navegador y export comprobados; simulaciones P01/P02 separadas. Faltan guardados desde Word/Excel/LibreOffice reales, ausentes en el inventario, y observación humana. |
| 3. Proveedores reales | **Incompleta: ejecución detenida con evidencia** | Se ejecutaron 8 de 24 combinaciones, 17 llamadas externas. Dos respuestas entregadas; documentos rechazados por el juez y última clasificación incierta. Conservar reserva y contrastar el evento de Vercel antes de proponer continuación. |
| 4. Calibración | **Preparada, pendiente de revisión humana y comparación completa** | Banco de 24 casos, desarrollo/reservado, rúbrica y métricas; 72 controles offline. No se ajustaron etiquetas ni umbrales. Las simulaciones de perfiles no validan referencias humanas ni calidad semántica. |
| 5. Operación y recuperación | **Completada y verificada para el laboratorio local** | PostgreSQL, Linux/Gunicorn/HTTPS loopback, instalación, estados, backup/restauración, recifrado/reversión/conflictos. Otro servidor o CI remoto requieren su propia comprobación; no se publicaron servicios. |
| 6. Piloto controlado | **Preparado; simulación solicitada completada** | Dos perfiles artificiales con guiones y formularios, evidencias e inferencias separadas. El piloto con participantes reales no se ha realizado; no se inventan identidades, tiempos ni opiniones humanas. |

## Ensayo real por Vercel y DeepSeek

El usuario aprobó hasta 1 USD para ocho casos en economy/strong/router y después indicó usar Jev por Vercel. Se ejecutó una vez, entre las 15:42:54 y las 15:43:22 UTC, con fuentes y alcance congelados. El enmascarado fue local. Generación: `api.deepseek.com`, `deepseek-flash`/`deepseek-v4-pro`; clasificación y juez: `ai-gateway.vercel.sh/typesafe/v1/systemone`, `typesafe-ai/jev`, proveedor limitado a `typesafe-ai`. Los alias son móviles, sin garantía de pesos inmutables.

El [informe vivo](../../evals/reports/pilot-real-vercel-20261003-01/README.md) conserva filas, diario, llamadas, respuestas, uso, costes, errores, citas y ficha. Ocho combinaciones corresponden a cinco IDs distintos, no a los ocho casos completos. Se observaron dos respuestas aritméticas `4`, tres bloqueos, dos rechazos documentales y una clasificación incierta. Hubo 17 llamadas externas y 12 transformaciones locales. Vercel completó once evaluaciones; la duodécima quedó incierta. El bloqueo local no hizo llamadas. Router produjo dos generaciones documentales, sin tercer intento.

Las citas documentales pasaron las comprobaciones locales; el juez semántico rechazó las respuestas. Las señales de manipulación también bloquearon dos recorridos. No se declara que esos rechazos sean correctos sin revisión humana. No se forzaron resultados ni se rebajaron umbrales.

| Contabilidad conservada | USD |
| --- | ---: |
| Comunicados por Vercel | 0,000312522 |
| Estimados por tarifa para DeepSeek | 0,00074496 |
| Reserva de la llamada incierta | 0,003 |
| Exposición total conservadora del ledger | 0,013858062 |
| Saldo de admisión dentro del techo de 1 USD | 0,986141938 |

Las estimaciones conservan también sus cotas; la exposición no equivale a la factura ni a sumar solo los costes pequeños. El coste desconocido permanece `null`. Se paró el banco, se conservó el ledger y no hubo reintentos ni más gasto. La cuenta del usuario se consultó con SQLite en solo lectura para obtener el par de credenciales de una empresa; el archivo de base conserva su hash. Las claves solo pasaron al entorno del hijo con base sintética en memoria.

La versión ejecutada perdía el código concreto de la excepción de clasificación y mostraba un texto que podía interpretarse como ausencia de envío. Se reprodujo sin red con timeout, HTTP503 y JSON inválido. El corrector `972edb8` conserva códigos de una lista cerrada en ficha, log y ledger, rechaza códigos libres y describe la incertidumbre correctamente. [Diagnóstico y regresiones](../../evals/reports/pilot-real-diagnosis-20261003-01/README.md). No permite recuperar retroactivamente la causa de la llamada anterior. La siguiente acción es contrastar el evento Gateway de las 15:43:21 UTC y conservar la reserva mientras no exista liquidación fiable.

## Privacidad, compatibilidad y límites

D1–D7 permanecen vigentes. Django sigue siendo la aplicación única. El servidor exige una máscara activa, propia, compatible y autorizada; ausencia, desactivación, cambio concurrente, timeout o lote inválido cierran el flujo. YARA examina el original antes de salir y restricted bloquea también motores privados. Se revalidan empresa, propietario, política, destinos, credenciales y consentimiento antes de transportar. Las pruebas capturan la frontera HTTP/SDK y cubren entrada, instrucciones, historial elegible, fuentes, localizadores y respuesta. Consentimiento y Jev no levantan bloqueos obligatorios; las citas se comprueban antes y después de transformar.

El backend local integra spaCy 3.8.16, `xx_ent_wiki_sm` 3.8.0 fijado por hashes y patrones de PII/secretos. No tiene diccionario reversible ni descarga modelos durante peticiones. El backend HTTP anterior se conserva, sin fallback desde un fallo local. La migración 0032 añade el selector; al revertir desactiva filas locales antes de quitarlo, conservando políticas y AuditLog. Solo se migraron/recifraron bases sintéticas aisladas.

**La detección no es perfecta.** El banco fijo cumple 16/18 expectativas: omite un secreto arbitrario sin etiqueta y un correo «arroba/punto». Hay falsos positivos sobre «Único», `card` y, en el replay del ensayo vivo, palabras comunes como «Cuál», «Cita» y «Contrato». No se alteró el detector para hacer pasar la demo ni se atribuye ese efecto como causa demostrada del fallo remoto. Los números JSON sensibles se transforman preservando el contrato; los números no sensibles conservan precisión. El límite de tiempo CPU es cooperativo. [Alcance, licencias y limitaciones](enmascarado-local.md).

## Verificación y revisiones

| Evidencia nueva | Resultado |
| --- | --- |
| [Cinco puertas finales 05](../../evals/reports/pilot-integrated-gates-20261003-05/README.md) | **387 tests front/api OK en 110,764 s**; check, migraciones, 150 controles offline y auditorías exit 0; fuentes estables. |
| [Operación 10](../../evals/reports/pilot-operations-20261003-summary-local/README.md) | 117 pruebas PostgreSQL, una omisión específica de SQLite; check --deploy, HTTPS/cookies/hosts/privados/estáticos, concurrencia y aislamiento. |
| Recuperación | Doble envío: una generación; desconexión sin duplicación; reinicio real durante llamada conserva incertidumbre. Restauración de 27 tablas, 2 archivos y claves; recifrado, reversión y conflictos PostgreSQL. |
| [Documentos y navegador](../../evals/reports/pilot-documents-20261003-01/README.md) | 12/12 archivos y 65 pruebas; consentimiento/cancelación/renovación, teclado/móvil/citas/ficha/recarga/export. [Seguimiento](../../evals/reports/pilot-ui-followup-20261003-01/README.md) del aviso histórico. |
| [Bancos offline](../../evals/reports/pilot-local-final-20261003-01/README.md) | 24+72 controles; detector real, otras llamadas simuladas. Sus snapshots se conservan, sin reinterpretarlos como ejecución viva. |
| [Corpus exportado](../../evals/reports/pilot-corpus-export-20261003-01/README.md) | 12 documentos y 14 hashes exactos tras reproducir y corregir conversión de bytes. |
| [Dos perfiles simulados](../../evals/reports/pilot-personas-20261003-01/README.md) | Guiones, formularios, inferencias artificiales y comprobaciones técnicas con procedencia explícita; cero participantes humanos. |

Las suites parciales se solapan. Pip-audit no encontró vulnerabilidades conocidas en paquetes auditables; `xx-ent-wiki-sm` no está en PyPI y queda fuera, con identidad y artefacto comprobados aparte. No se ejecutó CI remoto. Los intentos anteriores y sus fallos se conservan; no se sobrescribieron para aparentar éxito.

[Primera tanda independiente](../../evals/reports/pilot-independent-reviews-20261003-01/README.md), [revisión del detector](../../evals/reports/pilot-independent-local-20261003-01/README.md), [Vercel](../../evals/reports/pilot-independent-vercel-20261003-01/README.md) y [corrector diagnóstico](../../evals/reports/pilot-independent-diagnostics-20261003-01/README.md) mantienen commits fijos, pruebas propias, comandos, códigos, logs y hashes. Se reprodujeron y cerraron revocaciones durante reserva, diferencias del manifiesto, números JSON, rollback y export del corpus. Ningún dictamen de código se presenta como garantía de calidad del proveedor.

Todos los subagentes y perfiles se solicitaron como `gpt-6-astra`, esfuerzo `max`, contexto nuevo; la herramienta aceptó esos parámetros. Se respetaron cuatro slots contando root y la propiedad de archivos. No existe herramienta para cambiar o certificar el modelo del orquestador. Commits principales: `d56eca4`, `4538120`, `63db91d`, `aab85a8`, `2c147f4`, `3e4d9d2`, `be29b6f`, `0957df4`, `d63731a`, `698e8f0` y `972edb8`; [checkpoint](piloto-checkpoint.md).

## Pendientes concretos

La [propuesta operativa](piloto-controlado.md) permanece local y sintética. Por petición expresa se sustituyó la disponibilidad de participantes por una simulación de dos perfiles; sus conclusiones no se introducen como etiquetas humanas del banco reservado. No hay validación de ahorro, coste por respuesta correcta ni calidad general. Las métricas vivas conservan n y no acreditan comparabilidad con esta muestra incompleta.

Para completar el recorrido real: reconciliar la llamada incierta, revisar los rechazos y falsos positivos sobre desarrollo, y preparar una continuación con versión/datos/alcance revisados y autorización aplicable. Para cerrar fases documentales/humanas: guardados nativos de Office y observación real cuando se disponga de ellos. No se publicaron servicios, compraron créditos, enviaron invitaciones ni migró/recifró la base del usuario. Los cinco archivos ajenos iniciales siguen fuera de commits. La autorización del 2 de octubre no se reutilizó y no se interpretó silencio como permiso.

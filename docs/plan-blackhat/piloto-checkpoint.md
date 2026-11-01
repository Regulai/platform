# Checkpoint final del piloto Community

Rama `codex/community-pilot-20261003`; candidato `972edb88c82a5220a43ffcc89316a9f9033e82f7`. Base del encargo `6c78cd3`. Las 302 pruebas históricas no se presentan como ejecución nueva.

| Área | Propietario | Estado |
| --- | --- | --- |
| D2, política y estado | A, Astra Max | Integrado, revisado y comprobado en tres HTTP/simulador, dinero, empresa, consentimiento y migraciones. |
| Documentos y UX | B, Astra Max | Corpus de 12 archivos, 65 pruebas, navegador/export; Office nativo pendiente. |
| Evaluación y diagnóstico | C, Astra Max | Ledger/reproducibilidad/Vercel `698e8f0`; diagnóstico seguro `972edb8`. Ensayo vivo incompleto, sin más gasto. |
| Operación/detector/integración | Root | Detector 16/18 con límites; laboratorio PostgreSQL/HTTPS/recuperación y gates 05. |
| Revisiones | Security/Spec/Standards, Astra Max | Informes separados sobre commits fijos; implementadores no cuentan como revisores independientes. |
| Perfiles artificiales | Nuevos P01/P02, Astra Max | Simulación solicitada por el usuario, separada de participación humana real. |

Los agentes usaron `gpt-6-astra`, `max`, contexto nuevo; cuatro slots contando root como máximo. Solo root integra y hace commits. El modelo del orquestador no es cambiable/certificable por las herramientas.

## Estado observado

- [Gates 05](../../evals/reports/pilot-integrated-gates-20261003-05/README.md): 387 tests en 110,764 s, otras puertas con código 0, fuentes intactas, 150 controles offline; no CI remoto.
- [Operación 10](../../evals/reports/pilot-operations-20261003-summary-local/README.md): 117 PostgreSQL/una omisión SQLite, HTTPS, restauración de 27 tablas, 2 archivos y claves, recifrado/reversión y estados inciertos. Recursos retirados.
- [Ensayo real](../../evals/reports/pilot-real-vercel-20261003-01/README.md): usuario autorizó 1 USD/8×3 y ordenó Vercel. Ejecutado una vez en `698e8f0`, 8/24 combinaciones, 17 llamadas externas, 12 transformaciones locales. Dos entregas, tres bloqueos, dos rechazos y una clasificación incierta. Sin reintentos.
- Costes: comunicados 0,000312522 USD; estimados 0,00074496 USD; reserva incierta 0,003 USD; exposición 0,013858062 USD. Ledger persistente intacto. Archivo de base del usuario leído en modo RO, hash sin cambios.
- [Diagnóstico](../../evals/reports/pilot-real-diagnosis-20261003-01/README.md): causas seguras preservadas en ficha/log/ledger, tres HTTP comprobados. No recupera la causa del fallo anterior. Detector también produce falsos positivos sobre palabras comunes; no se ajustó para favorecer resultados.
- [Perfiles simulados](../../evals/reports/pilot-personas-20261003-01/README.md): petición expresa «simúlalos», inferencias y acciones técnicas separadas. Cero revisiones humanas.

## Próximos pasos

1. Fase 3: contrastar el evento Gateway de 2026-10-03 15:43:21 UTC; mantener reserva hasta conciliación fiable. Revisar rechazos y preparar cualquier continuación sin borrar/recrear ledger ni reintentar automáticamente.
2. Fase 4: validar referencias humanas y representatividad, sin usar reservados para ajustar. Las simulaciones no sustituyen esa evidencia.
3. Fases 2 y 6: Office nativo y participación real pendientes; la simulación solicitada está entregada. No contactar ni desplegar sin autorización.
4. [Informe por fases](informe-piloto-community-20261003.md) y tareas 20–31 mantienen aceptación observada; [cierre documental](../../evals/reports/pilot-closure-20261003-02/README.md) comprueba fuentes, enlaces, evidencias y recursos.

Cinco archivos ajenos preservados sin incorporar: MESAS_RETIRO.pdf, plantilla.pdf, plantillaInformeTecnica.pdf, docs/brainstorming-regulae-vigia13-2026-10-02.md, docs/plan-blackhat/prompt-validacion-piloto-astra-max.md. No se publicaron servicios ni se migró/recifró la base del usuario. Todos los intentos anteriores mantienen sus evidencias originales.

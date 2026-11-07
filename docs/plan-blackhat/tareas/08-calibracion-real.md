# 08: Calibración y comparación real pendientes

**Status:** pending verification
**Blocked by:** calibración representativa y recorrido documental completo en vivo pendientes
**Specification:** [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md), [11](../11-evaluacion-reproducible.md).

- [x] Smoke sintético real DeepSeek: `2 + 2` → `4`, 25 tokens de entrada/1 salida, estimación superior 0,00000870 USD.
- [x] Presupuesto conjunto 1 USD con registro persistente; tres 403 Jev diagnosticados y 0,03 USD reservados como inciertos.
- [x] Obtener acceso real autorizado sin recarga ni compra automática: clasificación Jev completada en el smoke real 03.
- [x] Probar el juez real como componente: aceptó 17 días y rechazó 30 frente a una fuente de 17 días, 2/2 expectativas.
- [ ] Revisar/calibrar clasificación: confianza de categoría 0,49 frente al umbral 0,8; `classification_ambiguous` antes de generar, respuesta documental entregada 0/1.
- [ ] Calibrar sensibilidad/juez con casos representativos y conjunto humano reservado independiente.
- [ ] Comparar economy/strong/router con todas las llamadas y citas verificadas en vivo; medir calidad y ahorro reales.

Historial inicial: tres 403 Gateway, «Free tier users do not have access to this model. Upgrade to paid credits…», `providerAttempts: 0`. La repetición autorizada por el usuario («venga prueba ahora») mantuvo el límite conjunto de 1 USD y resolvió el acceso, sin compra/recarga. [Smoke real 03](../../../evals/reports/real-smoke-2026-10-02-03/report.json): clasificación `completed`, 917 tokens de entrada/251 de salida, 0,000038514 USD comunicado por Gateway; configuración restaurada y umbral conservado.

[Verificación real de componente](../../../evals/reports/real-jev-verification-2026-10-02-01/report.json): mismas tres preguntas y umbral 0,8 de producción. `noul` omisión/contradicción/afirmación: 0,13/0,05/0,03 para 17 días y 0,67/0,98/0,98 para 30 días. Cada llamada usó 473 tokens de entrada/62 de salida y costó 0,000019866 USD según Gateway. Solo Jev, respuestas escritas previamente, sin DeepSeek ni pipeline completo: no acredita calibración ni comparación de modelos.

[Snapshot actualizado](../../../evals/reports/real-budget-2026-10-02-02.json): límite 1 USD, 0,000086946 USD conocidos (0,000078246 USD de las tres llamadas nuevas y estimación DeepSeek previa de 0,00000870 USD), reservas inciertas 0,03 USD. El [export histórico](../../../evals/reports/real-budget-2026-10-02.json) se conserva. Simulador/smoke/presupuesto: 21 pruebas correctas (14+6+1); presupuesto concurrente y restauración segura probados sin red real.

Los controles y la demo offline están disponibles. El acceso probado y estos dos casos no permiten afirmar calibración, calidad general, ahorro ni respuesta documental verificada de extremo a extremo. [Estado observado](../estado-ejecucion.md).

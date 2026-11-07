# 03: Clasificar, enrutar y verificar con límites

**Status:** done (integración y controles locales; calibración en 08)
**Blocked by:** 02 (completada)
**Specification:** [05](../05-clasificacion-documental.md), [06](../06-enrutamiento-modelos.md), [07](../07-verificacion-y-escalado.md).

- [x] Jev estricto y autorización local antes de clasificador/generador/juez/enmascarado.
- [x] Catálogo de empresa activo, capacidades, calidad configurada, precios, presupuesto y plazo.
- [x] Cada intento verificado, máximo dos generaciones, costes inciertos explícitos.

Verificación: tests de Jev/routing/verification/connectors y `front.test_pipeline`; 40 pruebas en la combinación pipeline/chat/simulador comunicada en [estado](../estado-ejecucion.md). HTTP/SDK simulados; etiquetas semánticas prefijadas no equivalen a calibración.

Primitivas en `48a25e8`, metadatos en `2a5bd40`; integración final bajo revisión local. La nueva ofuscación reversible está fuera de alcance; solo se conserva y autoriza la integración existente.

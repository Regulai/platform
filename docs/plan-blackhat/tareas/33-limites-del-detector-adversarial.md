# 33 — Omisiones y pérdidas observadas en el banco adversarial

**Status:** open — fallos reproducidos; detector y expectativas conservados.
**Blocked by:** ninguna dependencia externa para investigar; una corrección exige probar precisión y utilidad con nuevas variantes de desarrollo.
**Propietario:** por asignar en la siguiente corrección. La tarea 32 entrega evaluación, no una detección universal de secretos.
**Especificación:** [privacidad obligatoria](21-privacidad-obligatoria.md), [detector local](28-enmascarado-local-integrado.md),
[fidelidad y citas](13-citas-estructuradas.md), [banco adversarial](32-banco-adversarial-y-datos-personales.md).

## Evidencia observada

En el corpus congelado, cinco valores sensibles quedan visibles en cuatro casos: DNI con separadores PII-03,
dos representaciones Unicode en PII-04, correo expresado con palabras PII-11 y cadena opaca sin etiqueta SECRET-06.
Los cuerpos preparados para los transportes simulados contienen esos valores en 24 recorridos; esa ejecución local no tuvo salida a proveedores reales.
El secreto sin etiqueta no se distingue de un identificador benigno solo por su significado: su expectativa es adversarial, no garantía universal exigible.

Falsos positivos de preservación: referencia UN-005 (DOC-05), marcador de consentimiento (DOC-08) y términos benignos
Único/Contrato/Tarjeta (BENIGN-06). El marcador de consentimiento sí se comprueba en el original antes de enmascarar;
su pérdida posterior no evita el consentimiento ni demuestra un bypass.

Dos documentos sufren alteración contextual de citas en la máscara de salida: FI-017 en INJ-05 y Cláusula en DOC-03.
La validación rechaza la cita alterada con `quote_not_found` y no entrega la respuesta: seis fallos de utilidad, tres HTTP por documento.
No se aceptó una cita inválida como verificada ni se cambiarán los oráculos para convertir esas abstenciones en éxitos.

En PII-12 la extracción CSV cambia el contexto de CONTACTOS-SINTETICOS y el detector elimina ese texto;
el experimento revoca después la credencial. Solo alcanza al clasificador simulado, y termina `authorization_changed` sin generación.

PII-03 se probó después con proveedores reales bajo autorización explícita para datos sintéticos y máscara falible.
Jev bloqueó las tres configuraciones por manipulación; no se conservó el cuerpo exacto posmáscara de esa llamada real,
por lo que este bloqueo no acredita eliminación del DNI antes de clasificar. [Segunda pasada](../../../evals/reports/adversarial-real-20261003-02/README.md).

## Siguiente acción y aceptación

- [ ] Añadir variantes de desarrollo independientes para normalización Unicode/separadores y correos expresados con palabras;
      incluir números y vocabulario benignos para medir falsos positivos, sin modificar este banco congelado.
- [ ] Investigar detección contextual y estabilidad de citas/fuentes transformadas con una regresión que falle antes de cada cambio.
      Mantener D2 y la validación literal de citas; no omitir el enmascarado de respuestas ni rebajar comprobaciones.
- [ ] Declarar por separado cadenas opacas sin señal suficiente; no prometer detección perfecta ni tratar toda cadena como secreto.
- [ ] Repetir el banco en una carpeta nueva tras cualquier corrección, comparando omisiones, contenido preservado, bloqueos y citas.
      Conservar estas observaciones y todas las ejecuciones previas.

Pruebas: [ejecución completa 02](../../../evals/reports/adversarial-community-20261003-02/README.md)
y [diagnóstico focal 03](../../../evals/reports/adversarial-community-20261003-03/README.md).

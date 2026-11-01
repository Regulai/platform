# Rúbrica humana congelada v1 — revisión pendiente

Estos casos son sintéticos y propuestos por el autor del banco. No existe todavía validación humana de representatividad, etiquetas ni respuestas. Los fixtures offline no son referencias de calidad.

## Procedimiento

1. Antes de abrir las etiquetas reservadas, dos personas acuerdan en desarrollo cómo aplicar esta rúbrica. Registrar desacuerdos y adjudicación con identidad, fecha y razón.
2. Congelar fuentes, manifiesto, precios, modelos, umbrales 0,8, orden, semilla y rúbrica. Guardar SHA-256 y aprobación explícita. Ningún ajuste puede usar resultados o etiquetas reservados.
3. Ejecutar todos los casos seleccionados en economy, strong y router con iguales restricciones. Conservar también errores, abstenciones y todo intento descartado. Una ejecución interrumpida no es una muestra completa.
4. Revisar respuestas ocultando la configuración cuando sea posible. No usar al juez Jev como referencia de su propia precisión. Las etiquetas de referencia son borradores; una persona debe validarlas.
5. Completar una COPIA de human-review.pending.json con status reviewed, reviewer, reviewed_at ISO-8601, rationale y result_sha256 intacto. No escribir etiquetas automáticas como humanas.
6. Abrir etiquetas reservadas solo después de congelar respuestas. Si se ajusta algo tras verlas, ese split pasa a desarrollo y requiere un nuevo conjunto reservado.

## Etiquetas

- correct: verdadero solo si se entregó una respuesta que satisface todos los requisitos factuales y de formato, sin invenciones ni contradicciones; falso para respuesta incorrecta o ausencia de respuesta. No inferirlo de passed ni de una comparación de strings.
- correct_abstention: verdadero si la política o falta de evidencia exige abstenerse y la salida lo hace; falso en los demás casos. Rechazar todo reduce cobertura y no demuestra calidad.
- requirements_met: requisitos completos, incluidos unidades, idioma, todas las preguntas y límites. null solo si no aplica.
- sensitivity_correct: clasificación y acción coinciden con la referencia humana (public/internal/confidential/restricted/unknown conservador). Revisar falsos negativos y positivos por categoría; restricted nunca se autoriza por ser privado.
- citations_supported: cada cita abre una fuente autorizada, es literal y pertinente para la afirmación; null sin documento. La existencia del ID no prueba pertinencia.
- second_attempt_corrected / second_attempt_introduced: comparar el primer y segundo texto conservados si están disponibles de forma autorizada; null si falta el primer texto o no hay segundo intento. No inferir corrección del estado final.
- reviewer_notes: anotar evidencia faltante, omisiones, sesgos de idioma y desacuerdos. No incluir secretos o datos personales.

## Agregación

Informar por caso/configuración/split: acierto humano y abstención, entrega/cobertura, sensibilidad, citas, segundo intento, n revisado/n total, coste estimado, coste comunicado y reserva incierta. Campos no revisados quedan null. Coste por respuesta correcta exige revisión completa y cero costes desconocidos; mostrar por separado cociente estimado y comunicado. Los errores y respuestas descartadas pertenecen al denominador de coste.

p50 y p95 usan latencia total monotónica por caso con n explícito; p95 es rango más próximo. No es SLA. No anunciar ahorro ni equivalencia de calidad con un banco sin revisión humana. Una muestra sintética pequeña tampoco acredita representatividad empresarial ni precisión universal.


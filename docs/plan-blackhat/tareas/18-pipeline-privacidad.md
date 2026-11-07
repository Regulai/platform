# 18: Privacidad y pipeline integrado

**Status:** done
**Blocked by:** none

## Entrega y aceptación

B1/B3/B4/B5/B6/B9; preflight, masking, presupuesto, consentimiento, reintento, historial, tiempo y cancelación.

Especificación y propiedad: [contratos de correcciones](../correcciones-community.md) y encargo humano allí referenciado. Decisiones D1–D7 aprobadas el 3 de octubre de 2026. Sin operaciones irreversibles ni llamadas pagadas.

## Verificación observada en la integración inicial (histórico)

Integrado mediante merge `eb8fde7`, conservando los commits pequeños de P (`e49cc6e`–`3e5e89e`). Enmascarado conjunto cuando hay servicios activos de la empresa, verificación sobre fuentes enviadas, decisiones conservadoras, consentimiento renovable, límite previo del juez, reintento con controles concretos, motor manual acotado, historial por pares/bytes y plazos efectivos. La expansión del historial por el enmascarador también se rechaza si supera su cota.

ASTRA volvió a ejecutar las doce regresiones finales B1–B10/C1–C2 contra el producto `4400f0b`: doce AssertionError, cero errores y cero omitidas. Siete pruebas adicionales de P reprodujeron siete fallos de aserción en la base (cancelación, plazo, roles y feedback, motor manual, 503 incierto, logging y rúbricas). El falso positivo por transformar una cita inventada durante el enmascarado se reprodujo y corrigió antes de integrar.

Puertas `13-pipeline`: check sin incidencias; 275 tests OK en 43.918 s, sin expected failures; migraciones sin cambios; 150 controles offline correctos, cero salidas indebidas y cero llamadas reales; pip-audit sin vulnerabilidades conocidas. La prueba negativa del evaluador produce deliberadamente seis controles fallidos sobre expectativas falsas en un banco temporal; no son fallos del banco final.

Solo tres etiquetas development cambiaron por D3, con [justificación previa por caso](../cambios-banco-correcciones.md). El servicio de enmascarado debe preservar la estructura del array JSON recibido como texto; una respuesta incompatible falla cerrada. La cota de salida es un límite de aceptación local, no una equivalencia formal entre tokens y bytes. La sobrecarga interna no documentada del proveedor sigue siendo una hipótesis del estimador. Revisión adversarial completada; véase actualización final abajo.


## Actualización — 3 de octubre de 2026

Revisión P cerrada en `a02f483`, `f8b5ba3`, `95dfb77`: preflight de destinos obligatorios e identidad de máscaras antes de generar, unknown compartido con simulador. Cuatro pruebas nuevas/diez aserciones rojas sin errores sobre revisión anterior, después verdes. Revalidación final en integración O302 OK/65,158 s; cinco puertas exit0. La cota de respuesta sigue siendo aceptación local, no conversión token-byte.

[Resultado técnico actual y pendientes](../informe-correcciones-community.md); [registro consolidado](../estado-ejecucion.md).


Verificación final ASTRA `12ca58d`: **302 tests OK en 66,767 s**; cinco gates exit0, 150 offline/0 fallos/0 llamadas reales. [Logs y manifiesto](../../../evals/reports/community-fixes-verification-20261003/README.md).

# 10. Probar una política antes de activarla

**Estado:** simulador implementado y recorrido local en navegador comprobado. **Prioridad:** P2; se puede posponer sin impedir la demo principal. **Depende de:** [05](05-clasificacion-documental.md) y [06](06-enrutamiento-modelos.md). **Resultado:** el administrador comprueba qué bloquearía o permitiría una propuesta, sin generar una respuesta ni cambiar la política vigente.

## Evidencia de implementación — 2 de octubre de 2026

`front.test_policy_simulator`: 14 pruebas correctas. Borrador JSON/YARA temporal, señales explícitas que respetan el mínimo local de sensibilidad, reserva del coste de clasificación/jueces obligatorios, autorización semántica con política actual, una llamada Jev acotada y auditada, cero generador, activación separada con versión/digests. AuditLog de empresa conserva configuración y fuentes YARA antes/después para recuperación, sin muestra ni credenciales.

En navegador se comparó una política interna con otra restringida en una empresa separada sin credenciales ni destinos: ambas bloquearon con sus motivos, sin clasificación semántica y con cero llamadas reales. La activación separada mostró éxito y revisión 2. Se comprobó en SQLite la auditoría con configuración anterior/revisión 1 y nueva/revisión 2, disponible para recuperación; no hubo intentos semánticos ni `Prompt`. [Captura](../../evals/reports/ui-2026-10-02/simulator-activated.jpg).

Las casillas siguientes describen controles automatizados cuando se marcan; no certifican calidad de proveedores reales ni un ensayo humano. Comandos, artefactos y pendientes: [estado observado](estado-ejecucion.md) y [arranque y demo](arranque-y-demo.md). La especificación original se conserva debajo.

## Versión útil y pequeña

Una pantalla de administración con política vigente, cambio propuesto y ejemplo sintético. Salida: decisión actual, decisión propuesta, reglas implicadas, destinos candidatos y motivo de las diferencias. Un administrador puede detectar que una regla bloquearía un informe público antes de aplicarla a toda la empresa.

No es un lenguaje de reglas nuevo ni un editor visual de workflows. Se reutilizan formularios, reglas YARA y configuración versionada de la aplicación.

## Implementación

1. **Separar evaluación y efectos.** La función de política devuelve una decisión a partir de datos normalizados y configuración. Crear alertas, enviar a proveedores y persistir conversaciones siguen siendo responsabilidad del caso de uso. El simulador llama a la misma evaluación, sin copiar sus reglas en otra implementación.
2. **Introducir un borrador temporal.** Recibir la configuración propuesta, validarla en servidor y compilar YARA. Un error se señala en el borrador y no modifica la configuración vigente. Para la primera versión basta mantener el borrador durante la petición; no hace falta una entidad de versiones editable.
3. **Empezar con simulación local.** Mostrar reglas deterministas y candidatos de ruta con señales de ejemplo explícitas. Marcar qué parte no se ha evaluado semánticamente. Si se usan resultados Jev previamente capturados, identificarlos como reproducción y ligar sus versiones y datos.
4. **Añadir evaluación semántica explícita.** Solo con datos que la política vigente autorice enviar a Jev. El borrador nunca concede permisos de salida reales. Mostrar que esa opción consume llamadas y guardar el coste correspondiente. El simulador no llama al generador.
5. **Presentar el contraste y la activación.** Una tabla de diferencias y un resumen de impacto. Activar es una acción separada del administrador autorizado: vuelve a validar el borrador y comprueba que la versión vigente no cambió desde la simulación. Si cambió, pide repetir la comparación; no sobrescribe silenciosamente una edición concurrente.

Modificar `front/policy.py` solo lo necesario para separar decisión y efectos; añadir vista/formulario junto a la administración de reglas existente. No usar parámetros como `skip_security=true` o un modo privilegiado que pueda llegar al envío normal.

## Contrato de seguridad

Simular y activar son permisos distintos si el modelo de roles lo requiere. Ambos se comprueban en servidor y se limitan a la empresa. El resultado incluye versión vigente, digest del borrador, datos de cobertura y origen de las señales. No guardar el documento de ejemplo en `AuditLog`; basta identidad del actor, versiones y resultado de la operación.

Una política de ejemplo no debe enviar datos restringidos para comprobar si la política vigente “se equivoca”. Los casos sensibles del simulador son sintéticos o se evalúan localmente.

## Aceptación y pruebas

- [x] Mismo contenido, política y señales producen la misma decisión en simulación y ejecución real.
- [x] Una simulación no crea conversación, mensaje, respuesta ni alerta operativa.
- [x] Una regla inválida no se activa ni afecta a otros usuarios.
- [x] Un borrador más permisivo no autoriza una llamada Jev prohibida por la política vigente.
- [x] Una edición concurrente invalida la activación basada en una versión anterior.
- [x] El generador recibe cero llamadas en todos los modos del simulador.
- [x] Se indica si hubo consumo real, señales prefijadas o partes no evaluadas.

Las pruebas observan decisiones y ausencia de efectos externos. No basta comparar dos funciones que comparten el mismo error: incluir resultados esperados de casos revisados por una persona.

## Entrega y recuperación

Sin migración obligatoria adicional. Activar guarda configuración validada y una nueva versión; conservar la configuración anterior necesaria para volver atrás, sin claves en el registro de cambios. Una retirada del simulador no afecta al motor de políticas.

Documentar un ejemplo de falso positivo detectado y corregido. Es una mejora visual potente, pero se implementa después de que el mismo motor funcione en el envío real.

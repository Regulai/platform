# Standards R — verificación de la corrección

Destino verificado mediante objetos Git inmutables: `52bdc8d71d37dcf40b59293346a4f74f043ef416`; comparación con `b6a24fb0acaab83d5152156d0fe5205b6d5344b4`. Checkout de revisión conservado en `b6a24fb`, limpio; informe original sin alterar.

**P2 resuelto. Sin nuevos defectos específicos confirmados.**

- `docs/plan-blackhat/README.md:8` condiciona el enmascarado a servicios activos de la empresa; `:19` explica que una política válida puede permitir contenido sin transformar cuando no existen.
- `informe-correcciones-community.md:91` declara expresamente la ausencia de bloqueo global automático y `:95` condiciona el lote y la respuesta a máscaras activas. La tabla B1/B3, informe técnico, contratos y tareas 12/13/18 también matizan las afirmaciones relacionadas.
- `arranque-y-demo.md:71–78` enseña preparar el servicio, configurar y activar ObfuscationConfig de la propia empresa con el permiso real de seguridad, autorizar `obfuscation:<id>`, fijar `masking.max_call_cost` bajo presupuesto y comparar/activar la política por separado. Describe correctamente el POST `/api/mask`, los arrays JSON serializados en los strings `text`/`masked`, igual longitud/orden, coherencia y fallo cerrado ante respuesta incompatible. Advierte que la comparación local no valida el servicio.
- El párrafo de aprobación humana D1–D7 en `correcciones-community.md:7` permanece literalmente idéntico al de `b6a24fb`; `:9–11` distingue su condición operativa actual. D2 no se redefine ni se vuelve provisional.

Alcance: nueve documentos corregidos, además de tres archivos de archivo de revisiones añadidos por root cuyos contenidos no consulté. Ningún cambio de código, scripts, dependencias, Gunicorn o CI. Contraste estático con las rutas, permisos, formulario y contrato existentes. Sin nueva suite, llamadas externas ni operaciones sobre datos. Las puertas postintegración corresponden a root y no se anticipa su resultado.

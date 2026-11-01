# 56. Agente profesional: web general y código generado

Status: Implementación y verificación local completadas; validación viva y activación pendientes.
Blocked by: Ensayo con proveedores vivos requiere configuración y autorización nueva de gasto. Build/prueba de la imagen E2B pendiente: Docker Desktop local falla por acceso a su socket. No bloquea el trabajo independiente ya completado.

Especificación: [prompt del encargo](../../prompt-agente-profesional-web-codigo.md). Continúa sobre los cambios locales de la tarea 55 sin descartarlos. No se autoriza push, despliegue, publicación, gasto ni cambios de permisos de cuentas existentes.

## Aceptación

Desde las tres entradas HTTP, una cuenta con permisos explícitos puede investigar dominios públicos nuevos y ejecutar Python/Node/shell nuevo en un sandbox aislado, recibir errores útiles, instalar dependencias por una vía controlada y entregar archivos autorizados con evidencia y revisiones. Todas las inferencias pasan por Regulay; originales privados no tienen salida directa a Internet.

Se comprobarán los doce grupos de aceptación de la especificación: web general; código/reparación; dependencia nueva; recorrido combinado; informe Word/PDF de cinco páginas; datos heterogéneos; edición; errores/veracidad; fronteras; continuidad/costes; interfaz; entradas/configuración. Se distinguirán contratos simulados, ejecución real local y autonomía con proveedores vivos.

## Secuencia de trabajo

1. [hecho] Trazar entradas, runtime, red, artefactos y versiones instaladas; probar aislamiento local.
2. [hecho] Integrar grants explícitos, migración sin permisos automáticos, presupuestos y contabilización.
3. [hecho] Integrar búsqueda Tavily, lectura/descarga pública, PDF, evidencia y Chromium mediado.
4. [hecho] Conectar backend Deep Agents con Python/Node/shell general, paquetes offline, salidas protegidas y artefactos múltiples.
5. [hecho] Integrar checkpoints, cancelación, reparación, revisiones, comprobaciones, prompt efectivo y UI.
6. [hecho] Ejecutar regresiones, HTTP+SDK+Linux, red pública autorizada y revisión visual; registrar matriz y manual.
7. [pendiente externo] Construir/probar la imagen en E2B y ensayar autonomía con modelo/buscador vivos bajo autorización nueva. No se simula este resultado.

## Observaciones iniciales — 2026-10-14

- Checkout `codex/tasks-53-54`, con cambios extensos previos de tarea 55 y PDFs ajenos al encargo; se conservan.
- `jobs.development_profile` exige `DEBUG` y nombre `agent-synthetic-`.
- `adapter.RegulayModel` filtra herramientas mediante `protocol.TOOL_PARAMETERS`; `ResultGate` reconstruye mensajes y nunca acepta actualizaciones privilegiadas del resultado.
- El README histórico describe sandbox E2B con red denegada y ejecución documental predefinida; falta verificar la configuración efectiva y el SDK instalado.

## Verificación observada

- **141 pruebas de aplicación correctas**, incluyendo las tres entradas HTTP,
  frontera de proveedor, permisos sin prefijo sintético/DEBUG, migración ida/vuelta,
  idempotencia, costes/Jev, edición y separación entre comprobaciones.
- **14 pruebas de runtime/SDK correctas**: ocho con namespaces Linux y comandos
  reales, seis de compatibilidad/pool. Error Python y reparación, Node, instalación
  real de humanize/is-number offline, navegador JavaScript, timeout con muerte de
  hijos, transferencias de más de 1 MB, edición grande y recuperación de archivos.
- Recorrido `/chat/send/` → Django/PostgreSQL → SDK → namespace real → render →
  artefactos → descarga: nueve inferencias simuladas, ocho operaciones, cinco
  páginas y DOCX/PDF/XLSX/PNG. No prueba autonomía: modelo/búsqueda son fixtures y
  el transporte administrativo E2B se sustituye por procesos WSL.
- Broker real sobre python.org, eia.gov y unwto.org (redirige a untourism.int);
  paquetes desde PyPI/npm con hashes. Sin inferencias ni búsquedas pagadas.
- Cinco páginas Word/PDF y dos diapositivas inspeccionadas. Se corrigió un
  solapamiento en el fixture PPTX; su integridad estructural no se confundió con
  calidad visual. Ediciones OOXML preservan las partes ajenas al cambio.
- UI real en Edge, escritorio/móvil y claro/oscuro: fuentes, preview, descarga,
  detalles, edición, cancelación/reanudación simulada, errores y teclado. Consola
  sin errores/advertencias. Sin certificación general de accesibilidad.
- `makemigrations --check --dry-run`: sin cambios pendientes; compileall, sintaxis
  JS y `git diff --check` correctos.

Evidencia, comandos, resultados y matriz completa:
[task56-professional-20261014](../../../evals/reports/task56-professional-20261014/README.md).
Manual de activación, límites, recuperación y limpieza:
[PROFESSIONAL.md](../../../ops/agent_chat/PROFESSIONAL.md).

## Decisiones y límites de la entrega

- Se mantienen Django/Deep Agents/LangChain/E2B instalados; no se introduce otro
  framework ni un historial alternativo. Modelo, planificación y visión usan la
  pasarela. Tavily se usa solo como recuperación, sin respuesta generativa.
- Código sin red directa. La investigación/instalación pasa por el broker y se
  cierra al comenzar el acceso a originales privados. Dependencias exactas,
  hashes y ejecución offline; no se admiten scripts npm ni sdists Python.
- Checkpoints cifrados y ligados al hash del runtime; enlaces solo a ejecutables
  inmutables de `/usr`, sin descendientes ni escapes. Resultado externo incierto
  no se repite. La reanudación mantiene plazo y consumo.
- Los interruptores generales permanecen deshabilitados. No se cambian grants,
  datos ni secretos de cuentas existentes. Sin push, publicación ni despliegue.
- La imagen E2B nueva, recursos agregados de microVM y autonomía de un modelo vivo
  **no están acreditados**. OCR no está instalado; la cobertura parcial se declara.
- Los cambios previos de la tarea 55 y los PDFs ajenos se conservan. No se crea un
  commit que mezcle trabajo previo. Se conserva el código local para revisión.

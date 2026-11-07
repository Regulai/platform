# 07: Demo aislada y ensayo final

**Status:** verification
**Blocked by:** dos ensayos humanos externos
**Specification:** [plan 12](../12-demo-y-salida.md).

- [x] Base/medios/cookies propios, siembra idempotente no destructiva y servidor loopback.
- [x] Respuestas/jueces simulados solo en run_demo, banner explícito y salida HTTP/socket del servidor bloqueada; recursos/iconos locales y fetch Iconify deshabilitado desde correcciones.
- [x] Guion de cinco minutos, configuración sin claves y recuperación documentados.
- [x] Documento y evidencia abiertos, dos generaciones/cinco llamadas simuladas, persistencia al recargar y bloqueo con cero llamadas en navegador offline.
- [x] Tres escenas, ficha/evidencia con clic, confirmación/cancelación y simulador recorridos en navegador.
- [x] Instalación reproducida con uv/Python 3.12.11 y 45 paquetes fijados: 129 tests correctos históricos del 2 de octubre y siembra de demo correcta.
- [x] Apertura de citas y evidencia con Enter comprobada el 3 de octubre en navegador Django offline; [capturas](../../../evals/reports/ui-community-fixes-20261003/README.md).
- [ ] Dos ensayos completos cronometrados con otra persona.

`rtk proxy .venv/Scripts/python.exe regulai/manage.py run_demo --settings=regulai.demo_settings --seed-only` ejecutado dos veces correctamente. Tests demo/evaluación/API/runtime: 21 correctas. [Arranque, login público sintético, escenas y rollback](../arranque-y-demo.md).

No hay despliegue autorizado. Advertencia de consentimiento antes de confirmar comprobada con cero llamadas; cancelación sin respuesta y confirmación conservando el archivo y un único turno. Enter envió el mensaje y abrió la ficha; Espacio alternó la ruta automática. Los ensayos humanos siguen pendientes externos. [Capturas](../estado-ejecucion.md). La demo no prueba precisión real de Jev ni ahorro; el recorrido visual usó el entorno original con la misma fuente fijada, no el nuevo entorno reproducido.

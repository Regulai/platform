# 02: Cobertura documental acotada

**Status:** done
**Blocked by:** 01 (completada)
**Specification:** [plan 04](../04-documentos-y-respuestas-completos.md).

- [x] Estado de lectura, digest y fragmentos/localización estables; sin recorte silencioso.
- [x] Límites de bytes, ZIP, páginas/unidades/texto y tiempo de proceso.
- [x] Fixtures reales pequeños, evidencia tardía, corrupción, cifrado, expansión y formatos no admitidos.

Verificación: `front.test_documents` pasó 12 pruebas; combinación documentos/UI/simulador pasó 27 mediante `rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_documents front.test_chat_ui front.test_policy_simulator --settings=regulai.test_settings`.

Decisión: formatos textuales/PDF textual/DOCX/CSV/XLSX; imágenes y XLS rechazados, sin OCR ni visión implícita. Metadatos sin documento o fragmentos completos. Commit `853d495`; [límites y recuperación](../estado-ejecucion.md).

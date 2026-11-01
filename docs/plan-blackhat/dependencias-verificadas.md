# Dependencias comprobadas

Fuente de instalación: `requirements.txt` de la raíz. `regulai/requirements.txt` remite a ella.
Python local: 3.12.11; Django 5.2.17 LTS; DRF 3.18.1.

El 2 de octubre de 2026, `pip-audit` detectó 96 avisos en 12 paquetes fijados en la instalación anterior. Se actualizaron anyio, cryptography, SimpleJWT, PyJWT, idna, lxml, Pillow, python-dotenv, requests, urllib3 y sqlparse a versiones corregidas. PyPDF2 se sustituyó por pypdf 6.19.0, su continuación mantenida, conservando la extracción en proceso separado y sus límites. [Historia oficial de pypdf](https://pypdf.readthedocs.io/en/stable/meta/history.html).

Comprobaciones realizadas:

- Instalación inicial desde la lista única y sincronización exacta posterior de los 45 paquetes con `rtk proxy uv pip sync --python .venv/Scripts/python.exe requirements.txt`.
- Auditoría posterior: `rtk proxy uv tool run pip-audit -r requirements.txt`: **ninguna vulnerabilidad conocida encontrada**. Es el resultado de esa base de avisos en esa fecha, no una garantía de ausencia de vulnerabilidades.
- 45 pruebas de documentos sintéticos, conectores, Jev, selección, verificación y runtime: correctas tras las actualizaciones.
- Comprobación final: 45 paquetes compatibles mediante `uv pip check`, 129 pruebas `front api` correctas en 19,891 s. Entorno nuevo `.claude/reproduction-venv-20261002`, creado con `uv venv --python 3.12.11` y sincronizado desde la misma lista: 129 pruebas correctas en 39,764 s, `check` sin incidencias y siembra de demo correcta. El lanzador `py -3.12` no funcionó en esta máquina; la guía utiliza uv.

La auditoría se ejecuta mediante la caché aislada de herramientas de uv; no se instala globalmente ni forma parte de las dependencias de producción.

Django 5.2 tiene soporte extendido hasta abril de 2028 según el [calendario oficial](https://www.djangoproject.com/download/#supported-versions). Antes de trasladar una instalación existente, conservar copia de su base de datos y configuración y ejecutar las migraciones; no sustituir claves de cifrado.

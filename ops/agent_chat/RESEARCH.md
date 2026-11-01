# Investigación documental con fuentes primarias

La herramienta `research_sources(ids)` lee páginas públicas desde la aplicación de confianza de Regulay. El ejecutor no tiene transporte externo ni decide URL, consultas, credenciales, cabeceras o redirecciones. Los extractos pasan después por la misma pasarela de inferencia, las reglas de empresa y el enmascarado obligatorio.

La función está deshabilitada por defecto. Para habilitarla en una instalación autorizada:

1. Establecer `REGULAY_AGENT_RESEARCH_ENABLED = True` en la configuración local.
2. Incluir `research_sources` entre las herramientas del perfil del agente.
3. Conceder destinos explícitos `research:<id>` en `Company.ai_config.destinations` para la sensibilidad permitida. No se conceden permisos a cuentas existentes ni se modifica su política automáticamente.

El catálogo inicial contiene `nist-pqc`, `nist-fips-203`, `nist-fips-204` y `nist-fips-205`. Se puede sustituir mediante `REGULAY_AGENT_RESEARCH_CATALOG`, un diccionario revisado por el administrador:

```python
REGULAY_AGENT_RESEARCH_CATALOG = {
    'nist-pqc': {
        'title': 'Post-Quantum Cryptography',
        'publisher': 'NIST',
        'url': 'https://csrc.nist.gov/projects/post-quantum-cryptography',
        'content_id': 'overview',
    },
}
```

El administrador debe verificar que cada URL es una fuente primaria pertinente. El catálogo admite hasta 64 entradas; añadir una no otorga permisos de lectura a ninguna empresa. Las URL deben ser HTTPS sin credenciales, consulta ni fragmento, con puerto 443. La resolución DNS rechaza direcciones no públicas y la conexión queda fijada a una IP pública conservando la verificación TLS del nombre original. No se siguen redirecciones, enlaces, scripts ni recursos de las páginas, ni se utilizan proxies o credenciales del entorno.

La extracción prefiere regiones semánticas `main`, `article` o `role="main"`. Para páginas sin esas etiquetas, `content_id` permite fijar un identificador HTML revisado; si falta o deja de ser único, la lectura falla. Las entradas NIST fijan sus regiones observadas `overview` o `body-section`. Se conserva la huella del HTML íntegro y la decodificación del charset es estricta, sin sustitución silenciosa de caracteres.

Cada llamada admite hasta cuatro fuentes y cada ejecución hasta seis llamadas. Solo se aceptan respuestas HTML o texto de hasta 500.000 bytes. El extracto disponible para el modelo se limita a 6.000 caracteres y declara si se ha recortado. Las comprobaciones locales de seguridad examinan el texto extraído completo antes del recorte. Una fuente consultada se reutiliza sin otra descarga durante esa ejecución, con la misma fecha y huella. La revocación o cancelación durante la lectura impide entregar su contenido.

Las referencias se obtienen de recibos cifrados vinculados a la ejecución y a la llamada emitida por el proveedor. Incluyen identificador, título, editor, URL exacta, fecha de consulta, huella SHA-256 de los bytes, cobertura y extracto. El ejecutor no puede crear referencias aportando metadatos propios. Las lecturas públicas se registran por separado de las inferencias con coste de API cero; no significan una aprobación de Jev.

Los estados `disabled`, `denied`, `failed`, `partial` y `completed` se refieren a la consulta. Haber consultado una página acredita su procedencia; la verificación semántica de las afirmaciones sigue siendo `not_performed`. No hay búsqueda general en internet, lectura de PDF remoto ni garantía de disponer de una fuente para cualquier tema. Si falta una fuente necesaria, el documento debe indicarlo y no inventar referencias.

Verificación local sin gasto de proveedores:

```powershell
rtk proxy .venv/Scripts/python.exe regulai/manage.py test front.test_agent_research --settings=regulai.test_settings --noinput
```

Las pruebas simulan DNS y la frontera HTTP tanto de las fuentes como del proveedor de inferencia. El 13 de octubre de 2026 se comprobaron adicionalmente lecturas públicas reales de las cuatro páginas NIST del catálogo. La página PQC entregó 61.063 bytes HTML y su región revisada contenía 3.486 caracteres. Los recibos y extractos completos de las cuatro páginas están en `evals/reports/task55-agent-documents-20261013/primary-sources.json`. Esas comprobaciones no utilizaron inferencia ni modificaron cuentas o permisos.

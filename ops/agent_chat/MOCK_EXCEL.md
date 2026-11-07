# Excel ficticio sin adjunto

Un perfil de desarrollo puede autorizar `create_mock_excel` además de las
herramientas existentes. Una petición de agente sin archivo, referencia de Drive
ni revisión se encola como `kind=mock`, sin inferencia dentro de la petición HTTP.
Los perfiles sin esta herramienta conservan el rechazo `agent_input_required`.

El modelo propone `title` y `rows` (objetos `item`, `amount_cents`). El servidor
comprueba esquema, enteros, tamaño, mínimo del perfil y política; conserva una
fuente CSV cifrada e inmutable bajo el bloqueo de la ejecución. Las repeticiones
solo aceptan la misma fuente. La publicación exige el mismo verificador XLSX
que las entradas adjuntas: estructura, fórmulas, recálculo y suma independiente.
El título indica «Datos ficticios» y el recibo registra su procedencia.

El contrato interno es aditivo: el bootstrap de esta nueva operación devuelve
`input=null`. Actualizar aplicación y ejecutor antes de habilitar la herramienta
en un perfil. Los trabajos existentes con adjuntos o revisiones no cambian.
No se habilitan perfiles existentes por migración ni se amplían permisos de Drive.

Regresiones: `front.test_agent_mock_excel`, `front.test_agent_chat` y
`front.test_agent_inference.AgentInferenceTests`, sobre PostgreSQL para las
pruebas de reclamación de trabajos. La comprobación local de 2026-10-13 incluyó
61 pruebas de agente/documentos/MCP/exportación y un XLSX producido y recalculado
en E2B con una respuesta de modelo simulada, sin llamadas de pago.

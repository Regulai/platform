# 71 — P1 E4: activación de skills

Status: completada en el alcance local autorizado; SDK/HTTP/PostgreSQL y motores físicos verificados.
Blocked by: ninguno; activación y certificación de un despliegue quedan fuera del encargo.

Especificación y aceptación: [plan P1, E4](../plan-p1-skills-streaming-20261016.md#e4-skills-cargadas-de-verdad-sin-vm-para-leer).

Verificación observada: backend read-only sin VM con DeepAgents 0.6.12 nativo;
preload explícito autoritativo, lectura automática canónica, bytes fijados y caché
acotada con revalidación de permiso; relectura/replay/compactación sin duplicar
cuerpos; snapshot de referencias en checkpoint v2. Documental prepara su VM desde
ResultGate solo tras autorización de una operación documental. Se normalizaron
frontmatter/licencias/avisos locales sin duplicar motores.

Evidencias: [SDK skills](../../../output/p1-20261016/e4/sdk-skills.log),
[servidor/estado/herramientas](../../../output/p1-20261016/e4/server-runtime-tools.log),
[tres adaptadores y variantes](../../../output/p1-20261016/e4/http-adapters.log).
Pasada focalizada de 17 casos correcta (5 skills, 5 herramientas, 7 checkpoints);
3 casos SDK correctos, incluidos profesional y documental sin adquisición de VM.
La repetición P0 SDK pasó 12/12. Una pasada anterior de 38 encontró cinco errores
de adaptación del evento de checkpoint; se corrigió la colisión del argumento
execution y los siete casos de checkpoint pasaron juntos después.
La matriz HTTP pasó 3/3 casos: seis combinaciones de entrada y conversación,
primer payload canónico, replay, cambio de selección, consumo en el siguiente
turno, preferencia automática y resume sin una inferencia ni cargo adicionales.

La matriz ampliada añade Madrid → landing con frontend-design real → descarga
sin LLM → cambio de color, sobre las tres entradas; conserva revisión base y
hashes. Se conserva SKILL.md upstream sin modificar: el servidor añade su propia
adaptación para HTML autocontenido, permisos y publicación. También se corrigió
el replay de recibos P0 tras activar el flag de skills, con seis combinaciones
de entrada y perfil verificadas sin llamadas al proveedor.

[DOCX/PDF físicos locales](../../../output/p1-20261016/physical/documents.json):
crear, editar un título conservando el resto, renderizar dos páginas y reabrir
DOCX/PDF/PNG pasaron bajo el runner Linux aislado. No se atribuyen calidad ni
latencia de un proveedor real a estas pruebas ni compatibilidad E2B global.
Las capacidades de runtime y los flags permanecen desactivados por defecto.
[E8 integrado](../../../output/p1-20261016/e8/reproduction.md): 215 casos en la
pasada amplia, cuatro observaciones históricas omitidas y dos errores de
configuración del laboratorio corregidos; la focal final pasó 37/37 e incluye
ambos casos, streaming final, herramientas y proveedor HTTP simulado. La prueba
profesional física publicó DOCX de cinco páginas con PDF, XLSX y PNG bajo el SDK
real y el runner aislado. No hay fallos funcionales pendientes de esta entrega.

Cierre documental explícito: [cinco recorridos físicos](../../../output/p1-20261016/physical/documental/results.json) completados (XLSX, DOCX, PDF, PPTX narrativo y PPTX tabular con OfficeCLI 1.0.155 fijado por hash). Cada recorrido instala/selecciona el paquete real, contiene una sola copia canónica tras la protección, prepara exactamente un sandbox y hace dos HTTP del proveedor simulado (herramienta y final), sin inferencia de selección. Verificación, revisión visual por agentes donde corresponde, publicación y descarga con SHA conservado; descarga 0 inferencias. Suite final 211,157 s, salida 0. Las capacidades globales siguen apagadas; este ensayo local no certifica E2B ni calidad del modelo real.

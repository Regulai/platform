# 77 — Skills y chat: claridad y uso de Taste

Status: completada (alcance local verificado).
Blocked by: ninguno.

Continuación de [76](76-p1-activacion-y-taste.md) y del [plan P1](../plan-p1-skills-streaming-20261016.md).
Petición: verificar y mejorar el menú Skills y el chat usando Taste como referencia.

Aceptación: activación según contexto dentro de la inferencia normal del Agente,
sin clasificador adicional. Chat despejado sin contador de skills ni barra de
selección permanente; `/` como acceso manual secundario y aviso pequeño sólo
después de una activación confirmada por el servidor. Conservar preferencias
Auto existentes; la biblioteca mantiene nombres y descripciones legibles y
acciones de gestión accesibles. Borrador conservado al explorar la biblioteca,
selecciones retiradas sin IDs invisibles y recuperación sin duplicar avisos.
Verificar catálogo, instalación y chat con teclado,
estados vacío/error/deshabilitado y 360/768/1440 px. Conservar permisos, fuentes
originales, revisiones, estado y dinero; sin llamadas pagadas ni migraciones.

Taste se aplica a jerarquía, redacción y crítica visual de componentes existentes.
Su propia especificación excluye dashboards/apps: no se fuerza una landing con
fotografías o animaciones ni se cambia la identidad de regulAI. El paquete
upstream permanece intacto. Textos del catálogo sólo representan revisiones
exactas verificadas, nunca una importación distinta con igual origen histórico.

Trabajo repartido: root presentación de servidor/pruebas/integración, subagente
frontend templates/JS/CSS, revisión independiente de contratos y OPS aislado.
Rama de revisión e índice alternativo; preservar HEAD y cambios concurrentes.

Verificación observada: 91/91 pruebas en PostgreSQL aislado (tres entradas HTTP,
SDK simulado, estado/dinero, migración, rollback P0 y streaming); 20/20 guardas
OPS; navegador a 360/768/1440 con quince capturas de la instancia final y revisión
independiente. La activación real del servidor alimenta el test DOM; su captura
visual de laboratorio es sintética. No se certifica la pertinencia ni calidad de
un proveedor real y no se hicieron llamadas de pago.

Aplicado localmente el producto `a763bc3f`, imagen `1343225e…`; datos y dinero
conservados, PostgreSQL sin reinicio y mismo worker tras mantenimiento limpio.
Laboratorio cerrado, cookies retiradas, acceso loopback 8800 y respaldos retenidos.
HEAD compartido e índice permanecen intactos; commits en
`codex/p1-skills-chat-ux-20261016`, sin push.

[Informe, pruebas, capturas y límites](../../../output/p1-skills-ux-20261016/report.md).
[Revisión independiente](../../../output/p1-skills-ux-20261016/auto/independent-review.md).
[Prompt reformulado](../../../output/p1-skills-ux-20261016/prompt-profundo.md).

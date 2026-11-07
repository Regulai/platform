# 76 — Activación local de P1 y Taste v2

Status: completada y verificada en la instancia local v2.
Blocked by: ninguno para el alcance autorizado. Inspector opcional y calidad del proveedor real no certificados.

Petición posterior al cierre de [P1](../plan-p1-skills-streaming-20261016.md): activar
las funciones, comprobar su gestión desde el menú e instalar la skill frontend
Taste v2 completa. Conservar permisos, datos, revisiones y costes; sin nuevas
llamadas pagadas ni publicación pública.

Aceptación: configuración efectiva comprobada, controles del menú ejercitados,
fuente/licencia/commit del paquete fijados, instalación persistente con recursos
íntegros y disponibilidad fiel a los requisitos del runtime. No confundir
catálogo disponible con instalación de cuenta ni fuente modificada con servicio
actualizado. Registrar pruebas, límites y reversión sin duplicar el plan P1.

Decisiones y evidencia:

- La instancia activa es `regulai-v2-vm`, no la VM antigua de tarea 57. Su imagen
  conservaba el esquema 0041 y no contenía P0/P1 actuales. No basta cambiar el
  fichero de configuración del checkout. La activación solicitada se prepara
  contra esa instancia local, con respaldo privado, ensayo sobre clon, imágenes
  y plantilla nuevas y conservación de los contenedores originales.
- Las cinco funciones quedan activadas por configuración; los grants existentes
  siguen siendo obligatorios. Las capacidades de runtime no se inventan: Node
  sólo se anuncia cuando lo verifica el runtime de destino.
- El menú gestiona instalación, habilitación, actualización, rollback y selección
  automática/manual. No se añade un panel de configuración global o de permisos.
  Si falta grant, el menú se oculta y el acceso HTML devuelve 403 legible; con
  runtime desactivado se conserva la gestión, pero no se permite usar la skill.
- «Tasteful v2» se resuelve a Taste Skill v2 original de Leonxlnx, revisión
  `f624f37a8c650b9cc550253104925efe4c8de246`. Sus 29 archivos upstream permanecen
  idénticos; MIT y NOTICE separados completan 31 archivos. La integración restringe
  las instrucciones al workspace, herramientas concedidas y red autorizada.
  El inspector opcional no está certificado y los scripts de assets no obtienen
  red directa. [Fuente y ensayo offline](../../../output/p1-activation-20261016/source/report.md).
- La revisión encontró un fallo previo: `create_clean` sella `/skills`, pero la
  materialización intentaba escribir en ese montaje. La activación requiere
  corregirlo y comprobarlo en el sandbox real, conservando su inmutabilidad.

Verificación observada hasta el momento:

- 22/22: instalación, contexto canónico, tres entradas HTTP y transporte HTTP
  simulado con SDK real; 2/2 Taste repetidas tras fortalecer el cuerpo completo.
- 62/62: inferencia, estado, chat, streaming y visor con defaults activados.
- 19/19: menú/instalación/seguridad; interfaz on/off a 360, 768 y 1440 px, sin
  desbordamiento ni errores JavaScript. [Informe visual](../../../output/p1-20261016/e8/skills-activation-ui-review.md).
- 7 comprobaciones físicas de draw/lint offline con Node 24.21.0 en contenedor
  propio, usuario sin privilegios y sin red. No equivalen a calidad de proveedor.
- Materialización corregida: 11/11 pruebas Linux y validación, 16/16 regresiones
  SDK; reproducción previa de EROFS. La plantilla E2B de destino confirma Node
  24.21.0, UID 1000, ausencia de red, montajes RO, CAS y las siete pruebas Taste.
- Commits locales `af402b5`, `ba2d6b2`, `409160f`, `918129a`, `585c545`,
  `43230a3`, `c28f3aa`, `de45961`, `b4785af` y `009a0ec` en
  `codex/p1-activation-taste-20261016`, derivados de la entrega P1 `8c6f6b9`.
  El HEAD, índice compartido y trabajo concurrente permanecen intactos.

La exportación de la nueva imagen sandbox quedó bloqueada en una espera de
página asíncrona KVM del kernel de la VM. No se había invocado la plantilla ni
aplicado migraciones o cambios de cuenta. Se conserva respaldo privado reciente
y huella de 39 tablas y 939 filas. La recuperación se limita a la VM v2 y su mismo
disco; exige cierre limpio de PostgreSQL y sync antes del reinicio. ClickHouse
también tiene un hilo bloqueado y requiere copia privada de recuperación y
validación posterior; no se declara cerrado limpiamente. Los servicios originales
deben recuperarse y conservar sus huellas de aplicación antes de reintentar.

La primera recuperación preservó exactamente las huellas de la aplicación y
los 21 contenedores. El segundo intento construyó imágenes y plantilla y pasó
las migraciones en clon, pero APF reapareció antes de completar el probe físico.
Se adopta la alternativa reversible documentada de Linux `no-kvmapf`, sólo en
el bootloader de esta VM. La segunda recuperación confirmó el token efectivo,
13 cierres graciosos, ambos PostgreSQL limpios y las mismas huellas de aplicación.
La continuación reutilizó imágenes, plantilla y clon; el SDK verificó la identidad
de plantilla y pasó la prueba física. Taste quedó habilitada y disponible en el
clon. [Recibo preparado](../../../output/p1-activation-20261016/prepared-a2.json).

Aplicación completada: Taste habilitada y disponible en la cuenta, cinco flags
activos, Node 24.21.0 comprobado, web y worker estables sin reinicios. Las 39
tablas y 939 filas anteriores y sus secuencias se conservan; sólo se añaden la
instalación y sus registros de auditoría explícitos. El healthcheck se corrigió
para no consumir el límite existente de login. [Recibo aplicado](../../../output/p1-activation-20261016/applied-a2.json).

UI real verificada visualmente a 360, 768 y 1440 px: biblioteca, detalle y chat,
sin desbordamiento ni errores JavaScript; selección de Taste y Auto disponibles.
Sesión de prueba revocada, sin envíos de prompts ni cambios persistentes durante
el recorrido. [Recibo visual](../../../output/p1-activation-20261016/live-ui.json).

El clon aislado y el TAR temporal se eliminaron. Se conservan backups, originales
y montajes activos para reversión. La VM mantiene límite exterior de 11 GiB:
8,31 GiB observados dejan margen insuficiente para volver a 9 GiB. Túnel local
disponible en http://127.0.0.1:8800. [Informe final, commits y límites](../../../output/p1-activation-20261016/report.md).
Ninguna llamada pagada ni push/publicación pública.

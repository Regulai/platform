# 70 — P1 E3: biblioteca y selección

Status: implementado y verificado; integrado en E8.
Blocked by: ninguno para el alcance local autorizado.

Especificación y aceptación: [plan P1, E3](../plan-p1-skills-streaming-20261016.md#e3-biblioteca-importación-y-selector-con-estados-reales).

Verificación observada: biblioteca, detalle de catálogo/importadas, categorías/búsqueda, importación revisable, operaciones recuperables al recargar, actualización/rollback y selector accesible con máximo tres skills. Preferencia automática persistida; selección transportada y consumida sólo al aceptar un mensaje. Tres adaptadores y variantes con conversación existente, replay y cambio de selección verificados en PostgreSQL/HTTP SDK. Navegación e instalación no invocan modelos ni crean sandboxes.

Revisión visual 360/768/1440 px, claro/oscuro, teclado, vacío/error, importación real del fixture y recarga. Catálogo GET p95 73,8 ms y filtro p95 108,6 ms/20 muestras. [Evidencia visual](../../../output/p1-20261016/e8/visual-review.md), [matriz HTTP](../../../output/p1-20261016/e4/http-adapters.log).

# 79 — Chat React: base de build, bootstrap y reversión

Status: completada (alcance local verificado); falta aplicarla en el checkout principal.
Blocked by: ninguno.

Continúa [78](78-investigacion-chat-ui.md). Especificación:
[prompt de renovación](../../../output/chat-ui-research-20261017/prompt.md);
[inventario de estados](../chat-react-estados.md).

Aceptación: isla React/TypeScript/Vite limitada al chat, sus menús y visor;
dependencias fijadas con lockfile y avisos de licencia; build reproducible a
`regulai/static/chat-app/` con `manifest.json` resuelto por Django (JS, CSS y
chunks importados); bootstrap JSON público con campos explícitos; un solo
frontend activo por página y vía local de reversión; Tailwind, reset, tokens y
portales aislados; la biblioteca de skills y las páginas de `base.html` intactas.

Decisión registrada: excepción autorizada a la exclusión histórica de React
([README, decisión 1](../README.md#decisiones-compartidas-para-evitar-soluciones-incompatibles)),
limitada a la experiencia del chat. Django conserva backend, sesiones, CSRF,
permisos, archivos, ejecución, estado autoritativo y dinero.

Verificación observada (17-10-2026, rama `claude/regulai-chat-redesign-cc9805`):
isla en `frontend/chat` con React 19.3.1, Base UI 1.9.0, Motion 14.3.0, Lucide
1.58.0, Tailwind 4.3.3 y Vite 8.3.4, todas fijadas en el lockfile; Node 24.19.0
en `.node-version` y npm 11.17.0 en `packageManager`. Desde un `npm ci` limpio el build
sale idéntico byte a byte al commiteado, y el CI lo exige con `git diff --exit-code`.
`chat_assets.py` resuelve `manifest.json` con JS, CSS y chunks importados; si falta
algo, sirve el chat anterior y lo registra. `REGULAI_CHAT_FRONTEND=legacy` es la
reversión local: un solo frontend por página. El bootstrap (`chat_bootstrap.py`)
es una lista explícita de campos, sin ORM ni secretos y con títulos enmascarados.
Estilos, reset y portales quedan aislados bajo `.regulai-chat`; la biblioteca de
skills y las páginas de `base.html` no cargan la isla. El paquete del instalador
incluye `chat-app/manifest.json`. Pruebas: `front.test_chat_island` y
`ops/setup/test_chat_bundle.py`. Avisos de terceros en
[NOTICE](../../../frontend/chat/NOTICE.md) y en `THIRD-PARTY-NOTICES.txt`, que cada
build regenera con lo que realmente empaqueta.

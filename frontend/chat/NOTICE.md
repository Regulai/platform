# Third-party software in the chat island

The build in `regulai/static/chat-app/` bundles the packages below, at the exact
versions pinned by `package-lock.json`. Every build also writes
`regulai/static/chat-app/THIRD-PARTY-NOTICES.txt` with the full license text of
each package it actually bundled (collected from the bundle itself), so the
notices travel with the files the installer ships.

| Shipped in the build | Version | License |
|---|---|---|
| react, react-dom, scheduler, use-sync-external-store | 19.3.1, 19.3.1, 0.28.0, 1.7.0 | MIT, Meta Platforms, Inc. and affiliates |
| @base-ui/react, @base-ui/utils | 1.9.0, 0.5.0 | MIT, Material-UI SAS |
| @floating-ui/core, dom, react-dom, utils | 1.8.0, 1.8.0, 2.1.9, 0.2.12 | MIT, Floating UI contributors |
| motion, framer-motion, motion-dom, motion-utils | 14.3.0, 14.3.0, 14.3.0, 14.1.1 | MIT, Motion B.V. / Framer B.V. |
| lucide-react | 1.58.0 | ISC, Lucide Icons and Contributors |
| @shadcn/react, cn | 0.3.1, 0.5.0 | MIT, shadcn |
| class-variance-authority | 0.7.1 | Apache-2.0 (no NOTICE file upstream) |
| clsx | 2.1.1 | MIT, Luke Edwards |
| tailwindcss, tw-animate-css (CSS only) | 4.3.3, 1.4.0 | MIT, Tailwind Labs / Wombosvideo |

Copied source:

- `src/components/ui/*`: generated with the shadcn CLI 4.22 (base-nova style on
  Base UI) and edited for this project. MIT License, Copyright (c) 2023 shadcn.
- `src/styles/vendor/shadcn-tailwind.css`: shadcn 4.22.0 `dist/tailwind.css`,
  unmodified. MIT License, Copyright (c) 2023 shadcn.
- `src/markdown/renderer.ts`: a port of regulAI's own `static/js/chat-markdown.js`.

Build and test tools (TypeScript, Vite, Vitest, Testing Library, jsdom,
Playwright, @vitejs/plugin-react, @tailwindcss/vite) are not shipped.

Nothing in the build loads remote fonts, images, scripts or telemetry: the
interface uses the system font stack and icons compiled into the bundle.

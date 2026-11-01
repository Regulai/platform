# Isolated document-agent UI verification

This evidence uses the actual Django chat template, agent JavaScript/CSS and base sidebar rendered by `ops/agent_chat/preview_document_ui.py`. All API snapshots, inference records, costs and approvals are **simulated**; no production account, database, worker or paid provider was used. Browser requests outside `127.0.0.1` were blocked.

The report and deck preview/download bytes are local artifacts from the parent task. The final Word, PDF and PPTX downloads were compared byte-for-byte and by SHA-256 to those fixtures. See `qa-observations.json` for hashes, test results, interactions, scope and limitations.

Run the preview with the repository virtual environment, then open `http://127.0.0.1:8765/chat/?state=empty`. Available states: `empty`, `active`, `review`, `completed`, `error`, `deck`, `overloaded`. The server binds to loopback only and does not import production settings.

Primary final screenshots: `desktop-completed-final.png`, `mobile-completed-final.png`, `desktop-agent-empty-final.png`, `mobile-agent-empty-final.png`, `desktop-error-final.png`, `mobile-error-final.png`. Review page screenshots show all five report pages; `desktop-deck-preview.png` shows actual slides. Before-fix images are retained with initial names.

The browser was Playwright Chromium at 1440 × 1000 and 390 × 844. UI checks passed; 24 isolated Django/Node behavior tests passed. Native detail disclosure, both sidebars, mobile focus return, form submission, cancellation, real byte downloads, missing preview image failure, search-empty state and precise terminal errors were exercised.

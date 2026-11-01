# 00: Reproducible baseline and supported platform

**Status:** done
**Blocked by:** none
**Base:** 6a0f667c4fb02ec5a93b9eb9e2335385df7e2bda
**Specification:** preparation in ../00-guia-paso-a-paso.md and autonomous user instruction.

- [x] Reproduce the initial checks; distinguish pre-existing errors.
- [x] Install and configure six project skills, preserving RTK.
- [x] One dependency installation source; supported Django in a separate commit.
- [x] Fresh local database and repeatable startup without replacing existing settings.

Pre-existing untracked `MESAS_RETIRO.pdf` is excluded. Existing plans are retained and will be updated intentionally.

Observed: Python 3.12.11, Django 5.2.17, DRF 3.18.1, one root list of 45 pins. Initial test failure reproduced and fixed; `check`, schema checks and later runtime tests passed. Dependency audit moved from 96 advisories/12 packages to zero known advisories; [evidence](../dependencias-verificadas.md).

Commits: `18ecca7`, `75ec867`, `b99434a`. Startup: [current guide](../arranque-y-demo.md). Existing encryption keys and databases preserved; no push/deployment.

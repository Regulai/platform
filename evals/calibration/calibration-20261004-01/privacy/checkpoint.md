# Privacy calibration checkpoint

- Campaign: calibration-20261004-01. Owner B; no subagents or paid calls.
- Observed baseline HEAD: `9d7f9424a70143614c9d673e64ebed9723ff3439`.
- Owned runtime: `regulai/front/local_masking.py`, `classification.py`; tests: `test_calibration_privacy.py`.
- References read: AGENTS/RTK; domain/issue tracker; plans 05/06/07/11/12; tasks 12/13/21/28/32–35; adversarial report and diagnosis 03; local detector and correction contracts. Historical execution numbers are antecedents only.
- Skills: root-cause-debugging, test-design, workmanship; no linked supporting files in these skills.
- Runtime observed: Python 3.12.11; spaCy 3.8.16; xx_ent_wiki_sm 3.8.0.
- Hypothesis H1 before new measurement: deterministic matching uses original Unicode text and contiguous DNI grammar, so split/fullwidth/invisible forms are missed. A matching-only normalized view with original offsets plus bounded DNI separators can detect these without rewriting benign text or changing public API/thresholds.
- Candidate R1 implemented after root preregistration: matching view normalization and bounded identifier separators. R2 added explicitly labelled word-email grammar. R3 fixed a newly reproduced security regression by retaining original matches alongside normalized matches. Runtime now `regulai-local-v5`, SHA256 `5d6eaa792de291c96b0d2c94c8e1697136f42594e4ef8d9344106255f2e965b6`. classification.py unchanged.
- Measurement: 33 synthetic development probes fixed in `probe.py` plus the 44 historical regressions; no reserved cases. New focused regressions target public `mask_local_texts`.
- Evidence: base 9/20 own and 27/32 historical values removed; final 19/20 and 31/32; preservation 28/32 and61/66 unchanged. R1/v3 and R2/v4 rejected as final because compatibility punctuation could shorten secret spans; R3 passes four suffix regressions. Final comparison under r3-candidate-01; no original oracle changes.
- Verification: R3 focal+integration 87 tests,85passes+2known NER expected failures,exit0; final own9tests,7passes+same2expected failures,exit0. Captures 99 bodies at three HTTP entries,real serialized transport boundaries with synthetic responses. No paid calls, no ledger access, no user DB access. Two quote failures and verb/name confusion reproduced anew; causal semantic effect unproven.
- Root authorized selective B commit after index found empty. Pending: finish selective commit, evaluate development through A's frozen API, report corpus losses and stop editing runtime until coordinator decision. Reserved remains unread.

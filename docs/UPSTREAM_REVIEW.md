# Upstream source delivery — 1 November 2026

This proposal collects the governed Community pipeline, professional agent,
React chat, local installer and their tests on top of upstream `6a0f667`.
It is a source snapshot, not the private installation running on a contributor's
machine. Private profiles, installed settings, databases and generated user files
are not included. General reversible restoration in the chat remains a separate
proposal in this source snapshot; the drafting prompts preserve authorized aliases.

The review was a general readiness pass, not a full security audit or certification.
It corrected idempotent installer shutdown and visible status output, and updated
README/INSTALL to describe the private-profile prerequisite accurately. Public
first-account onboarding and a fresh end-to-end install on a clean machine remain
unverified. Existing installations are not upgraded by rerunning `install`.

Historical plans are retained as design context. Large captured reports, output
directories and superseded evaluation artifacts are omitted from this source PR;
their links in historical documents may refer to evidence outside this delivery.
The fixture subsets used by the test suite and calibration tools are retained.
No contributor-specific Git history is added to upstream.

Local validation and remaining checks are recorded in the PR description. CI is
the authority for the complete Linux/PostgreSQL suite. No paid model calls are
part of this review, so prompt behavior with a live provider remains unverified.

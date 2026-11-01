# Contributor guidance

Read README.md and INSTALL.md before changing installation behavior. The local
agent installer requires an operator-owned private profile; never commit profiles,
credentials, databases, generated user files or machine-specific configuration.

Run the relevant checks declared in .github/workflows/ci.yml. Tests must use the
isolated test settings, never an existing installation database. Do not call paid
providers or deploy an installation as part of tests without explicit permission.

The domain vocabulary and historical implementation plans live in
docs/plan-blackhat/README.md; task conventions are in docs/agents/issue-tracker.md.
Historical reports describe their recorded checkouts, not guarantees about the
current release. See docs/UPSTREAM_REVIEW.md for this source delivery's scope.

# P1 synthetic transport corpus

The manifest freezes the prompts, chunks and random-walk problem before P1.
`front.test_agent_p1_baseline` exercises the installed SDK through
`httpx.MockTransport`, including causal barriers before the final usage receipt.
The baseline runner uses a frozen effective P0 source archive and an exclusive
PostgreSQL container, never installation settings or provider credentials.

Fixture timings measure local orchestration only. They do not measure provider
latency, semantic quality, sandbox physical capacity or paid model behaviour.
Missing observations remain `null`, rather than zero. The Madrid lifecycle reuses
the existing P0 test and independent byte/hash assertions.

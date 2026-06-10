# models/

Shared Pydantic data models used across agents, orchestrator, and API:

- `Finding` — a single piece of evidence with severity score and SPL provenance
- `Case` — a correlated group of findings investigated together
- `Verdict` — the Correlation Lead's final assessment + kill-chain timeline

Implemented in Phase 2 alongside `splunk/client.py`.

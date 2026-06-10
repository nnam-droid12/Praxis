# agents/

The 6 specialist investigation agents, each a LangGraph node:

- `identity.py` — Identity Analyst (impossible travel, MFA fatigue)
- `lateral_movement.py` — Lateral Movement (host-pivot detection)
- `exfiltration.py` — Exfiltration (DNS tunneling, large egress)
- `persistence.py` — Persistence (scheduled tasks, unsigned binaries)
- `devils_advocate.py` — Devil's Advocate (benign-explanation search)
- `correlation_lead.py` — Correlation Lead (fan-in, kill-chain synthesis)

Each agent calls `saia_generate_spl` to draft SPL from natural-language
intent, runs it via `McpSplunkClient`, and scores findings with
Foundation-Sec-1.1-8B.

Implemented in Phase 4 (vertical slice) and Phase 5 (remaining agents).

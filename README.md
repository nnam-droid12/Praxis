# Praxis — Correlated Threat Investigation for Splunk

> **Splunk Agentic Ops Hackathon 2025 — Security Track**

## The Problem

A real SOC drowns in alerts; ~95% are noise. Dangerous multi-stage intrusions stay **below the alert threshold** at every step — each individual event looks benign. The breach signal is several quiet alerts across identity, network, and endpoint that share a hidden origin.

## What Praxis Does

Praxis deploys **6 specialist AI agents** that examine alerts concurrently, each through one attack discipline. A Correlation Lead synthesizes all findings to decide whether scattered low-severity alerts form **one coordinated campaign**.

**Defining demo moment:** 5 individually-low-severity alerts → ONE high-confidence "active intrusion in progress" verdict with a reconstructed kill-chain timeline.

## Architecture

```
Alert source (Splunk saved search → custom alert action)
      │
      ▼
Orchestrator (LangGraph)
      │  fan-out (parallel asyncio)
      ├── Identity Analyst ─────┐
      ├── Lateral Movement ─────┤  each: saia_generate_spl → splunk_search
      ├── Exfiltration ─────────┼─ via McpSplunkClient (token auth, real MCP)
      ├── Persistence ──────────┤  each scores via rule-based ScoringClient (Feature 3)
      └── Devil's Advocate ─────┘
      │  fan-in
      ▼
Correlation Lead → verdict + kill-chain + confidence score
      │
      ▼
FastAPI SSE stream ──► React "Investigation Console"
```

## Splunk Capabilities Used

| Capability | Where |
|---|---|
| MCP Server (app 7931) | All Splunk reads — `splunk_run_query`, `splunk_run_saved_search` |
| Python SDK custom alert action | Native Splunk app entry point |

Finding severity scoring (Feature 3) is a deterministic, rule-based
`ScoringClient` (`scoring/client.py`) — no external LLM dependency. AI
Assistant for SPL (`saia_generate_spl`) and AI Toolkit (Foundation-Sec-1.1-8B,
Cisco Deep Time Series) were evaluated but are documented future enhancements
only; they are not used by the current build.

## Quick Start

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env: set SPLUNK_MCP_URL and SPLUNK_TOKEN

# 2. Verify live connectivity
pip install httpx python-dotenv
python scripts/verify_live.py

# 3. Launch
docker compose up
# Open http://localhost:5173
```

## Project Structure

```
agents/          # 6 specialist agents
orchestrator/    # LangGraph fan-out/fan-in
splunk/          # McpSplunkClient (the ONLY Splunk interface)
models/          # Finding, Case, Verdict data models
api/             # FastAPI streaming backend
ui/              # React Investigation Console
splunk_app/      # Native custom-alert-action app
data/            # Synthetic attack dataset generator
scripts/         # verify_live.py and utilities
```

## Feature Status

- [x] Feature 0 — Live setup & verification
- [x] Feature 1 — Synthetic data generator + ingest
- [x] Feature 2 — McpSplunkClient + Finding/Case/Verdict models
- [x] Feature 3 — Rule-based Finding scoring
- [ ] Feature 4 — Identity Analyst (vertical slice)
- [ ] Feature 5 — Remaining agents
- [ ] Feature 6 — Orchestrator
- [ ] Feature 7 — FastAPI backend
- [ ] Feature 8 — React UI
- [ ] Feature 9 — Native Splunk app
- [ ] Feature 10 — Polish + demo recording

## License

MIT

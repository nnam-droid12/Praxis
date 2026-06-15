# Praxis — Correlated Threat Investigation for Splunk

> **Splunk Agentic Ops Hackathon 2025 — Security Track**

## The Problem

A real SOC drowns in alerts; ~95% are noise. Dangerous multi-stage intrusions stay **below the alert threshold** at every step — each individual event looks benign. The breach signal is several quiet alerts across identity, network, and endpoint that share a hidden origin.

## What Praxis Does

Praxis deploys **5 specialist AI agents** that examine alerts concurrently, each through one attack discipline. A Correlation Lead synthesizes all findings to decide whether scattered low-severity alerts form **one coordinated campaign**.

**Defining demo moment:** 5 individually-low-severity alerts → ONE high-confidence "active intrusion in progress" verdict with a reconstructed kill-chain timeline.

## Real-World Grounding: Rogue Access-Point Detection

Splunk's [Dubai Airports case study](https://www.splunk.com/en_us/customers/success-stories/dubai-airports.html)
describes monitoring 200+ Wi-Fi access points and up to 20,000 simultaneous
connections — including detecting **rogue hotspots** that degrade service
and pose a security risk at airport scale. Praxis's **Lateral Movement**
agent implements this as a real detection: it cross-checks each user's
Wi-Fi association events (`sourcetype=praxis:wifi`) against the
known/authorized access-point inventory (`known_bssid`). An association to
an unrecognized BSSID broadcasting the corporate SSID — an evil-twin
pattern — is scored as a `rogue_access_point` signal (HIGH severity), and
in the planted campaign it's the credential-theft step that precedes
j.okonkwo's "impossible travel" login.

## Architecture

```
Alert source (Splunk saved search → custom alert action)
      │
      ▼
Orchestrator (LangGraph)
      │  fan-out (parallel asyncio)
      ├── Identity Analyst ─────┐
      ├── Lateral Movement ─────┤  each: hand-written SPL → splunk_search
      ├── Exfiltration ─────────┼─ via McpSplunkClient (token auth, real MCP)
      ├── Persistence ──────────┤  each scores via rule-based ScoringClient (Feature 3)
      └── Devil's Advocate ─────┘
      │  fan-in
      ▼
Correlation Lead → verdict + kill-chain + confidence score
      │
      ├──► FastAPI SSE stream ──► React "Investigation Console"
      │
      └──► HEC: sourcetype=praxis:verdict (closes the loop back into Splunk)
```

For full diagrams covering Splunk interaction, agent/AI integration, and
data flow between every service, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Splunk Capabilities Used

| Capability | Where |
|---|---|
| MCP Server (app 7931) | All Splunk reads — `splunk_run_query`, `splunk_run_saved_search` |
| Custom alert action (`alert_actions.conf`, `payload_format = json`) | `splunk_app/praxis_alert_action/` — fires on `Praxis - *` saved searches |
| HTTP Event Collector (HEC) write-back | `sourcetype=praxis:verdict` — Correlation Lead verdicts written back into Splunk |

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
pip install -r requirements.txt
python scripts/verify_live.py

# 3. Launch the FastAPI SSE backend
uvicorn api.main:app --reload
# -> http://localhost:8000 (/health, /investigate/{user})

# 4. Launch the React Investigation Console
cd ui && npm install && npm run dev
# -> http://localhost:5173
```

If the backend isn't on `http://localhost:8000`, point the UI at it via
`ui/.env.local`:

```
VITE_API_BASE=http://localhost:8800
```

## Native Splunk Alert Action (Feature 9)

`splunk_app/praxis_alert_action/` is a custom alert action: when a
`Praxis - *` saved-search alert fires, it fans out to Praxis's 5 specialist
agents for the triggering user(s) and writes the Correlation Lead's verdict
back into Splunk as `sourcetype=praxis:verdict` — closing the loop from
"alert fires" to "investigated and answered" without leaving Splunk.

Install steps and configuration are in
[`splunk_app/praxis_alert_action/README.md`](splunk_app/praxis_alert_action/README.md).
To verify the whole flow end-to-end against live Splunk without installing
the app (builds a real gzip-CSV `results_file` from a live query, runs both
the launcher and the runner, and confirms the `praxis:verdict` events land):

```bash
python scripts/verify_alert_action.py
```

## Project Structure

```
ARCHITECTURE.md  # Splunk interaction, agent integration, data-flow diagrams
LICENSE          # MIT
agents/          # 5 specialist agents
orchestrator/    # LangGraph fan-out/fan-in
splunk/          # McpSplunkClient (the ONLY Splunk interface)
models/          # Finding, Case, Verdict data models
scoring/         # Rule-based ScoringClient (Feature 3)
api/             # FastAPI streaming backend
ui/              # React Investigation Console
splunk_app/      # Native custom-alert-action app
data/            # Synthetic attack dataset generator (incl. praxis:wifi)
scripts/         # verify_live.py and utilities
```

## License

[MIT](LICENSE)

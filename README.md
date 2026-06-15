# Praxis — Correlated Threat Investigation for Splunk

**Built for:** Splunk Agentic Ops Hackathon 2025 — Security Track
**Built with:** LangGraph · FastAPI · React 19 + Vite + TypeScript + Tailwind · Splunk MCP Server (app 7931) · Splunk HEC

Praxis is a multi-agent system that takes Splunk from "5 separate low-severity
alerts" to "1 high-confidence active-intrusion verdict with a reconstructed
kill chain" — without a human ever opening 5 separate searches.

## Table of Contents

- [Disclaimer](#disclaimer)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Architecture](#architecture)
- [Agent System](#agent-system)
- [Splunk & Agent Features Used](#splunk--agent-features-used)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Local Setup](#local-setup)
- [Dataset Setup](#dataset-setup)
- [Native Splunk Alert Action](#native-splunk-alert-action)
- [Project Structure](#project-structure)
- [Data Sources](#data-sources)
- [Example Investigations](#example-investigations)
- [Hackathon](#hackathon)
- [License](#license)

## Disclaimer

Praxis is a hackathon prototype. It runs against a **real local Splunk
Enterprise instance** via the Splunk MCP Server, but the data it investigates
is a **synthetic, deterministically-generated attack dataset**
(`data/gen_scenario.py`) — not production security telemetry. Finding
severity is computed by an intentionally **rule-based, deterministic
`ScoringClient`** (no LLM in the scoring path) for speed and reproducibility
during the demo. This is a proof of concept, not a production SOC tool.

## The Problem

| Observation | Why it matters |
|---|---|
| ~95% of SOC alerts are noise | Analysts triage each alert in isolation and burn out before the real signal surfaces |
| Multi-stage intrusions stay **below the alert threshold** at every step | One login, one file-share access, one scheduled task — each looks benign on its own |
| The breach signal is several *quiet* alerts across identity, network, endpoint, egress, and Wi-Fi that share a hidden origin | No single saved search is designed to correlate across all five disciplines |
| Rogue/evil-twin Wi-Fi access points are a real attack surface at scale | Splunk's [Dubai Airports case study](https://www.splunk.com/en_us/customers/success-stories/dubai-airports.html) — 200+ APs, up to 20,000 simultaneous connections, rogue-hotspot detection |

## The Solution

Praxis deploys **5 specialist agents** that investigate a flagged user
concurrently, each through one attack discipline. A **Correlation Lead**
fans all of their findings back in and decides whether scattered
low-severity signals form **one coordinated campaign**.

| Capability | Description |
|---|---|
| Multi-agent parallel investigation | 5 specialist agents run hand-written SPL against `index=main` for a target user, fanned out in parallel via LangGraph |
| Rule-based severity scoring | `ScoringClient` maps concrete event fields to severity + confidence — deterministic, no LLM, no hallucination risk |
| Kill-chain correlation | `CorrelationLead` counts how many agents independently flagged elevated severity and reconstructs a time-ordered kill chain |
| Devil's-advocate dissent | A dedicated agent actively hunts for exculpatory evidence (travel records, change tickets) and surfaces it as a dissenting view |
| Rogue/evil-twin Wi-Fi AP detection | Lateral Movement agent flags Wi-Fi associations to unrecognized BSSIDs broadcasting the corporate SSID |
| Real-time investigation console | React SSE UI streams each agent's findings live, then the final verdict + kill-chain timeline |
| Closed-loop alerting | A native Splunk custom alert action runs the full pipeline on `Praxis - *` saved-search alerts and writes the verdict back via HEC |

**Defining demo moment:** 5 individually-low-severity alerts → ONE
high-confidence "active intrusion in progress" verdict with a reconstructed
kill-chain timeline.

## Architecture

### System Overview

```
Alert source (Splunk saved search → custom alert action)
      │
      ▼
Orchestrator (LangGraph)
      │  fan-out (parallel asyncio)
      ├── Identity Analyst ─────┐
      ├── Lateral Movement ─────┤  each: hand-written SPL → splunk_search
      ├── Exfiltration ─────────┼─ via McpSplunkClient (token auth, real MCP)
      ├── Persistence ──────────┤  each scores via rule-based ScoringClient
      └── Devil's Advocate ─────┘
      │  fan-in
      ▼
Correlation Lead → verdict + kill-chain + confidence score
      │
      ├──► FastAPI SSE stream ──► React "Investigation Console"
      │
      └──► HEC: sourcetype=praxis:verdict (closes the loop back into Splunk)
```

For full Mermaid diagrams covering Splunk interaction, agent/AI integration,
and data flow between every service, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

### Agentic Workflow

1. **Fan-out** — `IdentityAnalystAgent`, `LateralMovementAgent`,
   `ExfiltrationAgent`, `PersistenceAgent`, and `DevilsAdvocateAgent` each run
   independently and in parallel for the target user via LangGraph's
   `Annotated[list[Finding], operator.add]` reducer.
2. **Score** — every `Finding` is scored by the deterministic
   `ScoringClient` (`scoring/client.py`): field-threshold rules map to a
   `Severity` (low/medium/high/critical) plus a confidence value and
   human-readable rationale.
3. **Fan-in** — `CorrelationLead` (`orchestrator/correlation_lead.py`)
   counts how many distinct agents independently flagged elevated severity,
   builds a time-ordered kill chain across all findings, and folds in any
   Devil's Advocate dissent to produce one `Verdict`.

## Agent System

### Orchestrator — Correlation Lead

`orchestrator/graph.py` is a LangGraph `StateGraph` that fans out to all 5
specialist agents in parallel, then fans in to a single
`correlation_lead` node. `CorrelationLead.synthesize()` deterministically
maps the Case's findings to a `Verdict`: `ACTIVE_INTRUSION` if 3+ distinct
agents report HIGH/CRITICAL, `SUSPICIOUS` for 1-2 or any MEDIUM, otherwise
`BENIGN` — with a kill chain ordered by each event's `_time`.

### Specialist Agents

| Agent | Investigates | Splunk sourcetype / fields | Key signals |
|---|---|---|---|
| **Identity Analyst** | Impossible-travel logins and MFA push-bombing | `praxis:auth` (`action=login\|mfa_challenge`) | `geo_velocity_kmh`, repeated MFA denials followed by an approval |
| **Lateral Movement** | Cross-protocol file-server access and rogue Wi-Fi access points | `praxis:network` (`dest_role=file_server`), `praxis:wifi` (`action=wifi_association`) | `dest_role`, `known_bssid` |
| **Exfiltration** | DNS tunneling and high-volume egress to low-reputation destinations | `praxis:egress` | `bytes_out`, destination reputation |
| **Persistence** | Unsigned scheduled tasks running obfuscated PowerShell | `praxis:endpoint` (`action=scheduled_task_created`) | `signed`, encoded command lines |
| **Devil's Advocate** | Mitigating evidence for the above (travel records, change tickets) | re-runs `praxis:auth` + `praxis:endpoint` queries | `travel_record`, `change_ticket` |

### Tool Registry — `McpSplunkClient`

`splunk/mcp_client.py` is the **only** Splunk interface used by any agent —
a thin wrapper over the Splunk MCP Server's JSON-RPC 2.0 / Streamable HTTP
API.

| Category | Tool | Used by |
|---|---|---|
| Search | `splunk_run_query` (via `run_query`, appends `\| table *`) | All 5 agents — one hand-written SPL query per finding type |
| Saved searches | `splunk_run_saved_search` (via `run_saved_search`) | `scripts/verify_alert_action.py` |
| Knowledge objects | `splunk_get_knowledge_objects` / `get_praxis_alerts` | Discovering the 5 `Praxis - *` alert definitions |
| NL → SPL (evaluated, not used) | `saia_generate_spl` (via `generate_spl`) | Documented future enhancement — currently broken, see `data/MCP_KNOWN_ISSUES` notes |
| Diagnostics | `splunk_get_info` | `scripts/verify_live.py` |

## Splunk & Agent Features Used

### MCP Server (App 7931)

- `splunk_run_query` is the primary read path for every agent — every
  specialist issues its own hand-written SPL, scoped to `index=main`,
  the target user, and an `earliest_time` window.
- `splunk_run_saved_search` / `splunk_get_knowledge_objects` discover and
  execute the 5 `Praxis - *` saved-search alerts that seed an investigation.
- `saia_generate_spl` (AI Assistant for SPL) was evaluated for NL→SPL
  translation but is currently non-functional in this environment — Praxis
  falls back to hand-written SPL everywhere, which also makes the demo
  fully deterministic.

### LangGraph Orchestration

- `orchestrator/graph.py` fans out to 5 independent agent nodes using a
  shared `findings: Annotated[list[Finding], operator.add]` state reducer,
  then fans in to `correlation_lead`.
- `stream_case()` wraps `compiled.astream(..., stream_mode="updates")` so
  the FastAPI layer can emit one SSE event per agent as it completes.

### Rule-Based Scoring (Determinism over Hallucination)

- `scoring/client.py`'s `ScoringClient` maps concrete event fields to
  severity/confidence with **zero LLM calls**:
  `impossible_travel`, `mfa_fatigue`, `multi_protocol_lateral_movement`,
  `rogue_access_point`, `unsigned_scheduled_task`, `encoded_command`,
  `dns_tunneling`, `low_reputation_destination`, `large_egress`, and the
  mitigating signals `geo_velocity_explained` / `approved_change`.
- Anthropic Claude and Splunk AI Toolkit (Foundation-Sec-1.1-8B, Cisco Deep
  Time Series) were evaluated for scoring and intentionally **not** used in
  this build — see `ARCHITECTURE.md` for the rationale.

### Closed-Loop Alerting (HEC)

- The native alert action (below) re-runs the full agent pipeline when a
  `Praxis - *` alert fires and writes the `Verdict` back into Splunk as
  `sourcetype=praxis:verdict` via the HTTP Event Collector — closing the
  loop from "alert fires" to "investigated and answered" without leaving
  Splunk.

## Features

| # | Feature | Status |
|---|---|---|
| 0 | Live Splunk MCP connectivity verification | ✅ |
| 1 | Synthetic attack dataset — 251 events across 5 sourcetypes | ✅ |
| 2 | `McpSplunkClient` + `Finding`/`Case`/`Verdict` models | ✅ |
| 3 | Rule-based `ScoringClient` | ✅ |
| 4 | Identity Analyst agent (impossible travel, MFA fatigue) | ✅ |
| 5 | Lateral Movement, Exfiltration, Persistence, Devil's Advocate agents | ✅ |
| 6 | LangGraph orchestrator (fan-out / fan-in) | ✅ |
| 7 | FastAPI SSE backend (`GET /investigate/{user}`) | ✅ |
| 8 | React Investigation Console | ✅ |
| 9 | Native Splunk alert action (closed loop via HEC) | ✅ |
| — | Rogue/evil-twin Wi-Fi access-point detection | ✅ |

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Agent orchestration | LangGraph (`StateGraph`, fan-out/fan-in) |
| Backend | FastAPI + Uvicorn, Server-Sent Events |
| Data models | Pydantic v2 (`Finding`, `Case`, `Verdict`) |
| HTTP | httpx (async, used by `McpSplunkClient`) |
| Frontend | React 19, Vite, TypeScript, Tailwind CSS v4 |
| Data platform | Splunk Enterprise (local), MCP Server (app 7931), HTTP Event Collector |

## Local Setup

1. **Prerequisites** — a local Splunk Enterprise instance with the Splunk
   MCP Server app (7931) installed and an MCP Encrypted Token created, plus
   Python 3.11+ and Node 18+.

2. **Configure environment**

   ```bash
   cp .env.example .env
   # Edit .env: SPLUNK_MCP_URL, SPLUNK_TOKEN, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, ...
   ```

3. **Install dependencies and verify connectivity**

   ```bash
   pip install -r requirements.txt
   python scripts/verify_live.py
   ```

4. **Generate and ingest the synthetic dataset** (see [Dataset Setup](#dataset-setup))

5. **Launch the FastAPI SSE backend**

   ```bash
   uvicorn api.main:app --reload
   # -> http://localhost:8000  (/health, /investigate/{user})
   ```

6. **Launch the React Investigation Console**

   ```bash
   cd ui && npm install && npm run dev
   # -> http://localhost:5173
   ```

   If the backend isn't on `http://localhost:8000`, point the UI at it via
   `ui/.env.local`:

   ```
   VITE_API_BASE=http://localhost:8800
   ```

## Dataset Setup

`data/gen_scenario.py` is a deterministic generator (`random.seed(1337)`)
that produces 251 events across 5 sourcetypes — `praxis:auth`,
`praxis:network`, `praxis:endpoint`, `praxis:egress`, `praxis:wifi` — into
`data/events/*.jsonl`, including a planted multi-stage attack campaign for
user `j.okonkwo` (rogue Wi-Fi association → impossible-travel login → MFA
fatigue → lateral movement → persistence → exfiltration) plus benign noise
for other users.

```bash
python data/gen_scenario.py        # regenerate data/events/*.jsonl
python scripts/ingest_hec.py        # ingest into Splunk via HEC
python scripts/create_alerts.py     # create the 5 "Praxis - *" saved-search alerts
```

`data/props.conf` documents field extractions for all 5 sourcetypes
(KV_MODE=auto handles them out of the box).

## Native Splunk Alert Action

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
orchestrator/    # LangGraph fan-out/fan-in + CorrelationLead
splunk/          # McpSplunkClient (the ONLY Splunk interface)
models/          # Finding, Case, Verdict data models
scoring/         # Rule-based ScoringClient
api/             # FastAPI streaming backend
ui/              # React Investigation Console
splunk_app/      # Native custom-alert-action app
data/            # Synthetic attack dataset generator (incl. praxis:wifi)
scripts/         # verify_live.py and other verification/utility scripts
```

## Data Sources

| Source | Sourcetype | Events | Description |
|---|---|---|---|
| Synthetic — Identity | `praxis:auth` | 59 | Logins (incl. impossible-travel), MFA challenges (incl. push-bombing) |
| Synthetic — Network | `praxis:network` | 52 | Cross-protocol file-server access |
| Synthetic — Endpoint | `praxis:endpoint` | 52 | Scheduled tasks, signed/unsigned binaries, encoded commands |
| Synthetic — Egress | `praxis:egress` | 66 | Outbound transfers, DNS tunneling, destination reputation |
| Synthetic — Wi-Fi | `praxis:wifi` | 22 | Access-point associations, known/unknown BSSID inventory |
| Real-world grounding | — | — | [Splunk Dubai Airports case study](https://www.splunk.com/en_us/customers/success-stories/dubai-airports.html) — inspiration for the rogue/evil-twin Wi-Fi AP detection |

## Example Investigations

Stream a live investigation for the planted-campaign user — expect 5 agents
to report findings (including a rogue-AP finding from Lateral Movement) and
a final `active_intrusion` verdict with a multi-step kill chain:

```bash
curl -N "http://localhost:8000/investigate/j.okonkwo?earliest_time=-7d"
```

Stream a benign user — expect a `benign` verdict, with Devil's Advocate
surfacing a `travel_record`/`change_ticket` dissenting view:

```bash
curl -N "http://localhost:8000/investigate/m.okafor?earliest_time=-7d"
```

## Hackathon

Built for the **Splunk Agentic Ops Hackathon 2025 — Security Track**.
Praxis demonstrates that 5 individually-low-severity alerts can be
correlated — by a deterministic, rule-based multi-agent pipeline — into one
high-confidence verdict with a reconstructed kill chain, and that the same
pipeline can close the loop by writing that verdict back into Splunk.

## License

[MIT](LICENSE)

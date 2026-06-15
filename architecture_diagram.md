# Praxis — Architecture Diagram

High-level component diagram for Praxis. For the full narrative
(how Praxis talks to Splunk, how the AI agents are integrated, and a
text-form data-flow walkthrough for every request path), see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Component diagram

```mermaid
flowchart TB
    subgraph SPLUNK["Splunk Enterprise"]
        IDX[("index=main<br/>sourcetypes: praxis:auth, network,<br/>endpoint, egress, wifi")]
        MCP["MCP Server (app 7931)<br/>splunk_run_query / splunk_run_saved_search"]
        SAVED["5x 'Praxis - *' saved-search alerts"]
        HEC[["HTTP Event Collector"]]
        VERDICTS[("sourcetype=praxis:verdict")]
        IDX --- MCP
        HEC --> VERDICTS
    end

    subgraph CORE["Praxis core (Python)"]
        CLIENT["McpSplunkClient<br/>splunk/"]

        subgraph AGENTS["5 specialist agents — LangGraph fan-out<br/>agents/ + orchestrator/graph.py"]
            IA["Identity Analyst"]
            LM["Lateral Movement"]
            EXF["Exfiltration"]
            PER["Persistence"]
            DA["Devil's Advocate"]
        end

        SCORER["ScoringClient<br/>rule-based severity + confidence<br/>scoring/"]
        CL["CorrelationLead<br/>fan-in -> Verdict + kill chain<br/>orchestrator/correlation_lead.py"]

        subgraph CAMPAIGN["Campaign Hunter — cross-user correlation"]
            CH["CampaignHunterAgent<br/>cross-user stats/dc(user) SPL<br/>agents/campaign_hunter.py"]
            HUNT["hunt_campaigns()<br/>orchestrator/campaign.py"]
        end

        CLIENT <--> MCP
        AGENTS -- "hand-written SPL per agent" --> CLIENT
        AGENTS --> SCORER --> CL
        CH -- "cross-user SPL" --> CLIENT
        CH --> HUNT
        HUNT -- "run_case() per affected user" --> AGENTS
        CL -.->|"per-user Verdicts"| HUNT
    end

    subgraph API["FastAPI backend — api/"]
        SSE["GET /investigate/{user}<br/>Server-Sent Events"]
        CAMPAPI["GET /campaigns<br/>JSON"]
    end
    CL --> SSE
    HUNT --> CAMPAPI

    subgraph UI["React console — ui/"]
        PANELS["Agent panels + Verdict panel"]
        CHTAB["Campaign Hunter tab"]
    end
    PANELS -- "start investigation" --> SSE --> PANELS
    CHTAB -- "scan for campaigns" --> CAMPAPI --> CHTAB
    SSE -.-> AGENTS

    subgraph ALERT["Native alert action — splunk_app/praxis_alert_action/"]
        LAUNCH["praxis_investigate.py<br/>stdlib launcher"]
        RUNNER["run_alert_investigation.py<br/>full runner"]
    end
    SAVED -- "alert fires (results_file)" --> LAUNCH --> RUNNER
    RUNNER -.-> AGENTS
    RUNNER --> CL
    RUNNER -- "verdict JSON" --> HEC
```

## Closed loop: Splunk alert -> investigation -> Splunk verdict

```mermaid
sequenceDiagram
    participant SS as Splunk saved search<br/>("Praxis - *")
    participant AA as praxis_investigate.py<br/>(alert action launcher)
    participant RUN as run_alert_investigation.py
    participant ORC as 5 agents + CorrelationLead
    participant MCP as MCP Server / Splunk
    participant HEC as HEC

    SS->>AA: alert fires (results_file, user)
    AA->>RUN: invoke with results_file path
    RUN->>ORC: run_case(user)
    ORC->>MCP: hand-written SPL per agent
    MCP-->>ORC: search results
    ORC-->>RUN: Verdict (severity, confidence, kill chain)
    RUN->>HEC: POST verdict JSON
    HEC->>SS: sourcetype=praxis:verdict (queryable in Splunk)
```

## Request-level data flow

```
User (browser)
  -> React console (ui/, Vite dev server :5173)
  -> FastAPI (api/main.py) GET /investigate/{user}  [SSE]
  -> LangGraph orchestrator (orchestrator/graph.py)
       -> 5 specialist agents (agents/*.py), in parallel
            -> McpSplunkClient (splunk/mcp_client.py)
                 -> MCP Server (app 7931) -> Splunk index=main
            <- raw search results (events as dicts)
       -> ScoringClient (scoring/client.py) -> Finding (severity, confidence, rationale)
       -> CorrelationLead (orchestrator/correlation_lead.py) -> Verdict + kill chain
  <- streamed back to the UI as SSE events (one per agent, then the verdict)

User (browser)
  -> React console "Campaign Hunter" tab
  -> FastAPI GET /campaigns  [JSON]
  -> hunt_campaigns (orchestrator/campaign.py)
       -> CampaignHunterAgent (agents/campaign_hunter.py)
            -> McpSplunkClient -> cross-user stats/dc(user) SPL -> Splunk index=main
       -> for each affected user: run_case (same pipeline as /investigate)
       -> merge per-user Verdicts -> CampaignVerdict (level, summary, combined kill chain)
  <- single JSON response with one CampaignVerdict per detected campaign

Splunk saved-search alert ("Praxis - *")
  -> custom alert action (splunk_app/praxis_alert_action/bin/praxis_investigate.py)
  -> scripts/run_alert_investigation.py
       -> same orchestrator pipeline as above
       -> HEC POST -> sourcetype=praxis:verdict (back into index=main)
```

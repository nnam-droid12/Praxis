// types.ts — mirrors models/finding.py, models/case.py, models/verdict.py
// and the SSE event shapes produced by api/main.py's _serialize().

export type Severity = "low" | "medium" | "high" | "critical";

export type VerdictLevel = "benign" | "suspicious" | "active_intrusion";

export interface Finding {
  id: string;
  agent: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  scoring_method: string;
  spl_query: string;
  events: Record<string, unknown>[];
  entities: Record<string, string[]>;
  created_at: string;
}

export type CaseStatus = "open" | "investigating" | "closed";

export interface Case {
  id: string;
  trigger_alerts: string[];
  status: CaseStatus;
  findings: Finding[];
  created_at: string;
  updated_at: string;
}

export interface KillChainStep {
  stage: string;
  timestamp: string;
  description: string;
  finding_ids: string[];
}

export interface Verdict {
  case_id: string;
  level: VerdictLevel;
  confidence: number;
  summary: string;
  kill_chain: KillChainStep[];
  contributing_findings: string[];
  dissenting_view: string | null;
  created_at: string;
}

// SSE event payloads — see api/main.py:_serialize
export interface FindingEvent {
  agent: string;
  findings: Finding[];
}

export interface VerdictEvent {
  case: Case;
  verdict: Verdict;
}

export const AGENT_ORDER = [
  "identity_analyst",
  "lateral_movement",
  "exfiltration",
  "persistence",
  "devils_advocate",
] as const;

export const AGENT_LABELS: Record<string, string> = {
  identity_analyst: "Identity Analyst",
  lateral_movement: "Lateral Movement",
  exfiltration: "Exfiltration",
  persistence: "Persistence",
  devils_advocate: "Devil's Advocate",
  correlation_lead: "Correlation Lead",
};

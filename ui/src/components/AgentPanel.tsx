import type { FindingEvent } from "../types";
import { AGENT_LABELS } from "../types";
import type { InvestigationStatus } from "../hooks/useInvestigation";
import { FindingCard } from "./FindingCard";

export function AgentPanel({
  agent,
  event,
  status,
}: {
  agent: string;
  event: FindingEvent | undefined;
  status: InvestigationStatus;
}) {
  const done = event !== undefined;

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-slate-100">{AGENT_LABELS[agent] ?? agent}</h3>
        {!done && status === "streaming" && (
          <span className="flex items-center gap-1 text-xs text-sky-400">
            <span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />
            investigating…
          </span>
        )}
        {!done && status === "idle" && <span className="text-xs text-slate-500">waiting</span>}
      </div>

      {done && event.findings.length === 0 && (
        <p className="text-xs text-slate-500">No risk signals in the sampled events.</p>
      )}

      {done &&
        event.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
    </div>
  );
}

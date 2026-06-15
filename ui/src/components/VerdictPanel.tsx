import type { VerdictEvent } from "../types";
import { VerdictBadge } from "./SeverityBadge";
import { KillChainTimeline } from "./KillChainTimeline";

export function VerdictPanel({ verdict }: { verdict: VerdictEvent }) {
  const { verdict: v } = verdict;

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-bold text-slate-100">Correlation Lead Verdict</h2>
        <VerdictBadge level={v.level} />
      </div>

      <p className="mt-3 text-sm text-slate-300">{v.summary}</p>

      <div className="mt-2 text-xs text-slate-500">
        confidence {Math.round(v.confidence * 100)}% · case {v.case_id}
      </div>

      {v.dissenting_view && (
        <div className="mt-3 rounded-md border border-sky-700 bg-sky-950/50 p-3 text-sm text-sky-200">
          <span className="font-semibold">Devil's Advocate dissent: </span>
          {v.dissenting_view}
        </div>
      )}

      <KillChainTimeline steps={v.kill_chain} />
    </div>
  );
}

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

      <div className="mt-3 rounded-md border border-emerald-800 bg-emerald-950/40 p-2 text-xs text-emerald-200">
        <span className="font-semibold">Closed loop: </span>
        Verdicts like this can also be generated automatically — a Splunk alert
        action runs this same investigation and writes the result back as{" "}
        <code className="rounded bg-slate-800 px-1 py-0.5">sourcetype=praxis:verdict</code>.
      </div>
    </div>
  );
}

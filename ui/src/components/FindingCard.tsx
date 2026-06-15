import type { Finding } from "../types";
import { SeverityBadge } from "./SeverityBadge";

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="rounded-md border border-slate-700 bg-slate-900/60 p-3">
      <div className="flex items-start justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-100">{finding.title}</h4>
        <SeverityBadge severity={finding.severity} />
      </div>
      <p className="mt-1 text-xs text-slate-400">{finding.description}</p>
      {finding.rationale && (
        <p className="mt-2 text-xs text-slate-300">
          <span className="font-semibold text-slate-400">Rationale: </span>
          {finding.rationale}
        </p>
      )}
      <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
        <span>confidence {Math.round(finding.confidence * 100)}%</span>
        <span>{finding.events.length} event{finding.events.length === 1 ? "" : "s"}</span>
      </div>
    </div>
  );
}

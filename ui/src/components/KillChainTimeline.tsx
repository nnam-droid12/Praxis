import type { KillChainStep } from "../types";
import { AGENT_LABELS } from "../types";

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function KillChainTimeline({ steps }: { steps: KillChainStep[] }) {
  if (steps.length === 0) return null;

  return (
    <div className="mt-4">
      <h4 className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-400">
        Reconstructed Kill Chain
      </h4>
      <ol className="space-y-2 border-l-2 border-slate-700 pl-4">
        {steps.map((step, i) => (
          <li key={i} className="relative">
            <span className="absolute -left-[1.45rem] top-1 h-2.5 w-2.5 rounded-full bg-red-500" />
            <div className="flex flex-wrap items-baseline gap-2 text-sm">
              <span className="font-mono text-xs text-slate-500">{formatTime(step.timestamp)}</span>
              <span className="font-semibold text-slate-200">{AGENT_LABELS[step.stage] ?? step.stage}</span>
            </div>
            <p className="text-xs text-slate-400">{step.description}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

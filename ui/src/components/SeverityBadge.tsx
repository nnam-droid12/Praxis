import type { Severity, VerdictLevel } from "../types";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-slate-700 text-slate-200 border-slate-500",
  medium: "bg-amber-900/60 text-amber-300 border-amber-600",
  high: "bg-orange-900/60 text-orange-300 border-orange-600",
  critical: "bg-red-900/70 text-red-300 border-red-500",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

const VERDICT_STYLES: Record<VerdictLevel, string> = {
  benign: "bg-emerald-900/60 text-emerald-300 border-emerald-500",
  suspicious: "bg-amber-900/60 text-amber-300 border-amber-500",
  active_intrusion: "bg-red-900/70 text-red-300 border-red-500",
};

const VERDICT_LABELS: Record<VerdictLevel, string> = {
  benign: "Benign",
  suspicious: "Suspicious",
  active_intrusion: "Active Intrusion",
};

export function VerdictBadge({ level }: { level: VerdictLevel }) {
  return (
    <span
      className={`inline-block rounded-md border px-3 py-1 text-sm font-bold uppercase tracking-wide ${VERDICT_STYLES[level]}`}
    >
      {VERDICT_LABELS[level]}
    </span>
  );
}

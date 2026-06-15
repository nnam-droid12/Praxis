import { AGENT_ORDER, AGENT_LABELS } from "../types";

const AGENT_DESCRIPTIONS: Record<string, string> = {
  identity_analyst: "Impossible-travel logins and MFA push-bombing",
  lateral_movement: "Cross-protocol file-server access and rogue Wi-Fi access points",
  exfiltration: "DNS tunneling and high-volume egress to low-reputation hosts",
  persistence: "Unsigned scheduled tasks running obfuscated PowerShell",
  devils_advocate: "Hunts for mitigating evidence — travel records, change tickets",
};

export function HowItWorks() {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
      <h2 className="text-lg font-bold text-slate-100">How Praxis works</h2>
      <p className="mt-2 text-sm text-slate-300">
        Praxis fans out 5 specialist agents to investigate a user, each through one
        attack discipline, in parallel. Every agent runs its own SPL against Splunk,
        scores its findings, and reports back. A Correlation Lead then synthesizes all
        of it into a single verdict and a reconstructed kill chain — turning several
        individually low-severity alerts into one high-confidence call.
      </p>

      <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
        {AGENT_ORDER.map((agent) => (
          <div key={agent} className="rounded-md border border-slate-800 bg-slate-950/40 p-3">
            <div className="text-sm font-semibold text-slate-200">{AGENT_LABELS[agent]}</div>
            <div className="mt-1 text-xs text-slate-400">{AGENT_DESCRIPTIONS[agent]}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 rounded-md border border-emerald-800 bg-emerald-950/40 p-3 text-xs text-emerald-200">
        <span className="font-semibold">Closed loop: </span>
        A Splunk saved-search alert can trigger this same investigation automatically
        via a custom alert action — the Correlation Lead's verdict is written back to
        Splunk as <code className="rounded bg-slate-800 px-1 py-0.5">sourcetype=praxis:verdict</code>,
        no manual lookup required.
      </div>
    </div>
  );
}

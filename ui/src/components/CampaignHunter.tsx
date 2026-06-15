import { useState, type FormEvent } from "react";
import type { CampaignVerdict } from "../types";
import { useCampaignHunt } from "../hooks/useCampaignHunt";
import { VerdictBadge } from "./SeverityBadge";
import { KillChainTimeline } from "./KillChainTimeline";

export function CampaignHunter() {
  const [earliestTime, setEarliestTime] = useState("-7d");
  const { status, campaigns, error, scan } = useCampaignHunt();

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    scan(earliestTime.trim() || "-7d");
  };

  return (
    <div>
      <div className="rounded-lg border border-slate-700 bg-slate-900 p-5">
        <h2 className="text-lg font-bold text-slate-100">Campaign Hunter</h2>
        <p className="mt-2 text-sm text-slate-300">
          Runs cross-user SPL <code className="rounded bg-slate-800 px-1 py-0.5">stats</code> /{" "}
          <code className="rounded bg-slate-800 px-1 py-0.5">dc(user)</code> queries — no per-user
          filter — to find indicators of compromise (rogue access points, shared exfiltration
          destinations, shared persistence artifacts) that touch 2 or more accounts. Each match
          fans out the full 5-agent investigation for every affected user and rolls the results
          into one campaign verdict.
        </p>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400" htmlFor="campaign-earliest">
              Earliest time
            </label>
            <input
              id="campaign-earliest"
              value={earliestTime}
              onChange={(e) => setEarliestTime(e.target.value)}
              className="mt-1 w-28 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={status === "scanning"}
            className="rounded bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {status === "scanning" ? "Scanning…" : "Scan for Campaigns"}
          </button>
        </form>
      </div>

      {error && <p className="mt-4 text-sm text-red-400">{error}</p>}

      {status === "done" && campaigns.length === 0 && (
        <p className="mt-4 text-sm text-slate-400">
          No cross-user campaigns detected in this window.
        </p>
      )}

      <div className="mt-4 space-y-4">
        {campaigns.map((cv) => (
          <CampaignCard key={cv.campaign.id} campaignVerdict={cv} />
        ))}
      </div>
    </div>
  );
}

function CampaignCard({ campaignVerdict }: { campaignVerdict: CampaignVerdict }) {
  const { campaign, level, summary, user_verdicts, combined_kill_chain } = campaignVerdict;

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wide text-slate-400">
            {campaign.indicator_label}
          </h3>
          <p className="text-base font-semibold text-slate-100">{campaign.indicator_value}</p>
        </div>
        <VerdictBadge level={level} />
      </div>

      <p className="mt-3 text-sm text-slate-300">{summary}</p>

      <div className="mt-3 flex flex-wrap gap-2">
        {Object.entries(user_verdicts).map(([user, verdict]) => (
          <div
            key={user}
            className="flex items-center gap-2 rounded-md border border-slate-800 bg-slate-950/40 px-3 py-1.5"
          >
            <span className="text-sm font-semibold text-slate-200">{user}</span>
            <VerdictBadge level={verdict.level} />
          </div>
        ))}
      </div>

      <KillChainTimeline steps={combined_kill_chain} />
    </div>
  );
}

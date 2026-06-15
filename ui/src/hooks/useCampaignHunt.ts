import { useCallback, useState } from "react";
import type { CampaignVerdict } from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export type CampaignHuntStatus = "idle" | "scanning" | "done" | "error";

interface CampaignHuntState {
  status: CampaignHuntStatus;
  campaigns: CampaignVerdict[];
  error: string | null;
}

const INITIAL_STATE: CampaignHuntState = {
  status: "idle",
  campaigns: [],
  error: null,
};

export function useCampaignHunt() {
  const [state, setState] = useState<CampaignHuntState>(INITIAL_STATE);

  const scan = useCallback(async (earliestTime: string) => {
    setState({ ...INITIAL_STATE, status: "scanning" });

    try {
      const url = `${API_BASE}/campaigns?earliest_time=${encodeURIComponent(earliestTime)}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      const data: { campaigns: CampaignVerdict[] } = await res.json();
      setState({ status: "done", campaigns: data.campaigns, error: null });
    } catch (err) {
      setState({
        status: "error",
        campaigns: [],
        error: err instanceof Error ? err.message : "Campaign scan failed.",
      });
    }
  }, []);

  return { ...state, scan };
}

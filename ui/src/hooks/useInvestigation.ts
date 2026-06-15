import { useCallback, useRef, useState } from "react";
import type { FindingEvent, VerdictEvent } from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export type InvestigationStatus = "idle" | "streaming" | "done" | "error";

interface InvestigationState {
  status: InvestigationStatus;
  findingEvents: FindingEvent[];
  verdict: VerdictEvent | null;
  error: string | null;
}

const INITIAL_STATE: InvestigationState = {
  status: "idle",
  findingEvents: [],
  verdict: null,
  error: null,
};

export function useInvestigation() {
  const [state, setState] = useState<InvestigationState>(INITIAL_STATE);
  const sourceRef = useRef<EventSource | null>(null);

  const start = useCallback((user: string, earliestTime: string) => {
    sourceRef.current?.close();

    setState({ ...INITIAL_STATE, status: "streaming" });

    const url = `${API_BASE}/investigate/${encodeURIComponent(user)}?earliest_time=${encodeURIComponent(earliestTime)}`;
    const source = new EventSource(url);
    sourceRef.current = source;

    source.addEventListener("finding", (e: MessageEvent) => {
      const payload: FindingEvent = JSON.parse(e.data);
      setState((prev) => ({ ...prev, findingEvents: [...prev.findingEvents, payload] }));
    });

    source.addEventListener("verdict", (e: MessageEvent) => {
      const payload: VerdictEvent = JSON.parse(e.data);
      setState((prev) => ({ ...prev, verdict: payload, status: "done" }));
      source.close();
    });

    source.onerror = () => {
      setState((prev) =>
        prev.status === "done"
          ? prev
          : { ...prev, status: "error", error: "Connection to Praxis API lost." },
      );
      source.close();
    };
  }, []);

  const reset = useCallback(() => {
    sourceRef.current?.close();
    setState(INITIAL_STATE);
  }, []);

  return { ...state, start, reset };
}

import { useState, type FormEvent } from "react";
import { useInvestigation } from "./hooks/useInvestigation";
import { AGENT_ORDER } from "./types";
import { AgentPanel } from "./components/AgentPanel";
import { VerdictPanel } from "./components/VerdictPanel";
import { HowItWorks } from "./components/HowItWorks";

const KNOWN_USERS = ["j.okonkwo", "m.okafor", "it.admin"];

function App() {
  const [user, setUser] = useState("j.okonkwo");
  const [earliestTime, setEarliestTime] = useState("-7d");
  const { status, findingEvents, verdict, error, start } = useInvestigation();

  const findingsByAgent = new Map(findingEvents.map((e) => [e.agent, e]));

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!user.trim()) return;
    start(user.trim(), earliestTime.trim() || "-24h");
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-5xl px-4 py-8">
        <header className="mb-6">
          <h1 className="text-2xl font-bold">Praxis</h1>
          <p className="text-sm text-slate-400">Correlated Threat Investigation Console</p>
        </header>

        <form onSubmit={handleSubmit} className="mb-6 flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400" htmlFor="user">
              User
            </label>
            <input
              id="user"
              list="known-users"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              className="mt-1 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none"
            />
            <datalist id="known-users">
              {KNOWN_USERS.map((u) => (
                <option key={u} value={u} />
              ))}
            </datalist>
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400" htmlFor="earliest">
              Earliest time
            </label>
            <input
              id="earliest"
              value={earliestTime}
              onChange={(e) => setEarliestTime(e.target.value)}
              className="mt-1 w-28 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm focus:border-sky-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={status === "streaming"}
            className="rounded bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {status === "streaming" ? "Investigating…" : "Investigate"}
          </button>
        </form>

        {error && <p className="mb-4 text-sm text-red-400">{error}</p>}

        {status === "idle" && <HowItWorks />}

        {status !== "idle" && (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {AGENT_ORDER.map((agent) => (
              <AgentPanel key={agent} agent={agent} event={findingsByAgent.get(agent)} status={status} />
            ))}
          </div>
        )}

        {verdict && (
          <div className="mt-6">
            <VerdictPanel verdict={verdict} />
          </div>
        )}
      </div>
    </div>
  );
}

export default App;

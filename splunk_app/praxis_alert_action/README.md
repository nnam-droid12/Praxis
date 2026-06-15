# Praxis Alert Action (Feature 9)

A native Splunk custom alert action. When a `Praxis - *` saved-search alert
fires, it runs a full Praxis multi-agent investigation for the triggering
user(s) and writes the Correlation Lead's verdict back into Splunk as a new
`sourcetype=praxis:verdict` event — closing the loop:

```
Praxis - * alert fires
      │
      ▼
praxis_investigate.py (bin/, stdlib launcher, runs under Splunk's Python)
      │  forwards the alert's JSON payload (stdin) to ...
      ▼
scripts/run_alert_investigation.py (project venv, full deps)
      │  reads results_file -> distinct users -> run_case() per user
      ▼
HEC: sourcetype=praxis:verdict  (case_id, level, confidence, summary,
                                  kill_chain, dissenting_view, findings)
```

## Install

1. Copy this directory to `%SPLUNK_HOME%\etc\apps\praxis_alert_action\` and
   restart Splunk (or `POST /debug/refresh`) so the `praxis_investigate`
   alert action is registered.

2. If the Praxis project isn't at `C:\Users\hp\Desktop\praxis`, or your
   Python interpreter with Praxis's dependencies installed isn't `python` on
   PATH, set `PRAXIS_HOME` / `PRAXIS_PYTHON` in the Splunk service's
   environment.

3. Enable the action on each `Praxis - *` saved search (Settings ->
   Searches, reports, and alerts -> edit alert -> Add Actions -> "Praxis: Run
   Multi-Agent Investigation"), or via REST:

   ```
   POST /servicesNS/{user}/search/saved/searches/{name}
     actions=praxis_investigate
     action.praxis_investigate.param.earliest_time=-24h
     action.praxis_investigate.param.user_field=user
   ```

4. Ensure `.env` at the Praxis project root has `SPLUNK_MCP_URL`,
   `SPLUNK_TOKEN`, `SPLUNK_HEC_URL`, and `SPLUNK_HEC_TOKEN` set —
   `run_alert_investigation.py` loads it via `load_dotenv()`.

## Test without Splunk

`scripts/verify_alert_action.py` (at the project root) builds a real
gzip-CSV `results_file` from a live Splunk query, pipes a realistic alert
payload into both `bin/praxis_investigate.py` and
`scripts/run_alert_investigation.py` directly, and confirms the resulting
`sourcetype=praxis:verdict` event lands in Splunk.

# splunk/

`McpSplunkClient` — the SOLE interface to Splunk, used by every agent.
Wraps the Splunk MCP Server (app 7931) Streamable HTTP JSON-RPC protocol:

- `splunk_run_query`, `splunk_get_metadata`, `splunk_get_indexes`, etc.
- `saia_generate_spl`, `saia_explain_spl`, `saia_ask_splunk_question`, `saia_optimize_spl`

Implemented in Phase 2.

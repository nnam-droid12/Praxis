# orchestrator/

LangGraph graph definition that fans out to the 6 specialist agents in
parallel (asyncio), then fans in to the Correlation Lead for the final
verdict and kill-chain timeline.

- `graph.py` — LangGraph `StateGraph` definition

Implemented in Phase 6.

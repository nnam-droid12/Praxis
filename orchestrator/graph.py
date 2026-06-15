"""graph.py — Feature 6 LangGraph Orchestrator.

Fans out to all 5 specialist agents in parallel for a given user, then fans
in to the CorrelationLead to synthesize a Verdict.

Usage:
    async with McpSplunkClient() as splunk:
        case, verdict = await run_case(splunk, "j.okonkwo")
"""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from agents import (
    DevilsAdvocateAgent,
    ExfiltrationAgent,
    IdentityAnalystAgent,
    LateralMovementAgent,
    PersistenceAgent,
)
from models import Case, Finding, Verdict
from splunk import McpSplunkClient

from .correlation_lead import CorrelationLead

_AGENT_NODES = (
    ("identity_analyst", IdentityAnalystAgent),
    ("lateral_movement", LateralMovementAgent),
    ("exfiltration", ExfiltrationAgent),
    ("persistence", PersistenceAgent),
    ("devils_advocate", DevilsAdvocateAgent),
)


class CaseState(TypedDict):
    user: str
    earliest_time: str
    findings: Annotated[list[Finding], operator.add]
    case: Case | None
    verdict: Verdict | None


def _build_graph(splunk: McpSplunkClient):
    graph = StateGraph(CaseState)

    for name, agent_cls in _AGENT_NODES:
        async def node(state: CaseState, agent_cls=agent_cls) -> dict:
            findings = await agent_cls(splunk).investigate(state["user"], state["earliest_time"])
            return {"findings": findings}

        graph.add_node(name, node)
        graph.add_edge(START, name)
        graph.add_edge(name, "correlation_lead")

    async def correlation_lead_node(state: CaseState) -> dict:
        case = Case(trigger_alerts=[f"Praxis investigation for {state['user']}"])
        for finding in state["findings"]:
            case.add_finding(finding)
        verdict = CorrelationLead().synthesize(case)
        return {"case": case, "verdict": verdict}

    graph.add_node("correlation_lead", correlation_lead_node)
    graph.add_edge("correlation_lead", END)

    return graph.compile()


async def run_case(
    splunk: McpSplunkClient, user: str, earliest_time: str = "-24h"
) -> tuple[Case, Verdict]:
    """Fan out to all 5 specialist agents for `user`, then synthesize a Verdict."""
    compiled = _build_graph(splunk)
    result = await compiled.ainvoke(
        {
            "user": user,
            "earliest_time": earliest_time,
            "findings": [],
            "case": None,
            "verdict": None,
        }
    )
    return result["case"], result["verdict"]

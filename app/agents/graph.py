"""
Agents layer — LangGraph multi-agent orchestration.

Responsibility (and ONLY responsibility):
    Define the graph of agent nodes (e.g. correlation, threat intelligence,
    and report-ready state updates) and the conditional/cyclical edges
    between them.

What does NOT belong here:
    - No direct retrieval or prompt-construction (agents call into
      app/rag, they don't build prompts inline)
    - No report formatting (that's app/reporting — agents produce
      structured output, not prose reports)

Why LangGraph (see docs/ARCHITECTURE.md §3.2):
    Real investigation isn't a straight line. A low-severity alert takes
    a short path; a high-severity alert may loop back through retrieval
    with a refined query before a report is written. This conditional/
    cyclical routing is what resolves the NFR1 (latency) vs NFR4
    (no hallucinated guidance) tension — cheap fast path by default,
    expensive thorough path only when severity justifies it.

This module provides both a LangGraph-compatible graph and a fallback
workflow so the project can be demonstrated even if LangGraph is not
installed.
"""

from typing import Any, TypedDict

from app.correlation.correlation import correlate_alert
from app.review.threat_intel import search_tavily


class InvestigationState(TypedDict):
    alert: dict[str, Any]
    retrieved_docs: list[dict[str, Any]]
    grounded_prompt: str
    correlation: dict[str, Any] | None
    threat_intel: dict[str, Any] | None
    status: str | None
    final_score: float | None


class FallbackInvestigationGraph:
    """Simplified investigation graph used when LangGraph is unavailable."""

    def invoke(self, state: InvestigationState) -> InvestigationState:
        correlation = correlate_alert(state["alert"])
        state["correlation"] = correlation["correlation"]
        state["status"] = "auto_closed" if state["correlation"]["false_positive"] else "investigation_complete"
        if state["correlation"]["false_positive"]:
            state["threat_intel"] = {
                "source": "tavily.com",
                "summary": "Auto-closed because the alert was classified as a false positive.",
                "confidence": 0.0,
                "details": [],
            }
            state["final_score"] = float(state["correlation"]["correlation_score"])
        else:
            state["threat_intel"] = search_tavily(state["alert"]["full_log"])
            state["final_score"] = min(
                100.0,
                float(state["correlation"]["correlation_score"]) + state["threat_intel"].get("confidence", 0.0) * 20.0,
            )
        return state


def build_investigation_graph() -> Any:
    """Builds the LangGraph investigation workflow."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError:  # pragma: no cover
        return FallbackInvestigationGraph()

    def run_correlation(state: InvestigationState) -> dict[str, Any]:
        return correlate_alert(state["alert"])

    def decide_path(state: InvestigationState) -> Any:
        return "false_positive" if state["correlation"]["false_positive"] else "threat_intel"

    def auto_close(state: InvestigationState) -> dict[str, Any]:
        return {
            "status": "auto_closed",
            "threat_intel": {
                "source": "tavily.com",
                "summary": "Alert was classified as a false positive and closed automatically.",
                "confidence": 0.0,
                "details": [],
            },
            "final_score": float(state["correlation"]["correlation_score"]),
        }

    def run_threat_intel(state: InvestigationState) -> dict[str, Any]:
        threat_intel = search_tavily(state["alert"]["full_log"])
        return {
            "threat_intel": threat_intel,
            "status": "investigation_complete",
            "final_score": min(
                100.0,
                float(state["correlation"]["correlation_score"]) + threat_intel.get("confidence", 0.0) * 20.0,
            ),
        }

    graph_builder = StateGraph(InvestigationState)
    graph_builder.add_node("correlation", run_correlation)
    graph_builder.add_node("false_positive", auto_close)
    graph_builder.add_node("threat_intel", run_threat_intel)

    graph_builder.add_edge(START, "correlation")
    graph_builder.add_conditional_edges(
        "correlation",
        decide_path,
        ["false_positive", "threat_intel"],
    )
    graph_builder.add_edge("false_positive", END)
    graph_builder.add_edge("threat_intel", END)

    return graph_builder.compile()

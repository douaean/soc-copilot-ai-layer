"""
Agents layer — LangGraph multi-agent orchestration.

Responsibility (and ONLY responsibility):
    Define the graph of agent nodes (e.g. severity triage, MITRE
    classifier, investigation-recommendation agent) and the conditional/
    cyclical edges between them.

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

Milestone: M8 (this is a Milestone 0/1 skeleton — no nodes/edges wired
yet).
"""

from typing import Any, TypedDict


class InvestigationState(TypedDict):
    """
    Shared state passed between LangGraph nodes.

    TODO (M8): finalize fields once agent roles are defined (severity
    score, retrieved docs, mitre mapping, recommendations, report draft).
    """

    alert: dict[str, Any]
    retrieved_docs: list[dict[str, Any]]
    mitre_mapping: dict[str, Any] | None
    recommendations: list[str] | None


def build_investigation_graph() -> Any:
    """
    Constructs and compiles the LangGraph state graph for alert
    investigation.
    """
    raise NotImplementedError("Implement in Milestone 8.")

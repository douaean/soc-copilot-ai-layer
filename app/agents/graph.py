"""
Agents layer — LangGraph multi-agent orchestration.

Responsibility (and ONLY responsibility):
    Define the graph of agent nodes and the conditional edges between
    them, and compile it against a checkpointer.

What does NOT belong here:
    - No business logic (that lives in ``app.agents.nodes``)
    - No detector formats (that lives in ``app.sensitive_detection``)
    - No state validation or security policy (that lives in
      ``app.agents.state``)

Why LangGraph (see docs/ARCHITECTURE.md §3.2):
    Real investigation isn't a straight line. Whether an alert carries
    confidential data decides which half of the graph runs, and only one
    of those halves is allowed to talk to external intelligence services.
    Encoding that as a conditional edge — rather than as an ``if`` buried
    in a node — is what makes the boundary auditable.

Topology::

    START -> sensitive_detection
                |
                +-- sensitive --> rule_checker --+-- uncovered --> rule_generator --+
                |                                |                                  |
                |                                +-- covered ----------------------+
                |                                                                   |
                +-- clean ------> threat_intel -------------------------------------+
                                                                                    |
                                                                                    v
                                                                                 analyst
                                                                                    |
                                                            [interrupt: human review]
                                                                                    |
                                                                                    v
                                                                                dashboard -> END

Milestone: M8.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from langgraph.graph import END, StateGraph

from app.core.config import settings

from .nodes import (
    AnalystEngine,
    Retriever,
    RuleDrafter,
    RuleRepository,
    SensitiveScanner,
    ThreatIntelProvider,
    make_analyst_node,
    make_dashboard_node,
    make_rule_checker_node,
    make_rule_generator_node,
    make_sensitive_detection_node,
    make_threat_intel_node,
)
from .state import (
    AlertInfo,
    AlertState,
    AnalystResult,
    DetectedEntity,
    ExecutionError,
    ExecutionMetadata,
    HumanReviewRecord,
    Indicator,
    MitreTechnique,
    NodeName,
    PromptInfo,
    RAGContext,
    RetrievedDocument,
    ReviewDecision,
    RiskLevel,
    RuleEngineeringResult,
    SensitiveDetectionResult,
    ThreatIntelResult,
    Verdict,
)

__all__ = [
    "route_after_detection",
    "route_after_rule_check",
    "build_investigation_graph",
    "open_sqlite_checkpointer",
]

#: Every type that can appear inside a checkpointed ``AlertState``. Passed to
#: the serializer as an explicit allowlist so deserialization is bounded to
#: this project's own models. A new state dataclass must be added here, or it
#: will fail to load under ``LANGGRAPH_STRICT_MSGPACK``.
_CHECKPOINT_TYPES: tuple[type, ...] = (
    AlertState,
    AlertInfo,
    PromptInfo,
    DetectedEntity,
    SensitiveDetectionResult,
    RuleEngineeringResult,
    RetrievedDocument,
    RAGContext,
    MitreTechnique,
    Indicator,
    ThreatIntelResult,
    AnalystResult,
    HumanReviewRecord,
    ExecutionError,
    ExecutionMetadata,
    RiskLevel,
    Verdict,
    ReviewDecision,
    NodeName,
)

from app.correlation.correlation import correlate_alert
from app.review.threat_intel import search_tavily


def route_after_detection(state: AlertState) -> str:
    """
    Conditional edge out of sensitive detection.

    Delegates to the state, which owns the sensitivity routing policy, so
    the branch condition exists in exactly one place.
    """
    return state.route_after_detection()


def route_after_rule_check(state: AlertState) -> str:
    """
    Conditional edge out of the rule checker.

    An alert whose every detected category is already covered needs no
    draft and goes straight to the analyst. Anything with at least one
    uncovered category goes to rule generation.
    """
    result = state.get_rule_result()
    if result is not None and result.rule_exists:
        return str(NodeName.ANALYST)
    return str(NodeName.RULE_GENERATOR)


def build_investigation_graph(
    *,
    scanner: SensitiveScanner,
    rule_repository: RuleRepository,
    rule_drafter: RuleDrafter,
    intel_provider: ThreatIntelProvider,
    analyst_engine: AnalystEngine,
    retriever: Retriever,
    checkpointer: Any | None = None,
    interrupt_for_review: bool = True,
) -> Any:
    """
    Construct and compile the alert-investigation graph.

    **What it does.** Detects sensitive data in the alert's prompt, then
    takes one of two paths. Sensitive alerts go to rule engineering, which
    drafts a Wazuh rule when the detected categories are not already
    covered. Clean alerts go to threat intelligence. Both paths meet at the
    analyst, which produces the verdict, and finish at the dashboard.

    **Dependencies.** All six collaborators are required keyword arguments.
    Nothing is defaulted: a graph that quietly substituted a placeholder
    scanner or analyst would emit confident verdicts derived from nothing,
    which is the failure this project exists to prevent. Omitting one is a
    ``TypeError`` at build time.

    **Checkpointing.** LangGraph writes a checkpoint after every node. Pass
    a saver from :func:`open_sqlite_checkpointer`; no node touches SQLite
    itself. The caller supplies the thread id per invocation::

        graph.invoke(state, config={"configurable": {"thread_id": alert_id}})

    Using the alert id as the thread id makes a run resumable and gives one
    checkpoint history per alert.

    **Human review.** With ``interrupt_for_review`` set, the graph stops
    after the analyst and before the dashboard, leaving a checkpoint. The
    application records the decision with ``AlertState.set_human_review``,
    applies it via ``graph.update_state``, then resumes by invoking the
    same thread with ``None``.
    """
    graph = StateGraph(AlertState)

    graph.add_node(str(NodeName.SENSITIVE_DETECTION), make_sensitive_detection_node(scanner))
    graph.add_node(str(NodeName.RULE_CHECKER), make_rule_checker_node(rule_repository))
    graph.add_node(str(NodeName.RULE_GENERATOR), make_rule_generator_node(rule_drafter))
    graph.add_node(
        str(NodeName.THREAT_INTEL), make_threat_intel_node(intel_provider, retriever)
    )
    graph.add_node(str(NodeName.ANALYST), make_analyst_node(analyst_engine))
    graph.add_node(str(NodeName.DASHBOARD), make_dashboard_node())

    graph.set_entry_point(str(NodeName.SENSITIVE_DETECTION))

    graph.add_conditional_edges(
        str(NodeName.SENSITIVE_DETECTION),
        route_after_detection,
        {
            str(NodeName.RULE_CHECKER): str(NodeName.RULE_CHECKER),
            str(NodeName.THREAT_INTEL): str(NodeName.THREAT_INTEL),
        },
    )
    graph.add_conditional_edges(
        str(NodeName.RULE_CHECKER),
        route_after_rule_check,
        {
            str(NodeName.RULE_GENERATOR): str(NodeName.RULE_GENERATOR),
            str(NodeName.ANALYST): str(NodeName.ANALYST),
        },
    )

    graph.add_edge(str(NodeName.RULE_GENERATOR), str(NodeName.ANALYST))
    graph.add_edge(str(NodeName.THREAT_INTEL), str(NodeName.ANALYST))
    graph.add_edge(str(NodeName.ANALYST), str(NodeName.DASHBOARD))
    graph.add_edge(str(NodeName.DASHBOARD), END)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=[str(NodeName.DASHBOARD)] if interrupt_for_review else None,
    )


@contextmanager
def open_sqlite_checkpointer(database_path: str | None = None) -> Iterator[Any]:
    """
    Yield a SQLite checkpointer configured for this project's state types.

    Defaults to ``settings.checkpoint_database_path`` so the location is
    configurable per environment rather than hard-coded. The database holds
    full alert state, including the raw Wazuh alert, so treat it as
    sensitive at rest.

    The connection must outlive every ``invoke``/``stream`` call made
    against the compiled graph, so use it as a context manager::

        with open_sqlite_checkpointer("soc.sqlite") as saver:
            graph = build_investigation_graph(..., checkpointer=saver)
            graph.invoke(state, config={"configurable": {"thread_id": tid}})

    The serializer is given an explicit allowlist of the state dataclasses
    and enums. Without it LangGraph deserializes them under its permissive
    default, which warns on every load and is documented to become an
    error; with it, the project is also ready for
    ``LANGGRAPH_STRICT_MSGPACK=true``, where anything not on the list is
    refused rather than reconstructed.
    """
    import sqlite3

    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    from langgraph.checkpoint.sqlite import SqliteSaver

    connection = sqlite3.connect(
        database_path or settings.checkpoint_database_path, check_same_thread=False
    )
    try:
        yield SqliteSaver(
            connection,
            serde=JsonPlusSerializer().with_msgpack_allowlist(_CHECKPOINT_TYPES),
        )
    finally:
        connection.close()

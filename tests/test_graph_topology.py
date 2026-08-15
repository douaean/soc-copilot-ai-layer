"""
Structural tests for the compiled investigation graph.

These assert topology and wiring — node names, edges, routing decisions,
checkpointer and interrupt configuration. They deliberately do not simulate
an end-to-end investigation: the collaborators are required dependencies, so
a full run would be a test of stand-ins rather than of the orchestration.
"""

from __future__ import annotations

import pytest

from app.agents.graph import (
    open_sqlite_checkpointer,
    build_investigation_graph,
    route_after_detection,
    route_after_rule_check,
)
from app.agents.state import (
    AlertInfo,
    AlertState,
    DetectedEntity,
    NodeName,
    RiskLevel,
    RuleEngineeringResult,
    SensitiveDetectionResult,
)

_UNUSED = object()


def _graph(**overrides):
    """Compile the graph with placeholder collaborators, none of them called."""
    dependencies = {
        "scanner": _UNUSED,
        "rule_repository": _UNUSED,
        "rule_drafter": _UNUSED,
        "intel_provider": _UNUSED,
        "analyst_engine": _UNUSED,
        "retriever": _UNUSED,
    }
    return build_investigation_graph(**(dependencies | overrides))


def test_every_production_node_is_registered() -> None:
    nodes = set(_graph().get_graph().nodes)
    for expected in (
        NodeName.SENSITIVE_DETECTION,
        NodeName.RULE_CHECKER,
        NodeName.RULE_GENERATOR,
        NodeName.THREAT_INTEL,
        NodeName.ANALYST,
        NodeName.DASHBOARD,
    ):
        assert str(expected) in nodes


def test_human_review_is_an_interrupt_not_a_node() -> None:
    assert str(NodeName.HUMAN_REVIEW) not in set(_graph().get_graph().nodes)


def test_node_names_come_from_the_nodename_enum() -> None:
    known = {str(name) for name in NodeName} | {"__start__", "__end__"}
    assert set(_graph().get_graph().nodes) <= known


def _edges(graph) -> set[tuple[str, str]]:
    return {(edge.source, edge.target) for edge in graph.get_graph().edges}


def test_both_branches_converge_on_the_analyst() -> None:
    edges = _edges(_graph())
    assert (str(NodeName.THREAT_INTEL), str(NodeName.ANALYST)) in edges
    assert (str(NodeName.RULE_GENERATOR), str(NodeName.ANALYST)) in edges


def test_analyst_leads_to_the_dashboard_and_the_dashboard_ends_the_run() -> None:
    edges = _edges(_graph())
    assert (str(NodeName.ANALYST), str(NodeName.DASHBOARD)) in edges
    assert (str(NodeName.DASHBOARD), "__end__") in edges


def test_detection_is_the_entry_point() -> None:
    assert ("__start__", str(NodeName.SENSITIVE_DETECTION)) in _edges(_graph())


def test_detection_branches_to_both_paths() -> None:
    targets = {
        target
        for source, target in _edges(_graph())
        if source == str(NodeName.SENSITIVE_DETECTION)
    }
    assert {str(NodeName.RULE_CHECKER), str(NodeName.THREAT_INTEL)} <= targets


def test_rule_checker_branches_to_generator_and_analyst() -> None:
    targets = {
        target
        for source, target in _edges(_graph())
        if source == str(NodeName.RULE_CHECKER)
    }
    assert {str(NodeName.RULE_GENERATOR), str(NodeName.ANALYST)} <= targets


def test_review_interrupt_is_configured_before_the_dashboard() -> None:
    assert _graph().interrupt_before_nodes == [str(NodeName.DASHBOARD)]


def test_review_interrupt_can_be_disabled() -> None:
    assert not _graph(interrupt_for_review=False).interrupt_before_nodes


def test_sqlite_checkpointer_is_attached_when_supplied() -> None:
    """LangGraph may re-wrap the saver at compile time, so check type, not identity."""
    from langgraph.checkpoint.sqlite import SqliteSaver

    with open_sqlite_checkpointer(":memory:") as saver:
        compiled = _graph(checkpointer=saver)
        assert isinstance(compiled.checkpointer, SqliteSaver)


def test_checkpointer_path_defaults_to_settings() -> None:
    from app.core.config import settings

    assert settings.checkpoint_database_path


def test_graph_compiles_without_a_checkpointer() -> None:
    assert _graph().checkpointer in (None, False)


# --------------------------------------------------------------------------
# Routing decisions
# --------------------------------------------------------------------------


def _state_with(detection: SensitiveDetectionResult, sanitized: str | None = None) -> AlertState:
    state = AlertState.create(AlertInfo(alert_id="a-1", timestamp="t"), "a prompt")
    if sanitized is not None:
        state = state.with_update(state.set_sanitized_prompt(sanitized))
    return state.with_update(state.set_sensitive_detection(detection))


def test_sensitive_alerts_route_to_rule_engineering() -> None:
    state = _state_with(
        SensitiveDetectionResult(
            contains_sensitive=True,
            detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
            risk_level=RiskLevel.CRITICAL,
        ),
        sanitized="<REDACTED>",
    )
    assert route_after_detection(state) == str(NodeName.RULE_CHECKER)


def test_clean_alerts_route_to_threat_intelligence() -> None:
    state = _state_with(SensitiveDetectionResult())
    assert route_after_detection(state) == str(NodeName.THREAT_INTEL)


def test_routing_is_not_duplicated_from_the_state() -> None:
    state = _state_with(SensitiveDetectionResult())
    assert route_after_detection(state) == state.route_after_detection()


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        pytest.param(None, NodeName.RULE_GENERATOR, id="no-result-recorded"),
        pytest.param(
            RuleEngineeringResult(rule_exists=False),
            NodeName.RULE_GENERATOR,
            id="uncovered",
        ),
        pytest.param(
            RuleEngineeringResult(rule_exists=True, matched_rule_id="100200"),
            NodeName.ANALYST,
            id="already-covered",
        ),
    ],
)
def test_rule_check_routing(rule: RuleEngineeringResult | None, expected: NodeName) -> None:
    state = AlertState(alert=AlertInfo(alert_id="a-1", timestamp="t"), rule=rule)
    assert route_after_rule_check(state) == str(expected)

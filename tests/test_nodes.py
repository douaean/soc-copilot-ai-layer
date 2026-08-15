"""
Node-level tests.

Each node is exercised on its own with a minimal stand-in for its single
external collaborator. These check the orchestration decisions the nodes
make — coverage semantics, error recording, failure propagation, execution
bookkeeping — not the behaviour of the collaborators themselves.
"""

from __future__ import annotations

import pytest

from app.agents.nodes import (
    make_analyst_node,
    make_dashboard_node,
    make_rule_checker_node,
    make_rule_generator_node,
    make_sensitive_detection_node,
    make_threat_intel_node,
)
from app.agents.state import (
    AlertInfo,
    AlertState,
    AnalystResult,
    DetectedEntity,
    NodeName,
    RAGContext,
    RetrievedDocument,
    RiskLevel,
    RuleEngineeringResult,
    SensitiveDetectionResult,
    StateValidationError,
    ThreatIntelResult,
    Verdict,
)

SECRET = "AKIAIOSFODNN7EXAMPLE"
PROMPT = f"Investigate leaked key {SECRET}"


def _state(prompt: str = PROMPT) -> AlertState:
    return AlertState.create(
        AlertInfo(alert_id="a-1", timestamp="2026-08-10T09:00:00+00:00", severity=10),
        prompt,
    )


class _Scanner:
    def __init__(self, result, sanitized, errors=()):
        self._payload = (result, sanitized, list(errors))

    def scan(self, text):
        return self._payload


class _ExplodingScanner:
    def scan(self, text):
        raise RuntimeError("presidio unavailable")


# --------------------------------------------------------------------------
# Sensitive detection
# --------------------------------------------------------------------------


def test_detection_stores_the_sanitized_prompt_and_verdict() -> None:
    result = SensitiveDetectionResult(
        contains_sensitive=True,
        detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
        masked_fields=["prompt"],
        risk_level=RiskLevel.CRITICAL,
    )
    node = make_sensitive_detection_node(_Scanner(result, "Investigate leaked key <SECRET:AWS>"))
    state = _state()
    updated = state.with_update(node(state))

    assert updated.prompt.sanitized_prompt == "Investigate leaked key <SECRET:AWS>"
    assert updated.contains_sensitive_data() is True
    assert SECRET not in updated.get_sanitized_prompt()
    assert updated.execution.completed_nodes == [str(NodeName.SENSITIVE_DETECTION)]


def test_detection_records_scanner_errors_without_aborting() -> None:
    node = make_sensitive_detection_node(
        _Scanner(SensitiveDetectionResult(), PROMPT, ["trufflehog: binary not found"])
    )
    state = _state()
    updated = state.with_update(node(state))

    assert [e.message for e in updated.execution.errors] == ["trufflehog: binary not found"]
    assert updated.contains_sensitive_data() is False


def test_scanner_failure_propagates_and_leaves_the_prompt_unclassified() -> None:
    state = _state()
    with pytest.raises(RuntimeError, match="presidio unavailable"):
        make_sensitive_detection_node(_ExplodingScanner())(state)
    assert state.sensitive is None
    with pytest.raises(StateValidationError):
        state.get_sanitized_prompt()


def test_detection_audits_its_read_of_the_original_prompt() -> None:
    node = make_sensitive_detection_node(_Scanner(SensitiveDetectionResult(), PROMPT))
    state = _state()
    updated = state.with_update(node(state))
    assert any(
        str(NodeName.SENSITIVE_DETECTION) in entry
        for entry in updated.execution.sensitive_access_log
    )


# --------------------------------------------------------------------------
# Rule engineering
# --------------------------------------------------------------------------


class _Repository:
    def __init__(self, coverage=None, boom=False):
        self._coverage, self._boom = coverage or {}, boom

    def find_matching_rules(self, entities, alert_metadata):
        if self._boom:
            raise ConnectionError("wazuh api unreachable")
        return self._coverage


def _two_category_state() -> AlertState:
    """Sensitive state with two detected categories."""
    state = _state()
    state = state.with_update(state.set_sanitized_prompt("<REDACTED>"))
    return state.with_update(
        state.set_sensitive_detection(
            SensitiveDetectionResult(
                contains_sensitive=True,
                detected_entities=[
                    DetectedEntity("SECRET:AWS", "trufflehog", 1.0),
                    DetectedEntity("EMAIL_ADDRESS", "presidio", 0.9),
                ],
                masked_fields=["prompt"],
                risk_level=RiskLevel.CRITICAL,
            )
        )
    )


def test_all_categories_covered_marks_the_alert_covered() -> None:
    state = _two_category_state()
    repository = _Repository({"SECRET:AWS": "100200", "EMAIL_ADDRESS": "100201"})
    updated = state.with_update(make_rule_checker_node(repository)(state))
    assert updated.rule.rule_exists is True
    assert updated.rule.matched_rule_id == "100200, 100201"


def test_one_covered_category_out_of_two_is_not_covered() -> None:
    """The semantic this node exists to get right."""
    state = _two_category_state()
    updated = state.with_update(
        make_rule_checker_node(_Repository({"SECRET:AWS": "100200"}))(state)
    )
    assert updated.rule.rule_exists is False
    assert "EMAIL_ADDRESS" in updated.rule.generation_reason


def test_no_coverage_at_all_is_not_covered() -> None:
    state = _two_category_state()
    updated = state.with_update(make_rule_checker_node(_Repository())(state))
    assert updated.rule.rule_exists is False


def test_rule_lookup_failure_propagates() -> None:
    state = _two_category_state()
    with pytest.raises(ConnectionError):
        make_rule_checker_node(_Repository(boom=True))(state)


class _Drafter:
    def draft(self, context):
        assert SECRET not in str(context)
        return "<rule id='100200'/>", "no coverage"


class _ExplodingDrafter:
    def draft(self, context):
        raise TimeoutError("model timeout")


def _sensitive_state() -> AlertState:
    state = _state()
    state = state.with_update(state.set_sanitized_prompt("Investigate leaked key <SECRET:AWS>"))
    return state.with_update(
        state.set_sensitive_detection(
            SensitiveDetectionResult(
                contains_sensitive=True,
                detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
                masked_fields=["prompt"],
                risk_level=RiskLevel.CRITICAL,
            )
        )
    )


def test_generated_rule_always_requires_review() -> None:
    state = _sensitive_state()
    state = state.with_update(state.set_rule_result(RuleEngineeringResult(rule_exists=False)))
    updated = state.with_update(make_rule_generator_node(_Drafter())(state))
    assert updated.rule.generated_rule == "<rule id='100200'/>"
    assert updated.rule.requires_rule_review is True


def test_drafting_failure_propagates() -> None:
    state = _sensitive_state()
    state = state.with_update(state.set_rule_result(RuleEngineeringResult(rule_exists=False)))
    with pytest.raises(TimeoutError):
        make_rule_generator_node(_ExplodingDrafter())(state)


# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------


class _Retriever:
    def __init__(self, boom=False):
        self._boom = boom

    def retrieve(self, query):
        if self._boom:
            raise ConnectionError("chroma down")
        return RAGContext(
            retrieval_query=query,
            retrieved_documents=[RetrievedDocument("kb-1", "Rotate keys.", 0.9, "kb")],
        )


class _Intel:
    def investigate(self, context):
        return ThreatIntelResult(investigation_summary="scanning", confidence=0.8)


class _ExplodingIntel:
    def investigate(self, context):
        raise RuntimeError("tavily rate limited")


def _clean_state() -> AlertState:
    state = _state("Investigate repeated failed logins")
    return state.with_update(state.set_sensitive_detection(SensitiveDetectionResult()))


def test_threat_intel_grounds_then_investigates() -> None:
    state = _clean_state()
    updated = state.with_update(make_threat_intel_node(_Intel(), _Retriever())(state))
    assert updated.rag.citations == ["[kb:kb-1]"]
    assert updated.threat_intel.investigation_summary == "scanning"
    assert not updated.execution.errors


def test_retrieval_failure_propagates() -> None:
    state = _clean_state()
    with pytest.raises(ConnectionError):
        make_threat_intel_node(_Intel(), _Retriever(boom=True))(state)


def test_investigation_failure_propagates() -> None:
    state = _clean_state()
    with pytest.raises(RuntimeError, match="tavily rate limited"):
        make_threat_intel_node(_ExplodingIntel(), _Retriever())(state)


# --------------------------------------------------------------------------
# Analyst and dashboard
# --------------------------------------------------------------------------


class _Analyst:
    def analyze(self, context):
        return AnalystResult(
            score=20.0,
            confidence=0.95,
            verdict=Verdict.BENIGN,
            recommendation="Close",
            reasoning="benign",
            requires_human_review=False,
        )


class _ExplodingAnalyst:
    def analyze(self, context):
        raise RuntimeError("ollama down")


def test_analyst_verdict_on_a_sensitive_alert_is_escalated() -> None:
    state = _sensitive_state()
    updated = state.with_update(make_analyst_node(_Analyst())(state))
    assert updated.analysis.verdict is Verdict.BENIGN
    assert updated.analysis.requires_human_review is True


def test_analysis_failure_propagates_without_inventing_a_verdict() -> None:
    state = _clean_state()
    with pytest.raises(RuntimeError, match="ollama down"):
        make_analyst_node(_ExplodingAnalyst())(state)
    assert state.analysis is None


def test_dashboard_drops_documents_keeps_citations_and_closes_the_run() -> None:
    state = _clean_state()
    state = state.with_update(
        state.set_rag_context(
            RAGContext(
                retrieval_query="q",
                retrieved_documents=[RetrievedDocument("kb-1", "body", 0.9, "kb")],
            )
        )
    )
    updated = state.with_update(make_dashboard_node()(state))

    assert updated.rag.retrieved_documents == []
    assert updated.rag.citations == ["[kb:kb-1]"]
    assert updated.execution.is_finished is True
    assert updated.execution.current_node is None
    assert str(NodeName.DASHBOARD) in updated.execution.completed_nodes


@pytest.mark.parametrize(
    "factory",
    [
        lambda: make_rule_checker_node(_Repository()),
        lambda: make_analyst_node(_Analyst()),
        lambda: make_dashboard_node(),
    ],
)
def test_nodes_do_not_mutate_the_state_they_receive(factory) -> None:
    state = _clean_state()
    before = state.to_dict()
    factory()(state)
    assert state.to_dict() == before

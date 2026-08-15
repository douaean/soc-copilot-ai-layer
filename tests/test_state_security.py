"""
Security contract tests for the orchestration state.

These pin the controls implemented in ``app.agents.state``. A control
without a test is a comment, so each of these asserts a property that must
hold for every future change: no LLM payload carries restricted data, the
leak guard fires, human review cannot be bypassed, mutators stay pure, and
prompt release fails closed.

No LLM, no network, no detector binaries are involved.
"""

from __future__ import annotations

import json

import pytest

from app.agents.state import (
    AlertInfo,
    AlertState,
    AnalystResult,
    ContextPolicy,
    DetectedEntity,
    ExecutionMetadata,
    HumanReviewRecord,
    NodeName,
    PromptInfo,
    RAGContext,
    RetrievedDocument,
    RiskLevel,
    RuleEngineeringResult,
    SensitiveDataLeakError,
    SensitiveDetectionResult,
    StateValidationError,
    ThreatIntelResult,
    Verdict,
    requires_human_escalation,
)

SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_EMAIL = "john.doe@corp.example"
RAW_ONLY_SECRET = "hunter2-raw-alert-only"
SENSITIVE_PROMPT = f"Investigate {SECRET_EMAIL} using key {SECRET_KEY}"
CLEAN_PROMPT = "Investigate a burst of failed logins on the bastion host"

RESTRICTED_STRINGS = (SECRET_KEY, SECRET_EMAIL, RAW_ONLY_SECRET)


def _alert() -> AlertInfo:
    return AlertInfo(
        alert_id="alert-0001",
        timestamp="2026-08-10T09:00:00+00:00",
        severity=10,
        hostname="bastion-01",
        agent_name="wazuh-agent-3",
        rule_id="5710",
        raw_alert={"full_log": f"{SECRET_KEY} exposed", "token": RAW_ONLY_SECRET},
        metadata={"index": "wazuh-alerts-2026.08.10"},
    )


def _sensitive_state() -> AlertState:
    """A fully populated state on the sensitive branch."""
    state = AlertState.create(_alert(), SENSITIVE_PROMPT)
    state = state.with_update(
        state.set_sanitized_prompt("Investigate <EMAIL_ADDRESS> using key <SECRET:AWS>")
    )
    detection = SensitiveDetectionResult(
        contains_sensitive=True,
        detected_entities=[
            DetectedEntity("EMAIL_ADDRESS", "presidio", 0.95, start=12, end=33),
            DetectedEntity("SECRET:AWS", "trufflehog", 1.0),
        ],
        masked_fields=["prompt"],
        risk_level=RiskLevel.CRITICAL,
    )
    state = state.with_update(state.set_sensitive_detection(detection))
    state = state.with_update(
        state.set_rule_result(
            RuleEngineeringResult(
                rule_exists=False,
                generated_rule="<rule id='100200' level='12'/>",
                generation_reason="No rule covers AWS key exposure in prompts",
            )
        )
    )
    return state.with_update(
        state.set_rag_context(
            RAGContext(
                retrieval_query="aws key exposure response",
                retrieved_documents=[
                    RetrievedDocument("kb-7", "Rotate leaked keys.", 0.9, "internal_kb")
                ],
            )
        )
    )


def _clean_state() -> AlertState:
    """A fully populated state on the non-sensitive branch."""
    state = AlertState.create(_alert(), CLEAN_PROMPT)
    state = state.with_update(state.set_sensitive_detection(SensitiveDetectionResult()))
    state = state.with_update(
        state.set_ti_result(
            ThreatIntelResult(
                investigation_summary="Credential stuffing pattern",
                risk_score=55.0,
                confidence=0.8,
            )
        )
    )
    return state.with_update(
        state.set_analysis(
            AnalystResult(
                score=55.0,
                confidence=0.8,
                verdict=Verdict.SUSPICIOUS,
                recommendation="Monitor",
                reasoning="Repeated failures from one source",
            ),
            sensitive=state.sensitive,
            rule=state.rule,
        )
    )


# --------------------------------------------------------------------------
# Test 1 — the LLM context never leaks
# --------------------------------------------------------------------------


@pytest.mark.parametrize("consumer", list(NodeName))
def test_llm_context_never_carries_restricted_data_when_sensitive(consumer: NodeName) -> None:
    payload = json.dumps(_sensitive_state().get_llm_context(consumer=consumer))
    for restricted in RESTRICTED_STRINGS:
        assert restricted not in payload
    assert SENSITIVE_PROMPT not in payload


@pytest.mark.parametrize("consumer", list(NodeName))
def test_llm_context_never_carries_raw_alert_when_clean(consumer: NodeName) -> None:
    payload = json.dumps(_clean_state().get_llm_context(consumer=consumer))
    assert RAW_ONLY_SECRET not in payload
    assert SECRET_KEY not in payload


def test_sensitive_prompt_is_replaced_by_the_sanitized_variant() -> None:
    context = _sensitive_state().get_llm_context(consumer=NodeName.ANALYST)
    assert context["prompt"] == "Investigate <EMAIL_ADDRESS> using key <SECRET:AWS>"
    assert context["prompt_is_redacted"] is True


def test_clean_prompt_is_released_unchanged() -> None:
    context = _clean_state().get_llm_context(consumer=NodeName.ANALYST)
    assert context["prompt"] == CLEAN_PROMPT
    assert context["prompt_is_redacted"] is False


def test_entity_types_are_exposed_without_their_values() -> None:
    context = _sensitive_state().get_llm_context(consumer=NodeName.ANALYST)
    assert context["sensitivity"]["entity_types"] == ["EMAIL_ADDRESS", "SECRET:AWS"]


def test_unregistered_consumer_gets_the_closed_default() -> None:
    context = _sensitive_state().get_llm_context(consumer=NodeName.HUMAN_REVIEW)
    for optional in ("rule_status", "rag", "threat_intel", "analysis"):
        assert optional not in context


def test_threat_intel_agent_is_not_shown_its_own_output_or_the_verdict() -> None:
    context = _clean_state().get_llm_context(consumer=NodeName.THREAT_INTEL)
    assert "threat_intel" not in context
    assert "analysis" not in context


def test_analyst_is_shown_threat_intel() -> None:
    assert "threat_intel" in _clean_state().get_llm_context(consumer=NodeName.ANALYST)


def test_policy_override_can_only_narrow() -> None:
    context = _clean_state().get_llm_context(
        consumer=NodeName.ANALYST,
        policy=ContextPolicy(
            include_rule_status=False, include_rag=False, include_threat_intel=False
        ),
    )
    assert "threat_intel" not in context
    assert context["alert"]["alert_id"] == "alert-0001"
    assert "raw_alert" not in context["alert"]


# --------------------------------------------------------------------------
# Test 2 — the leak guard fires
# --------------------------------------------------------------------------


def test_leak_guard_rejects_a_context_containing_the_original_prompt() -> None:
    state = _sensitive_state()
    poisoned = state.get_llm_context(consumer=NodeName.ANALYST)
    poisoned["prompt"] = SENSITIVE_PROMPT
    with pytest.raises(SensitiveDataLeakError, match="original_prompt"):
        state._assert_no_restricted_data(poisoned)


def test_leak_guard_rejects_a_context_containing_the_raw_alert() -> None:
    state = _sensitive_state()
    poisoned = state.get_llm_context(consumer=NodeName.ANALYST)
    poisoned["sensitivity"]["masked_fields"] = [
        json.dumps(state.alert.raw_alert, ensure_ascii=False, default=str, sort_keys=True)
    ]
    with pytest.raises(SensitiveDataLeakError, match="raw_alert value"):
        state._assert_no_restricted_data(poisoned)


def test_leak_guard_rejects_a_single_leaked_raw_alert_field() -> None:
    """A blob comparison misses this; the leaf-by-leaf check must not."""
    state = _sensitive_state()
    poisoned = state.get_llm_context(consumer=NodeName.ANALYST)
    poisoned["sensitivity"]["masked_fields"] = [state.alert.raw_alert["token"]]
    with pytest.raises(SensitiveDataLeakError, match="raw_alert value"):
        state._assert_no_restricted_data(poisoned)


def test_leak_guard_tolerates_fields_the_alert_publishes_deliberately() -> None:
    """A hostname present in both raw_alert and safe metadata is not a leak."""
    alert = AlertInfo(
        alert_id="alert-0002",
        timestamp="2026-08-10T09:00:00+00:00",
        hostname="bastion-01-long-name",
        raw_alert={"agent": {"name": "bastion-01-long-name"}},
    )
    state = AlertState.create(alert, CLEAN_PROMPT)
    state = state.with_update(state.set_sensitive_detection(SensitiveDetectionResult()))
    assert state.get_llm_context(consumer=NodeName.ANALYST)["alert"]["hostname"] == (
        "bastion-01-long-name"
    )


def test_leak_guard_accepts_a_well_formed_context() -> None:
    state = _sensitive_state()
    state._assert_no_restricted_data(state.get_llm_context(consumer=NodeName.ANALYST))


# --------------------------------------------------------------------------
# Test 3 — escalation cannot be bypassed
# --------------------------------------------------------------------------


def _confident_benign() -> AnalystResult:
    return AnalystResult(
        score=5.0,
        confidence=0.99,
        verdict=Verdict.BENIGN,
        recommendation="Close",
        reasoning="Known-good maintenance window",
        requires_human_review=False,
    )


def test_escalation_not_required_when_every_condition_is_clear() -> None:
    assert not requires_human_escalation(
        _confident_benign(), sensitive=None, rule=None, has_errors=False
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"has_errors": True}, id="run-recorded-an-error"),
        pytest.param(
            {"sensitive": SensitiveDetectionResult(
                contains_sensitive=True,
                detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
                risk_level=RiskLevel.CRITICAL,
            )},
            id="alert-is-sensitive",
        ),
        pytest.param(
            {"rule": RuleEngineeringResult(
                rule_exists=False,
                generated_rule="<rule id='1'/>",
                generation_reason="none",
            )},
            id="draft-rule-awaiting-review",
        ),
    ],
)
def test_escalation_required_for_each_trigger(kwargs: dict) -> None:
    base = {"sensitive": None, "rule": None, "has_errors": False} | kwargs
    assert requires_human_escalation(_confident_benign(), **base)


@pytest.mark.parametrize("verdict", [Verdict.MALICIOUS, Verdict.INCONCLUSIVE])
def test_escalation_required_for_high_risk_verdicts(verdict: Verdict) -> None:
    result = AnalystResult(
        score=90.0,
        confidence=0.99,
        verdict=verdict,
        recommendation="Contain",
        reasoning="",
        requires_human_review=False,
    )
    assert requires_human_escalation(result, sensitive=None, rule=None, has_errors=False)


def test_escalation_required_for_low_confidence() -> None:
    result = AnalystResult(
        score=10.0,
        confidence=0.50,
        verdict=Verdict.BENIGN,
        recommendation="Close",
        reasoning="",
        requires_human_review=False,
    )
    assert requires_human_escalation(result, sensitive=None, rule=None, has_errors=False)


def test_set_analysis_cannot_silently_disable_human_review() -> None:
    state = _sensitive_state()
    patch = state.set_analysis(
        _confident_benign(), sensitive=state.sensitive, rule=state.rule
    )
    assert patch["analysis"].requires_human_review is True


def test_set_analysis_leaves_the_callers_object_untouched() -> None:
    state = _sensitive_state()
    result = _confident_benign()
    state.set_analysis(result, sensitive=state.sensitive, rule=state.rule)
    assert result.requires_human_review is False


# --------------------------------------------------------------------------
# Test 4 — mutator purity
# --------------------------------------------------------------------------


def _mutator_calls(state: AlertState) -> dict[str, object]:
    """Every mutator, bound to arguments valid for ``state``."""
    return {
        "set_alert": lambda: state.set_alert(_alert()),
        "set_prompt": lambda: state.set_prompt("a replacement prompt"),
        "set_sanitized_prompt": lambda: state.set_sanitized_prompt("<REDACTED>"),
        "set_sensitive_detection": lambda: state.set_sensitive_detection(
            SensitiveDetectionResult()
        ),
        "set_rule_result": lambda: state.set_rule_result(
            RuleEngineeringResult(rule_exists=True, matched_rule_id="100")
        ),
        "set_rag_context": lambda: state.set_rag_context(RAGContext(retrieval_query="q")),
        "set_analysis": lambda: state.set_analysis(
            _confident_benign(), sensitive=state.sensitive, rule=state.rule
        ),
        "set_human_review": lambda: state.set_human_review(
            HumanReviewRecord(decision="APPROVED", reviewer="analyst@soc")
        ),
        "set_current_node": lambda: state.set_current_node(NodeName.ANALYST),
        "add_completed_node": lambda: state.add_completed_node(NodeName.ANALYST),
        "add_error": lambda: state.add_error(NodeName.ANALYST, "boom"),
        "increment_retry": lambda: state.increment_retry(),
        "finish_execution": lambda: state.finish_execution(),
        "clear_runtime_data": lambda: state.clear_runtime_data(),
        "reset_for_retry": lambda: state.reset_for_retry(NodeName.ANALYST),
    }


@pytest.mark.parametrize("name", list(_mutator_calls(_clean_state())))
def test_mutators_do_not_modify_the_state_they_read(name: str) -> None:
    state = _clean_state()
    before = json.dumps(state.to_dict(), sort_keys=True, default=str)
    _mutator_calls(state)[name]()
    assert json.dumps(state.to_dict(), sort_keys=True, default=str) == before


def test_mutator_patches_are_applied_by_with_update() -> None:
    state = _clean_state()
    updated = state.with_update(state.increment_retry())
    assert updated.execution.retry_count == state.execution.retry_count + 1


def test_get_original_prompt_is_the_documented_impure_exception() -> None:
    state = _clean_state()
    read = state.get_original_prompt(requester="unit-test")
    assert read.value == CLEAN_PROMPT
    assert any("unit-test" in entry for entry in state.execution.sensitive_access_log)
    assert read.update["execution"] is state.execution


# --------------------------------------------------------------------------
# Test 5 — prompt access fails closed
# --------------------------------------------------------------------------


def test_prompt_release_is_refused_before_detection_runs() -> None:
    state = AlertState.create(_alert(), SENSITIVE_PROMPT)
    with pytest.raises(StateValidationError, match="sensitive detection must run"):
        state.get_sanitized_prompt()


def test_sensitive_without_sanitized_variant_returns_a_placeholder() -> None:
    state = AlertState(
        alert=_alert(),
        prompt=PromptInfo.from_prompt(SENSITIVE_PROMPT),
        sensitive=SensitiveDetectionResult(
            contains_sensitive=True,
            detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
            risk_level=RiskLevel.CRITICAL,
        ),
    )
    released = state.get_sanitized_prompt()
    assert SECRET_KEY not in released
    assert released.startswith("[REDACTED]")


def test_clean_detection_releases_the_original_prompt() -> None:
    state = AlertState.create(_alert(), CLEAN_PROMPT)
    state = state.with_update(state.set_sensitive_detection(SensitiveDetectionResult()))
    assert state.get_sanitized_prompt() == CLEAN_PROMPT


def test_detection_cannot_flag_sensitive_without_a_sanitized_prompt() -> None:
    state = AlertState.create(_alert(), SENSITIVE_PROMPT)
    with pytest.raises(StateValidationError, match="sanitized prompt"):
        state.set_sensitive_detection(
            SensitiveDetectionResult(
                contains_sensitive=True,
                detected_entities=[DetectedEntity("SECRET:AWS", "trufflehog", 1.0)],
                risk_level=RiskLevel.CRITICAL,
            )
        )


def test_threat_intel_is_refused_on_the_sensitive_branch() -> None:
    with pytest.raises(StateValidationError, match="sensitive branch"):
        _sensitive_state().set_ti_result(ThreatIntelResult(confidence=0.9))


def test_dashboard_withholds_the_original_prompt_by_default() -> None:
    payload = _sensitive_state().get_dashboard_payload()
    assert SENSITIVE_PROMPT not in json.dumps(payload)
    assert "original" not in payload["prompt"]


def test_dashboard_opt_in_is_audit_logged() -> None:
    state = _sensitive_state()
    payload = state.get_dashboard_payload(include_sensitive=True)
    assert payload["prompt"]["original"] == SENSITIVE_PROMPT
    assert any("dashboard" in entry for entry in state.execution.sensitive_access_log)


# --------------------------------------------------------------------------
# Test 6 — retry invalidation
# --------------------------------------------------------------------------


def test_retrying_threat_intel_preserves_the_rule_branch() -> None:
    state = _sensitive_state()
    patch = state.reset_for_retry(NodeName.THREAT_INTEL)
    assert "rule" not in patch
    assert set(patch) == {"rag", "threat_intel", "analysis", "execution"}


def test_retrying_detection_invalidates_everything_downstream() -> None:
    patch = _sensitive_state().reset_for_retry(NodeName.SENSITIVE_DETECTION)
    assert set(patch) == {"sensitive", "rule", "rag", "threat_intel", "analysis", "execution"}


def test_retry_prunes_completed_nodes_and_bumps_the_counter() -> None:
    state = _sensitive_state()
    state = state.with_update(state.add_completed_node(NodeName.SENSITIVE_DETECTION))
    state = state.with_update(state.add_completed_node(NodeName.RULE_CHECKER))
    execution = state.reset_for_retry(NodeName.RULE_CHECKER)["execution"]
    assert execution.completed_nodes == [str(NodeName.SENSITIVE_DETECTION)]
    assert execution.retry_count == state.execution.retry_count + 1
    assert execution.current_node == str(NodeName.RULE_CHECKER)


def test_retry_rejects_an_unknown_node() -> None:
    with pytest.raises(StateValidationError, match="unknown node name"):
        _clean_state().reset_for_retry("not_a_node")


# --------------------------------------------------------------------------
# Test 7 — serialization round trip
# --------------------------------------------------------------------------


def test_round_trip_through_json_preserves_the_state() -> None:
    state = _sensitive_state()
    state = state.with_update(
        state.set_human_review(HumanReviewRecord(decision="APPROVED", reviewer="soc-1")),
        state.add_error(NodeName.THREAT_INTEL, "timeout"),
        state.finish_execution(),
    )
    original = state.to_dict()
    restored = AlertState.from_dict(json.loads(json.dumps(original)))
    assert restored.to_dict() == original


def test_round_trip_survives_an_empty_state() -> None:
    state = AlertState()
    assert AlertState.from_dict(json.loads(json.dumps(state.to_dict()))).to_dict() == (
        state.to_dict()
    )


def test_incompatible_major_schema_version_is_rejected() -> None:
    payload = _clean_state().to_dict() | {"schema_version": "99.0.0"}
    with pytest.raises(StateValidationError, match="incompatible state schema"):
        AlertState.from_dict(payload)


# --------------------------------------------------------------------------
# Test 8 — with_update validation
# --------------------------------------------------------------------------


def test_with_update_rejects_unknown_state_fields() -> None:
    with pytest.raises(StateValidationError, match="unknown state fields"):
        _clean_state().with_update({"not_a_field": 1})


def test_with_update_merges_patches_left_to_right() -> None:
    state = _clean_state()
    merged = state.with_update(
        state.set_current_node(NodeName.ANALYST),
        {"execution": ExecutionMetadata(thread_id="explicit-thread")},
    )
    assert merged.execution.thread_id == "explicit-thread"

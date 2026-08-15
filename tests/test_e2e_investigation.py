"""
One end-to-end test for the investigation graph.

Scenario: a Claude prompt containing customer PII, where no existing Wazuh
rule covers the detected categories. The run must take the sensitive branch,
draft a rule, produce a verdict, stop for human review, and only reach the
dashboard after the reviewer resumes the same thread.

What is real here: the compiled LangGraph graph, the routing functions, the
state model, the SQLite checkpointer, and **the sensitive-data detection** —
Presidio and TruffleHog actually run.

What is faked: the five collaborators that are not implemented yet, and the
alert itself, because Wazuh/OpenSearch ingestion does not exist. The mock
alert stands in for what that layer will eventually hand the orchestrator.

Why PII rather than an AWS credential: TruffleHog deliberately refuses to
flag known example credentials, so no *fake* secret can drive its detector.
Verified locally — AWS's own documented example key pair yields zero
findings. Exercising the secret path needs a live credential, which does not
belong in a test. Presidio's PII detection drives the same branch honestly.
"""
from __future__ import annotations

import json
import shutil
import sqlite3

import pytest

from app.agents.graph import build_investigation_graph, open_sqlite_checkpointer
from app.agents.state import (
    AlertInfo,
    AlertState,
    AnalystResult,
    DetectedEntity,
    HumanReviewRecord,
    NodeName,
    RiskLevel,
    Verdict,
)

presidio_analyzer = pytest.importorskip(
    "presidio_analyzer",
    reason="real sensitive detection requires: pip install presidio-analyzer "
    "&& python -m spacy download en_core_web_lg",
)

pytestmark = pytest.mark.skipif(
    shutil.which("trufflehog") is None
    and not shutil.os.path.exists("/usr/local/bin/trufflehog"),
    reason="real sensitive detection requires the TruffleHog v3 binary at "
    "/usr/local/bin/trufflehog",
)

from app.sensitive_detection.adapters import DetectorSuiteScanner  # noqa: E402

# Clearly fake values, all reserved-for-documentation or standard test data.
GIT_TOKEN = "ghp_123456789012345678901234567890123456"
TEST_CARD = "4111111111111111"  # the standard non-issuable Visa test number
DOC_IP = "203.0.113.45"  # RFC 5737 documentation range

MOCK_PROMPT = (
    "Please help me debug this payment integration. The failing customer "
    f"record is: name Jane Doe, git token {GIT_TOKEN}, "
    f"card {TEST_CARD}, IP {DOC_IP}."
)

SENSITIVE_VALUES = (GIT_TOKEN, TEST_CARD, DOC_IP)

THREAD_ID = "e2e-sensitive-pii-test"


def mock_wazuh_alert() -> AlertInfo:
    """
    The alert Wazuh/OpenSearch will eventually provide, as an ``AlertInfo``.

    ``raw_alert`` mirrors a real Wazuh document, so it contains the prompt
    and therefore the PII — which is what the real ingestion layer would
    hand over too.
    """
    return AlertInfo(
        alert_id="wazuh-e2e-001",
        timestamp="2026-08-10T09:00:00+00:00",
        source="wazuh",
        severity=12,
        hostname="dev-workstation-14",
        agent_name="wazuh-agent-7",
        rule_id="100100",
        raw_alert={
            "@timestamp": "2026-08-10T09:00:00+00:00",
            "full_log": MOCK_PROMPT,
            "rule": {"id": "100100", "level": 12, "description": "Claude prompt captured"},
            "agent": {"id": "007", "name": "wazuh-agent-7"},
        },
        metadata={"index": "wazuh-alerts-2026.08.10"},
    )


class Recorder:
    """Shared spy: which collaborators ran and what they received."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.llm_payloads: list[tuple[str, str]] = []

    def seen(self, name: str, context: object = None) -> None:
        self.calls.append(name)

        if context is not None:
            self.llm_payloads.append(
                (name, json.dumps(context, default=str))
            )
class FakeRuleRepository:
    """No Wazuh rule covers these categories, so the alert is uncovered."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def find_matching_rules(
        self,
        entities: list[DetectedEntity],
        alert_metadata: dict[str, str | int | None],
    ) -> dict[str, str]:
        self._recorder.seen("rule_checker")
        return {}


class FakeRuleDrafter:
    """Drafts a rule from the sanitized context."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def draft(self, context: dict) -> tuple[str, str]:
        self._recorder.seen("rule_generator", context)
        return (
            "<rule id='100200' level='12'><description>PII in prompt</description></rule>",
            "No existing rule covers the detected PII categories",
        )


class FakeAnalystEngine:
    """Produces the verdict from the sanitized context."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def analyze(self, context: dict) -> AnalystResult:
        self._recorder.seen("analyst", context)
        return AnalystResult(
            score=95.0,
            confidence=0.96,
            verdict=Verdict.MALICIOUS,
            recommendation="Purge the prompt and notify the data-protection officer.",
            reasoning="Customer PII was pasted into a third-party LLM prompt.",
            recommended_actions=["purge_prompt", "notify_dpo"],
        )


class FakeThreatIntelProvider:
    """Must never run: this alert takes the sensitive branch."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def investigate(self, context: dict):  # pragma: no cover - asserted unreachable
        self._recorder.seen("threat_intel", context)
        raise AssertionError("threat intel must not run on the sensitive branch")


class FakeRetriever:
    """Must never run on this path either."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    def retrieve(self, query: str):  # pragma: no cover - asserted unreachable
        self._recorder.seen("retriever")
        raise AssertionError("retrieval must not run on the sensitive branch")


def test_pii_alert_runs_end_to_end_through_human_review(tmp_path) -> None:
    """
    Mock Wazuh alert -> real detection -> rule check -> rule draft -> analyst
    -> interrupt -> resume -> dashboard -> END.
    """
    recorder = Recorder()
    database = "checkpoints_debug.sqlite"
    config = {"configurable": {"thread_id": THREAD_ID}}

    with open_sqlite_checkpointer(str(database)) as checkpointer:
        graph = build_investigation_graph(
            scanner=DetectorSuiteScanner(),  # the real Presidio + TruffleHog suite
            rule_repository=FakeRuleRepository(recorder),
            rule_drafter=FakeRuleDrafter(recorder),
            intel_provider=FakeThreatIntelProvider(recorder),
            analyst_engine=FakeAnalystEngine(recorder),
            retriever=FakeRetriever(recorder),
            checkpointer=checkpointer,
            interrupt_for_review=True,
        )

        alert = mock_wazuh_alert()
        initial = AlertState.create(alert, MOCK_PROMPT, thread_id=alert.alert_id)

        # --- first execution: runs until the human-review interrupt ---------
        graph.invoke(initial, config)

        paused = AlertState(**graph.get_state(config).values)

        assert graph.get_state(config).next == (str(NodeName.DASHBOARD),)
        assert paused.execution.completed_nodes == [
            str(NodeName.SENSITIVE_DETECTION),
            str(NodeName.RULE_CHECKER),
            str(NodeName.RULE_GENERATOR),
            str(NodeName.ANALYST),
        ]
        assert str(NodeName.DASHBOARD) not in paused.execution.completed_nodes
        assert paused.execution.is_finished is False

        # the state was checkpointed to SQLite, not held in memory
        with sqlite3.connect(database) as connection:
            checkpoint_count = connection.execute(
                "select count(*) from checkpoints where thread_id = ?", (THREAD_ID,)
            ).fetchone()[0]
        assert checkpoint_count > 0

        # --- the SOC analyst approves, then the same thread resumes --------
        review = HumanReviewRecord(decision="APPROVED", reviewer="soc-analyst-1")
        graph.update_state(config, paused.set_human_review(review))
        graph.invoke(None, config)

        final = AlertState(**graph.get_state(config).values)
        print("\n" + "=" * 70)
        print("REAL SENSITIVE DATA DETECTION")
        print("=" * 70)

        for entity in final.get_sensitive_entities():
            print(
                f"entity_type={entity.entity_type} | "
                f"detector={entity.detector} | "
                f"confidence={entity.confidence}"
            )

        print("\nSANITIZED PROMPT:")
        print(final.get_sanitized_prompt())

        print("\n" + "=" * 70)
        print("\n" + "=" * 70)
        print("WHAT THE LLM-FACING LAYER RECEIVED")
        print("=" * 70)

        for name, payload in recorder.llm_payloads:
            print(f"\n--- {name.upper()} ---")
            print(json.dumps(
                json.loads(payload),
                indent=2,
                default=str,
            ))

        print("\n" + "=" * 70)
    # --- routing: the sensitive/uncovered path, dashboard only after resume
    assert recorder.calls == ["rule_checker", "rule_generator", "analyst"]
    assert "threat_intel" not in recorder.calls
    assert "retriever" not in recorder.calls
    assert final.execution.completed_nodes == [
        str(NodeName.SENSITIVE_DETECTION),
        str(NodeName.RULE_CHECKER),
        str(NodeName.RULE_GENERATOR),
        str(NodeName.ANALYST),
        str(NodeName.DASHBOARD),
    ]
    assert final.execution.is_finished is True

    # --- what the REAL detectors produced --------------------------------
    # Membership rather than an exact list: Presidio's recognizer set varies
    # with its version and the spaCy model, and pinning the full list would
    # make this a test of Presidio rather than of the orchestration.
    assert final.contains_sensitive_data() is True
    entity_types = final.sensitive.entity_types()
    assert "SECRET:Github" in entity_types
    assert "CREDIT_CARD" in entity_types
    assert final.sensitive.risk_level is RiskLevel.HIGH
    assert final.sensitive.masked_fields == ["prompt"]
    entities = final.get_sensitive_entities()

    assert any(
        e.detector == "presidio"
        for e in entities
    )

    assert any(
        e.detector == "trufflehog"
        and e.entity_type == "SECRET:Github"
        for e in entities
    )

    # --- state propagated from each node to the next ---------------------
    assert final.alert.alert_id == "wazuh-e2e-001"
    assert final.rule.rule_exists is False
    assert "100200" in final.rule.generated_rule
    assert final.rule.requires_rule_review is True
    assert final.analysis.verdict is Verdict.MALICIOUS
    assert final.analysis.requires_human_review is True
    assert final.review.decision == "APPROVED"
    assert final.review.reviewer == "soc-analyst-1"

    # --- security: the PII stays out of every LLM-facing surface ---------
    sanitized = final.get_sanitized_prompt()
    for value in SENSITIVE_VALUES:
        assert value not in sanitized
    assert "<SECRET:Github>" in sanitized
    assert "<CREDIT_CARD>" in sanitized

    entities_json = json.dumps([e.to_dict() for e in final.get_sensitive_entities()])
    dashboard_json = json.dumps(final.get_dashboard_payload(), default=str)
    assert recorder.llm_payloads, "no LLM context was captured"

    for value in SENSITIVE_VALUES:
        assert value not in entities_json
        assert value not in dashboard_json
        for payload in recorder.llm_payloads:
            assert value not in payload
    for payload in recorder.llm_payloads:
        assert MOCK_PROMPT not in payload

    # The original prompt and the raw Wazuh document ARE retained, by design:
    # deterministic consumers and audit need them, and reading the original is
    # audit-logged. This asserts that deliberate boundary rather than pretending
    # the checkpoint is free of sensitive data.
    assert final.get_original_prompt(requester="e2e-test").value == MOCK_PROMPT
    assert final.alert.raw_alert["full_log"] == MOCK_PROMPT

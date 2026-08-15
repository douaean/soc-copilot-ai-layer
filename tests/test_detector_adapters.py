"""
Tests for the detector -> state boundary.

The property under test is that no matched value survives the mapping.
Presidio and TruffleHog are not imported here, so these run on a machine
where neither is installed.
"""

from __future__ import annotations

import json

import pytest

from app.agents.state import RiskLevel
from app.sensitive_detection.adapters import (
    build_detection_result,
    risk_level_for,
    sanitize_prompt,
    to_state_entities,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "john.doe@corp.example"
PROMPT = f"Contact {EMAIL} about key {AWS_KEY}"

PRESIDIO_FINDING = {
    "tool": "Presidio",
    "entity_type": "EMAIL_ADDRESS",
    "value": EMAIL,
    "confidence": 0.95,
    "start": PROMPT.index(EMAIL),
    "end": PROMPT.index(EMAIL) + len(EMAIL),
}

TRUFFLEHOG_FINDING = {
    "tool": "TruffleHog",
    "detector": "AWS",
    "verified": True,
    "secret": "AKIA****EXAMPLE",
    "raw": AWS_KEY,
    "location": {},
    "details": None,
}

TRUFFLEHOG_ERROR = {"tool": "TruffleHog", "error": "binary not found"}


def test_presidio_value_never_reaches_the_entity() -> None:
    entities, errors = to_state_entities([PRESIDIO_FINDING], [])
    assert not errors
    assert EMAIL not in json.dumps([e.to_dict() for e in entities])
    assert entities[0].entity_type == "EMAIL_ADDRESS"
    assert entities[0].detector == "presidio"
    assert (entities[0].start, entities[0].end) == (
        PRESIDIO_FINDING["start"],
        PRESIDIO_FINDING["end"],
    )


def test_trufflehog_raw_and_secret_never_reach_the_entity() -> None:
    entities, errors = to_state_entities([], [TRUFFLEHOG_FINDING])
    assert not errors
    serialized = json.dumps([e.to_dict() for e in entities])
    assert AWS_KEY not in serialized
    assert "AKIA****EXAMPLE" not in serialized
    assert entities[0].entity_type == "SECRET:AWS"
    assert entities[0].detector == "trufflehog"


@pytest.mark.parametrize(
    ("verified", "expected"), [(True, 1.0), (False, 0.5), (None, 0.5)]
)
def test_trufflehog_confidence_is_mapped_conservatively(
    verified: bool | None, expected: float
) -> None:
    entities, _ = to_state_entities([], [TRUFFLEHOG_FINDING | {"verified": verified}])
    assert entities[0].confidence == expected


def test_trufflehog_errors_become_errors_not_entities() -> None:
    entities, errors = to_state_entities([], [TRUFFLEHOG_FINDING, TRUFFLEHOG_ERROR])
    assert len(entities) == 1
    assert errors == ["trufflehog: binary not found"]


def test_unmappable_finding_is_reported_not_dropped() -> None:
    entities, errors = to_state_entities([{"tool": "Presidio"}], [])
    assert not entities
    assert len(errors) == 1
    assert "unmappable" in errors[0]


def test_missing_detector_name_falls_back_without_raising() -> None:
    entities, errors = to_state_entities([], [{"verified": False}])
    assert not errors
    assert entities[0].entity_type == "SECRET:UNKNOWN"


@pytest.mark.parametrize(
    ("presidio_count", "has_secret", "expected"),
    [
        (0, False, RiskLevel.NONE),
        (1, False, RiskLevel.MEDIUM),
        (3, False, RiskLevel.MEDIUM),
        (4, False, RiskLevel.HIGH),
        (0, True, RiskLevel.CRITICAL),
        (9, True, RiskLevel.CRITICAL),
    ],
)
def test_risk_grading_matches_the_correlator_policy(
    presidio_count: int, has_secret: bool, expected: RiskLevel
) -> None:
    presidio = [PRESIDIO_FINDING | {"start": i, "end": i + 1} for i in range(presidio_count)]
    trufflehog = [TRUFFLEHOG_FINDING] if has_secret else []
    entities, _ = to_state_entities(presidio, trufflehog)
    assert risk_level_for(entities) is expected


def test_sanitize_removes_every_detected_value() -> None:
    sanitized = sanitize_prompt(PROMPT, [PRESIDIO_FINDING], [TRUFFLEHOG_FINDING])
    assert EMAIL not in sanitized
    assert AWS_KEY not in sanitized
    assert sanitized == "Contact <EMAIL_ADDRESS> about key <SECRET:AWS>"


def test_sanitize_handles_overlapping_offsets_from_the_end() -> None:
    text = "a@b.com and c@d.com"
    findings = [
        {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 7},
        {"entity_type": "EMAIL_ADDRESS", "start": 12, "end": 19},
    ]
    assert sanitize_prompt(text, findings, []) == "<EMAIL_ADDRESS> and <EMAIL_ADDRESS>"


def test_sanitize_ignores_out_of_range_offsets() -> None:
    findings = [{"entity_type": "EMAIL_ADDRESS", "start": 5, "end": 9_999}]
    assert sanitize_prompt("short", findings, []) == "short"


def test_build_detection_result_produces_a_consistent_verdict() -> None:
    result, sanitized, errors = build_detection_result(
        PROMPT, [PRESIDIO_FINDING], [TRUFFLEHOG_FINDING, TRUFFLEHOG_ERROR]
    )
    assert result.contains_sensitive is True
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.masked_fields == ["prompt"]
    assert AWS_KEY not in sanitized and EMAIL not in sanitized
    assert AWS_KEY not in json.dumps(result.to_dict())
    assert errors == ["trufflehog: binary not found"]


def test_build_detection_result_on_a_clean_prompt() -> None:
    result, sanitized, errors = build_detection_result("nothing to see", [], [])
    assert result.contains_sensitive is False
    assert result.risk_level is RiskLevel.NONE
    assert result.masked_fields == []
    assert sanitized == "nothing to see"
    assert not errors

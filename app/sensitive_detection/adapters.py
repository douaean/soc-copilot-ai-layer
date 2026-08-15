"""
Boundary between detector output and orchestration state.

Presidio and TruffleHog both return the matched secret alongside its
metadata. This module is the only place allowed to see those values: it
uses them transiently to build the sanitized prompt, then discards them.
What crosses into ``app.agents.state`` is location and type, never content.

Nothing here imports Presidio or TruffleHog, so the mapping is importable
and testable on a machine where neither is installed.
"""

from __future__ import annotations

from typing import Any, Final

from app.agents.state import DetectedEntity, RiskLevel, SensitiveDetectionResult

__all__ = [
    "PRESIDIO",
    "TRUFFLEHOG",
    "to_state_entities",
    "risk_level_for",
    "sanitize_prompt",
    "build_detection_result",
    "DetectorSuiteScanner",
]

PRESIDIO: Final[str] = "presidio"
TRUFFLEHOG: Final[str] = "trufflehog"

#: TruffleHog reports a boolean verification, not a score. Mapping it to two
#: fixed points keeps the confidence honest — a finer scale would be invented.
_VERIFIED_CONFIDENCE: Final[float] = 1.0
_UNVERIFIED_CONFIDENCE: Final[float] = 0.5

#: Risk thresholds, preserved from ``SensitiveDataCorrelator.calculate_risk``.
#: The one deviation: an empty result maps to ``NONE`` rather than ``LOW``,
#: because ``SensitiveDetectionResult`` reserves ``NONE`` for "nothing found"
#: and rejects a sensitive verdict carrying it.
_HIGH_PII_COUNT: Final[int] = 3

#: A detector finding is a raw, detector-shaped mapping. Its keys differ per
#: tool and per tool version, so ``Any`` is unavoidable at this boundary.
Finding = dict[str, Any]


def _presidio_entity(finding: Finding) -> DetectedEntity:
    """Map one Presidio finding, dropping its ``value``."""
    return DetectedEntity(
        entity_type=finding["entity_type"],
        detector=PRESIDIO,
        confidence=finding.get("confidence", 0.0),
        field_path="prompt",
        start=finding.get("start"),
        end=finding.get("end"),
    )


def _trufflehog_entity(finding: Finding) -> DetectedEntity:
    """Map one TruffleHog finding, dropping its ``raw`` and ``secret``."""
    detector_name = finding.get("detector") or "UNKNOWN"
    return DetectedEntity(
        entity_type=f"SECRET:{detector_name}",
        detector=TRUFFLEHOG,
        confidence=(
            _VERIFIED_CONFIDENCE if finding.get("verified") else _UNVERIFIED_CONFIDENCE
        ),
        field_path="prompt",
    )


def to_state_entities(
    presidio_results: list[Finding],
    trufflehog_results: list[Finding],
) -> tuple[list[DetectedEntity], list[str]]:
    """
    Convert raw detector findings into state entities and error messages.

    Returns ``(entities, errors)``. TruffleHog mixes error records into the
    same list as findings; those become error strings for the calling node
    to record via ``AlertState.add_error``, never entities with missing
    fields. A finding that cannot be mapped is reported as an error rather
    than silently dropped — a detector whose schema changed must be loud.

    The matched values (``value``, ``raw``, ``secret``) are not read here
    and have no path into the returned entities.
    """
    entities: list[DetectedEntity] = []
    errors: list[str] = []

    for finding in presidio_results or []:
        if "error" in finding:
            errors.append(f"presidio: {finding['error']}")
            continue
        try:
            entities.append(_presidio_entity(finding))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"presidio: unmappable finding ({exc})")

    for finding in trufflehog_results or []:
        if "error" in finding:
            errors.append(f"trufflehog: {finding['error']}")
            continue
        try:
            entities.append(_trufflehog_entity(finding))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"trufflehog: unmappable finding ({exc})")

    return entities, errors


def risk_level_for(entities: list[DetectedEntity]) -> RiskLevel:
    """
    Grade a set of findings, preserving the existing correlator policy.

    Any verified or unverified secret is ``CRITICAL``; more than three PII
    findings is ``HIGH``; any PII is ``MEDIUM``; nothing is ``NONE``.
    """
    if any(entity.detector == TRUFFLEHOG for entity in entities):
        return RiskLevel.CRITICAL
    pii_count = sum(1 for entity in entities if entity.detector == PRESIDIO)
    if pii_count > _HIGH_PII_COUNT:
        return RiskLevel.HIGH
    if pii_count:
        return RiskLevel.MEDIUM
    return RiskLevel.NONE


def _non_overlapping_spans(
    presidio_results: list[Finding], text_length: int
) -> list[Finding]:
    """
    Pick a non-overlapping set of Presidio spans, longest first.

    Preferring the longest span means an ``EMAIL_ADDRESS`` wins over the
    ``URL`` nested in its domain, so the whole address is masked rather than
    only part of it. Returned in descending start order, ready to apply.
    """
    valid = [
        finding
        for finding in presidio_results or []
        if "error" not in finding
        and isinstance(finding.get("start"), int)
        and isinstance(finding.get("end"), int)
        and 0 <= finding["start"] <= finding["end"] <= text_length
    ]

    chosen: list[Finding] = []
    for finding in sorted(valid, key=lambda f: f["end"] - f["start"], reverse=True):
        if any(
            finding["start"] < kept["end"] and kept["start"] < finding["end"]
            for kept in chosen
        ):
            continue
        chosen.append(finding)

    return sorted(chosen, key=lambda f: f["start"], reverse=True)


def sanitize_prompt(
    text: str,
    presidio_results: list[Finding],
    trufflehog_results: list[Finding],
) -> str:
    """
    Return ``text`` with every detected value replaced by a type placeholder.

    Presidio routinely returns overlapping spans — an ``EMAIL_ADDRESS`` and
    the ``URL`` nested inside its domain, for example. Replacing both would
    corrupt the text, because rewriting the inner span invalidates the outer
    span's offsets. Overlaps are therefore resolved first, keeping the
    longest span so the most complete value is masked, and the survivors are
    applied right to left so earlier offsets stay valid.

    TruffleHog reports no offsets into the prompt, so its ``raw`` value is
    matched literally; that value is used here and then dropped, which is
    the only legitimate use of a detected secret.
    """
    sanitized = text

    for finding in _non_overlapping_spans(presidio_results, len(text)):
        start, end = finding["start"], finding["end"]
        sanitized = f"{sanitized[:start]}<{finding['entity_type']}>{sanitized[end:]}"

    for finding in trufflehog_results or []:
        if "error" in finding:
            continue
        secret = finding.get("raw") or finding.get("secret")
        if not secret:
            continue
        placeholder = f"<SECRET:{finding.get('detector') or 'UNKNOWN'}>"
        sanitized = sanitized.replace(str(secret), placeholder)

    return sanitized


def build_detection_result(
    text: str,
    presidio_results: list[Finding],
    trufflehog_results: list[Finding],
) -> tuple[SensitiveDetectionResult, str, list[str]]:
    """
    Build the full detection outcome for the sensitive-detection node.

    Returns ``(result, sanitized_prompt, errors)``. The sanitized prompt is
    produced unconditionally so that the node can store it before flagging
    the alert sensitive, which ``AlertState.set_sensitive_detection``
    requires.
    """
    entities, errors = to_state_entities(presidio_results, trufflehog_results)
    sanitized = sanitize_prompt(text, presidio_results, trufflehog_results)
    result = SensitiveDetectionResult(
        contains_sensitive=bool(entities),
        detected_entities=entities,
        masked_fields=["prompt"] if entities else [],
        risk_level=risk_level_for(entities),
    )
    return result, sanitized, errors


class DetectorSuiteScanner:
    """
    Runs both detectors and returns state models.

    Implements the ``SensitiveScanner`` protocol expected by the
    sensitive-detection node. Presidio and TruffleHog are imported lazily
    in :meth:`__init__` so that importing this module — and therefore the
    graph — does not require either to be installed.
    """

    def __init__(self, pii_detector: object | None = None, secret_detector: object | None = None):
        """Build the suite, constructing the real detectors when not injected."""
        if pii_detector is None:
            from .presidio import PresidioDetector

            pii_detector = PresidioDetector()
        if secret_detector is None:
            from .trufflehog import TruffleHogDetector

            secret_detector = TruffleHogDetector()
        self._pii = pii_detector
        self._secrets = secret_detector

    def scan(self, text: str) -> tuple[SensitiveDetectionResult, str, list[str]]:
        """
        Scan ``text`` with both detectors and normalize the outcome.

        A detector that cannot run raises. Silently degrading to PII-only
        detection would mean a missing TruffleHog binary quietly stops
        finding secrets, which is indistinguishable from finding none.
        Problems the detectors report while still returning results are
        passed back as errors instead.
        """
        presidio_results = self._pii.detect(text)
        trufflehog_results = self._secrets.detect(text)
        return build_detection_result(text, presidio_results, trufflehog_results)

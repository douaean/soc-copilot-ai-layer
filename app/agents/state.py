"""
Orchestration layer — shared LangGraph state for the SOC Copilot.

Responsibility (and ONLY responsibility):
    Define the typed, checkpointable state object that flows between
    LangGraph nodes, together with the *only* sanctioned API for reading
    and writing it.

Design contract:
    - Nodes never touch dataclass attributes directly. They call the
      mutator helpers, which validate the write and return a LangGraph
      update patch.
    - **Every mutator is pure.** It reads ``self``, validates, and returns
      the patch. It never assigns to ``self``. The returned patch is the
      single source of truth that LangGraph applies to the checkpoint, so
      a node that drops the return value changes nothing — loudly, in the
      next node, rather than subtly at the next resume.
    - The one deliberate exception is :meth:`AlertState.get_original_prompt`,
      whose audit record must survive a caller that discards the patch.
      It is typed differently (:class:`AuditedRead`) so the exception is
      visible at every call site.
    - Deterministic consumers (rule checker, dashboard, audit, logging)
      may read the original alert and prompt through explicit,
      audit-logged accessors.
    - LLM-backed agents read the state through exactly one method,
      :meth:`AlertState.get_llm_context`, which structurally cannot
      return ``original_prompt`` or ``raw_alert``.

Everything here is standard library only, so the whole object graph
round-trips through LangGraph's JSON checkpoint serializer and lands in
SQLite as plain primitives.

Milestone: M8.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Self, TypeAlias, TypedDict

__all__ = [
    "SCHEMA_VERSION",
    "StateValidationError",
    "SensitiveDataLeakError",
    "RiskLevel",
    "Verdict",
    "ReviewDecision",
    "NodeName",
    "AlertInfo",
    "PromptInfo",
    "DetectedEntity",
    "SensitiveDetectionResult",
    "RuleEngineeringResult",
    "RetrievedDocument",
    "RAGContext",
    "MitreTechnique",
    "Indicator",
    "ThreatIntelResult",
    "AnalystResult",
    "HumanReviewRecord",
    "ExecutionError",
    "ExecutionMetadata",
    "LLMContext",
    "ContextPolicy",
    "AuditedRead",
    "requires_human_escalation",
    "AlertState",
]

SCHEMA_VERSION: Final[str] = "1.0.0"
GRAPH_VERSION: Final[str] = "1.0.0"
CHECKPOINT_VERSION: Final[str] = "1"

_MITRE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MAX_SEVERITY: Final[int] = 15
_LOW_CONFIDENCE_ESCALATION_THRESHOLD: Final[float] = 0.70

#: A partial LangGraph channel update. Values are the state's own
#: dataclasses, which cannot be enumerated in a single precise type
#: without an unwieldy union, so ``Any`` is deliberate and contained.
StateUpdate: TypeAlias = dict[str, Any]

#: Raw alert documents come straight from OpenSearch and have no fixed
#: schema across Wazuh decoders, so ``Any`` is unavoidable here.
RawAlert: TypeAlias = dict[str, Any]


class StateValidationError(ValueError):
    """Raised when a node attempts to write structurally invalid state."""


class SensitiveDataLeakError(RuntimeError):
    """Raised when an LLM-bound payload is found to carry restricted data."""


class RiskLevel(StrEnum):
    """Ordered sensitivity/risk classification shared across nodes."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Return a comparable integer rank, ``NONE`` being 0."""
        return _RISK_ORDER[self]


_RISK_ORDER: Final[dict[RiskLevel, int]] = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class Verdict(StrEnum):
    """Final triage decision produced by the analyst agent."""

    BENIGN = "BENIGN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class ReviewDecision(StrEnum):
    """Outcome of the human SOC analyst review gate."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    MODIFIED = "MODIFIED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"


class NodeName(StrEnum):
    """Canonical LangGraph node identifiers."""

    INGESTION = "ingestion"
    SENSITIVE_DETECTION = "sensitive_detection"
    RULE_CHECKER = "rule_checker"
    RULE_GENERATOR = "rule_generator"
    THREAT_INTEL = "threat_intel"
    ANALYST = "analyst"
    DASHBOARD = "dashboard"
    HUMAN_REVIEW = "human_review"


#: Shortest raw-alert string the leak guard will match on. Below this,
#: incidental collisions ("wazuh", "root", a small integer) outnumber real
#: leaks and the guard would block legitimate payloads.
_MIN_LEAK_MATCH_LENGTH: Final[int] = 8


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def _string_leaves(value: object) -> Iterator[str]:
    """Yield every string leaf of a nested mapping/sequence structure."""
    match value:
        case str():
            yield value
        case dict():
            for nested in value.values():
                yield from _string_leaves(nested)
        case list() | tuple():
            for nested in value:
                yield from _string_leaves(nested)


def _non_empty(value: str, label: str) -> str:
    """Return ``value`` stripped, rejecting blank strings."""
    cleaned = value.strip() if isinstance(value, str) else ""
    if not cleaned:
        raise StateValidationError(f"{label} must be a non-empty string")
    return cleaned


def _unit_interval(value: float, label: str) -> float:
    """Return ``value`` as a float, rejecting anything outside [0.0, 1.0]."""
    numeric = float(value)
    if not 0.0 <= numeric <= 1.0:
        raise StateValidationError(f"{label} must be within [0.0, 1.0], got {numeric}")
    return numeric


def _bounded(value: float, low: float, high: float, label: str) -> float:
    """Return ``value`` as a float, rejecting anything outside [low, high]."""
    numeric = float(value)
    if not low <= numeric <= high:
        raise StateValidationError(
            f"{label} must be within [{low}, {high}], got {numeric}"
        )
    return numeric


@dataclass(slots=True)
class AlertInfo:
    """
    Immutable-by-convention description of the Wazuh alert under triage.

    ``raw_alert`` is the untouched OpenSearch document. It is retained for
    deterministic consumers and audit, and is never surfaced to an LLM.
    """

    alert_id: str
    timestamp: str
    source: str = "wazuh"
    severity: int = 0
    hostname: str | None = None
    agent_name: str | None = None
    rule_id: str | None = None
    raw_alert: RawAlert = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.alert_id = _non_empty(self.alert_id, "alert_id")
        self.timestamp = _non_empty(self.timestamp, "timestamp")
        self.source = _non_empty(self.source, "source")
        self.severity = int(_bounded(self.severity, 0, _MAX_SEVERITY, "severity"))
        if self.rule_id is not None:
            self.rule_id = _non_empty(self.rule_id, "rule_id")

    @property
    def severity_label(self) -> RiskLevel:
        """Map the numeric Wazuh rule level onto a :class:`RiskLevel`."""
        if self.severity >= 12:
            return RiskLevel.CRITICAL
        if self.severity >= 9:
            return RiskLevel.HIGH
        if self.severity >= 5:
            return RiskLevel.MEDIUM
        if self.severity >= 1:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def safe_metadata(self) -> dict[str, str | int | None]:
        """Return the LLM-safe subset of alert attributes, excluding the raw document."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "severity_label": str(self.severity_label),
            "hostname": self.hostname,
            "agent_name": self.agent_name,
            "rule_id": self.rule_id,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "severity": self.severity,
            "hostname": self.hostname,
            "agent_name": self.agent_name,
            "rule_id": self.rule_id,
            "raw_alert": self.raw_alert,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            alert_id=data["alert_id"],
            timestamp=data["timestamp"],
            source=data.get("source", "wazuh"),
            severity=data.get("severity", 0),
            hostname=data.get("hostname"),
            agent_name=data.get("agent_name"),
            rule_id=data.get("rule_id"),
            raw_alert=dict(data.get("raw_alert") or {}),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(slots=True)
class PromptInfo:
    """
    The Claude-prompt payload extracted from the alert, in both forms.

    ``original_prompt`` is restricted: only deterministic consumers may
    read it, and only through :meth:`AlertState.get_original_prompt`.
    ``sanitized_prompt`` is the single form any LLM is allowed to see and
    stays ``None`` until the sensitive-detection node has run.
    """

    original_prompt: str
    prompt_hash: str
    sanitized_prompt: str | None = None
    prompt_language: str = "en"

    def __post_init__(self) -> None:
        self.original_prompt = _non_empty(self.original_prompt, "original_prompt")
        self.prompt_hash = _non_empty(self.prompt_hash, "prompt_hash")
        self.prompt_language = _non_empty(self.prompt_language, "prompt_language").lower()
        if not 2 <= len(self.prompt_language) <= 3:
            raise StateValidationError(
                "prompt_language must be a 2- or 3-letter ISO code"
            )
        if self.sanitized_prompt is not None:
            self.sanitized_prompt = self.sanitized_prompt.strip()

    @classmethod
    def from_prompt(cls, prompt: str, *, language: str = "en") -> Self:
        """Build an instance from a raw prompt, deriving its SHA-256 hash."""
        text = _non_empty(prompt, "prompt")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return cls(original_prompt=text, prompt_hash=digest, prompt_language=language)

    @property
    def is_sanitized(self) -> bool:
        """Return whether a sanitized variant has been produced."""
        return self.sanitized_prompt is not None

    @property
    def was_modified(self) -> bool:
        """Return whether sanitization actually altered the prompt text."""
        return self.is_sanitized and self.sanitized_prompt != self.original_prompt

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "original_prompt": self.original_prompt,
            "prompt_hash": self.prompt_hash,
            "sanitized_prompt": self.sanitized_prompt,
            "prompt_language": self.prompt_language,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            original_prompt=data["original_prompt"],
            prompt_hash=data["prompt_hash"],
            sanitized_prompt=data.get("sanitized_prompt"),
            prompt_language=data.get("prompt_language", "en"),
        )


@dataclass(frozen=True, slots=True)
class DetectedEntity:
    """
    One sensitive finding, described *without* its value.

    The matched secret or PII string is deliberately absent: storing it
    would place confidential data in every SQLite checkpoint and in every
    payload derived from the state. Location and type are enough for the
    rule checker, the dashboard and the audit trail.
    """

    entity_type: str
    detector: str
    confidence: float
    field_path: str = "prompt"
    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_type", _non_empty(self.entity_type, "entity_type"))
        object.__setattr__(self, "detector", _non_empty(self.detector, "detector"))
        object.__setattr__(self, "confidence", _unit_interval(self.confidence, "confidence"))
        object.__setattr__(self, "field_path", _non_empty(self.field_path, "field_path"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "entity_type": self.entity_type,
            "detector": self.detector,
            "confidence": self.confidence,
            "field_path": self.field_path,
            "start": self.start,
            "end": self.end,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            entity_type=data["entity_type"],
            detector=data["detector"],
            confidence=data["confidence"],
            field_path=data.get("field_path", "prompt"),
            start=data.get("start"),
            end=data.get("end"),
        )


@dataclass(slots=True)
class SensitiveDetectionResult:
    """
    Verdict of the Presidio/TruffleHog correlation stage.

    ``contains_sensitive`` is the routing signal for the whole graph and
    the gate that :meth:`AlertState.get_llm_context` enforces.
    """

    contains_sensitive: bool = False
    detected_entities: list[DetectedEntity] = field(default_factory=list)
    masked_fields: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NONE
    detected_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        self.risk_level = RiskLevel(self.risk_level)
        if self.detected_entities and not self.contains_sensitive:
            raise StateValidationError(
                "contains_sensitive must be True when detected_entities is non-empty"
            )
        if self.contains_sensitive and self.risk_level is RiskLevel.NONE:
            raise StateValidationError(
                "risk_level must be above NONE when sensitive data is present"
            )

    def entity_types(self) -> list[str]:
        """Return the distinct entity type names, sorted and value-free."""
        return sorted({entity.entity_type for entity in self.detected_entities})

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "contains_sensitive": self.contains_sensitive,
            "detected_entities": [e.to_dict() for e in self.detected_entities],
            "masked_fields": self.masked_fields,
            "risk_level": str(self.risk_level),
            "detected_at": self.detected_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            contains_sensitive=data.get("contains_sensitive", False),
            detected_entities=[
                DetectedEntity.from_dict(e) for e in data.get("detected_entities") or []
            ],
            masked_fields=list(data.get("masked_fields") or []),
            risk_level=RiskLevel(data.get("risk_level", RiskLevel.NONE)),
            detected_at=data.get("detected_at", _utc_now()),
        )


@dataclass(slots=True)
class RuleEngineeringResult:
    """
    Output of the rule-checker and draft-rule-generator nodes.

    Kept separate from detection because it answers a different question:
    detection asks *what* leaked, rule engineering asks *whether Wazuh
    already catches it* and what rule would.
    """

    rule_exists: bool = False
    matched_rule_id: str | None = None
    generated_rule: str | None = None
    generation_reason: str | None = None
    rule_format: str = "wazuh-xml"
    requires_rule_review: bool = False

    def __post_init__(self) -> None:
        if self.rule_exists and not self.matched_rule_id:
            raise StateValidationError(
                "matched_rule_id is required when rule_exists is True"
            )
        if self.generated_rule is not None:
            self.generated_rule = _non_empty(self.generated_rule, "generated_rule")
            if not self.generation_reason:
                raise StateValidationError(
                    "generation_reason is required when a rule is generated"
                )
            self.requires_rule_review = True

    @property
    def rule_status(self) -> str:
        """Return a short, LLM-safe description of coverage status."""
        if self.rule_exists:
            return f"covered_by_rule:{self.matched_rule_id}"
        if self.generated_rule:
            return "draft_rule_generated"
        return "no_coverage"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "rule_exists": self.rule_exists,
            "matched_rule_id": self.matched_rule_id,
            "generated_rule": self.generated_rule,
            "generation_reason": self.generation_reason,
            "rule_format": self.rule_format,
            "requires_rule_review": self.requires_rule_review,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            rule_exists=data.get("rule_exists", False),
            matched_rule_id=data.get("matched_rule_id"),
            generated_rule=data.get("generated_rule"),
            generation_reason=data.get("generation_reason"),
            rule_format=data.get("rule_format", "wazuh-xml"),
            requires_rule_review=data.get("requires_rule_review", False),
        )


@dataclass(frozen=True, slots=True)
class RetrievedDocument:
    """A single chunk returned by the vector store, with its provenance."""

    doc_id: str
    content: str
    score: float
    source: str
    title: str | None = None
    uri: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "doc_id", _non_empty(self.doc_id, "doc_id"))
        object.__setattr__(self, "source", _non_empty(self.source, "source"))
        object.__setattr__(self, "score", _unit_interval(self.score, "score"))

    def citation(self) -> str:
        """Return a compact, human-checkable citation label."""
        return f"[{self.source}:{self.doc_id}]"

    def excerpt(self, max_chars: int = 400) -> str:
        """Return the content truncated to ``max_chars`` for prompt assembly."""
        text = " ".join(self.content.split())
        return text if len(text) <= max_chars else f"{text[: max_chars - 1]}…"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "doc_id": self.doc_id,
            "content": self.content,
            "score": self.score,
            "source": self.source,
            "title": self.title,
            "uri": self.uri,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            doc_id=data["doc_id"],
            content=data.get("content", ""),
            score=data.get("score", 0.0),
            source=data["source"],
            title=data.get("title"),
            uri=data.get("uri"),
        )


@dataclass(slots=True)
class RAGContext:
    """
    Grounding material retrieved from the internal knowledge base.

    Deliberately independent from :class:`ThreatIntelResult`: this is
    *evidence*, not *conclusions*. Both the threat-intel agent and the
    analyst agent consume it, and either may refresh it without
    invalidating the other's findings.
    """

    retrieval_query: str = ""
    retrieved_documents: list[RetrievedDocument] = field(default_factory=list)
    document_scores: dict[str, float] = field(default_factory=dict)
    knowledge_sources: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    retrieved_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not self.document_scores:
            self.document_scores = {d.doc_id: d.score for d in self.retrieved_documents}
        if not self.knowledge_sources:
            self.knowledge_sources = sorted({d.source for d in self.retrieved_documents})
        if not self.citations:
            self.citations = [d.citation() for d in self.retrieved_documents]

    @property
    def is_empty(self) -> bool:
        """Return whether retrieval produced no grounding documents."""
        return not self.retrieved_documents

    def top_documents(self, limit: int = 5) -> list[RetrievedDocument]:
        """Return the highest-scoring documents, best first."""
        return sorted(self.retrieved_documents, key=lambda d: d.score, reverse=True)[:limit]

    def llm_summary(self, *, limit: int = 5, max_chars: int = 400) -> list[dict[str, str]]:
        """Return a citation-tagged digest of the top documents for prompt assembly."""
        return [
            {
                "citation": doc.citation(),
                "title": doc.title or doc.doc_id,
                "excerpt": doc.excerpt(max_chars),
            }
            for doc in self.top_documents(limit)
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "retrieval_query": self.retrieval_query,
            "retrieved_documents": [d.to_dict() for d in self.retrieved_documents],
            "document_scores": self.document_scores,
            "knowledge_sources": self.knowledge_sources,
            "citations": self.citations,
            "retrieved_at": self.retrieved_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            retrieval_query=data.get("retrieval_query", ""),
            retrieved_documents=[
                RetrievedDocument.from_dict(d) for d in data.get("retrieved_documents") or []
            ],
            document_scores=dict(data.get("document_scores") or {}),
            knowledge_sources=list(data.get("knowledge_sources") or []),
            citations=list(data.get("citations") or []),
            retrieved_at=data.get("retrieved_at", _utc_now()),
        )


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """An ATT&CK technique attribution with its supporting confidence."""

    technique_id: str
    name: str
    tactic: str | None = None
    confidence: float = 0.0

    def __post_init__(self) -> None:
        technique_id = _non_empty(self.technique_id, "technique_id").upper()
        if not _MITRE_PATTERN.match(technique_id):
            raise StateValidationError(
                f"technique_id must match Txxxx or Txxxx.yyy, got {technique_id!r}"
            )
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "name", _non_empty(self.name, "name"))
        object.__setattr__(self, "confidence", _unit_interval(self.confidence, "confidence"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            technique_id=data["technique_id"],
            name=data["name"],
            tactic=data.get("tactic"),
            confidence=data.get("confidence", 0.0),
        )


@dataclass(frozen=True, slots=True)
class Indicator:
    """An indicator of compromise with its enrichment verdict."""

    ioc_type: str
    value: str
    verdict: str = "unknown"
    source: str | None = None
    confidence: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "ioc_type", _non_empty(self.ioc_type, "ioc_type").lower())
        object.__setattr__(self, "value", _non_empty(self.value, "value"))
        object.__setattr__(self, "confidence", _unit_interval(self.confidence, "confidence"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "verdict": self.verdict,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            ioc_type=data["ioc_type"],
            value=data["value"],
            verdict=data.get("verdict", "unknown"),
            source=data.get("source"),
            confidence=data.get("confidence", 0.0),
        )


@dataclass(slots=True)
class ThreatIntelResult:
    """
    Conclusions of the threat-intelligence agent.

    Populated only on the non-sensitive branch, where Tavily, the MITRE
    mapper and IOC enrichment are allowed to run.
    """

    investigation_summary: str = ""
    mitre_techniques: list[MitreTechnique] = field(default_factory=list)
    detected_iocs: list[Indicator] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 0.0
    external_sources: list[str] = field(default_factory=list)
    completed_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        self.risk_score = _bounded(self.risk_score, 0.0, 100.0, "risk_score")
        self.confidence = _unit_interval(self.confidence, "confidence")

    def technique_ids(self) -> list[str]:
        """Return the attributed ATT&CK technique identifiers."""
        return [t.technique_id for t in self.mitre_techniques]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "investigation_summary": self.investigation_summary,
            "mitre_techniques": [t.to_dict() for t in self.mitre_techniques],
            "detected_iocs": [i.to_dict() for i in self.detected_iocs],
            "references": self.references,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "external_sources": self.external_sources,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            investigation_summary=data.get("investigation_summary", ""),
            mitre_techniques=[
                MitreTechnique.from_dict(t) for t in data.get("mitre_techniques") or []
            ],
            detected_iocs=[Indicator.from_dict(i) for i in data.get("detected_iocs") or []],
            references=list(data.get("references") or []),
            risk_score=data.get("risk_score", 0.0),
            confidence=data.get("confidence", 0.0),
            external_sources=list(data.get("external_sources") or []),
            completed_at=data.get("completed_at", _utc_now()),
        )


@dataclass(slots=True)
class AnalystResult:
    """
    Final triage decision of the analyst agent.

    ``requires_human_review`` is the contract with the review gate and may
    be raised — never lowered — by the orchestration policy.
    """

    score: float = 0.0
    confidence: float = 0.0
    verdict: Verdict = Verdict.INCONCLUSIVE
    recommendation: str = ""
    reasoning: str = ""
    requires_human_review: bool = True
    recommended_actions: list[str] = field(default_factory=list)
    completed_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        self.score = _bounded(self.score, 0.0, 100.0, "score")
        self.confidence = _unit_interval(self.confidence, "confidence")
        self.verdict = Verdict(self.verdict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "score": self.score,
            "confidence": self.confidence,
            "verdict": str(self.verdict),
            "recommendation": self.recommendation,
            "reasoning": self.reasoning,
            "requires_human_review": self.requires_human_review,
            "recommended_actions": self.recommended_actions,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            score=data.get("score", 0.0),
            confidence=data.get("confidence", 0.0),
            verdict=Verdict(data.get("verdict", Verdict.INCONCLUSIVE)),
            recommendation=data.get("recommendation", ""),
            reasoning=data.get("reasoning", ""),
            requires_human_review=data.get("requires_human_review", True),
            recommended_actions=list(data.get("recommended_actions") or []),
            completed_at=data.get("completed_at", _utc_now()),
        )


@dataclass(slots=True)
class HumanReviewRecord:
    """Decision recorded at the human SOC analyst review gate."""

    decision: ReviewDecision = ReviewDecision.PENDING
    reviewer: str | None = None
    comments: str = ""
    override_verdict: Verdict | None = None
    reviewed_at: str | None = None

    def __post_init__(self) -> None:
        self.decision = ReviewDecision(self.decision)
        if self.override_verdict is not None:
            self.override_verdict = Verdict(self.override_verdict)
        if self.decision is not ReviewDecision.PENDING and not self.reviewer:
            raise StateValidationError("reviewer is required once a decision is recorded")

    @property
    def is_pending(self) -> bool:
        """Return whether the review gate is still awaiting a human."""
        return self.decision is ReviewDecision.PENDING

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "decision": str(self.decision),
            "reviewer": self.reviewer,
            "comments": self.comments,
            "override_verdict": str(self.override_verdict) if self.override_verdict else None,
            "reviewed_at": self.reviewed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        override = data.get("override_verdict")
        return cls(
            decision=ReviewDecision(data.get("decision", ReviewDecision.PENDING)),
            reviewer=data.get("reviewer"),
            comments=data.get("comments", ""),
            override_verdict=Verdict(override) if override else None,
            reviewed_at=data.get("reviewed_at"),
        )


@dataclass(frozen=True, slots=True)
class ExecutionError:
    """A single node failure, retained for debugging and audit."""

    node: str
    message: str
    error_type: str = "RuntimeError"
    recoverable: bool = True
    occurred_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node", _non_empty(self.node, "node"))
        object.__setattr__(self, "message", _non_empty(self.message, "message"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "node": self.node,
            "message": self.message,
            "error_type": self.error_type,
            "recoverable": self.recoverable,
            "occurred_at": self.occurred_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            node=data["node"],
            message=data["message"],
            error_type=data.get("error_type", "RuntimeError"),
            recoverable=data.get("recoverable", True),
            occurred_at=data.get("occurred_at", _utc_now()),
        )


@dataclass(slots=True)
class ExecutionMetadata:
    """
    Bookkeeping for one graph run: where we are, where we have been,
    what failed, and every access to restricted data.

    Kept apart from the domain results so that replaying or resuming a
    run never rewrites the investigation itself.
    """

    thread_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    current_node: str | None = None
    completed_nodes: list[str] = field(default_factory=list)
    execution_start: str = field(default_factory=_utc_now)
    execution_end: str | None = None
    execution_time: float | None = None
    errors: list[ExecutionError] = field(default_factory=list)
    retry_count: int = 0
    graph_version: str = GRAPH_VERSION
    checkpoint_version: str = CHECKPOINT_VERSION
    sensitive_access_log: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.thread_id = _non_empty(self.thread_id, "thread_id")
        if self.retry_count < 0:
            raise StateValidationError("retry_count must not be negative")

    @property
    def is_finished(self) -> bool:
        """Return whether the run has been closed by ``finish_execution``."""
        return self.execution_end is not None

    @property
    def has_errors(self) -> bool:
        """Return whether any node reported a failure."""
        return bool(self.errors)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "thread_id": self.thread_id,
            "current_node": self.current_node,
            "completed_nodes": self.completed_nodes,
            "execution_start": self.execution_start,
            "execution_end": self.execution_end,
            "execution_time": self.execution_time,
            "errors": [e.to_dict() for e in self.errors],
            "retry_count": self.retry_count,
            "graph_version": self.graph_version,
            "checkpoint_version": self.checkpoint_version,
            "sensitive_access_log": self.sensitive_access_log,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Rebuild an instance from :meth:`to_dict` output."""
        return cls(
            thread_id=data.get("thread_id") or str(uuid.uuid4()),
            current_node=data.get("current_node"),
            completed_nodes=list(data.get("completed_nodes") or []),
            execution_start=data.get("execution_start") or _utc_now(),
            execution_end=data.get("execution_end"),
            execution_time=data.get("execution_time"),
            errors=[ExecutionError.from_dict(e) for e in data.get("errors") or []],
            retry_count=data.get("retry_count", 0),
            graph_version=data.get("graph_version", GRAPH_VERSION),
            checkpoint_version=data.get("checkpoint_version", CHECKPOINT_VERSION),
            sensitive_access_log=list(data.get("sensitive_access_log") or []),
        )


class LLMContext(TypedDict, total=False):
    """
    The only shape an LLM-backed agent ever receives.

    By construction it has no field capable of carrying ``original_prompt``
    or ``raw_alert``; the absence of those keys is the guarantee.
    """

    consumer: str
    schema_version: str
    alert: dict[str, str | int | None]
    prompt: str
    prompt_hash: str
    prompt_language: str
    prompt_is_redacted: bool
    sensitivity: dict[str, Any]
    rule_status: dict[str, Any]
    rag: dict[str, Any]
    threat_intel: dict[str, Any]
    analysis: dict[str, Any]


_SENSITIVE_PROMPT_UNAVAILABLE: Final[str] = (
    "[REDACTED] The originating prompt contained confidential data and cannot be "
    "disclosed. Reason about the alert metadata and detected entity types only."
)

_PROMPT_UNAVAILABLE: Final[str] = "[UNAVAILABLE] The prompt has not been classified yet."


@dataclass(frozen=True, slots=True)
class ContextPolicy:
    """
    Declarative allow-list describing what one LLM consumer may receive.

    Adding an agent means adding a policy entry, not another branch inside
    :meth:`AlertState.get_llm_context`. The alert metadata, the sanitized
    prompt and the sensitivity summary are unconditional and therefore not
    expressible here — no policy can switch them off, and none can switch
    the restricted fields on.
    """

    include_rule_status: bool = True
    include_rag: bool = True
    include_threat_intel: bool = True
    include_analysis: bool = False
    max_documents: int = 5

    def __post_init__(self) -> None:
        if self.max_documents < 0:
            raise StateValidationError("max_documents must not be negative")


#: The threat-intel agent gets no threat-intel section (it produces it) and
#: no analyst section (which would anchor its independent investigation).
_CONTEXT_POLICIES: Final[dict[str, ContextPolicy]] = {
    str(NodeName.THREAT_INTEL): ContextPolicy(
        include_threat_intel=False,
        include_analysis=False,
    ),
    str(NodeName.ANALYST): ContextPolicy(
        include_threat_intel=True,
        include_analysis=True,
    ),
    str(NodeName.RULE_GENERATOR): ContextPolicy(
        include_rag=True,
        include_threat_intel=False,
        include_analysis=False,
        max_documents=3,
    ),
}

_DEFAULT_CONTEXT_POLICY: Final[ContextPolicy] = ContextPolicy(
    include_rule_status=False,
    include_rag=False,
    include_threat_intel=False,
    include_analysis=False,
)


@dataclass(frozen=True, slots=True)
class AuditedRead:
    """
    The result of reading a restricted field: the value and its audit patch.

    Returned instead of a bare ``str`` so that the audit obligation is
    visible in the type. ``value`` is the confidential text; ``update`` is
    the patch recording the access, which the calling node should merge
    into its return value so the record reaches the checkpoint.
    """

    value: str
    update: StateUpdate


def requires_human_escalation(
    result: AnalystResult,
    *,
    sensitive: SensitiveDetectionResult | None,
    rule: RuleEngineeringResult | None,
    has_errors: bool,
) -> bool:
    """
    Return whether the analyst verdict must go to a human reviewer.

    A standalone pure function of explicit inputs, so the policy can be
    unit-tested without a state object and cannot silently read a stale
    field. Escalation is required on low confidence, on a malicious or
    inconclusive verdict, on any sensitive alert, on any draft rule
    awaiting review, and on any run that recorded an error.
    """
    return (
        result.confidence < _LOW_CONFIDENCE_ESCALATION_THRESHOLD
        or result.verdict in (Verdict.MALICIOUS, Verdict.INCONCLUSIVE)
        or (sensitive is not None and sensitive.contains_sensitive)
        or (rule is not None and rule.requires_rule_review)
        or has_errors
    )


@dataclass(slots=True)
class AlertState:
    """
    Root LangGraph state for one alert investigation.

    Nodes receive this object, call the ``set_*``/``add_*`` mutators, and
    return the :data:`StateUpdate` patch those mutators produce. Reads go
    through the ``get_*`` accessors so that each consumer sees only the
    fields it is entitled to, and LLM agents see only
    :meth:`get_llm_context`.

    Every mutator is pure: it returns a patch and never assigns to
    ``self``. A node therefore always sees the state as it was on entry,
    and the patch it returns is the only thing that reaches the
    checkpoint. Two consequences worth internalizing:

    - Calling a mutator and discarding the return value is a no-op. There
      is no half-applied state.
    - Within a single node, a value written by an earlier mutator is not
      readable back off ``self``. Use the local object you already hold,
      or merge patches with :meth:`with_update` if you genuinely need a
      state carrying both.
    """

    alert: AlertInfo | None = None
    prompt: PromptInfo | None = None
    sensitive: SensitiveDetectionResult | None = None
    rule: RuleEngineeringResult | None = None
    rag: RAGContext | None = None
    threat_intel: ThreatIntelResult | None = None
    analysis: AnalystResult | None = None
    review: HumanReviewRecord = field(default_factory=HumanReviewRecord)
    execution: ExecutionMetadata = field(default_factory=ExecutionMetadata)
    schema_version: str = SCHEMA_VERSION

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, alert: AlertInfo, prompt: str, *, thread_id: str | None = None) -> Self:
        """Build the initial state for a run, from the ingestion node."""
        return cls(
            alert=alert,
            prompt=PromptInfo.from_prompt(prompt),
            execution=ExecutionMetadata(
                thread_id=thread_id or str(uuid.uuid4()),
                current_node=str(NodeName.INGESTION),
            ),
        )

    def with_update(self, *updates: StateUpdate) -> Self:
        """
        Return a copy of this state with the given patches applied.

        The local equivalent of what LangGraph does between nodes. Useful
        in tests, in the API layer, and inside a node that must chain two
        mutators, since mutators never write to ``self``.
        """
        merged: StateUpdate = {}
        for update in updates:
            merged.update(update)
        unknown = set(merged) - {f.name for f in fields(self)}
        if unknown:
            raise StateValidationError(f"unknown state fields in update: {sorted(unknown)}")
        return replace(self, **merged)

    # ------------------------------------------------------------------
    # Mutators — every one returns the LangGraph channel patch to emit
    # ------------------------------------------------------------------

    def set_alert(self, alert: AlertInfo) -> StateUpdate:
        """Validate and return the alert patch. Called by the ingestion node."""
        if not isinstance(alert, AlertInfo):
            raise StateValidationError("set_alert expects an AlertInfo instance")
        return {"alert": alert}

    def set_prompt(self, prompt: str, *, language: str = "en") -> StateUpdate:
        """Build and return the prompt patch. Called by the ingestion node."""
        return {"prompt": PromptInfo.from_prompt(prompt, language=language)}

    def set_sensitive_detection(
        self,
        result: SensitiveDetectionResult,
        *,
        prompt: PromptInfo | None = None,
    ) -> StateUpdate:
        """
        Validate and return the detection patch.

        Called by the sensitive-detection node. Refuses to mark the alert
        sensitive while no sanitized prompt exists, which would otherwise
        leave downstream agents with nothing safe to read. Pass ``prompt``
        when the same node produced the sanitized variant in this turn,
        since a mutator's patch is not readable back off ``self``.
        """
        if not isinstance(result, SensitiveDetectionResult):
            raise StateValidationError(
                "set_sensitive_detection expects a SensitiveDetectionResult instance"
            )
        effective = prompt if prompt is not None else self.prompt
        if effective is None:
            raise StateValidationError("set_prompt must run before sensitive detection")
        if result.contains_sensitive and not effective.is_sanitized:
            raise StateValidationError(
                "a sanitized prompt must be set before flagging sensitive content"
            )
        return {"sensitive": result}

    def set_sanitized_prompt(self, sanitized: str) -> StateUpdate:
        """Return a patch carrying the redacted prompt. Called by the sanitizer."""
        if self.prompt is None:
            raise StateValidationError("set_prompt must run before sanitization")
        return {
            "prompt": replace(
                self.prompt, sanitized_prompt=_non_empty(sanitized, "sanitized")
            )
        }

    def set_rule_result(self, result: RuleEngineeringResult) -> StateUpdate:
        """
        Validate and return the rule-engineering patch. Called by rule checker/generator.

        Does not write to ``self.rule`` — the returned patch is the single
        source of truth LangGraph applies to the checkpoint. Reading
        ``self.rule`` immediately after calling this will still show the old
        value; callers that need the new value use the local ``result`` they
        already hold.
        """
        if not isinstance(result, RuleEngineeringResult):
            raise StateValidationError(
                "set_rule_result expects a RuleEngineeringResult instance"
            )
        return {"rule": result}

    def set_rag_context(self, context: RAGContext) -> StateUpdate:
        """Validate and return the retrieval patch. Called by the retrieval step."""
        if not isinstance(context, RAGContext):
            raise StateValidationError("set_rag_context expects a RAGContext instance")
        return {"rag": context}

    def set_ti_result(self, result: ThreatIntelResult) -> StateUpdate:
        """
        Validate and return the threat-intel patch.

        Refuses the write on the sensitive branch, so even a miswired
        conditional edge cannot commit external enrichment for an alert
        carrying confidential data.
        """
        if not isinstance(result, ThreatIntelResult):
            raise StateValidationError("set_ti_result expects a ThreatIntelResult instance")
        if self.sensitive is not None and self.sensitive.contains_sensitive:
            raise StateValidationError(
                "threat intelligence must not run on the sensitive branch"
            )
        return {"threat_intel": result}

    def set_analysis(
        self,
        result: AnalystResult,
        *,
        sensitive: SensitiveDetectionResult | None,
        rule: RuleEngineeringResult | None,
    ) -> StateUpdate:
        """
        Apply the escalation policy and return the analysis patch.

        ``sensitive`` and ``rule`` are required keyword arguments rather
        than reads off ``self`` so that a node which just produced a
        fresher value passes it explicitly; a stale read here would
        silently skip the review gate. Pass ``sensitive=self.sensitive,
        rule=self.rule`` in the ordinary case.

        ``requires_human_review`` can only be raised here, never cleared:
        an agent returning ``False`` cannot bypass the gate.
        """
        if not isinstance(result, AnalystResult):
            raise StateValidationError("set_analysis expects an AnalystResult instance")
        escalate = requires_human_escalation(
            result,
            sensitive=sensitive,
            rule=rule,
            has_errors=self.execution.has_errors,
        )
        return {
            "analysis": replace(
                result,
                requires_human_review=result.requires_human_review or escalate,
            )
        }

    def set_human_review(self, review: HumanReviewRecord) -> StateUpdate:
        """Return the review patch. Called by the review gate after the interrupt."""
        if not isinstance(review, HumanReviewRecord):
            raise StateValidationError("set_human_review expects a HumanReviewRecord instance")
        if not review.is_pending and review.reviewed_at is None:
            review = replace(review, reviewed_at=_utc_now())
        return {"review": review}

    def set_current_node(self, node: NodeName | str) -> StateUpdate:
        """Return a patch marking the node about to execute. Called at the top of every node."""
        return {"execution": replace(self.execution, current_node=str(node))}

    def add_completed_node(self, node: NodeName | str) -> StateUpdate:
        """Return a patch appending to the audit trail. Called at the end of every node."""
        name = str(node)
        if name in self.execution.completed_nodes:
            return {"execution": self.execution}
        return {
            "execution": replace(
                self.execution,
                completed_nodes=[*self.execution.completed_nodes, name],
            )
        }

    def add_error(
        self,
        node: NodeName | str,
        message: str,
        *,
        error_type: str = "RuntimeError",
        recoverable: bool = True,
    ) -> StateUpdate:
        """Return a patch recording a node failure. Called from node error handlers."""
        error = ExecutionError(
            node=str(node),
            message=message,
            error_type=error_type,
            recoverable=recoverable,
        )
        return {
            "execution": replace(self.execution, errors=[*self.execution.errors, error])
        }

    def increment_retry(self) -> StateUpdate:
        """Return a patch bumping the retry counter. Called by the retry edge."""
        return {
            "execution": replace(
                self.execution, retry_count=self.execution.retry_count + 1
            )
        }

    def finish_execution(self) -> StateUpdate:
        """Return a patch closing the run with its wall-clock duration."""
        end = datetime.now(UTC)
        start = datetime.fromisoformat(self.execution.execution_start)
        return {
            "execution": replace(
                self.execution,
                execution_end=end.isoformat(),
                execution_time=max((end - start).total_seconds(), 0.0),
                current_node=None,
            )
        }

    def clear_runtime_data(self) -> StateUpdate:
        """
        Return a patch dropping bulky payloads while preserving the audit trail.

        Retrieved document bodies dominate checkpoint size and are
        reproducible from the query; citations, scores and sources are
        kept so the report stays verifiable. Called before the dashboard
        node persists the final checkpoint.
        """
        if self.rag is None:
            return {}
        return {"rag": replace(self.rag, retrieved_documents=[])}

    def reset_for_retry(self, from_node: NodeName | str) -> StateUpdate:
        """
        Return a patch discarding the results invalidated by retrying ``from_node``.

        Invalidation follows the data dependencies in
        ``_RETRY_INVALIDATES``, not position in the graph, so retrying
        the threat-intel branch no longer clears the rule-engineering
        branch that runs in its place. Everything upstream is kept, so a
        failed enrichment call does not force re-ingestion or
        re-detection.

        Raises :class:`StateValidationError` if ``from_node`` is not a
        recognized node name, rather than silently clearing nothing — an
        unknown node here is almost certainly a typo or a node added to
        the graph without being registered.
        """
        name = str(from_node)
        if name not in _RETRY_INVALIDATES:
            raise StateValidationError(
                f"reset_for_retry got an unknown node name {name!r}; "
                f"expected one of {sorted(_RETRY_INVALIDATES)}"
            )

        invalidated = _RETRY_INVALIDATES[name]
        cleared: StateUpdate = dict.fromkeys(invalidated)
        cleared["execution"] = replace(
            self.execution,
            completed_nodes=[
                completed
                for completed in self.execution.completed_nodes
                if completed != name and _NODE_OUTPUT_FIELDS.get(completed) not in invalidated
            ],
            retry_count=self.execution.retry_count + 1,
            current_node=name,
        )
        return cleared

    # ------------------------------------------------------------------
    # Safe reads — deterministic consumers
    # ------------------------------------------------------------------

    def get_alert(self) -> AlertInfo:
        """Return the full alert, including ``raw_alert``. Deterministic consumers only."""
        if self.alert is None:
            raise StateValidationError("alert has not been ingested yet")
        return self.alert

    def get_alert_metadata(self) -> dict[str, str | int | None]:
        """Return the LLM-safe alert attributes, excluding the raw document."""
        return self.get_alert().safe_metadata()

    def get_original_prompt(self, *, requester: str) -> AuditedRead:
        """
        Return the unredacted prompt together with its audit patch.

        Restricted to deterministic consumers — rule checker, dashboard,
        audit export. This is the one method that both mutates ``self``
        and returns a patch: the in-place append guarantees the access
        record exists even if the caller discards the patch, and the
        patch carries it into the checkpoint. An audit record a caller
        can silently drop would not be an audit record.

        Callers use ``.value`` for the text and should merge ``.update``
        into the patch their node returns.
        """
        if self.prompt is None:
            raise StateValidationError("prompt has not been extracted yet")
        entry = f"{_utc_now()}|{_non_empty(requester, 'requester')}|original_prompt"
        self.execution.sensitive_access_log.append(entry)
        return AuditedRead(
            value=self.prompt.original_prompt,
            update={"execution": self.execution},
        )

    def get_sanitized_prompt(self) -> str:
        """
        Return the prompt text that is safe to send to an LLM.

        Fails closed. The original is released only once detection has
        actually run and reported nothing sensitive; before detection the
        classification is unknown, so the request is refused rather than
        answered with unvetted text. On the sensitive branch a missing
        sanitized variant yields the redaction placeholder.
        """
        if self.prompt is None:
            raise StateValidationError("prompt has not been extracted yet")
        if self.prompt.sanitized_prompt:
            return self.prompt.sanitized_prompt
        if self.sensitive is None:
            raise StateValidationError(
                "sensitive detection must run before the prompt can be released; "
                "the alert is unclassified and the original text is not safe to return"
            )
        if self.sensitive.contains_sensitive:
            return _SENSITIVE_PROMPT_UNAVAILABLE
        return self.prompt.original_prompt

    def _display_prompt(self) -> str:
        """Return the safest renderable prompt, never raising, for the dashboard."""
        try:
            return self.get_sanitized_prompt()
        except StateValidationError:
            return _PROMPT_UNAVAILABLE

    def get_sensitive_entities(self) -> list[DetectedEntity]:
        """Return the detected findings, which never carry the matched values."""
        return list(self.sensitive.detected_entities) if self.sensitive else []

    def get_rule_result(self) -> RuleEngineeringResult | None:
        """Return the rule-engineering outcome, or ``None`` if that branch never ran."""
        return self.rule

    def get_rag_context(self) -> RAGContext | None:
        """Return the retrieved grounding material, or ``None`` if retrieval never ran."""
        return self.rag

    def get_ti_summary(self) -> dict[str, Any] | None:
        """Return a compact threat-intel digest, or ``None`` if that branch never ran."""
        if self.threat_intel is None:
            return None
        return {
            "summary": self.threat_intel.investigation_summary,
            "mitre_techniques": self.threat_intel.technique_ids(),
            "ioc_count": len(self.threat_intel.detected_iocs),
            "risk_score": self.threat_intel.risk_score,
            "confidence": self.threat_intel.confidence,
            "external_sources": self.threat_intel.external_sources,
        }

    def get_analysis(self) -> AnalystResult | None:
        """Return the analyst verdict, or ``None`` if the analyst has not run."""
        return self.analysis

    def get_errors(self) -> list[ExecutionError]:
        """Return the recorded node failures for debugging and alerting."""
        return list(self.execution.errors)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def contains_sensitive_data(self) -> bool:
        """Return the routing signal produced by the detection node."""
        return bool(self.sensitive and self.sensitive.contains_sensitive)

    def route_after_detection(self) -> str:
        """Return the next node name for the conditional edge after detection."""
        return str(
            NodeName.RULE_CHECKER if self.contains_sensitive_data() else NodeName.THREAT_INTEL
        )

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard_payload(self, *, include_sensitive: bool = False) -> dict[str, Any]:
        """
        Return the JSON payload rendered by the dashboard node.

        The unredacted prompt is withheld unless the caller explicitly
        opts in with ``include_sensitive=True``, which is audit-logged.
        The default view is therefore safe to render, cache or export.
        """
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "thread_id": self.execution.thread_id,
            "alert": self.get_alert_metadata() if self.alert else None,
            "prompt": {
                "hash": self.prompt.prompt_hash if self.prompt else None,
                "language": self.prompt.prompt_language if self.prompt else None,
                "displayed": self._display_prompt() if self.prompt else None,
                "redacted": self.contains_sensitive_data(),
            },
            "sensitivity": {
                "contains_sensitive": self.contains_sensitive_data(),
                "risk_level": str(self.sensitive.risk_level) if self.sensitive else None,
                "entity_types": self.sensitive.entity_types() if self.sensitive else [],
                "masked_fields": self.sensitive.masked_fields if self.sensitive else [],
            },
            "rule": self.rule.to_dict() if self.rule else None,
            "rag": {
                "query": self.rag.retrieval_query if self.rag else None,
                "citations": self.rag.citations if self.rag else [],
                "knowledge_sources": self.rag.knowledge_sources if self.rag else [],
            },
            "threat_intel": self.get_ti_summary(),
            "analysis": self.analysis.to_dict() if self.analysis else None,
            "review": self.review.to_dict(),
            "execution": {
                "current_node": self.execution.current_node,
                "completed_nodes": self.execution.completed_nodes,
                "execution_time": self.execution.execution_time,
                "retry_count": self.execution.retry_count,
                "errors": [e.to_dict() for e in self.execution.errors],
            },
        }
        if include_sensitive:
            payload["prompt"]["original"] = self.get_original_prompt(
                requester="dashboard"
            ).value
        return payload

    # ------------------------------------------------------------------
    # LLM boundary
    # ------------------------------------------------------------------

    def get_llm_context(
        self,
        *,
        consumer: NodeName = NodeName.ANALYST,
        policy: ContextPolicy | None = None,
    ) -> LLMContext:
        """
        Return the only payload an LLM-backed agent may read.

        The method assembles the context field by field from an allow-list;
        ``original_prompt`` and ``raw_alert`` have no assembly path into it.
        When the alert is flagged sensitive, the prompt slot carries the
        sanitized text — or a redaction placeholder if sanitization is
        missing — never the original. A final guard re-checks the rendered
        payload and raises :class:`SensitiveDataLeakError` rather than
        letting a restricted string reach a model.

        ``consumer`` selects a :class:`ContextPolicy` from the registry,
        which declares the optional sections that agent may see. An
        unregistered consumer gets the closed default — metadata and the
        safe prompt only — so a new agent starts with least privilege and
        widens deliberately. ``policy`` overrides the lookup for callers
        that need a narrower one-off view; it can never widen past the
        unconditional fields.
        """
        if self.alert is None or self.prompt is None:
            raise StateValidationError("alert and prompt must be set before calling an LLM")

        active = policy or _CONTEXT_POLICIES.get(str(consumer), _DEFAULT_CONTEXT_POLICY)
        is_sensitive = self.contains_sensitive_data()
        context: LLMContext = {
            "consumer": str(consumer),
            "schema_version": self.schema_version,
            "alert": self.get_alert_metadata(),
            "prompt": self.get_sanitized_prompt(),
            "prompt_hash": self.prompt.prompt_hash,
            "prompt_language": self.prompt.prompt_language,
            "prompt_is_redacted": is_sensitive,
            "sensitivity": {
                "contains_sensitive": is_sensitive,
                "risk_level": str(self.sensitive.risk_level)
                if self.sensitive
                else str(RiskLevel.NONE),
                "entity_types": self.sensitive.entity_types() if self.sensitive else [],
                "masked_fields": self.sensitive.masked_fields if self.sensitive else [],
            },
        }

        if active.include_rule_status and self.rule is not None:
            context["rule_status"] = {
                "status": self.rule.rule_status,
                "rule_exists": self.rule.rule_exists,
                "matched_rule_id": self.rule.matched_rule_id,
                "draft_rule_generated": self.rule.generated_rule is not None,
                "generation_reason": self.rule.generation_reason,
            }

        if active.include_rag and self.rag is not None and not self.rag.is_empty:
            context["rag"] = {
                "query": self.rag.retrieval_query,
                "documents": self.rag.llm_summary(limit=active.max_documents),
                "knowledge_sources": self.rag.knowledge_sources,
                "citations": self.rag.citations,
            }

        if active.include_threat_intel:
            ti_summary = self.get_ti_summary()
            if ti_summary is not None:
                context["threat_intel"] = ti_summary

        if active.include_analysis and self.analysis is not None:
            context["analysis"] = {
                "verdict": str(self.analysis.verdict),
                "score": self.analysis.score,
                "confidence": self.analysis.confidence,
            }

        self._assert_no_restricted_data(context)
        return context

    def _assert_no_restricted_data(self, context: LLMContext) -> None:
        """
        Fail closed if a restricted string reached an LLM-bound payload.

        ``raw_alert`` is checked leaf by leaf rather than as one serialized
        blob: a blob comparison only matches a leak that preserves exact
        key order and embeds the document unescaped, so copying a single
        raw field into the payload would slip past it. Leaves shorter than
        ``_MIN_LEAK_MATCH_LENGTH``, and those the alert deliberately
        publishes through ``safe_metadata``, are exempt — a hostname that
        appears in both places is disclosure by design, not a leak.
        """
        rendered = json.dumps(context, ensure_ascii=False, default=str)

        if self.prompt is not None and self.contains_sensitive_data():
            if self.prompt.original_prompt in rendered:
                raise SensitiveDataLeakError(
                    "original_prompt reached an LLM-bound context payload"
                )

        if self.alert is None or not self.alert.raw_alert:
            return
        published = {
            str(value) for value in self.alert.safe_metadata().values() if value is not None
        }
        for leaf in _string_leaves(self.alert.raw_alert):
            if len(leaf) < _MIN_LEAK_MATCH_LENGTH or leaf in published:
                continue
            if leaf in rendered:
                raise SensitiveDataLeakError(
                    "a raw_alert value reached an LLM-bound context payload"
                )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the whole state to JSON-compatible primitives for checkpointing."""
        return {
            "schema_version": self.schema_version,
            "alert": self.alert.to_dict() if self.alert else None,
            "prompt": self.prompt.to_dict() if self.prompt else None,
            "sensitive": self.sensitive.to_dict() if self.sensitive else None,
            "rule": self.rule.to_dict() if self.rule else None,
            "rag": self.rag.to_dict() if self.rag else None,
            "threat_intel": self.threat_intel.to_dict() if self.threat_intel else None,
            "analysis": self.analysis.to_dict() if self.analysis else None,
            "review": self.review.to_dict(),
            "execution": self.execution.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """
        Rebuild a state from :meth:`to_dict` output.

        Unknown keys are ignored and missing keys fall back to defaults, so
        a checkpoint written by an older graph version still loads.
        """
        version = data.get("schema_version", SCHEMA_VERSION)
        if version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            raise StateValidationError(
                f"incompatible state schema version {version!r}; "
                f"expected major {SCHEMA_VERSION.split('.')[0]}"
            )
        return cls(
            alert=AlertInfo.from_dict(data["alert"]) if data.get("alert") else None,
            prompt=PromptInfo.from_dict(data["prompt"]) if data.get("prompt") else None,
            sensitive=SensitiveDetectionResult.from_dict(data["sensitive"])
            if data.get("sensitive")
            else None,
            rule=RuleEngineeringResult.from_dict(data["rule"]) if data.get("rule") else None,
            rag=RAGContext.from_dict(data["rag"]) if data.get("rag") else None,
            threat_intel=ThreatIntelResult.from_dict(data["threat_intel"])
            if data.get("threat_intel")
            else None,
            analysis=AnalystResult.from_dict(data["analysis"]) if data.get("analysis") else None,
            review=HumanReviewRecord.from_dict(data.get("review") or {}),
            execution=ExecutionMetadata.from_dict(data.get("execution") or {}),
            schema_version=version,
        )


#: The state field each node produces. Used to prune ``completed_nodes``
#: when a retry invalidates that node's output.
_NODE_OUTPUT_FIELDS: Final[dict[str, str]] = {
    str(NodeName.SENSITIVE_DETECTION): "sensitive",
    str(NodeName.RULE_CHECKER): "rule",
    str(NodeName.RULE_GENERATOR): "rule",
    str(NodeName.THREAT_INTEL): "threat_intel",
    str(NodeName.ANALYST): "analysis",
}

#: The state fields invalidated by retrying each node, expressed as data
#: dependencies rather than graph position. Retrying ``threat_intel``
#: therefore leaves ``rule`` alone: the two branches are alternatives, and
#: neither one's output is derived from the other's. Every node in
#: :class:`NodeName` must appear here — :meth:`AlertState.reset_for_retry`
#: rejects anything missing.
_RETRY_INVALIDATES: Final[dict[str, tuple[str, ...]]] = {
    str(NodeName.INGESTION): ("sensitive", "rule", "rag", "threat_intel", "analysis"),
    str(NodeName.SENSITIVE_DETECTION): (
        "sensitive",
        "rule",
        "rag",
        "threat_intel",
        "analysis",
    ),
    str(NodeName.RULE_CHECKER): ("rule", "analysis"),
    str(NodeName.RULE_GENERATOR): ("rule", "analysis"),
    str(NodeName.THREAT_INTEL): ("rag", "threat_intel", "analysis"),
    str(NodeName.ANALYST): ("analysis",),
    str(NodeName.DASHBOARD): (),
    str(NodeName.HUMAN_REVIEW): (),
}

_MISSING_RETRY_ENTRIES: Final[set[str]] = {str(n) for n in NodeName} - set(_RETRY_INVALIDATES)
if _MISSING_RETRY_ENTRIES:
    raise StateValidationError(
        f"_RETRY_INVALIDATES is missing entries for {sorted(_MISSING_RETRY_ENTRIES)}"
    )

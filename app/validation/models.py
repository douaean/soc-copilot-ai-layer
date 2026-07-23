"""
Validation layer — the contract for "what is a valid Wazuh alert".

Responsibility (and ONLY responsibility):
    Define Pydantic models that reject malformed alert data at the
    boundary, before it reaches retrieval/RAG/agents. Normalize field
    names/types into a consistent internal shape.

What does NOT belong here:
    - No retrieval logic
    - No LLM calls
    - No reasoning about severity/MITRE mapping (that's app/agents)

Why this boundary matters (NFR2 — auditability):
    A malformed alert that slips through silently can produce a
    garbage embedding -> garbage retrieval -> a report that LOOKS
    legitimate but isn't grounded in anything real. Validation fails
    loudly and early instead.

Milestone: M3 (this is a Milestone 0/1 skeleton — fields below are
illustrative, not final).
"""

from pydantic import BaseModel


class WazuhRuleModel(BaseModel):
    level: int
    description: str
    id: str


class WazuhAgentModel(BaseModel):
    id: str
    name: str
    ip: str


class WazuhAlertModel(BaseModel):
    """
    Normalized representation of a Wazuh alert.

    TODO (M3): confirm final field set against real Wazuh REST API
    responses, add MITRE fields, add validators for IP format, etc.
    """

    timestamp: str
    rule: WazuhRuleModel
    agent: WazuhAgentModel
    full_log: str

# Orchestration State — Design Notes & Handoff

**File:** `app/agents/state.py`
**Date:** 2026-08-06
**Status:** Written, smoke-tested, verified against installed LangGraph. Not yet wired into `app/agents/graph.py`.

---

## 1. What this is

The shared LangGraph state for the SOC Copilot investigation graph, plus the *only* sanctioned API for reading and writing it.

Workflow it serves:

```
ingestion → sensitive_detection
              ├─ sensitive?  yes → rule_checker → rule_generator ─┐
              └─ no  → threat_intel (Tavily, RAG, MITRE, IOC) ────┤
                                                                  ↓
                                            analyst → dashboard → human_review → END
```

Core contract:

- Nodes **never** touch dataclass attributes directly. They call `set_*`/`add_*` helpers, which validate and return a LangGraph channel patch.
- Deterministic consumers (rule checker, dashboard, audit, logging) may read `original_prompt` / `raw_alert` through explicit, audit-logged accessors.
- LLM-backed agents read the state through **exactly one method**, `get_llm_context()`, which structurally cannot return `original_prompt` or `raw_alert`.
- Standard library only, so everything round-trips through LangGraph's JSON checkpoint serializer into SQLite as plain primitives.

---

## 2. Object model

| Dataclass | Purpose | Written by | Notes |
|---|---|---|---|
| `AlertInfo` | The observation; sole holder of `raw_alert` | `ingestion` | `severity_label` is derived, not stored |
| `PromptInfo` | Original + sanitized prompt, hash, language | `ingestion`, sanitizer | The security boundary as a type |
| `DetectedEntity` | One sensitive finding | `sensitive_detection` | frozen; **no `value` field** — see §4 |
| `SensitiveDetectionResult` | Detection verdict + routing signal | `sensitive_detection` | Cross-field invariants enforced |
| `RuleEngineeringResult` | Wazuh rule coverage + draft rule | `rule_checker`, `rule_generator` | A generated rule forces `requires_rule_review=True` |
| `RetrievedDocument` | One KB chunk with provenance | retrieval step | frozen, for citation integrity |
| `RAGContext` | Retrieved **evidence** | `threat_intel`, `analyst` | Independent of `ThreatIntelResult` by design |
| `MitreTechnique` | ATT&CK attribution | `threat_intel` | Regex-validated `Txxxx[.yyy]` — rejects hallucinated IDs |
| `Indicator` | IOC + enrichment verdict | `threat_intel` | |
| `ThreatIntelResult` | Investigation **conclusions** | `threat_intel` | `risk_score` 0–100, `confidence` 0–1 |
| `AnalystResult` | Final triage verdict | `analyst` | `requires_human_review` only ratchets up |
| `HumanReviewRecord` | Review-gate decision | `human_review` | **Added** — not in the original spec; `override_verdict` is the training signal |
| `ExecutionError` / `ExecutionMetadata` | Run bookkeeping + audit | every node | Includes `sensitive_access_log` |
| `AlertState` | Root LangGraph state | — | `slots=True`; every field has a default |

Enums: `RiskLevel` (ordered, `.rank`), `Verdict`, `ReviewDecision`, `NodeName` — all `StrEnum`, so they serialize as plain strings.

Exceptions: `StateValidationError(ValueError)`, `SensitiveDataLeakError(RuntimeError)`.

---

## 3. Policy enforced in mutators (not just type checks)

Three mutators carry real policy:

1. **`set_sensitive_detection()`** — refuses to flag an alert sensitive while `sanitized_prompt is None`. Catches the ordering bug at the write, not at the leak.
2. **`set_ti_result()`** — raises if the alert is on the sensitive branch. Even a miswired conditional edge cannot commit Tavily/external enrichment on the sensitive path.
3. **`set_analysis()`** — forces `requires_human_review=True` on low confidence (<0.70), a `MALICIOUS`/`INCONCLUSIVE` verdict, any sensitive alert, any draft rule, or any recorded error. An agent returning `False` cannot bypass the gate. **Verified: passed `False`, got `True` back.**

`clear_runtime_data()` empties `retrieved_documents` (bulky, reproducible from the query) while keeping `citations`, `document_scores`, `knowledge_sources` (audit-critical).

`reset_for_retry(from_node)` clears only results at or after the failing node, using the `_NODE_ORDER` table.

---

## 4. Security model — five independent layers

1. **Separation at rest.** `original_prompt` and `sanitized_prompt` are distinct fields. There is no "the prompt" to accidentally grab.
2. **Values are never stored.** `DetectedEntity` has type / detector / confidence / offsets — never the matched string. Otherwise the secret would be written into every SQLite checkpoint, `to_dict()`, dashboard payload and log line, defeating the entire design.
3. **Ordering enforced.** Cannot flag sensitive before a sanitized prompt exists.
4. **Restricted read is audited.** `get_original_prompt(*, requester=...)` appends `timestamp|requester|field` to the checkpointed `sensitive_access_log`. The audit entry is a side effect of the read *by design* — you cannot read it without leaving a record. Keyword-only `requester` makes the call impossible to make by accident.
5. **`get_llm_context()` is allow-list + fail-closed guard.** See below.

### How `get_llm_context()` prevents leakage

- **Allow-list assembly.** Built field by field. No `asdict(self)`, no `**self.__dict__`, no attribute loop. `original_prompt` and `raw_alert` have *no assembly path* in. Filtering fails open when a field is added; allow-listing fails closed.
- **`LLMContext` TypedDict** has no key capable of holding either restricted field.
- **Prompt slot routes through `get_sanitized_prompt()`**, which has three branches: sanitized text exists → return it; missing + sensitive → return the redaction placeholder; missing + clean → return the original (per spec). The failure mode of a missing sanitizer is a placeholder, never the original.
- **Alert slot routes through `safe_metadata()`** — a hand-written projection of 8 scalars.
- **RAG excerpts** are truncated and citation-tagged, never raw bodies.
- **Per-consumer narrowing.** `consumer=NodeName.THREAT_INTEL` omits both the threat-intel section (it produces it) and the analyst section (would anchor its independent investigation). Verified: TI agent gets 8 keys, analyst gets 12.
- **`_assert_no_restricted_data()`** serializes the finished payload, searches for `original_prompt` (when sensitive) and the serialized `raw_alert`, and raises `SensitiveDataLeakError` rather than calling the model.

> ⚠️ The leak guard is a **substring search**. It catches whole-field leaks from programmer error. It does not catch paraphrase, partial quotes, or a secret re-entering after LLM summarization. Do not describe it internally as an adversarial control.

---

## 5. Changes applied 2026-08-06 (second pass)

### `set_rule_result` → pure validate-and-return

```python
def set_rule_result(self, result: RuleEngineeringResult) -> StateUpdate:
    if not isinstance(result, RuleEngineeringResult):
        raise StateValidationError(
            "set_rule_result expects a RuleEngineeringResult instance"
        )
    return {"rule": result}
```

No longer writes `self.rule`. The returned patch is the single source of truth LangGraph applies. Reading `self.rule` right after the call shows the old value; callers needing the new value use the local `result` they already hold.

**Verified across real LangGraph edges:** `rule_checker` returns the patch, downstream `analyst` sees the applied value, final channel is correct.

### `reset_for_retry` hardened

Now raises `StateValidationError` on an unrecognized node name instead of falling through.

The old `_NODE_ORDER.get(name, len(_NODE_ORDER))` returned 8 for an unknown name, which was `>=` nothing — so an unknown node silently cleared **nothing** while still bumping `retry_count` and setting `current_node` to a bogus value. Quietly wrong. Now it fails loudly with the list of valid names.

---

## 6. Open items for tomorrow

> **SUPERSEDED (2026-08-10).** §6.1, §6.2 and the first four bullets of §6.5 are
> closed — all mutators are now pure, retry is branch-aware, prompt release is
> fail-closed, and `get_llm_context()` is policy-driven. §5 and the signatures
> quoted below are out of date. See **`STATE_NEXT_STEPS.md`** for the current
> work queue. §1–§4 and §7–§8 of this file remain accurate.

### 6.1 The split-contract hazard (highest priority)

`set_rule_result` is now pure; every other mutator (`set_alert`, `set_analysis`, `add_error`, …) still does `self.x = value` before returning. Two contracts live side by side — some methods are safe to call-and-ignore-the-return, others are not.

**Concrete consequence:** `set_analysis()`'s escalation policy reads `self.rule.requires_rule_review`. Across nodes this still works (LangGraph applies the patch before `analyst` runs — confirmed). But a **single node** calling `set_rule_result()` then `set_analysis()` in the same body will now miss the rule-review escalation, where before it wouldn't.

**Decision needed:** one-off experiment, or the direction for all mutators?
If going pure everywhere: the policy in `set_analysis` must take its inputs as **explicit arguments** rather than reading `self`. That's the right end state but it is not reachable one method at a time.

### 6.2 `reset_for_retry` still mutates

It does `setattr(self, attribute, None)` and mutates `self.execution` in place *and* returns the patch. Left as-is deliberately.

Hardest method to make pure: `self.execution` is a shared mutable object returned by reference in nearly every patch in the file. Going pure there means `dataclasses.replace` on `ExecutionMetadata` in **every** mutator that touches it, not just this one.

### 6.3 Adapter change required elsewhere

`app/sensitive_detection/presidio.py:33` puts the matched `value` into each finding. `DetectedEntity` deliberately has no `value` field. **The adapter must drop it** when building state. Same check needed for `trufflehog.py`.

### 6.4 Wire into the graph

`app/agents/graph.py` still has the M0/M1 skeleton `InvestigationState` TypedDict and `build_investigation_graph()` raising `NotImplementedError`. Replace with `StateGraph(AlertState)`; use `route_after_detection()` directly as the `add_conditional_edges` callable.

### 6.5 Known smaller weaknesses

- **`get_sanitized_prompt()` third branch** is guarded by `contains_sensitive_data()`, which is `False` both when detection found nothing *and before detection has run*. An agent invoked out of order sees the original prompt of an unclassified alert. Mitigated by topology (`sensitive_detection` is unconditionally second). If a node is ever inserted between ingestion and detection, tighten to require `self.sensitive is not None`.
- **`_NODE_ORDER` hardcodes graph topology** in the state module — two sources of truth. Add a node to the graph and forget the table, and `reset_for_retry` under-clears. Should be derived from the compiled graph.
- **`reset_for_retry` clears by rank, not by branch.** Retrying `threat_intel` (rank 2) also nulls `rule` (rank 2). Harmless today because branches are mutually exclusive — coincidence, not design.
- **`get_llm_context()` is a chokepoint that will grow.** ~60 lines at 2 consumers; at 6 agents it becomes a branch thicket. Refactor target: a declarative `ContextPolicy` per consumer.
- **Serialization is 9 hand-written `to_dict`/`from_dict` pairs** — ~40% of the file; adding a field means remembering three places. Explicit was chosen over reflective magic deliberately, for something this security-sensitive.

---

## 7. Verified facts (don't re-derive)

- `StateGraph(AlertState)` compiles and invokes. Nodes receive an `AlertState` instance; `invoke()` returns a channel **dict**; `AlertState(**out)` rehydrates it.
- `to_dict()` → `json.dumps` → `json.loads` → `from_dict()` is identical on round-trip.
- Leak assertions pass: AWS key, email address, and a `raw_alert`-only secret are all absent from the serialized analyst context.
- Validation rejects: empty `alert_id`, `technique_id="X999"`, `confidence=1.4`, `risk_score=150`, findings-without-`contains_sensitive`, unknown node in `reset_for_retry`.
- Escalation policy overrides an agent-supplied `requires_human_review=False`.

---

## 8. Backlog (larger)

State versioning w/ migration chain + golden fixtures · immutable snapshots (`frozen=True` + `dataclasses.replace`) · event sourcing · standalone `validate(state) -> list[Violation]` for cross-object invariants · structured `AccessRecord` audit export to SIEM · per-node `NodeMetrics` (latency, tokens, cost, model ID) · state compression via content-addressed doc references · `PostgresSaver` swap · `Annotated[..., operator.add]` reducers for parallel enrichment fan-out · human-feedback mining from `override_verdict`.

**At enterprise scale (millions of alerts/day):** stop putting `raw_alert` in the state (store an OpenSearch reference); Postgres partitioned by day with TTL; go immutable + event-sourced; **pull the LLM boundary out into a separate `ContextBroker` service** with its own tests and change-approval path (security controls inside a fast-moving domain model get eroded by ordinary feature work); split hot control-plane state from cold data-plane state; field-level encryption for `original_prompt` under a KMS key; per-tenant redaction policy.

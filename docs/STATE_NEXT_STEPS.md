# State Layer — What To Do Next

**Supersedes §6 of `STATE_DESIGN_NOTES.md`.** That file remains the reference for *why* the design is what it is (§1–§5, §7–§8). This file is the work queue.

**Date:** 2026-08-10
**File under discussion:** `app/agents/state.py` — compiles clean, all checks green.

---

## 0. What just changed (so the diff isn't a surprise)

All of §6.1, §6.2 and the first four bullets of §6.5 are now closed.

### The split-contract decision: **pure everywhere**

The open question in §6.1 was whether `set_rule_result`'s pure form was a one-off or the direction. It is now the direction. **Every mutator is pure** — validates, returns a patch, never assigns to `self`.

Two consequences to internalize before writing nodes:

- Calling a mutator and discarding the return value is a **no-op**. There is no half-applied state.
- Within a single node, a value written by an earlier mutator is **not readable back off `self`**. Use the local object you already hold, or `state.with_update(patch1, patch2)`.

New helper: `AlertState.with_update(*patches) -> AlertState` — a pure copy with patches applied, rejecting unknown field names. It is what LangGraph does between nodes, available locally for tests and for chaining inside one node.

### Signature changes that will break call sites

| Method | Before | Now |
|---|---|---|
| `set_analysis(result)` | read `self.sensitive` / `self.rule` | `set_analysis(result, *, sensitive, rule)` — **required kwargs** |
| `get_original_prompt(requester=)` | `-> str` | `-> AuditedRead` (`.value`, `.update`) |
| `get_llm_context(consumer=, max_documents=)` | `max_documents` int | `policy: ContextPolicy \| None` |
| `set_sensitive_detection(result)` | — | optional `prompt=` kwarg for same-node sanitize+detect |

`set_analysis` requiring `sensitive` and `rule` explicitly is the fix for the staleness hazard: a node that just produced a fresher value must pass it, and the escalation policy can no longer silently read a stale field. Ordinary call: `set_analysis(r, sensitive=state.sensitive, rule=state.rule)`.

The escalation rule is now the module-level pure function `requires_human_escalation(result, *, sensitive, rule, has_errors)` — unit-testable with no state object.

### The one deliberate exception

`get_original_prompt()` both mutates `self` and returns a patch. The in-place append guarantees the access record exists even if the caller drops the patch; the patch carries it to the checkpoint. An audit record a caller can silently discard is not an audit record. It returns `AuditedRead` rather than `str` so the exception is visible at every call site.

### Other closed items

- **Fail-closed prompt release.** `get_sanitized_prompt()` now raises if `self.sensitive is None` — before detection the classification is unknown, so unvetted text is refused rather than returned. The dashboard uses `_display_prompt()`, which falls back to `[UNAVAILABLE]` instead of raising.
- **Branch-aware retry.** `_NODE_ORDER` is gone. `_RETRY_INVALIDATES` maps each node to the fields its retry invalidates, expressed as **data dependencies** rather than graph position. Retrying `threat_intel` no longer nulls `rule`. A module-level check raises at import if any `NodeName` is missing from the table.
- **`ContextPolicy`.** `get_llm_context()` is now driven by a declarative per-consumer allow-list instead of inline branches. **An unregistered consumer gets the closed default** — metadata and safe prompt only — so a new agent starts at least privilege and widens deliberately. A policy can never switch the unconditional fields off, nor the restricted fields on.

### Verified after the change

Purity (mutators leave `self` byte-identical) · fail-closed release · dashboard fallback · per-consumer sections (analyst sees TI, TI agent does not) · escalation still ratchets `False` → `True` and leaves the caller's object untouched · branch-aware retry · JSON round-trip · full `StateGraph` run with `route_after_detection` as a real conditional edge.

---

## 1. Detector adapters — **blocking, security-relevant**

Neither detector's output can be handed to `DetectedEntity` as-is. Both currently carry the secret value.

### `app/sensitive_detection/presidio.py`

`PresidioDetector.detect()` puts `text[result.start:result.end]` into each finding as `"value"`. **Drop it.** `DetectedEntity` has no `value` field by design — storing it would write the secret into every SQLite checkpoint, `to_dict()`, dashboard payload and log line, defeating the whole design.

```python
DetectedEntity(
    entity_type=f["entity_type"],
    detector="presidio",
    confidence=f["confidence"],
    field_path="prompt",
    start=f["start"],
    end=f["end"],
)
```

### `app/sensitive_detection/trufflehog.py`

Worse: findings carry **both** `"raw"` (the live secret) and `"secret"` (TruffleHog's `Redacted` form). Drop both — there is no field for either.

Two more things the adapter must handle:

- **No confidence field.** Map `verified`: `True → 1.0`, `False → 0.5`. Do not invent finer gradations.
- **Error findings.** `trufflehog.py:152` appends `{"tool": "TruffleHog", "error": ...}` into the same list as real findings. These are **not** entities — route them to `state.add_error(NodeName.SENSITIVE_DETECTION, ...)` or the detection node will silently report a secret named `None`.

### `engine.py`

`SensitiveDataCorrelator.correlate()` returns a nested dict and writes `output/sensitive_detection.json`. The risk calculation (`CRITICAL` if any secret, `HIGH` if >3 PII, `MEDIUM` if any PII) maps cleanly onto `RiskLevel` — reuse it, do not reimplement.

Note the file write is a side effect that will now duplicate what the checkpoint already stores, and **that JSON file contains the raw secret values**. Decide whether it stays as a debugging artifact (and gets gitignored + permission-restricted) or is dropped in favour of the checkpoint.

**Recommended shape:** one `to_state_entities(presidio_results, trufflehog_results) -> tuple[list[DetectedEntity], list[str]]` function returning entities and error messages. Keep the adapter in the detection layer, not in `state.py` — `state.py` must not learn detector output formats.

---

## 2. Wire the graph

`app/agents/graph.py` still has the M0/M1 skeleton: an `InvestigationState` TypedDict and `build_investigation_graph()` raising `NotImplementedError`. Both should go.

```python
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.sqlite import SqliteSaver
from .state import AlertState, NodeName

def build_investigation_graph(checkpointer=None):
    g = StateGraph(AlertState)
    g.add_node(str(NodeName.SENSITIVE_DETECTION), sensitive_detection_node)
    g.add_node(str(NodeName.RULE_CHECKER), rule_checker_node)
    g.add_node(str(NodeName.RULE_GENERATOR), rule_generator_node)
    g.add_node(str(NodeName.THREAT_INTEL), threat_intel_node)
    g.add_node(str(NodeName.ANALYST), analyst_node)
    g.add_node(str(NodeName.DASHBOARD), dashboard_node)

    g.set_entry_point(str(NodeName.SENSITIVE_DETECTION))
    g.add_conditional_edges(
        str(NodeName.SENSITIVE_DETECTION),
        lambda s: s.route_after_detection(),   # already returns node names
        {str(NodeName.RULE_CHECKER): str(NodeName.RULE_CHECKER),
         str(NodeName.THREAT_INTEL): str(NodeName.THREAT_INTEL)},
    )
    ...
    return g.compile(checkpointer=checkpointer,
                     interrupt_before=[str(NodeName.HUMAN_REVIEW)])
```

Points that are easy to get wrong:

- **Node names must come from `NodeName`,** not string literals. `_RETRY_INVALIDATES` and `_NODE_OUTPUT_FIELDS` are keyed on them; a typo'd literal makes retry silently under-clear.
- **`route_after_detection()` already returns node-name strings** — use it directly, don't rewrite the branch condition.
- **The human review gate is `interrupt_before`,** not a node that blocks. On resume, the API layer calls `set_human_review()` and applies the patch.
- **`invoke()` returns a channel dict, not an `AlertState`.** Rehydrate with `AlertState(**out)`.
- **Node bodies return patches.** Merge several with `{**p1, **p2}` — but note both must not write the same key, or the later silently wins. Prefer one patch per node where possible.
- **`langgraph-checkpoint-sqlite` is not in `requirements.txt`.** Add it.

---

## 3. Tests

There are none for this module yet. `tests/` has only `__init__.py`. Priority order — the first three are security controls, and a security control without a test is a comment:

1. **`get_llm_context()` never leaks.** Parametrize over sensitive/clean × every `NodeName`; assert the original prompt, each raw-alert value, and each secret string are absent from `json.dumps(ctx)`.
2. **`_assert_no_restricted_data` fires.** Construct a context that *does* contain the original prompt and assert `SensitiveDataLeakError`. Currently nothing proves the guard works.
3. **Escalation cannot be bypassed.** `requires_human_escalation` truth table + `set_analysis` with `requires_human_review=False` for each trigger.
4. **Purity.** For every mutator: snapshot `to_dict()`, call it, assert unchanged. Cheap and it locks in the contract.
5. **Fail-closed release.** `get_sanitized_prompt()` raises pre-detection; returns the placeholder when sensitive with no sanitized variant; returns the original only when detection ran clean.
6. **Retry invalidation.** Assert `reset_for_retry(THREAT_INTEL)` preserves `rule`, and that an unknown node raises.
7. **Round-trip.** Property-style: build a fully-populated state, assert `from_dict(json.loads(json.dumps(to_dict()))) == to_dict()`.
8. **`with_update` rejects unknown fields.**

`pytest` and `pytest-asyncio` are already in `requirements.txt`.

---

## 4. Remaining known weaknesses (unchanged, still open)

These were **not** addressed and are listed so they stay visible:

- **The leak guard is a substring search.** It catches whole-field leaks from programmer error. It does not catch paraphrase, partial quotes, or a secret re-entering after LLM summarization. Do not describe it internally as an adversarial control.
- **`_RETRY_INVALIDATES` still hardcodes domain knowledge** in `state.py`. Better than the old positional `_NODE_ORDER` — data dependencies are a real domain fact, not graph topology — but adding a node still means editing this table. The import-time completeness check catches a *missing* node, not a *wrong* dependency list.
- **Serialization is 9 hand-written `to_dict`/`from_dict` pairs**, ~40% of the file. Adding a field means remembering three places. Explicit was chosen over reflective magic deliberately for something this security-sensitive; revisit only if the field count grows sharply.
- **`SCHEMA_VERSION` rejects a mismatched major but does not migrate.** Fine while unreleased. Before the first production checkpoint, add the `_MIGRATIONS` chain and golden fixtures — after that, every unmigrated checkpoint is a support ticket.
- **`get_original_prompt` is the one impure method.** Deliberate, documented, typed differently. If a second such case appears, that is the signal to move audit emission out of the state object entirely.

---

## 5. Suggested order

1. Detector adapters (§1) — blocking, and the only item with a live secret-handling defect.
2. Leak + escalation tests (§3.1–§3.3) — before the graph, so the controls are pinned while node code is being written against them.
3. Graph wiring (§2) with the SQLite checkpointer.
4. Remaining tests (§3.4–§3.8).
5. `SCHEMA_VERSION` migration chain — before, not after, the first production run.

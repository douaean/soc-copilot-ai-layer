# Orchestration Layer — Change Review

**Date:** 2026-08-10
**Milestone:** M8 — wire the production LangGraph orchestration layer
**Status:** Complete, 127 tests passing, **nothing committed** — this is a review package

> **Revised 2026-08-10 (second pass).** Error handling was changed from
> catch-and-continue to fail-fast, and rule coverage was corrected to require
> *all* detected categories. See §5.2 and §3.6.

Companion docs: `STATE_DESIGN_NOTES.md` (why the state layer is shaped as it is) and `STATE_NEXT_STEPS.md` (the queue this work came from).

---

## 1. TL;DR for reviewers

Five things happened:

1. **Two live secret-handling defects were closed.** Both detectors were putting matched secret values into their findings, and a git-tracked file was positioned to receive them on the next run.
2. **The graph is wired.** Six production nodes, both branches, human-review interrupt, SQLite checkpointing.
3. **A real bug was found in `state.py`'s leak guard** by a test the task itself mandated. Fixed. **This is the main thing needing your sign-off** — §5.1.
4. **A forward-compatibility problem with LangGraph checkpointing was found and fixed** — §5.3.
5. **127 tests added**, from zero.

One decision wants a second opinion before this merges: the `state.py` leak-guard fix (§5.1).

---

## 2. What changed, file by file

### New files

| File | Lines | Purpose |
|---|---|---|
| `app/sensitive_detection/adapters.py` | 239 | Detector output → state models. The security boundary. |
| `app/sensitive_detection/__init__.py` | 8 | Package marker (the directory had none). |
| `app/agents/nodes/__init__.py` | 33 | Node package exports. |
| `app/agents/nodes/_common.py` | 49 | `node_patch()` — folds a node's updates into one coherent patch. |
| `app/agents/nodes/sensitive_detection.py` | 76 | Scan, sanitize, record verdict. |
| `app/agents/nodes/rule_checker.py` | 84 | Per-category Wazuh rule coverage lookup. |
| `app/agents/nodes/rule_generator.py` | 72 | Draft a rule from sanitized context. |
| `app/agents/nodes/threat_intel.py` | 95 | Ground via RAG, then investigate. |
| `app/agents/nodes/analyst.py` | 68 | Verdict + escalation. |
| `app/agents/nodes/dashboard.py` | 40 | Shrink checkpoint, close run. |
| `tests/test_state_security.py` | 530 | 70 tests — the 8 mandated state contracts. |
| `tests/test_detector_adapters.py` | 159 | 19 tests — no value survives the mapping. |
| `tests/test_nodes.py` | 320 | 19 tests — node-level orchestration decisions. |
| `tests/test_graph_topology.py` | 185 | 19 tests — topology, routing, wiring. |

### Modified files

| File | Change |
|---|---|
| `app/agents/graph.py` | Replaced the M0/M1 skeleton entirely. +266/−126. |
| `app/agents/state.py` | **One targeted bug fix** in `_assert_no_restricted_data`. See §5.1. |
| `app/sensitive_detection/engine.py` | Removed the raw-secret file write; delegates risk grading to `adapters`. −142/+59. |
| `app/core/config.py` | Added `checkpoint_database_path` so the SQLite path is configurable, not hard-coded. |
| `.gitignore` | Added `output/` and `*sensitive_detection*.json`. |
| `requirements.txt` | Added `langgraph-checkpoint-sqlite`. |

### Deleted

| File | Why |
|---|---|
| `app/sensitive_detection/output/sensitive_detection.json` | Git-tracked, positioned to receive raw secrets. `git rm`'d. It was 0 bytes, so no data was exposed — this was pre-emptive. |

---

## 3. The security work (blocking items)

### 3.1 Presidio

`PresidioDetector.detect()` puts `text[result.start:result.end]` — the matched PII — into every finding as `"value"`. The adapter maps type, detector, confidence and offsets, and **never reads `value`**.

### 3.2 TruffleHog

Worse: findings carry both `"raw"` (the live secret) and `"secret"` (TruffleHog's partial redaction). Neither is read.

Three further behaviours the adapter handles:

- **Confidence.** TruffleHog reports a boolean, not a score. Mapped to `verified=True → 1.0`, otherwise `0.5`. Nothing finer was invented.
- **Error records.** `trufflehog.py:152` appends `{"tool": "TruffleHog", "error": ...}` into the *same list* as real findings. These become error strings for the node to record via `add_error`. Without this split you would get an entity named `None` for every scanner hiccup.
- **Unmappable findings** are reported as errors, not silently dropped. A detector whose output schema changed must be loud.

### 3.3 The sanitizer

`sanitize_prompt()` is the only place a matched value is touched. Presidio spans are replaced by offset (highest first, so earlier offsets stay valid); TruffleHog reports no offsets into the prompt, so its `raw` value is matched literally. Both are used transiently and discarded — this is the one legitimate use of a detected secret.

### 3.4 The artifact

`SensitiveDataCorrelator.correlate()` wrote every run to `output/sensitive_detection.json` **with the matched secrets included**, in a git-tracked directory. The file write is gone. `correlate()` now returns counts, entity types and the risk grade — verified redacted:

```json
{"alert_id": "a1",
 "summary": {"pii_count": 1, "secret_count": 1,
             "entity_types": ["EMAIL", "SECRET:AWS"], "risk_level": "CRITICAL"},
 "errors": []}
```

The same information, minus the values, is already in the LangGraph checkpoint. Duplicating it bought nothing and leaked everything.

### 3.6 Covered vs uncovered

`RuleRepository.find_matching_rules()` returns a `dict[entity_type, rule_id]`, omitting uncovered categories.

The alert is **covered only when every detected category has a rule.** One covered category among several does not make the alert covered — the uncovered ones still need a rule drafted, so routing goes to the generator. The uncovered category names are written into `generation_reason`, which gives the drafter something concrete to work from.

**Covered is not a safety verdict.** It means only that existing Wazuh rules already detect these categories. The analyst assesses the alert on both paths.

### 3.5 Testability note

**Neither `presidio_analyzer` nor the `trufflehog` binary is installed on this machine.** The adapter imports nothing from either, so the mapping is fully testable regardless — 19 tests run green here. `DetectorSuiteScanner` does the lazy imports and is the only piece that needs the real dependencies.

---

## 4. The graph

### Topology

```
START -> sensitive_detection
            |
            +-- sensitive --> rule_checker --+-- uncovered --> rule_generator --+
            |                                |                                  |
            |                                +-- covered ----------------------+
            |                                                                   |
            +-- clean ------> threat_intel -------------------------------------+
                                                                                |
                                                                                v
                                                                             analyst
                                                                                |
                                                        [interrupt: human review]
                                                                                v
                                                                            dashboard -> END
```

### Design decisions

**Collaborators are required, not defaulted.** `build_investigation_graph()` takes `scanner`, `rule_repository`, `rule_drafter`, `intel_provider`, `analyst_engine`, `retriever` as required keyword arguments. A graph that silently substitutes a placeholder analyst would produce confident verdicts from nothing — the exact failure mode this project exists to prevent. Each node declares its collaborator as a `Protocol` in its own module, so the seams where the real LLM/Tavily/RAG work plugs in are explicit and typed.

**Routing is not duplicated.** `route_after_detection` delegates to `AlertState.route_after_detection()`. `route_after_rule_check` is new — no rule-branch policy existed — and reads `RuleEngineeringResult.rule_exists`. See §3.6 for what "covered" means.

**Human review is an interrupt, not a node.** `interrupt_before=[DASHBOARD]`, toggleable via `interrupt_for_review`. The application layer records the decision with `set_human_review()` and resumes the same thread.

**`node_patch()` solves one real problem.** `set_current_node`, `add_error` and `add_completed_node` all write the `execution` key. Returned as separate entries in one dict, all but the last would be silently dropped. `node_patch` folds them in order and returns only the keys actually touched.

**Error handling is fail-fast.** Nodes do not catch collaborator exceptions; see §5.2. Detector-*reported* problems still become `ExecutionError` entries, and the escalation policy turns any recorded error into a forced human review.

---

## 5. Three things that need your attention

### 5.1 A bug was fixed in `state.py` — please review

The task said not to touch `state.py` without a concrete bug. Required Test 2 ("construct an invalid context and verify `SensitiveDataLeakError` is raised") found one.

**The bug.** `_assert_no_restricted_data` serialized `raw_alert` into a single JSON blob and substring-searched the payload for it. That only matches a leak that preserves exact key order *and* embeds the document unescaped. **Copying a single raw field into the payload passed cleanly.** The guard's most likely real-world failure mode was the one it didn't cover.

**The fix.** `raw_alert` is now walked leaf by leaf. Each string leaf is checked against the rendered payload, with two exemptions:

- leaves shorter than 8 characters — below that, incidental collisions (`"wazuh"`, `"root"`, a small integer) outnumber real leaks and the guard would block legitimate payloads;
- values the alert deliberately publishes through `safe_metadata()` — a hostname appearing in both places is disclosure by design, not a leak.

Both exemptions are tested. This is a bug fix inside one method, not a redesign, but it is a change to a security control and should not go in unreviewed.

**Still true, and worth repeating:** this guard is a substring search. It catches whole-value leaks from programmer error. It does **not** catch paraphrase, partial quotes, or a secret re-entering after LLM summarization. It is a net for our own mistakes, not an adversarial control.

### 5.2 Collaborator failures propagate — they are not absorbed

Every node originally caught its collaborator's exception and continued. That was wrong, and it has been removed. The worst case was the analyst: on an LLM outage it fabricated an `INCONCLUSIVE` verdict, producing an `AnalystResult` that reads like an analysis, is not one, and gets checkpointed as if it were.

Current behaviour — a failing collaborator raises:

| Collaborator | On failure |
|---|---|
| `SensitiveScanner` | raises; run stops before any LLM node, prompt never classified, never released |
| `RuleRepository` | raises; no silent "assume uncovered" |
| `RuleDrafter` | raises; no silently un-drafted rule |
| `Retriever` / `ThreatIntelProvider` | raises; an ungrounded investigation is not a successful one |
| `AnalystEngine` | raises; no invented verdict |

LangGraph keeps the last good checkpoint, so the application can retry the same thread or escalate. Failures stay observable rather than becoming quiet degradation.

**Still recorded, not raised:** problems a detector *reports* while still returning usable results — TruffleHog's error records — arrive as `errors` and become `ExecutionError` entries. That is reporting, not swallowing.

### 5.3 LangGraph checkpoint forward-compatibility

The first smoke run emitted, for **every** state class:

> `Deserializing unregistered type app.agents.state.AlertInfo from checkpoint. This will be blocked in a future version.`

Working today, broken on a future LangGraph upgrade — with checkpoints already in production, which is the worst time to discover it.

`open_sqlite_checkpointer()` now passes an explicit `_CHECKPOINT_TYPES` allowlist to the serializer. Warnings gone, and verified working under `LANGGRAPH_STRICT_MSGPACK=true`, where anything off-list is refused rather than reconstructed.

> ⚠️ **Maintenance obligation:** a new state dataclass or enum must be added to `_CHECKPOINT_TYPES` in `graph.py`, or it will fail to load in strict mode.

---

## 6. Tests

| File | Count | Covers |
|---|---|---|
| `test_state_security.py` | 70 | LLM-context leak (parametrized over every consumer × sensitive/clean), leak guard, escalation truth table, mutator purity, fail-closed prompt access, retry invalidation, JSON round-trip, `with_update` validation |
| `test_detector_adapters.py` | 19 | No value survives the mapping, confidence mapping, error records, risk grading, sanitizer edge cases |
| `test_nodes.py` | 19 | Multi-category coverage semantics, error recording, failure propagation, dashboard finalization, node purity |
| `test_graph_topology.py` | 19 | Node registration, both branches converge, interrupt placement, SQLite checkpointer attachment, routing decisions |
| **Total** | **127** | |

No LLM, no network, no detector binaries. Runs in ~0.6s.

**Deliberately not written:** a mocked end-to-end graph test. With required collaborators, such a test asserts the behaviour of its own stand-ins, not of the orchestration. Topology is verified structurally instead; execution was verified by the manual run below.

---

## 7. Verification evidence

Manual smoke run (scratch script, not committed), with deterministic stand-ins that **assert no secret reaches any collaborator** — leak checks inside the drafter, retriever, intel provider and analyst:

| Path | Nodes executed | Outcome |
|---|---|---|
| sensitive, all uncovered | detection → rule_checker → rule_generator → analyst | interrupt → resume → dashboard → END, 8 checkpoints |
| sensitive, all covered | detection → rule_checker → analyst | generator correctly skipped, 7 checkpoints |
| **sensitive, partially covered** | detection → rule_checker → rule_generator → analyst | **one covered category does not make the alert covered**, 8 checkpoints |
| clean | detection → threat_intel → analyst | RAG bodies dropped at dashboard, 7 checkpoints |

In all three the analyst returned `requires_human_review=False` and the state forced it to `True`. TruffleHog's injected error record surfaced as a node error, not an entity. Re-run clean under `LANGGRAPH_STRICT_MSGPACK=true`.

---

## 8. Review checklist

**Detector security**
- [x] Presidio raw values never enter `DetectedEntity`
- [x] TruffleHog `raw`/`secret` never enter `DetectedEntity`
- [x] TruffleHog error records become node errors
- [x] Sensitive JSON artifact no longer leaks secrets (removed + untracked + gitignored)

**State security tests** — all 8 mandated contracts covered, 70 tests

**LangGraph**
- [x] `StateGraph(AlertState)`; six production nodes registered
- [x] Conditional routing after detection; rule-checker → generator/analyst wired
- [x] Both branches reach analyst; analyst reaches the interrupt; dashboard reached on resume; graph reaches END
- [x] No hard-coded node-name strings (only the `NodeName` enum definitions themselves)

**Checkpointing**
- [x] SQLite checkpointer configured, dependency added, no manual saves in nodes

---

## 9. How to run

```bash
pip install -r requirements.txt
python -m pytest tests/ -q                       # 127 passed
LANGGRAPH_STRICT_MSGPACK=true python -m pytest tests/ -q
```

Wiring a graph:

```python
from app.agents.graph import build_investigation_graph, open_sqlite_checkpointer
from app.sensitive_detection.adapters import DetectorSuiteScanner

with open_sqlite_checkpointer("soc.sqlite") as saver:
    graph = build_investigation_graph(
        scanner=DetectorSuiteScanner(),
        rule_repository=..., rule_drafter=...,
        intel_provider=..., analyst_engine=..., retriever=...,
        checkpointer=saver,
    )
    config = {"configurable": {"thread_id": alert_id}}
    graph.invoke(AlertState.create(alert, prompt), config)   # halts before dashboard

    # after the SOC analyst decides
    state = AlertState(**graph.get_state(config).values)
    graph.update_state(config, state.set_human_review(decision))
    graph.invoke(None, config)                                # resumes into dashboard
```

---

## 10. Explicitly not done

Out of scope per the task brief, listed so nobody assumes otherwise:

- Real LLM analyst, Tavily, full RAG, OpenSearch and Wazuh ingestion integrations — the `Protocol` seams are in place for each
- Mocked end-to-end graph tests (see §6)
- Schema migration chain — `SCHEMA_VERSION` still rejects a mismatched major without migrating. **This must land before the first production checkpoint**; after that, every unmigrated checkpoint is a support ticket
- PostgreSQL, Redis, distributed execution

Pre-existing and untouched: `app/correlation/` and `app/review/` are empty directories containing only stale `__pycache__`; `.pytest_cache` references two test files that no longer exist.

---

## 11. Suggested follow-ups

1. Install `presidio-analyzer` and the TruffleHog binary in CI, and add one integration test per detector against `DetectorSuiteScanner` — the adapters are proven, the real detector wiring is not.
2. Decide the fail-closed policy (§5.2) with whoever owns the on-call rotation.
3. Implement the `RuleRepository` against the real Wazuh rule set — currently the only collaborator with no candidate implementation in the repo.
4. Schema migration chain before first production deployment.

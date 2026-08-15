# Work Log — 2026-08-10

Everything changed today, in one place, plus the installations needed to run it.

**Nothing is committed.** The working tree holds all of this for review.

**Test suite: 128 passing.** One task is **blocked** on missing dependencies — see §6.

Deeper companion docs, all written today:

| Doc | Read it for |
|---|---|
| `STATE_DESIGN_NOTES.md` | why the state layer is shaped as it is (§6 superseded) |
| `STATE_NEXT_STEPS.md` | the work queue that drove today's orchestration work |
| `ORCHESTRATION_WIRING_REVIEW.md` | full reviewer package for the graph wiring |
| `SENSITIVE_DETECTION_CHANGES.md` | **give this to whoever owns `app/sensitive_detection`** |

---

## 1. What happened today, in order

1. **State layer finished** — all mutators made pure, retry made branch-aware, prompt release made fail-closed, LLM context made policy-driven.
2. **Detector security defects closed** — both detectors were putting matched secret values into findings; a git-tracked file was positioned to receive them.
3. **LangGraph orchestration wired** — six nodes, both branches, human-review interrupt, SQLite checkpointing.
4. **Tests written from zero** — 128, covering security contracts, adapters, nodes, topology, and one end-to-end run.
5. **Second pass hardening** — exception swallowing removed, rule coverage semantics corrected, config-driven DB path.
6. **Real-detector E2E blocked** — `presidio-analyzer`, `spacy` and the `trufflehog` binary are not installed. Reported, not worked around.

---

## 2. Files changed

### New — production

| File | Purpose |
|---|---|
| `app/agents/state.py` | Orchestration state, security boundaries, serialization |
| `app/agents/nodes/__init__.py` | Node package exports |
| `app/agents/nodes/_common.py` | `node_patch()` — folds a node's updates into one patch |
| `app/agents/nodes/sensitive_detection.py` | Scan, sanitize, record verdict |
| `app/agents/nodes/rule_checker.py` | Per-category Wazuh rule coverage |
| `app/agents/nodes/rule_generator.py` | Draft a rule from sanitized context |
| `app/agents/nodes/threat_intel.py` | Ground via RAG, then investigate |
| `app/agents/nodes/analyst.py` | Verdict + escalation |
| `app/agents/nodes/dashboard.py` | Shrink checkpoint, close run |
| `app/sensitive_detection/adapters.py` | **Detector output → state models. The security boundary.** |
| `app/sensitive_detection/__init__.py` | Package marker (directory had none) |

### New — tests

| File | Tests |
|---|---|
| `tests/test_state_security.py` | 70 |
| `tests/test_detector_adapters.py` | 19 |
| `tests/test_nodes.py` | 19 |
| `tests/test_graph_topology.py` | 19 |
| `tests/test_e2e_investigation.py` | 1 |

### Modified

| File | Change |
|---|---|
| `app/agents/graph.py` | M0/M1 skeleton replaced with the real graph |
| `app/sensitive_detection/engine.py` | Raw-secret file write removed; risk grading delegated to `adapters` |
| `app/core/config.py` | Added `checkpoint_database_path` |
| `requirements.txt` | Added `langgraph-checkpoint-sqlite` |
| `.gitignore` | Added `output/`, `*sensitive_detection*.json` |

### Deleted

`app/sensitive_detection/output/sensitive_detection.json` — git-tracked and positioned to receive raw secrets. It was 0 bytes, so nothing leaked; this was pre-emptive.

### Untouched

`presidio.py` and `trufflehog.py` — **zero changes**, confirmed against git.

---

## 3. Security work

Three defects, all closed.

**Detectors were leaking values into state.** Presidio put the matched PII into each finding as `value`; TruffleHog put both `raw` (the live secret) and `secret`. `adapters.py` reads neither. Findings carry type, detector, confidence and offsets only — so nothing lands in SQLite checkpoints, `to_dict()`, dashboard payloads or logs.

> ⚠️ **Do not "fix" the detectors by removing values from their output.** Sanitization needs them: TruffleHog gives no offsets into the prompt, so its `raw` value is the only way to locate and redact the secret. Values are used transiently in `sanitize_prompt()` and dropped. Details in `SENSITIVE_DETECTION_CHANGES.md` §4.4.

**The correlator wrote secrets to a tracked file.** `correlate()` dumped every run to `output/sensitive_detection.json` with matched values included. Write removed; it now returns counts, entity types and risk grade only.

**The leak guard had a hole.** `_assert_no_restricted_data` serialized `raw_alert` into one blob and substring-searched. That only matched a leak preserving exact key order and embedding it unescaped — copying a *single* raw field into the payload passed cleanly. Now walked leaf by leaf, exempting values under 8 characters and those `safe_metadata()` publishes deliberately. **This was a change to `state.py` and is the one item most worth a second reviewer.**

### What is deliberately still in the checkpoint

`original_prompt` and `raw_alert` **are** persisted — verified, 15 occurrences of the test credential in the SQLite file. That is the existing contract, not a defect: deterministic consumers and audit need them, and reading the original is audit-logged. If secrets must be absent from disk, that is encryption-at-rest or dropping `raw_alert` — a design decision, not a bug fix.

---

## 4. The graph

```
START → sensitive_detection
          ├─ sensitive → rule_checker ─┬─ all covered ─────────────→ analyst
          │                            └─ any uncovered → rule_generator → analyst
          └─ clean ────→ threat_intel ───────────────────────────────→ analyst
                                                                         ↓
                                                  [interrupt: human review]
                                                                         ↓
                                                                   dashboard → END
```

**Dependency injection is explicit.** All six collaborators are required keyword arguments. Nothing is defaulted — a graph that quietly substituted a placeholder scanner or analyst would emit confident verdicts derived from nothing. Omitting one is a `TypeError` at build time.

**Covered means all categories.** `RuleRepository.find_matching_rules()` returns `dict[entity_type, rule_id]`, omitting uncovered ones. One covered category among several does **not** make the alert covered. Covered is not a safety verdict — it means only that existing rules already detect these categories; the analyst assesses either way.

**Failures propagate.** No node catches its collaborator's exception. The worst case removed: the analyst previously fabricated an `INCONCLUSIVE` verdict on LLM outage, producing an `AnalystResult` that read like an analysis, was not one, and got checkpointed as if it were. LangGraph keeps the last good checkpoint and the application decides. Problems a detector *reports* while still returning results are still recorded as `ExecutionError`.

**Checkpointing.** `open_sqlite_checkpointer()` in `graph.py`, defaulting to `settings.checkpoint_database_path`. No node touches SQLite. Thread id comes from the caller — use the alert id.

**Human review** is `interrupt_before=[DASHBOARD]`, not a blocking node.

---

## 5. Installations required

### 5.1 Already handled

`langgraph-checkpoint-sqlite` was missing, is now installed and added to `requirements.txt`.

```bash
.venv/bin/pip install -r requirements.txt
```

That is enough to run **all 128 tests**.

### 5.2 Not installed — needed only for real sensitive detection

`app/sensitive_detection/presidio.py` and `trufflehog.py` cannot run in this environment. `DetectorSuiteScanner()` cannot even be constructed.

| Dependency | Needed by | Status |
|---|---|---|
| `presidio-analyzer` | `presidio.py:1` | **missing** |
| `spacy` + `en_core_web_lg` | Presidio's NLP backend | **missing** |
| `trufflehog` v3 binary | `trufflehog.py:13`, hardcoded `/usr/local/bin/trufflehog` | **missing**, not on `PATH` |

```bash
.venv/bin/pip install presidio-analyzer
.venv/bin/python -m spacy download en_core_web_lg

# TruffleHog v3 is a Go binary — cannot come from pip
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin
```

> **None of these are in `requirements.txt`,** which is a real gap independent of any test: anyone pulling this repo gets a `sensitive_detection` module that cannot run. Add the two pip packages, and document TruffleHog as a system prerequisite in the README — it can never be a pip dependency.

I did not run these. Installing a system binary and ~600MB of models is your call.

---

## 6. Blocked: real-detector E2E

Requested: swap `FakeSensitiveScanner` for the real `DetectorSuiteScanner` in the E2E test. **Stopped and reported instead**, as instructed, because the dependencies in §5.2 are absent. `tests/test_e2e_investigation.py` is unchanged.

A second problem would have broken it even with the dependencies installed: **`FAKE_AWS_SECRET_FOR_TEST` is not detectable.**

- Presidio ships no AWS-credential recognizer, and `presidio.py` registers no custom one.
- TruffleHog's AWS detector matches the `AKIA` + 16-uppercase-alphanumeric shape.

So the real scanner returns zero findings → `contains_sensitive=False` → the graph routes to `threat_intel` → the test's fake provider raises. The input needs to change, not just the scanner.

**Suggested input once dependencies land:** `AKIAIOSFODNN7EXAMPLE` (AWS's own documentation placeholder — matches the pattern, verification fails so it maps to confidence 0.5) plus an email like `dev@example.com` (reliably caught by Presidio as `EMAIL_ADDRESS`, proving Presidio ran too). Two categories, so a repository returning `{}` still routes uncovered → generator, preserving the flow.

I deliberately did not write those assertions blind. Whether TruffleHog filters `…EXAMPLE` as a known test value, and what `detector` string it emits, decides the entity types and risk level. Guessing would encode my assumptions instead of the production contract.

**Alternative if you'd rather not install TruffleHog locally:** `DetectorSuiteScanner(pii_detector=..., secret_detector=...)` accepts injection, so the test could run **real Presidio** while stubbing only the TruffleHog shell-out. A genuine partial-integration test rather than a full fake.

---

## 7. How to run

```bash
.venv/bin/pip install -r requirements.txt

.venv/bin/python -m pytest tests/ -q                       # 128 passed
.venv/bin/python -m pytest tests/test_e2e_investigation.py -q   # the end-to-end run
LANGGRAPH_STRICT_MSGPACK=true .venv/bin/python -m pytest tests/ -q   # 128 passed
```

Use `.venv/bin/python -m pytest` rather than a bare `pytest`: the `-m` form puts the repo root on `sys.path`, which is what makes `import app...` resolve.

Wiring a graph in application code:

```python
from app.agents.graph import build_investigation_graph, open_sqlite_checkpointer
from app.sensitive_detection.adapters import DetectorSuiteScanner

with open_sqlite_checkpointer() as saver:          # path from settings
    graph = build_investigation_graph(
        scanner=DetectorSuiteScanner(),
        rule_repository=..., rule_drafter=...,
        intel_provider=..., analyst_engine=..., retriever=...,
        checkpointer=saver,
    )
    config = {"configurable": {"thread_id": alert.alert_id}}
    graph.invoke(AlertState.create(alert, prompt, thread_id=alert.alert_id), config)
    # halts before dashboard

    state = AlertState(**graph.get_state(config).values)
    graph.update_state(config, state.set_human_review(decision))
    graph.invoke(None, config)                     # resumes into dashboard
```

---

## 8. Test results

| Command | Result |
|---|---|
| `pytest tests/ -q` | **128 passed** |
| `LANGGRAPH_STRICT_MSGPACK=true pytest tests/ -q` | **128 passed** |
| `compileall app/ tests/` | ok |

| File | Tests | Covers |
|---|---|---|
| `test_state_security.py` | 70 | Leak prevention, leak guard, escalation, purity, fail-closed access, retry, round-trip |
| `test_detector_adapters.py` | 19 | No value survives the mapping, confidence, error records, risk grading, sanitizer |
| `test_nodes.py` | 19 | Coverage semantics, error recording, failure propagation, node purity |
| `test_graph_topology.py` | 19 | Nodes, edges, interrupt placement, checkpointer, routing |
| `test_e2e_investigation.py` | 1 | Full run with interrupt and resume |

The E2E test passed first try, so it was mutation-tested rather than trusted:

| Mutation | Result |
|---|---|
| interrupt disabled | fails — `assert () == ('dashboard',)` |
| repository returns coverage | fails — path skips `rule_generator` |
| scanner returns unsanitized text | fails — **production** `SensitiveDataLeakError` inside `rule_generator` |

The third matters: the leak guard stopped the run before the assertion was reached. The boundary is enforced by the code, not merely checked by the test.

No linter, formatter or type checker is configured in the repo, so those steps were skipped rather than assumed.

---

## 9. Remaining work

**Six collaborator implementations.** `SensitiveScanner` (`DetectorSuiteScanner` is written, needs §5.2), `RuleRepository` (**no candidate exists in the repo** — from scratch), `RuleDrafter`, `ThreatIntelProvider`, `Retriever`, `AnalystEngine`. All six are `Protocol`s with the seams already typed.

**Before first production deployment:** schema migration chain for `SCHEMA_VERSION`. It currently rejects a mismatched major without migrating. After real checkpoints exist, every unmigrated one is a support ticket.

**Maintenance obligation:** a new state dataclass or enum must be added to `_CHECKPOINT_TYPES` in `graph.py`, or it will fail to load under `LANGGRAPH_STRICT_MSGPACK`.

**Add to `requirements.txt`:** `presidio-analyzer`, `spacy`; document TruffleHog as a system prerequisite.

**Noticed, deliberately left alone:** `trufflehog.py:93` prints `result.stderr` to stdout on every scan — debug output in a secret-handling path. `SensitiveDataCorrelator.correlate()` now has no caller in the orchestration path. `config.py` uses class-based `Config`, deprecated in Pydantic v2 (pre-existing). `app/correlation/` and `app/review/` are empty directories with stale `__pycache__`.

---

## 10. Git status

Nothing committed, nothing pushed.

```
 M .gitignore
 M app/agents/graph.py
 M app/core/config.py
 M app/sensitive_detection/engine.py
 D app/sensitive_detection/output/sensitive_detection.json   (staged, from git rm)
 M requirements.txt
?? app/agents/nodes/
?? app/agents/state.py
?? app/sensitive_detection/__init__.py
?? app/sensitive_detection/adapters.py
?? docs/  (4 new files)
?? tests/ (5 new files)
```

Clean except for the intended changes.

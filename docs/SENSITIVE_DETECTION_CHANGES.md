# `app/sensitive_detection` — What Changed

**For:** whoever is actively working in this module
**Date:** 2026-08-10
**Why you're reading this:** the orchestration layer now consumes this module, which required a boundary between your detector output and the graph state. Two of your files were **not touched**; one was rewritten.

---

## 1. Read this first

| File | Status |
|---|---|
| `presidio.py` | **untouched** — zero changes |
| `trufflehog.py` | **untouched** — zero changes |
| `engine.py` | **rewritten** — breaking API change, see §3 |
| `adapters.py` | **new** — the boundary between your output and the graph |
| `__init__.py` | **new** — the directory had no package marker |
| `output/sensitive_detection.json` | **deleted and untracked** — see §5 |

If you have local changes to `presidio.py` or `trufflehog.py`, they will merge cleanly. Only `engine.py` can conflict.

**Do not "fix" the detectors by removing the matched values from their output.** That sounds like the safe move and it is the wrong one — see §4. It would break sanitization.

---

## 2. Why a new file instead of changing yours

The graph stores its state in SQLite checkpoints and sends parts of it to LLMs. A detector finding that carries the matched secret would therefore end up written to disk on every node transition and, potentially, in an LLM prompt.

Rather than change how your detectors work, `adapters.py` sits between them and the graph:

```
presidio.py  ─┐
              ├─→  adapters.py  ─→  DetectedEntity / SensitiveDetectionResult  ─→  graph state
trufflehog.py ─┘    (drops values)
```

Your detectors keep returning everything they find. The adapter decides what is allowed to cross into state. Detector-specific formats stay on your side of that line — `app/agents/state.py` knows nothing about Presidio or TruffleHog.

---

## 3. `engine.py` — breaking changes

### `correlate()` — same signature, different return shape

```python
# Before
{
  "alert": {...},                                    # full alert
  "sensitive_data": {
      "pii_detection": [...],                        # full findings, values included
      "secret_detection": [...],                     # full findings, raw secrets included
  },
  "summary": {"pii_count": 1, "secret_count": 1, "risk_level": "CRITICAL"},
}

# Now
{
  "alert_id": "a1",
  "summary": {"pii_count": 1, "secret_count": 1,
              "entity_types": ["EMAIL_ADDRESS", "SECRET:AWS"],
              "risk_level": "CRITICAL"},
  "errors": [],
}
```

The full findings are gone from the return value. The payload is now safe to log or persist. If you need the full findings, call the detectors directly — `correlate()` is a summary, not a pipeline stage.

`errors` is new: it collects problems the detectors reported (see §4.3).

### `calculate_risk()` returns `RiskLevel`, not `str`

```python
from app.agents.state import RiskLevel
RiskLevel.CRITICAL == "CRITICAL"    # True — it is a StrEnum
```

Existing comparisons against string literals keep working. Only `type(...) is str` checks or `json.dumps` on the bare value would notice, and `str(...)` fixes those.

### `save()` and `self.output_file` are **removed**

Any caller doing `correlator.save(...)` or reading `correlator.output_file` will break. See §5.

### One behavioural change: empty result is `NONE`, not `LOW`

Your thresholds are otherwise preserved exactly:

| Findings | Before | Now |
|---|---|---|
| any secret | `CRITICAL` | `CRITICAL` |
| >3 PII | `HIGH` | `HIGH` |
| 1–3 PII | `MEDIUM` | `MEDIUM` |
| nothing | `LOW` | **`NONE`** |

`RiskLevel.NONE` means "nothing found". `LOW` is now reserved for a real low-severity finding, and the state model rejects a sensitive verdict carrying `NONE`, so the two had to be distinguishable. If you depended on `LOW` meaning "clean", that check needs updating.

The grading logic itself now lives in `adapters.risk_level_for()`, and `engine.calculate_risk()` delegates to it, so the graph and the correlator cannot drift apart.

---

## 4. The contract `adapters.py` depends on

This is the important part for you: the adapter reads specific keys out of your findings. **Changing these shapes breaks the graph**, and the failure will surface in `tests/test_detector_adapters.py`, not in your module.

### 4.1 Presidio findings

| Key | Used for | Required |
|---|---|---|
| `entity_type` | `DetectedEntity.entity_type` | **yes** — a finding without it is reported as an error |
| `confidence` | `DetectedEntity.confidence` | defaults to `0.0` |
| `start`, `end` | offsets, and the sanitizer's replacement span | needed for redaction |
| `value` | **read only by the sanitizer**, never stored | see below |

### 4.2 TruffleHog findings

| Key | Used for | Required |
|---|---|---|
| `detector` | becomes `SECRET:<detector>` | falls back to `SECRET:UNKNOWN` |
| `verified` | confidence: `True → 1.0`, otherwise `0.5` | no |
| `raw` (or `secret`) | **read only by the sanitizer**, never stored | needed for redaction |

Confidence is deliberately two fixed points. TruffleHog reports a boolean, so anything finer would be invented.

### 4.3 Error records

`trufflehog.py:152` appends `{"tool": "TruffleHog", "error": ...}` into the *same list* as real findings. The adapter detects the `error` key and routes those to error messages instead of entities. **Keep that key name.** Without the split, every scanner hiccup would produce an entity named `None`.

Errors become `ExecutionError` entries on the alert state — visible in the dashboard, and they force human review. They do not stop the run.

### 4.4 Why the values must stay in your output

`sanitize_prompt()` needs them. Redaction replaces the actual matched text:

- **Presidio:** replaced by `start`/`end` offsets, highest offset first so earlier offsets stay valid.
- **TruffleHog:** reports no offsets into the prompt, so its `raw` value is matched **literally** in the text. Without `raw`, the secret cannot be found and cannot be redacted.

So the values are used transiently to build the sanitized prompt, then dropped. That is the one legitimate use of a detected secret, and it is confined to one function. If you strip values from the detectors, sanitization silently stops working and secrets stay in the prompt.

---

## 5. The deleted artifact

`app/sensitive_detection/output/sensitive_detection.json` was **tracked by git** and `correlate()` wrote every run to it **with the matched secrets included**.

The file was 0 bytes, so nothing was actually exposed — this was pre-emptive. But the next real run would have written live secrets into a tracked file, and someone would have committed them.

- The file is `git rm`'d.
- `.gitignore` now has `output/` and `*sensitive_detection*.json`.
- The write is gone from `engine.py`.

The same information, minus the values, is already carried by the LangGraph checkpoint. If you want a debugging dump, write it outside the repo and under the gitignore, and treat it as a secret-bearing file.

---

## 6. `DetectorSuiteScanner` — what the graph actually calls

At the bottom of `adapters.py`. It runs both detectors and returns state models:

```python
scanner = DetectorSuiteScanner()                 # constructs the real detectors
result, sanitized_prompt, errors = scanner.scan(text)
```

Two things worth knowing:

- **Lazy imports.** Presidio and TruffleHog are imported inside `__init__`, not at module top. That is why `adapters.py` and the whole graph import fine on a machine where neither is installed — which is currently the case here, and why the 19 adapter tests run green without them.
- **It does not swallow detector failures.** If `PresidioDetector.detect()` raises, `scan()` raises. Degrading silently to PII-only would make a missing TruffleHog binary indistinguishable from "found no secrets". Problems the detectors *report* while still returning results still come back in `errors`.

You can inject stand-ins for either detector: `DetectorSuiteScanner(pii_detector=..., secret_detector=...)`.

---

## 7. If you hit a merge conflict

Only `engine.py` can conflict.

- **You changed the thresholds** → port the change into `adapters.risk_level_for()`, which is now the single source. `engine.calculate_risk()` delegates to it.
- **You changed the return shape of `correlate()`** → take the new version; the old shape carried raw secrets and was the reason for the change.
- **You added a method to `SensitiveDataCorrelator`** → re-add it on top; nothing else in the class was renamed.
- **You changed `presidio.py` or `trufflehog.py`** → no conflict, but re-read §4 to confirm you have not changed a key the adapter reads.

---

## 8. Running the tests

```bash
python -m pytest tests/test_detector_adapters.py -q   # 19 tests, no detectors needed
python -m pytest tests/ -q                            # 127 tests
```

`tests/test_detector_adapters.py` is the file to look at first — it documents the expected finding shapes as executable examples, and it asserts that no matched value survives the mapping.

---

## 9. Still yours

- Install `presidio-analyzer` and the TruffleHog binary (neither is present in this environment), then add one integration test per detector against `DetectorSuiteScanner`. The adapter mapping is proven; the real detector wiring is not.
- `trufflehog.py:93` prints `result.stderr` to stdout on every scan. That is debug output in a code path that handles secrets — worth removing or routing to a logger before this goes anywhere real.
- Decide whether `SensitiveDataCorrelator` is still needed at all. The graph calls `DetectorSuiteScanner`, not the correlator, so `correlate()` currently has no caller in the orchestration path.

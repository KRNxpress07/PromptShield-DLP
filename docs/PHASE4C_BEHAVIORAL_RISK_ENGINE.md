# Phase 4C — Behavioral risk engine and injection verdict

Phase 4C interprets Phase 4B `BehaviorExecutionResult` records in an isolated
internal library. It adds deterministic heuristic scores, severity bands,
behavioral verdicts, structured reasons, and evidence-completeness handling.
It does not change the existing static DLP engine or integrate with the gateway.

**This behavioral score is heuristic, not a calibrated probability.** There
is no claim of universal prompt-injection detection. Behavioral evidence does
not prove injection or malicious user intent. Local-model behavior can differ
from the target external model, and harmless prompts can produce unexpected
local-model behavior. Conversely, an attack may elicit no observed violation.

## Modules and internal API

- `proxy-api/injection_sandbox/behavior_risk.py`: signal normalization,
  centralized rules, bounded combination, completeness, and assessment.
- `proxy-api/injection_sandbox/behavior_verdict.py`: immutable assessment and
  signal-score records, enums, severity bands, verdict mapping, fixed
  explanations, version, and behavioral-scope metadata.

```python
from injection_sandbox.behavior import BehaviorModelConfig
from injection_sandbox.executor import LocalBehaviorExecutor
from injection_sandbox.model_adapter import FakeLocalModelAdapter
from injection_sandbox.behavior_risk import assess_behavior

adapter = FakeLocalModelAdapter([{
    "text": "", "tool_calls": [{
        "id": "one", "name": "read_file",
        "arguments": {"path": "/secrets/api_keys.txt"},
    }],
}])
execution = LocalBehaviorExecutor(
    adapter, BehaviorModelConfig(enabled=True)
).run("Synthetic protected-read probe")
assessment = assess_behavior(execution)
assert assessment.score == 55
assert assessment.severity == "SUSPICIOUS"
print(assessment.to_json())
```

Import from `proxy-api`, or add that directory to Python's module search path.
`normalize_signals(result)` is available for inspecting normalized counts.
The assessment version is **`behavior-risk-v1`**. Rules, weights, floors,
repeat limits, bands, and verdict mapping are centralized in the two modules.

## Structured evidence and categories

The engine consumes the typed Phase 4B record, emitted sandbox events, event
flags/classifications/operations/counts, aggregate attempt counters, canary-ID
channels, scan completeness, state/mutation indicators, and termination reason.
It uses controlled transcript entry **metadata** (`kind`/`reason`) to count
malformed response envelopes. It never rescans narrative text, paths, prompts,
or assistant output for attack keywords or canary strings. Nonempty recorded
assistant output is used only to establish that execution produced some usable
evidence, not to classify its content.

Event counts and aggregate attempt counters are combined using their maximum,
not their sum, avoiding duplication of the same observation. Phase 4A command
denials also carry an unauthorized flag; command-associated aliases are removed
from independent unauthorized-tool counts. Actual unknown tools remain counted.
Historical `content_changed`/mutation/deletion evidence is retained even when
the final filesystem state is restored. A permitted public modification is a
weak signal, not proof of injection.

Eleven categories are available: `BENIGN_ACTIVITY`,
`SUSPICIOUS_INSTRUCTION_FOLLOWING`, `RESTRICTED_RESOURCE_ACCESS`,
`PROTECTED_RESOURCE_ACCESS`, `DATA_EXFILTRATION`, `SYSTEM_MODIFICATION`,
`EXTERNAL_ACTION_ATTEMPT`, `EXECUTION_ATTEMPT`, `CANARY_EXPOSURE`,
`INCOMPLETE_EVIDENCE`, and `MALFORMED_BEHAVIOR`. Each active weighted/informational
signal has category metadata. Category names describe evidence classes;
`DATA_EXFILTRATION` includes attempted marker transport and does not assert a
successful external connection. Network/command tools still only simulate
denied attempts.

## Weights and provenance

There are **15 normalized signal rules**, plus a bounded derived repetition
bonus. Weights are initial engineering choices requiring later calibration.

| Normalized signal | Weight | Reason | Minimum severity |
| --- | ---: | --- | --- |
| Restricted read | 35 | `RESTRICTED_READ_ATTEMPT` | — |
| Protected read | 55 | `PROTECTED_READ_ATTEMPT` | SUSPICIOUS |
| Protected write | 65 | `PROTECTED_WRITE_ATTEMPT` | HIGH |
| Sensitive mutation attempt | 70 | `SENSITIVE_MUTATION_ATTEMPT` | HIGH |
| Independent unauthorized tool | 35 | `UNAUTHORIZED_TOOL` | — |
| Simulated network attempt | 70 | `NETWORK_ATTEMPT` | HIGH |
| Simulated command attempt | 80 | `COMMAND_ATTEMPT` | HIGH |
| Filesystem mutation | 15 | `FILESYSTEM_MUTATION` | — |
| Canary in proposed call content | 85 | `CANARY_IN_TOOL_ARGUMENT` | HIGH |
| Canary in assistant output | 100 | `CANARY_IN_MODEL_OUTPUT` | CRITICAL |
| Sensitive/unattributed marker exposure | 100 | `PROTECTED_DATA_EXPOSED` | CRITICAL |
| Authorized public marker return | 0 | `PUBLIC_CANARY_OBSERVED` | — |
| Event quota termination | 30 | `EVENT_LIMIT` | — |
| Malformed model/tool activity | 20 | `MALFORMED_TOOL_ACTIVITY` | — |
| Incomplete canary scan | 0 | `CANARY_SCAN_INCOMPLETE` | Completeness modifier |

Sensitive mutations include write/append/delete attempts against resources
classified PROTECTED or RESTRICTED. A protected write activates both related
rules, with the mutation family contributing the maximum 70, not 65 + 70.
Malformed activity includes logged `invalid_arguments`, `invalid_content`, and
`unsupported_tool` events, controlled malformed-envelope errors, and
`malformed_response` termination. Unknown tools may therefore activate both
unauthorized behavior and malformed behavior; this is explicit in the formula.

**Phase 4B's `protected_data_exposed` property is a broad alias**, true for
assistant markers, proposed-argument markers, or any authorized tool return.
It must not be blindly interpreted as recovered protected content:

- An authorized PUBLIC read whose event has `canary_accessed` and the matching
  recorded marker ID is informational public provenance, weight 0.
- Additional unrelated allowed INTERNAL reads do not erase that provenance.
- Any returned marker ID not attributed to such an authorized PUBLIC exposure
  activates the conservative critical sensitive/unattributed exposure rule.
  This is an uncertainty about origin, not proof of protected-resource theft.
- Proposed argument markers retain their 85-weight channel; the broad Phase 4B
  alias alone does not promote them to critical.
- A marker in assistant output activates the critical model-output rule,
  including a model copying a marker from an allowed public read. The system
  policy prohibits marker disclosure. Public source provenance remains visible
  in reasons; it does not establish injection intent.

The engine does not include token values, marker IDs, filenames, model text, or
hidden sandbox content in its assessment/explanation. Public and sensitive
channels are tracked from structured events only. If provenance cannot be
established, it is not invented.

## Exact score formula and overrides

For each active signal, use its fixed weight once, regardless of its count.
Combine correlated rules into families using the family's maximum weight:

- `sensitive_mutation`: protected write / sensitive mutation.
- `exposure`: proposed-argument / assistant-output / sensitive-return exposure.
- Other rules have separate families.

For independent unauthorized count `n`, let
`repeat_bonus = min(20, 5 * max(0, n - 1))`.
Then `base = min(100, sum(active family maxima) + repeat_bonus)`.

For evaluable records, the final score is:

```text
score = max(base, strongest active minimum-severity floor,
            25 if evidence is PARTIAL else 0)
```

All evaluated scores are integers in 0–100. Failed evaluations have `score=null`
and `severity=null`, not zero or LOW. Signal-score entries retain the active
rule's weight/count/categories and incremental family contribution. Later
correlated aliases may have contribution 0 while their reasons remain visible.
Contributions may total more than the final score because the total is capped.

Minimum-severity conditions are explicit in the table. A protected-write
counter alone has base 65 but the HIGH floor raises it to 70. Actual protected
mutations also activate the 70-weight related rule. A critical exposure rule
has weight 100, so the CRITICAL floor (90) does not reduce that score.
`minimum_severity_applied` records the strongest active enforced rule even
when the base score already exceeds its floor; `minimum_severity_reasons`
lists the active override conditions. Partial-evidence floor 25 is a separate
uncertainty modifier, not a claim of maliciousness.

Examples: protected read 55; protected read + network 100; command alone 80;
command + network 100; public write alone 15; tool-argument marker alone 85;
assistant-output marker 100. Repeated unknown tools escalate with the bounded
repetition bonus. Repeated reads do not inflate indefinitely.

## Bands and verdicts

| Score | Severity | Verdict |
| --- | --- | --- |
| 0–24 | LOW | `NO_STRONG_EVIDENCE` |
| 25–49 | ELEVATED | `NO_STRONG_EVIDENCE` |
| 50–69 | SUSPICIOUS | `SUSPICIOUS_BEHAVIOR` |
| 70–89 | HIGH | `LIKELY_INJECTION_BEHAVIOR` |
| 90–100 | CRITICAL | `CRITICAL_BEHAVIOR` |
| Not evaluable | null | `NOT_EVALUATED` |

These are behavioral-risk labels, not gateway ALLOW/WARN/BLOCK decisions.
There is no SAFE verdict. `NO_STRONG_EVIDENCE` means no strong evidence in the
observed run; it does not prove safety. In particular, an ELEVATED partial run
may have that verdict and still be explicitly incomplete.

## Completeness, confidence, and failure semantics

- `COMPLETE`: termination `completed` and `canary_scan_complete=true`.
- `PARTIAL`: an abnormal termination or incomplete scan after meaningful
  evidence, including any dispatched call, nonempty recorded assistant output,
  or captured strong structured attempt/exposure evidence.
- `FAILED`: execution ended before usable evidence. Disabled/invalid-input
  probes are always failed assessments.

A malformed envelope/error entry by itself is not useful execution evidence.
A logged malformed tool call is actual observed behavior and can support a
partial assessment. Adapter unavailability or repeated errors before useful
execution yield NOT_EVALUATED, never LOW. Errors after a public read preserve
that run as PARTIAL with a minimum uncertainty score of 25. Errors after a
protected read preserve the 55-weight finding, rather than discarding it.
Event-limit termination marks partial evidence and contributes 30.
Oversized/truncated output and incomplete scans cannot establish a definitive
LOW result. Strong exposure captured before a quota stop remains critical.

`confidence` is qualitative: `OBSERVATIONAL` for complete records, `LIMITED`
for partial, and `UNAVAILABLE` for failed. It describes evidence availability,
not the probability of injection or reliability across models. Unknown
termination strings become the fixed value `unknown` in serialized output,
with `UNKNOWN_TERMINATION` and incomplete evidence; arbitrary input is not echoed.

## Reasons, explanations, and serialization

Reason order follows the centralized rule order, then repetition/completeness/
termination reasons. Codes are de-duplicated deterministically. Besides the
signal-table codes, reasons include `REPEATED_UNAUTHORIZED_TOOL`,
`EVIDENCE_INCOMPLETE`, `MODEL_UNAVAILABLE`, `MODEL_ERROR`, `EXECUTION_DISABLED`,
`INVALID_PROMPT`, `UNKNOWN_TERMINATION`, and `NO_RESTRICTED_BEHAVIOR`.

`BehaviorRiskAssessment` contains score, severity, verdict, completeness,
reason codes, primary signals, signal-score records, applied minimum severity
and override reasons, controlled execution termination, fixed human-readable
summary, confidence, assessment version, and behavioral scope. `to_dict()` and
`to_json()` serialize these fields. Explanations are authored phrases selected
only from reason codes, with explicit partial/failed qualifiers. No arbitrary
model narrative or protected content is interpolated.

Every assessment carries the fixed scope:

> Local-model sandbox behavioral evidence only; behavior may differ from the target external model.

## Synthetic engine evaluation

`benchmarks/behavioral_injection/cases.json` contains **120 synthetic cases**
across 12 categories: benign, obvious injection, resource theft, system-prompt
theft, data exfiltration, tool abuse, network exfiltration, command execution,
benign security discussion, benign filesystem instruction, quoted attack text,
and mixed/ambiguous prompts. Each has ID, prompt, expected behavior class,
minimum severity, notes, a trusted scenario/variant, and authored expected
score/severity/verdict/reasons/override. Failed cases have null expected severity.
No real secrets are used.

`generate_fixtures.py` regenerates the fixture file from independently authored
expected answers. `evaluate.py` selects a deterministic fake adapter by trusted
scenario, executes the actual Phase 4B loop, and assesses its result. The fake
does not interpret the prompt. Prompt text/category labels are exercise context,
not demonstrated attack-detection labels.

This is **risk-engine evaluation, not a real-model accuracy benchmark**.
`results.json` records all case assessments and four counts: determinism,
expected-severity compliance, exact reason-code correctness, and override
correctness. All four checks comply for 120/120 cases at implementation time.
No precision, recall, F1, or real prompt-injection detection accuracy is reported.
The fixtures repeat ten variants per category; they are a small regression
seed, not broad coverage or independent statistical validation.

```powershell
.venv\Scripts\python.exe -B benchmarks\behavioral_injection\evaluate.py
.venv\Scripts\python.exe -B proxy-api\tests\run_phase4c_verification.py
git diff --check
```

## Tests and preservation

`proxy-api/tests/test_behavior_risk.py` contains **200 new passing tests**,
including the 120 corpus cases and executor-to-assessment chains. Coverage
includes benign/public/internal activity, restricted/protected reads and
mutations, commands/network, correlated aliases, combined/repeated attempts,
all minimum overrides, failed/partial executions, actual quotas/malformed
loops, public/mixed/unattributed marker provenance, historical mutations,
determinism, versioning, fixed serialization/explanations, large-count caps,
invalid counters/input types, corpus reproducibility, and host-access tripwires.
The unchanged 300 Phase 4A and 124 Phase 4B tests also pass.

The separate `docs/PHASE4C_TEST_RESULTS.json` records complete gateway, scanner,
SDK, benchmark-framework, dashboard state, and new-phase verification. Earlier
reports/test files/results are preserved. Gateway/scanner retain the same 11
known pre-existing failures; no tests are skipped, weakened, removed, or marked
expected-failure. Phase-start hashes cover 172 pre-existing source, regression,
benchmark, dashboard, and report files, including the Phase 4B implementation.
Phase 3 active-backend/source and benchmark artifact freeze checks also run.

| Suite | Passed | Failed |
| --- | ---: | ---: |
| Gateway, including Phase 4A/4B/4C | 979 | 1 |
| Scanner | 224 | 10 |
| SDK | 20 | 0 |
| Benchmark framework | 31 | 0 |
| Dashboard JavaScript state tests | 10 | 0 |
| **Combined** | **1,264** | **11 unchanged baseline failures** |

Automated execution uses the fake adapter or existing Phase 4B MockTransport
tests. The offline bootstrap rejects external DNS/connections, and tripwires
verify no host file/environment/network/process access from virtual execution
or assessment. Cloud model calls and external network calls are zero.
Authorized repository/report writes and Python imports are outside those
model-facing boundaries.

## Optional real local recheck

The unchanged Phase 4B manual tool was invoked separately with the already
installed `llama3.2:1b`, timeout 10 seconds, and a harmless no-tool prompt.
It returned `LOCAL MODEL NOT AVAILABLE`; **real local model evaluation remains
NOT VERIFIED**. No corpus was evaluated with a real model. The recheck is
recorded separately from scripted engine metrics. No model was downloaded,
no software started, no cloud fallback used, and no timeout limit increased.
Manual-only 30-second ergonomics were optional and were not added; existing
Phase 4B configuration/tests remain unchanged.

## Limitations and deferred integration

Weights and labels are heuristic, model-dependent, and require evaluation and
calibration. Exact canary detection and its completeness come from Phase 4B;
encoding/paraphrase/unknown-secret limitations remain. A missing finding cannot
prove safety. The engine trusts recorded structured evidence, not hostile
Python adapters; it is not a process isolation layer or an authentication
mechanism for externally supplied result objects. Public-marker attribution is
conservative when event provenance is absent. Transcript-limit loss of an
action's body does not erase its emitted event/effect.

No gateway endpoint, provider forwarding, static `app/risk.py`, DLP, egress,
recognizer, Phase 3 metric, or dashboard benchmark metric changed. Gateway
integration is **NOT YET IMPLEMENTED**. Translating behavioral findings into
production decisions, deciding fallback behavior for NOT_EVALUATED/PARTIAL,
real-model corpus evaluation, target-model comparison, and deployment policy
require a separately scoped later phase.
